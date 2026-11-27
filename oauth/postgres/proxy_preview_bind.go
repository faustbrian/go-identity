package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"reflect"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	oauthproxy "github.com/faustbrian/go-identity/oauth/proxy"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// Bind persistently records the expected production response and original
// browser before the caller sends the authorization redirect. The preview
// creates one scoped callback proof; it neither consumes the browser nor
// creates an account or session. Only the exact command may be retried.
func (s *ProxyPreviewService) Bind(ctx context.Context, r ProxyPreviewBindRequest) (err error) {
	if s == nil || s.signin == nil || ctx == nil || r.Origin != s.config.Target.Origin ||
		!rpASCII(r.Device, 1, 128) || !rpASCII(r.Network, 1, 128) {
		return oauthproxy.CompletionInvalid
	}
	defer func() {
		if recover() != nil {
			err = oauthproxy.CompletionUnavailable
		}
	}()
	if _, ok := s.registered(r.Binding); !ok {
		return oauthproxy.CompletionDenied
	}
	start := s.signin.start
	ctx, stop := context.WithTimeout(ctx, start.config.MaximumDuration)
	defer stop()
	if err := requireProxyProviderAuthority(ctx, s.authority, r.Binding); err != nil {
		return err
	}
	p, err := s.bindPhase(ctx, r)
	if err != nil {
		return err
	}
	defer p.row.clear()
	if err := p.configure(); err != nil {
		return err
	}
	receipt, err := p.coordinator.ExecutePreparedFeature(ctx, p.command, p.plan(nil))
	if err != nil {
		return err
	}
	if receipt.Outcome != identity.CommitOutcomeCommitted || ctx.Err() != nil {
		return oauthproxy.CompletionUnavailable
	}
	return requireProxyProviderAuthority(ctx, s.authority, r.Binding)
}

type proxyPreviewBindPhase struct {
	service     *ProxyPreviewService
	request     ProxyPreviewBindRequest
	flow        session.PreAuthTransaction
	expected    proxyPreviewBinding
	readStarted time.Time
	locator     proxyPreviewBindingLocator
	original    identity.CommandBinding
	requestSum  [32]byte
	command     identity.Command
	coordinator *kernel.Coordinator
	registry    *kernel.ContributorRegistry
	audit       kernel.AuditPlan
	row         proxyPreviewRow
	issued      capabilitypg.PreparedIssuance
	generation  uint64
	sealedSum   [32]byte
	admission   risk.AuthenticationAdmission
}

func (s *ProxyPreviewService) bindPhase(ctx context.Context, r ProxyPreviewBindRequest) (*proxyPreviewBindPhase, error) {
	start, b := s.signin.start, r.Binding
	readStarted := s.config.Clock.Now().UTC()
	l := proxyPreviewBindingLocator{Tenant: s.config.TenantID, Flow: b.TransactionID, OriginCommand: b.CommandID, IssuedAt: b.IssuedAt, ExpiresAt: b.ExpiresAt}
	original := s.originCommand(l)
	if original.ValidateFor(rpSigninStartOperation()) != nil || string(l.Flow) == string(l.OriginCommand) ||
		readStarted.Before(l.IssuedAt) || !readStarted.Before(l.ExpiresAt) {
		return nil, oauthproxy.CompletionDenied
	}
	flow, err := sessionpg.ReadPreAuth(ctx, start.pool.Raw(), start.config.Session, l.Tenant, l.Flow)
	if err != nil {
		return nil, err
	}
	stored, err := flow.Bindings()
	if err != nil {
		return nil, err
	}
	if cutoff := stored.Binding.ExpiresAt.UTC().Truncate(time.Second); cutoff.Before(l.ExpiresAt) {
		l.ExpiresAt = cutoff
	}
	if !readStarted.Before(l.ExpiresAt) || !proxyBindingSQLTime(l.IssuedAt) || !proxyBindingSQLTime(l.ExpiresAt) ||
		l.IssuedAt.Nanosecond() != 0 || l.ExpiresAt.Nanosecond() != 0 || !l.ExpiresAt.After(l.IssuedAt) || l.ExpiresAt.Sub(l.IssuedAt) > 5*time.Minute {
		return nil, oauthproxy.CompletionDenied
	}
	scope := signinBrowserScope{Tenant: l.Tenant, FlowID: l.Flow, Cookie: r.FlowCookie, Origin: r.Origin,
		Callback: s.config.Target.Redirect, Remember: b.Remember}
	if err := checkSigninOriginalBrowser(scope, flow, start.config.FlowKeys, original.PolicyID, original.PolicyVersion, s.config.Clock.Now().UTC()); err != nil {
		return nil, err
	}
	commitment, err := signinFlowDigest(flow)
	if err != nil {
		return nil, err
	}
	authority, err := start.directory.GetDirectoryAuthority(ctx, kernel.DirectoryAuthorityQuery{GlobalAuthorityID: start.config.GlobalAuthorityID, TenantID: l.Tenant})
	if err != nil {
		return nil, err
	}
	if !authority.Enabled {
		return nil, oauthproxy.CompletionDenied
	}
	expected := proxyPreviewBinding{Evidence: b, PreAuthDigest: commitment, GlobalVersion: authority.GlobalVersion, TenantVersion: authority.TenantVersion}
	record, err := freezeProxyEvidence(b)
	if err != nil {
		return nil, err
	}
	if _, err := record.evidence(); err != nil {
		return nil, oauthproxy.CompletionDenied
	}
	frame, err := json.Marshal([]any{"identity.oauth.proxy-preview.request.v1", record, commitment, l.ExpiresAt, authority.GlobalVersion,
		authority.TenantVersion, r.Network, r.Device, s.signin.profile})
	defer clear(frame)
	if err != nil {
		return nil, err
	}
	requestSum := sha256.Sum256(frame)
	command, err := identity.NewFeaturePreAuthCommand(identity.FeatureCommandSpec{Binding: original, Operation: rpSigninStartOperation(),
		Fields: []identity.FeatureField{previewField("oauth.proxy.preview.request", requestSum)}}, r.FlowCookie)
	if err != nil {
		return nil, err
	}
	auditPlan, err := rpTransactionAudit(ctx, original, rpSigninStartOperation(), 0, 1, l.IssuedAt, start.config.AuditRetentionPolicyVersion)
	if err != nil {
		return nil, err
	}
	return &proxyPreviewBindPhase{service: s, request: r, flow: flow, expected: expected, readStarted: readStarted,
		locator: l, original: original, requestSum: requestSum, command: command, audit: auditPlan}, nil
}

func (*proxyPreviewBindPhase) Descriptor() kernel.ContributorDescriptor {
	return (&signinStartPhase{}).Descriptor()
}

func (*proxyPreviewBindPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{rpSigninStartOperation()}
}

func (p *proxyPreviewBindPhase) configure() error {
	start := p.service.signin.start
	auditOwner, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return err
	}
	lifecycle, err := lifecyclepg.NewContributor()
	if err != nil {
		return err
	}
	p.registry, err = kernel.NewContributorRegistry([]kernel.Contributor{start.directory, auditOwner, lifecycle, p, start.issuer})
	if err != nil {
		return err
	}
	p.coordinator, err = kernel.NewCoordinator(start.pool, p.registry, start.config.Coordinator)
	return err
}

func (p *proxyPreviewBindPhase) plan(issuance *kernel.CapabilityIssuancePlan) kernel.CommandPlan {
	feature := kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: rpSigninStartOperation()}
	lifecycle := rpStartLifecycle()
	owners := p.registry.Descriptors()
	if issuance == nil {
		owners = owners[:len(owners)-1]
	}
	return kernel.CommandPlan{Feature: &feature, Contributors: owners, SubjectType: "oauth_transaction", Audits: []kernel.AuditPlan{p.audit}, Lifecycle: &lifecycle, CapabilityIssuance: issuance}
}

func (p *proxyPreviewBindPhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if c != p.command || plan.Feature == nil || *plan.Feature != (kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: rpSigninStartOperation()}) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *proxyPreviewBindPhase) ValidateFeaturePreparation(c identity.Command, plan kernel.CommandPlan) error {
	if plan.CapabilityIssuance != nil {
		return identity.ForbiddenError{}
	}
	return p.ValidateFeatureCommand(c, plan)
}

func (p *proxyPreviewBindPhase) check(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.command {
		return identity.ForbiddenError{}
	}
	if err := requireProxyProviderAuthority(ctx, p.service.authority, p.expected.Evidence); err != nil {
		return err
	}
	s := p.service.signin.start
	if err := w.RequireActiveDirectoryAuthority(ctx, p, kernel.DirectoryAuthorityAdmission{
		Query:         kernel.DirectoryAuthorityQuery{GlobalAuthorityID: s.config.GlobalAuthorityID, TenantID: p.locator.Tenant},
		GlobalVersion: p.expected.GlobalVersion, TenantVersion: p.expected.TenantVersion,
	}); err != nil {
		return err
	}
	if err := sessionpg.RequirePreAuth(ctx, w, s.config.Session, p.flow); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil || now.Before(p.readStarted) || !now.Before(p.readStarted.Add(20*time.Second)) || !now.Before(p.locator.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	scope := signinBrowserScope{Tenant: p.locator.Tenant, FlowID: p.locator.Flow, Cookie: p.request.FlowCookie, Origin: p.request.Origin,
		Callback: p.service.config.Target.Redirect, Remember: p.expected.Evidence.Remember}
	return checkSigninOriginalBrowser(scope, p.flow, s.config.FlowKeys, p.original.PolicyID, p.original.PolicyVersion, now)
}

func (p *proxyPreviewBindPhase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, c identity.Command) error {
	return p.check(ctx, w, c)
}

func (p *proxyPreviewBindPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if err := p.check(ctx, w, c); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	return p.admission.CheckAt(ctx, now)
}

func (p *proxyPreviewBindPhase) riskScope() (risk.Context, risk.Subject) {
	b := p.original
	return risk.Context{Tenant: string(b.TenantID), Operation: risk.Action(b.OperationID), Attempt: string(b.CommandID)},
		risk.Subject{Network: p.request.Network, Device: p.request.Device}
}

type proxyPreviewBindAdmission struct {
	phase     *proxyPreviewBindPhase
	admission risk.AuthenticationAdmission
}

func (a proxyPreviewBindAdmission) Check(ctx context.Context) error {
	now := a.phase.service.config.Clock.Now().UTC()
	if ctx.Err() != nil || now.Before(a.phase.readStarted) || !now.Before(a.phase.readStarted.Add(20*time.Second)) || !now.Before(a.phase.locator.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	return a.admission.CheckAt(ctx, now)
}

func (a proxyPreviewBindAdmission) Generate(ctx context.Context, gen uint64) ([]byte, error) {
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	return a.phase.generate(ctx, gen, a.admission)
}

func (p *proxyPreviewBindPhase) PrepareFeatureAdmission(ctx context.Context, c identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if c != p.command {
		return nil, identity.ForbiddenError{}
	}
	start := p.service.signin.start
	scope, subject := p.riskScope()
	id := p.original.CommandID
	result, err := start.config.Risk.Evaluation.Evaluate(ctx, risk.EvaluateRequest{Context: scope, Phase: risk.NonIssuing, Subject: subject,
		Attribution: &risk.DecisionAttribution{CommandID: id, CorrelationID: id, Actor: audit.ActorInput{Kind: audit.ActorAnonymous},
			Subject: identity.SecurityAuthenticationAttempt, SubjectID: string(id)}})
	if err != nil {
		return nil, err
	}
	admission, err := start.custody.Prepare(ctx, result, scope, subject)
	if err != nil {
		return nil, err
	}
	a := proxyPreviewBindAdmission{phase: p, admission: admission}
	return a, a.Check(ctx)
}

func (*proxyPreviewBindPhase) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, identity.ForbiddenError{}
}

type proxyPreviewBindOutput struct {
	Version                    uint8
	Callback                   identity.CommandID
	Binding, Proof, Checkpoint []byte
	Grant                      rpStoredGrant
	Admission                  signinStoredAdmission
}

func (o *proxyPreviewBindOutput) clear() {
	clear(o.Binding)
	clear(o.Proof)
	clear(o.Checkpoint)
	*o = proxyPreviewBindOutput{}
}

func (p *proxyPreviewBindPhase) outputAAD(gen uint64) (envelope.Context, error) {
	if gen == 0 || p.requestSum == ([32]byte{}) {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	frame, err := json.Marshal([]any{string(p.original.TenantID), string(p.original.CommandID), string(p.locator.Flow), p.requestSum, gen})
	defer clear(frame)
	if err != nil {
		return envelope.Context{}, err
	}
	digest := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"profile": "identity-oauth-preview-bind-output-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func (p *proxyPreviewBindPhase) generate(ctx context.Context, gen uint64, admission risk.AuthenticationAdmission) ([]byte, error) {
	aad, err := p.outputAAD(gen)
	if err != nil {
		return nil, err
	}
	start, l := p.service.signin.start, p.locator
	l.CallbackCommand, err = identity.NewCommandID()
	if err != nil || l.CallbackCommand == l.OriginCommand || string(l.CallbackCommand) == string(l.Flow) {
		return nil, identity.UnavailableError{}
	}
	out := proxyPreviewBindOutput{Version: 1, Callback: l.CallbackCommand, Admission: signinStoredAdmission(admission.Prepared())}
	defer out.clear()
	var digest [32]byte
	out.Binding, digest, err = sealProxyPreviewBinding(ctx, start.envelopes, start.config.CurrentEnvelopeKey, l, p.expected)
	if err != nil {
		return nil, err
	}
	proofAAD, err := proxyPreviewProofAAD(digest)
	if err != nil {
		return nil, err
	}
	config := start.config.Capability
	issued, err := start.issuer.Prepare(ctx, p.original, []capability.Payload{proxyPreviewGrantPayload(l, config.Crypto.Issuer, config.Audience, digest)})
	if err != nil {
		return nil, err
	}
	plan, err := issued.Plan()
	if err != nil || len(plan.Grants) != 1 {
		return nil, identity.UnavailableError{}
	}
	out.Grant = rpStoredGrant(plan.Grants[0])
	out.Checkpoint, err = start.checkpoint.CheckpointPreparation(ctx, issued, gen, func(ctx context.Context, index uint16, proof []byte) error {
		if index != 0 || len(proof) == 0 || len(proof) > proxyPreviewProofLimit-5 || len(out.Proof) != 0 {
			return identity.ForbiddenError{}
		}
		plain := binary.BigEndian.AppendUint32([]byte{1}, out.Grant.ReplayKeyVersion)
		plain = append(plain, proof...)
		defer clear(plain)
		var err error
		out.Proof, err = start.seal(ctx, proofAAD, plain)
		return err
	})
	if err != nil || len(out.Proof) == 0 {
		return nil, identity.UnavailableError{}
	}
	plain, err := json.Marshal(out)
	defer clear(plain)
	if err != nil || len(plain) > 160<<10 {
		return nil, identity.UnavailableError{}
	}
	return start.seal(ctx, aad, plain)
}

func (p *proxyPreviewBindPhase) RestoreFeatureAdmission(ctx context.Context, c identity.Command, gen uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if _, _, err := p.RestoreFeaturePreparation(ctx, c, gen, wire); err != nil {
		return nil, err
	}
	a := proxyPreviewBindAdmission{phase: p, admission: p.admission}
	return a, a.Check(ctx)
}

func (p *proxyPreviewBindPhase) RestoreFeaturePreparation(ctx context.Context, c identity.Command, gen uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	if c != p.command {
		return identity.Command{}, kernel.CommandPlan{}, identity.ForbiddenError{}
	}
	aad, err := p.outputAAD(gen)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	start := p.service.signin.start
	plain, err := start.open(ctx, aad, wire, 160<<10)
	defer clear(plain)
	var out proxyPreviewBindOutput
	defer out.clear()
	if err != nil || decodeRPOutput(plain, &out) != nil || out.Version != 1 || len(out.Proof) == 0 || len(out.Proof) > proxyBindingMaximumWire {
		return identity.Command{}, kernel.CommandPlan{}, identity.ForbiddenError{}
	}
	l := p.locator
	l.CallbackCommand = out.Callback
	row := proxyPreviewRow{locator: l, binding: out.Binding, proof: out.Proof}
	stored, digest, err := openProxyPreviewBinding(ctx, start.envelopes, l, row.binding)
	if err != nil || !reflect.DeepEqual(stored, p.expected) || string(l.CallbackCommand) == string(l.Flow) {
		return identity.Command{}, kernel.CommandPlan{}, identity.ForbiddenError{}
	}
	grant, err := p.service.openGrant(ctx, row, digest, p.original)
	if err != nil || grant != kernel.CapabilityPlan(out.Grant) {
		return identity.Command{}, kernel.CommandPlan{}, identity.ForbiddenError{}
	}
	plan := kernel.CapabilityIssuancePlan{Contributor: start.issuer.Descriptor(), Grants: []kernel.CapabilityPlan{grant}}
	issued, err := start.checkpoint.RestorePreparation(ctx, p.original, gen, plan, out.Checkpoint)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	scope, subject := p.riskScope()
	admission, err := start.custody.Restore(ctx, risk.PreparedAuthenticationAdmission(out.Admission), scope, subject)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	p.row.clear()
	p.row, p.issued, p.admission, p.generation, p.sealedSum = row, issued, admission, gen, sha256.Sum256(wire)
	out.Binding, out.Proof = nil, nil
	return c, p.plan(&plan), nil
}

func (p *proxyPreviewBindPhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if err := w.RequireFeatureCommand(ctx, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	wire, generation, err := w.FeaturePreparationOutput(p)
	defer clear(wire)
	if err != nil || generation != p.generation || sha256.Sum256(wire) != p.sealedSum {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	if err := p.CheckFeatureCommit(ctx, w, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	start := p.service.signin.start
	if err := insertProxyPreviewRow(ctx, w, start.config.Schema, p.row); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := start.issuer.Stage(ctx, w, p.issued); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: rpSigninStartOperation(), AfterVersion: 1}, nil
}

func (p *proxyPreviewBindPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, err := w.Scope()
	if err != nil || b.ValidateFor(rpSigninStartOperation()) != nil || b.AnonymousFlowID != b.RecordID {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	command, err := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	if err != nil {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	rows, err := w.Query(ctx, recoverProxyPreviewBindingSQL(p.service.signin.start.config.Schema), string(b.TenantID), b.RecordID, command)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return kernel.RecoveryUnknown, identity.UnavailableError{}
		}
		return kernel.RecoveryNotCommitted, nil
	}
	var flow string
	if rows.Scan(&flow) != nil || rows.Next() || rows.Err() != nil || flow != b.RecordID {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	return kernel.RecoveryCommitted, nil
}

var _ kernel.FeatureAdmissionPreparationContributor = (*proxyPreviewBindPhase)(nil)
var _ kernel.FeatureCommitContributor = (*proxyPreviewBindPhase)(nil)
