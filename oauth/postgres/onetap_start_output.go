package postgres

import (
	"context"
	"encoding/base64"
	"reflect"
	"time"

	authorization "github.com/faustbrian/go-authorization/v3"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

const oneTapCallbackPurpose = "identity.oauth.onetap-callback"

type oneTapStartOutput struct {
	Generation           uint64
	IssuedAt, ExpiresAt  time.Time
	Nonce                [32]byte
	CookieDigest         session.TokenDigest
	Admission            signinStoredAdmission
	Plan                 rpStoredIssuancePlan
	Checkpoint, Callback []byte
}

type oneTapStoredCallbackGrant struct {
	Original rpStoredBinding
	Grant    rpStoredGrant
	Proof    []byte
	// Redirect POST cannot supply the start's trusted stable device. Keep it
	// sealed for future original-cookie-bound completion, never as a public hint.
	Device string `json:",omitempty"`
}

func (p *oneTapStartPhase) outputAAD(generation uint64) (envelope.Context, error) {
	if p.input == nil || generation == 0 {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	return oneTapEnvelopeContext("identity-oauth-onetap-start-output-v1", struct {
		Input      oneTapStartInput
		Generation uint64
	}{*p.input, generation})
}

func (s *OneTapStartService) callbackAAD(binding identity.CommandBinding, expires time.Time) (envelope.Context, error) {
	return oneTapEnvelopeContext("identity-oauth-onetap-callback-proof-v1", struct {
		Original rpStoredBinding
		Profile  [32]byte
		Expires  time.Time
	}{rpStoredBinding(binding), s.profile, expires})
}

func (p *oneTapStartPhase) generateOutput(ctx context.Context, generation uint64, admission risk.AuthenticationAdmission) ([]byte, error) {
	aad, err := p.outputAAD(generation)
	if err != nil || p.sessionIssuer == nil || p.generation != 0 {
		return nil, identity.ForbiddenError{}
	}
	b, s := identity.CommandBinding(p.input.Binding), p.service
	prepared, err := p.sessionIssuer.PrepareOneTapStart(b, p.request.Remember)
	if err != nil {
		return nil, err
	}
	command, ok := prepared.Command()
	if !ok {
		return nil, identity.ForbiddenError{}
	}
	original, err := command.Record.ProviderBindings()
	if err != nil || original.Provider != s.selected {
		return nil, identity.ForbiddenError{}
	}
	flow := original.Transaction.Binding
	c := s.config()
	grant, err := s.issuer.Prepare(ctx, b, []capability.Payload{{Version: 1, Issuer: c.Capability.Crypto.Issuer, Audiences: []string{c.Capability.Audience},
		Subject: b.AnonymousFlowID, Resource: b.RecordID, Operation: oneTapCallbackPurpose, IssuedAt: flow.IssuedAt, NotBefore: flow.IssuedAt,
		ExpiresAt: flow.ExpiresAt, Tenant: string(b.TenantID), CorrelationID: b.CorrelationID, MaxUses: 1}})
	if err != nil {
		return nil, err
	}
	plan, err := grant.Plan()
	if err != nil || len(plan.Grants) != 1 {
		return nil, identity.ForbiddenError{}
	}
	callbackAAD, err := s.callbackAAD(b, flow.ExpiresAt)
	if err != nil {
		return nil, err
	}
	var callback []byte
	checkpoint, err := s.checkpoint.CheckpointPreparation(ctx, grant, generation, func(ctx context.Context, index uint16, proof []byte) error {
		if index != 0 || len(callback) != 0 {
			return identity.ForbiddenError{}
		}
		var err error
		stored := oneTapStoredCallbackGrant{Original: rpStoredBinding(b), Grant: rpStoredGrant(plan.Grants[0]), Proof: proof}
		if s.selected.Mode == session.PreAuthProviderRedirect {
			stored.Device = p.request.Device
		}
		callback, err = s.sealOneTap(ctx, callbackAAD, stored, 65536)
		return err
	})
	defer clear(checkpoint)
	defer clear(callback)
	if err != nil {
		return nil, err
	}
	output := oneTapStartOutput{Generation: generation, IssuedAt: flow.IssuedAt, ExpiresAt: flow.ExpiresAt, Nonce: flow.Intent.Nonce,
		CookieDigest: original.Transaction.Cookie, Admission: signinStoredAdmission(admission.Prepared()),
		Plan: rpStoredIssuancePlan{Contributor: plan.Contributor, Grants: []rpStoredGrant{rpStoredGrant(plan.Grants[0])}}, Checkpoint: checkpoint, Callback: callback}
	wire, err := s.sealOneTap(ctx, aad, output, 256<<10)
	if err == nil {
		p.generated, p.generation = prepared, generation
	}
	return wire, err
}

func (p *oneTapStartPhase) restoreOutput(ctx context.Context, generation uint64, wire []byte) (out oneTapStartOutput, record session.PreAuthTransaction, grant capabilitypg.PreparedIssuance, plan kernel.CapabilityIssuancePlan, err error) {
	aad, err := p.outputAAD(generation)
	if err != nil {
		return out, record, grant, plan, err
	}
	if err := p.service.openOneTap(ctx, aad, wire, 256<<10, &out); err != nil {
		return out, record, grant, plan, err
	}
	if out.Generation != generation || !rpUTCTime(out.IssuedAt) || out.IssuedAt.Nanosecond() != 0 ||
		out.IssuedAt.Before(p.input.ObservedAt.Truncate(time.Second)) || !out.IssuedAt.Before(p.input.ValidUntil) || !out.ExpiresAt.Equal(out.IssuedAt.Add(5*time.Minute)) ||
		len(out.Plan.Grants) != 1 || len(out.Callback) == 0 || len(out.Callback) > 65536 || len(out.Checkpoint) == 0 {
		return oneTapStartOutput{}, record, grant, plan, identity.ForbiddenError{}
	}
	plan = out.Plan.native()
	meta := plan.Grants[0]
	if meta.Purpose != oneTapCallbackPurpose || meta.MaxUses != 1 || !meta.ExpiresAt.Equal(out.ExpiresAt) {
		return oneTapStartOutput{}, record, grant, kernel.CapabilityIssuancePlan{}, identity.ForbiddenError{}
	}
	b := identity.CommandBinding(p.input.Binding)
	grant, err = p.service.checkpoint.RestorePreparation(ctx, b, generation, plan, out.Checkpoint)
	if err != nil {
		return oneTapStartOutput{}, record, grant, kernel.CapabilityIssuancePlan{}, err
	}
	flow := session.PreAuthBinding{ID: identity.PreAuthTransactionID(b.AnonymousFlowID), IssuedAt: out.IssuedAt, ExpiresAt: out.ExpiresAt,
		Intent: session.PreAuthIntent{TenantID: b.TenantID, Action: b.OperationID, Origin: p.request.Origin, CallbackURL: p.service.config().Issuance.CallbackURL, Nonce: out.Nonce, Remember: p.request.Remember,
			PolicyID: b.PolicyID, PolicyVersion: b.PolicyVersion, Purpose: session.PreAuthSessionIssuance}}
	record, err = session.NewProviderPreAuthTransaction(session.ProviderPreAuthTransactionSpec{Provider: p.service.selected,
		Transaction: session.PreAuthTransactionSpec{Binding: flow, Cookie: out.CookieDigest, Version: 1}})
	return out, record, grant, plan, err
}

func (p *oneTapStartPhase) stageCallbackGrant(ctx context.Context, w kernel.Work, out oneTapStartOutput) error {
	b := identity.CommandBinding(p.input.Binding)
	flow, _ := base64.RawURLEncoding.Strict().DecodeString(b.AnonymousFlowID)
	command, _ := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if len(flow) != 16 || len(command) != 16 {
		return identity.ForbiddenError{}
	}
	statement := `INSERT INTO ` + rpQuotedSchema(p.service.config().Schema) + `.onetap_callback_grants
	 (tenant_id,flow_id,origin_command_id,origin_operation,issued_at,expires_at,proof_ciphertext) VALUES($1,$2,$3,$4,$5,$6,$7)`
	count, err := w.Exec(ctx, statement, string(b.TenantID), flow, command, b.OperationID, out.IssuedAt, out.ExpiresAt, out.Callback)
	if err != nil {
		return err
	}
	if count != 1 {
		return identity.ConflictError{}
	}
	return nil
}

func (p *oneTapStartPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	status, err := sessionpg.RecoverOneTapStartPreAuth(ctx, w, p, p.service.config().Session)
	if err != nil || status == kernel.RecoveryUnknown {
		return status, err
	}
	b, _, _, err := w.FeatureScope(p)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	flow, _ := base64.RawURLEncoding.Strict().DecodeString(b.AnonymousFlowID)
	command, _ := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if len(flow) != 16 || len(command) != 16 {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	rows, err := w.Query(ctx, `SELECT origin_command_id=$3 FROM `+rpQuotedSchema(p.service.config().Schema)+`.onetap_callback_grants WHERE tenant_id=$1 AND flow_id=$2`, string(b.TenantID), flow, command)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil || status != kernel.RecoveryNotCommitted {
			return kernel.RecoveryUnknown, identity.UnavailableError{}
		}
		return status, nil
	}
	var original bool
	if rows.Scan(&original) != nil || !original || rows.Next() || rows.Err() != nil || status != kernel.RecoveryCommitted {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	return status, nil
}

func (p *oneTapStartPhase) deliver(ctx context.Context, result OneTapStartResult, receipt identity.CommandResult) (OneTapStartResult, error) {
	if receipt.Outcome != identity.CommitOutcomeCommitted || result.Outcome != identity.CommitOutcomeCommitted || receipt.Binding != identity.CommandBinding(p.input.Binding) || receipt.Feature == nil || receipt.Feature.Operation != kernel.OneTapStartOperation() || receipt.Feature.AfterVersion != 1 {
		return result, identity.UnavailableError{}
	}
	if !p.applied {
		result.Replayed = true
		return result, nil
	}
	p.delivery = &receipt
	issued, err := p.sessionIssuer.Issue(ctx, p.generated)
	if err != nil {
		return result, err
	}
	bound, err := issued.Flow.ProviderBindings()
	if err != nil || bound.Provider != p.service.selected || issued.Token == (session.Token{}) || issued.Replayed || issued.CommitOutcome != identity.CommitOutcomeCommitted {
		return result, identity.UnavailableError{}
	}
	flow := bound.Transaction.Binding
	if bound.Provider.Mode == session.PreAuthProviderRedirect {
		return p.deliverRedirect(result, issued, bound)
	}
	if bound.Provider.Mode != session.PreAuthProviderCallback || issued.Cookie.Name != "__Host-identity_flow" {
		return result, identity.UnavailableError{}
	}
	browser := OneTapBrowserStart{FlowID: flow.ID, ClientID: bound.Provider.ClientID, Nonce: base64.RawURLEncoding.EncodeToString(flow.Intent.Nonce[:]),
		Origin: flow.Intent.Origin, ExpiresAt: flow.ExpiresAt, Options: p.request.Options, Cookie: issued.Cookie, Token: issued.Token}
	result.browser = func() OneTapBrowserStart { return browser }
	return result, nil
}

func (p *oneTapStartPhase) deliverRedirect(result OneTapStartResult, issued session.PreAuthIssueResult, bound session.ProviderPreAuthTransactionSpec) (OneTapStartResult, error) {
	s := p.service
	c := s.config()
	flow := bound.Transaction.Binding
	policy, err := session.NewOneTapRedirectFrontchannelCookiePolicy(c.Issuance.Origin, c.Issuance.CallbackURL)
	if err != nil || issued.Cookie.MaxAge <= 0 || issued.Cookie.MaxAge > 300 {
		return result, identity.UnavailableError{}
	}
	// Reconstruct only the issuer cookie's attribute timestamp, never flow
	// authority. The original provider-bound flow is checked independently.
	cookieAt := issued.Cookie.Expires.Add(-time.Duration(issued.Cookie.MaxAge) * time.Second)
	wantCookie, err := policy.Attributes(cookieAt, flow.ExpiresAt)
	if err != nil || !reflect.DeepEqual(issued.Cookie, wantCookie) {
		return result, identity.UnavailableError{}
	}
	projection, err := s.redirectValidator.BrowserRedirectStart(p.request.Options, issued.Flow)
	if err != nil {
		return result, identity.UnavailableError{}
	}
	now := c.Issuance.Clock.Now().UTC()
	if issued.Flow.CheckProvider(now, flow, s.selected, bound.Transaction.Cookie) != nil || !now.Before(issued.Cookie.Expires) {
		return result, identity.UnavailableError{}
	}
	browser := OneTapRedirectBrowserStart{Projection: projection, Cookie: issued.Cookie, Token: issued.Token}
	result.redirectBrowser = func() OneTapRedirectBrowserStart { return browser }
	return result, nil
}

func (p *oneTapStartPhase) ExecutePreAuthIssuance(ctx context.Context, command session.PreAuthIssueCommand) (session.PreAuthIssueExecution, error) {
	original, ok := p.generated.Command()
	if ctx == nil || ctx.Err() != nil || p.delivery == nil || !ok || original != command {
		return session.PreAuthIssueExecution{}, identity.ForbiddenError{}
	}
	receipt := *p.delivery
	p.delivery = nil
	return session.PreAuthIssueExecution{Receipt: receipt}, nil
}

func (p *oneTapStartPhase) RecoverPreAuthIssue(ctx context.Context, q identity.RecoveryQuery) (identity.CommandResult, error) {
	return p.service.recoverOneTap(ctx, q)
}

func (s *OneTapStartService) recoverOneTap(ctx context.Context, q identity.RecoveryQuery) (identity.CommandResult, error) {
	c := s.config()
	if q.TenantID != c.TenantID || q.ActorID != c.Issuance.ActorID || q.ActorKind != authorization.SubjectServiceAccount ||
		q.OperationID != oneTapStartOperationID || q.AnonymousFlowID != q.RecordID || q.AnonymousFlowID == "" || q.UserID != "" {
		return identity.CommandResult{}, identity.ForbiddenError{}
	}
	coordinator, _, err := s.coordinator(&oneTapStartPhase{service: s})
	if err != nil {
		return identity.CommandResult{}, err
	}
	// The coordinator authorizes the original action with its own recovery
	// attribute. A separate action cannot match the historical receipt scope.
	return coordinator.RecoverFeatureCommand(ctx, q, s.caller(oneTapStartOperationID, "identity.anonymous-flow", q.AnonymousFlowID))
}
