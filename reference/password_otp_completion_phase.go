package reference

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization"
	policy "github.com/faustbrian/go-authorization/postgres"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/v2/postgres/identity"
)

type passwordOTPCompletionPhase struct {
	state                     *passwordOTPCompletionState
	request                   mfa.OtpVerifyRequest
	source                    *passwordOTPCompletionSource
	original, mapped, command identity.Command
	child                     kernel.CapabilityPlan
	otp                       kernel.OTPAttemptPlan
	counter                   kernel.CommandCounterPlan
	registry                  *kernel.ContributorRegistry
	coordinator               *kernel.Coordinator
	admission                 risk.ProtectedProviderAdmission
	issuer                    *session.SessionIssuer
	delivery                  *passwordOTPCompletionDelivery
	prepared                  session.PreparedIssuance
	observedUntil, preparedAt time.Time
	locked                    mfapg.LockedOTPCompletionAttempt
	applied                   bool
}

func (*passwordOTPCompletionPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}
}
func (*passwordOTPCompletionPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{passwordOTPCompletionOperation()}
}
func (p *passwordOTPCompletionPhase) compose() error {
	a, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return err
	}
	l, err := lifecyclepg.NewContributor()
	if err != nil {
		return err
	}
	s := p.state.sender
	p.registry, err = kernel.NewContributorRegistry([]kernel.Contributor{s.directory, a, l, p, s.counters, s.config.Issuance.CompletionContributor(), capabilitypg.NewParticipant()})
	if err != nil {
		return err
	}
	p.coordinator, err = kernel.NewCoordinator(s.pool, p.registry, s.config.Coordinator)
	if err != nil {
		return err
	}
	p.delivery = &passwordOTPCompletionDelivery{}
	p.issuer, err = session.NewMFAPasswordSessionIssuerWithCSRF(p.delivery, p.state.config.SessionIssuer, p.state.config.CSRF)
	return err
}

func (p *passwordOTPCompletionPhase) originalCommand() (identity.Command, error) {
	r, s := p.request, p.state.sender
	key := s.config.intentKey()
	defer clear(key[:])
	digest, err := r.Proof.CommandDigest(key, "password-otp-completion-original-proof-v1", 65536)
	if err != nil {
		return identity.Command{}, err
	}
	op := passwordOTPCompletionOperation()
	b := identity.CommandBinding{CommandID: r.CommandID, TenantID: r.TenantID, AnonymousFlowID: string(r.PreAuthID), ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: r.Caller.Request.Subject.Kind, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: s.config.PolicyID, PolicyVersion: s.config.Coordinator.AdmissionPolicy.PolicyVersion, CorrelationID: string(r.CommandID)}
	text := func(name, value string) identity.FeatureField {
		return identity.FeatureField{Name: name, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: value}}
	}
	root := identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: []identity.FeatureField{
		text("factor.continuation", string(r.ContinuationID)), text("transport.origin", r.Origin), text("transport.callback", r.Callback), text("transport.network", r.Network), text("transport.device", r.Device), text("factor.configuration", p.state.config.ConfigurationID),
		{Name: "factor.proof", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}},
		{Name: "factor.sender", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: s.identity[:]}},
	}}
	return identity.NewFeatureOneTimeCodePreAuthCommand(root, r.Code, r.Cookie)
}

func (p *passwordOTPCompletionPhase) completion() (kernel.MFACompletionPlan, error) {
	if p.source == nil {
		return kernel.MFACompletionPlan{}, invalidPasswordOTPCompletion()
	}
	c, err := p.source.continuation.Bindings()
	if err != nil {
		return kernel.MFACompletionPlan{}, err
	}
	digest, err := p.source.continuation.ScopeDigest()
	if err != nil {
		return kernel.MFACompletionPlan{}, err
	}
	return kernel.MFACompletionPlan{ID: identity.CommandID(c.ID), UserID: identity.UserID(c.SubjectID), ScopeDigest: digest, PolicyVersion: c.PolicyVersion, FactorVersion: c.FactorVersion, ContinuationVersion: c.Version}, nil
}

func (p *passwordOTPCompletionPhase) prepareCommand(ctx context.Context, retained identity.FeatureCommandSpec, plan kernel.CommandPlan, retry bool) error {
	s := p.state.sender
	root, _ := p.original.Feature()
	grant, _, version, err := s.issuer.ReadIssuanceOrigin(ctx, s.pool, p.request.Proof, "identity.mfa.complete")
	if err != nil {
		return err
	}
	c, err := p.source.continuation.Bindings()
	if err != nil {
		return err
	}
	scope, err := p.source.continuation.ScopeDigest()
	if err != nil {
		return err
	}
	p.child, err = s.issuer.PrepareMFAConsumption(ctx, root.Binding, identity.UserID(c.SubjectID), identity.CommandID(c.ID), scope, s.config.IssuerURL, p.request.Proof, grant.EnvelopeDigest(), version)
	if err != nil {
		return err
	}
	if retry {
		if plan.CommandCounters == nil || plan.OTP == nil || plan.Capability == nil || *plan.Capability != p.child {
			return identity.ConflictError{}
		}
		spec := retained
		spec.Fields = nil
		for _, field := range retained.Fields {
			if !strings.HasPrefix(field.Name, "otp.") {
				spec.Fields = append(spec.Fields, field)
			}
		}
		base, err := identity.NewFeaturePreAuthCommand(spec, p.request.Cookie)
		if err != nil {
			return err
		}
		p.mapped, p.otp, err = p.source.completion.RestorePrepared(ctx, base, p.request.Code, retained)
		if err != nil {
			return err
		}
		p.counter = *plan.CommandCounters
		for _, field := range retained.Fields {
			if field.Name == "counter.prepared-at" {
				p.preparedAt = field.Value.Time
			}
		}
		if p.preparedAt.IsZero() || *plan.OTP != p.otp {
			return identity.ConflictError{}
		}
		return nil
	}
	if err := s.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&p.preparedAt); err != nil {
		return identity.UnavailableError{}
	}
	p.preparedAt = p.preparedAt.UTC().Round(0)
	base, err := identity.NewFeaturePreAuthCommand(root, p.request.Cookie)
	if err != nil {
		return err
	}
	command, otp, err := p.source.completion.Prepare(ctx, s.pool, base, p.request.Code, p.state.config.AttemptKeyVersion)
	if err != nil {
		return err
	}
	p.otp = otp
	completion, err := p.completion()
	if err != nil {
		return err
	}
	p.mapped, p.counter, err = s.counters.PrepareMFACompletionCommandCounters(command, risk.Subject{User: string(completion.UserID), Network: p.request.Network}, p.child, completion, p.preparedAt)
	return err
}

func (p *passwordOTPCompletionPhase) declaration() (kernel.CommandPlan, error) {
	completion, err := p.completion()
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	f, _ := p.original.Feature()
	b := f.Binding
	actor := audit.ActorService
	if b.ActorKind == authorization.SubjectUser {
		actor = audit.ActorHuman
	}
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	subject := "authentication_attempt"
	seed, err := builder.Build(audit.RecordInput{OccurredAt: p.preparedAt, Action: b.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: actor, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: subject, ID: b.AnonymousFlowID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": subject, "aggregate.id": b.AnonymousFlowID, "aggregate.before_version": "0", "aggregate.after_version": "0", "retention.class": "protected"}})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, f.Operation, subject, seed)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	child, otp, counter := p.child, p.otp, p.counter
	return kernel.CommandPlan{Contributors: p.registry.Descriptors(), Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: f.Operation}, SubjectType: subject, MFACompletion: &completion, Capability: &child, OTP: &otp, CommandCounters: &counter, Lifecycle: &kernel.LifecyclePlan{EventType: "session.created.v1"}, Audits: []kernel.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}}, nil
}

func (p *passwordOTPCompletionPhase) ValidateMFACompletion(command identity.Command, child kernel.CapabilityPlan, scope kernel.MFACompletionPlan) error {
	want, err := p.completion()
	if err != nil || child != p.child || scope != want || command != (p.mapped) && command != (p.command) {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *passwordOTPCompletionPhase) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	if plan.Feature == nil || plan.Feature.Contributor != p.Descriptor() || plan.Feature.Operation != passwordOTPCompletionOperation() || plan.MFACompletion == nil || plan.Capability == nil || plan.OTP == nil || *plan.OTP != p.otp || plan.CommandCounters == nil || *plan.CommandCounters != p.counter || plan.SubjectType != "authentication_attempt" || plan.Lifecycle == nil || plan.Lifecycle.EventType != "session.created.v1" || plan.Lifecycle.BeforeVersion != 0 || plan.Lifecycle.AfterVersion != 0 || plan.Delivery != nil || plan.CapabilityIssuance != nil || plan.MFAContinuation != nil || plan.RiskEvidence != nil || plan.CaptchaEvidence != nil {
		return invalidPasswordOTPCompletion()
	}
	return p.ValidateMFACompletion(command, *plan.Capability, *plan.MFACompletion)
}
func (p *passwordOTPCompletionPhase) ValidateFeaturePreparation(command identity.Command, plan kernel.CommandPlan) error {
	if command != p.mapped {
		return invalidPasswordOTPCompletion()
	}
	return p.ValidateFeatureCommand(command, plan)
}

func (p *passwordOTPCompletionPhase) flow() (session.PreAuthTransaction, error) {
	if p.source == nil {
		return session.PreAuthTransaction{}, invalidPasswordOTPCompletion()
	}
	b, err := p.source.native.Continuation.Bindings()
	if err != nil {
		return session.PreAuthTransaction{}, err
	}
	flow, correlation, ok := b.Authorization.MFAContinuation()
	if !ok || correlation.PrimaryCommandID != p.source.primary.CommandID {
		return session.PreAuthTransaction{}, identity.ForbiddenError{}
	}
	return flow, nil
}
func (p *passwordOTPCompletionPhase) browser(ctx context.Context, now time.Time) error {
	if p.source == nil || ctx == nil {
		return invalidPasswordOTPCompletion()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	c, err := p.source.continuation.Bindings()
	if err != nil || now.Before(c.IssuedAt) || !now.Before(c.ExpiresAt) || !now.Before(c.PrimaryProofExpiresAt) || p.observedUntil.IsZero() || !now.Before(p.observedUntil) {
		return identity.ForbiddenError{}
	}
	flow, err := p.flow()
	if err != nil {
		return err
	}
	f, err := flow.Bindings()
	if err != nil {
		return err
	}
	token, err := session.ParseToken(p.request.Cookie.Token())
	if err != nil {
		return identity.ForbiddenError{}
	}
	digest, err := token.PreAuthDigest(p.state.sender.config.CookieKeys[f.Cookie.KeyVersion], f.Binding)
	if err != nil || flow.Check(now, f.Binding, digest) != nil {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *passwordOTPCompletionPhase) directoryAdmission() (kernel.DirectoryAuthorityAdmission, error) {
	a, err := p.source.primary.Authority.Bindings()
	if err != nil {
		return kernel.DirectoryAuthorityAdmission{}, err
	}
	return kernel.DirectoryAuthorityAdmission{Query: kernel.DirectoryAuthorityQuery{GlobalAuthorityID: p.state.sender.config.Profile.GlobalAuthorityID, TenantID: p.request.TenantID}, GlobalVersion: a.Global.Version, TenantVersion: a.Tenant.Version}, nil
}
func (p *passwordOTPCompletionPhase) credential() (kernel.CredentialAdmission, error) {
	s := p.source.primary.Authentication
	a, err := p.source.primary.Authority.Bindings()
	if err != nil {
		return kernel.CredentialAdmission{}, err
	}
	return kernel.CredentialAdmission{Credential: identity.CredentialRef{ID: identity.CredentialID(s.CredentialID), TenantID: p.request.TenantID, UserID: p.source.primary.Recipient.User.ID, Kind: identity.CredentialPassword, Owner: "identity/password", Version: s.CredentialVersion}, UserAuthorityVersion: a.User.Version, IdentifierAuthorityVersion: a.Identifier.Version, CredentialAuthorityVersion: a.Credential.Version}, nil
}
func (p *passwordOTPCompletionPhase) policyScope() policy.AuthorityScope {
	return policy.AuthorityScope{TenantID: authorization.TenantID(p.request.TenantID), SubjectID: authorization.SubjectID(p.source.primary.Recipient.User.ID), PolicyNamespace: p.state.sender.config.Profile.PolicyNamespace}
}

func (p *passwordOTPCompletionPhase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, command identity.Command) error {
	if p.source == nil || command != p.mapped && command != p.command {
		return identity.ForbiddenError{}
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if err = p.browser(ctx, now); err != nil {
		return err
	}
	f, _ := command.Feature()
	flow, err := p.flow()
	if err != nil {
		return err
	}
	if err = sessionpg.RequireMFAOTPConsumedPreAuth(ctx, w, f.Binding, p.state.sender.config.Session, flow, p.source.primary.CommandID); err != nil {
		return err
	}
	d, err := p.directoryAdmission()
	if err != nil {
		return err
	}
	if err = w.RequireActiveDirectoryAuthority(ctx, p, d); err != nil {
		return err
	}
	r := p.source.primary.Recipient
	if err = w.RequireRecipient(ctx, p, r); err != nil {
		return err
	}
	credential, err := p.credential()
	if err != nil {
		return err
	}
	if _, err = w.RequireRecipientCredential(ctx, p, r, credential); err != nil {
		return err
	}
	a, _ := p.source.primary.Authority.Bindings()
	return policy.RequireAuthority(ctx, w, p.policyScope(), a.Authorization.Version, p.state.sender.config.MaximumDuration)
}

func (p *passwordOTPCompletionPhase) PrepareMFAOTPAttempt(ctx context.Context, w kernel.MFAOTPAttemptWork) (kernel.MFAAttemptDisposition, error) {
	command, err := w.NativeCommand(p)
	if err != nil || command != p.command {
		return 0, identity.ForbiddenError{}
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return 0, err
	}
	if err = p.browser(ctx, now); err != nil {
		return 0, err
	}
	if err = p.admission.CheckAt(ctx, now); err != nil {
		return 0, err
	}
	f, _ := command.Feature()
	flow, err := p.flow()
	if err != nil {
		return 0, err
	}
	if err = sessionpg.RequireMFAOTPConsumedPreAuth(ctx, w, f.Binding, p.state.sender.config.Session, flow, p.source.primary.CommandID); err != nil {
		return 0, err
	}
	d, err := p.directoryAdmission()
	if err != nil {
		return 0, err
	}
	if err = w.RequireActiveDirectoryAuthority(ctx, p, d); err != nil {
		return 0, err
	}
	r := p.source.primary.Recipient
	if err = w.RequireRecipient(ctx, p, r); err != nil {
		return 0, err
	}
	credential, err := p.credential()
	if err != nil {
		return 0, err
	}
	if _, err = w.RequireRecipientCredential(ctx, p, r, credential); err != nil {
		return 0, err
	}
	a, _ := p.source.primary.Authority.Bindings()
	if err = policy.RequireAuthority(ctx, w, p.policyScope(), a.Authorization.Version, p.state.sender.config.MaximumDuration); err != nil {
		return 0, err
	}
	reserved, err := w.ReserveCommandCounters(ctx, p)
	if err != nil {
		return 0, err
	}
	if reserved == kernel.CommandCounterDenied {
		return kernel.MFAAttemptDenied, nil
	}
	p.locked, err = mfapg.LockOTPCompletionAttempt(ctx, w, p)
	if err != nil {
		return 0, err
	}
	return kernel.MFAAttemptUnchanged, nil
}
func (p *passwordOTPCompletionPhase) RecordMFAOTPAttemptDenial(ctx context.Context, w kernel.MFAOTPAttemptWork) error {
	return mfapg.RecordOTPCompletionAttemptDenial(ctx, w, p, p.locked)
}

func (p *passwordOTPCompletionPhase) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	if command != p.command || command == (identity.Command{}) {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	if err := p.AdmitFeaturePreparation(ctx, w, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err = p.admission.CheckAt(ctx, now); err != nil {
		return identity.FeatureReceipt{}, err
	}
	locked, err := mfapg.LockOTPCompletion(ctx, w, p, command, p.source.snapshot)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err = mfapg.RecordOTPCompletion(ctx, w, p, command, locked); err != nil {
		return identity.FeatureReceipt{}, err
	}
	receipt, err := p.state.effect.Apply(ctx, w, p, command, p.source.primary.Recipient, locked)
	if err == nil {
		p.applied = true
	}
	return receipt, err
}
func (p *passwordOTPCompletionPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, command identity.Command) error {
	if !p.applied || command != p.command {
		return identity.ForbiddenError{}
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if err = p.browser(ctx, now); err != nil {
		return err
	}
	return p.admission.CheckAt(ctx, now)
}
func (p *passwordOTPCompletionPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return p.state.effect.Recover(ctx, w, p)
}

type passwordOTPCompletionDelivery struct {
	command     identity.Command
	receipt     identity.CommandResult
	record      session.Session
	deliverable bool
}

func (p *passwordOTPCompletionDelivery) ExecuteIssue(ctx context.Context, r session.IssueRequest) (session.IssueExecution, error) {
	if ctx == nil || p == nil || !p.deliverable || ctx.Err() != nil || p.receipt.Outcome != identity.CommitOutcomeCommitted || p.receipt.Validate() != nil {
		return session.IssueExecution{}, invalidPasswordOTPCompletion()
	}
	command, record, ok := r.MFACommand()
	if !ok || command != p.command {
		return session.IssueExecution{}, invalidPasswordOTPCompletion()
	}
	a, err := sessionpg.MFAOTPCompletionSessionFields(record)
	b, other := sessionpg.MFAOTPCompletionSessionFields(p.record)
	if err != nil || other != nil || !reflect.DeepEqual(a, b) {
		return session.IssueExecution{}, invalidPasswordOTPCompletion()
	}
	p.deliverable = false
	return session.IssueExecution{Receipt: p.receipt, Session: p.record}, nil
}
func (*passwordOTPCompletionDelivery) RecoverIssue(context.Context, session.IssueRequest) (session.IssueExecution, error) {
	return session.IssueExecution{}, identity.ForbiddenError{}
}

func (p *passwordOTPCompletionPhase) outputAAD(generation uint64) (envelope.Context, error) {
	if p.source == nil || generation == 0 {
		return envelope.Context{}, invalidPasswordOTPCompletion()
	}
	f, _ := p.mapped.Feature()
	wire, err := json.Marshal(struct {
		Feature       identity.FeatureCommandSpec
		Generation    uint64
		Configuration string
		Sender        [32]byte
	}{f, generation, p.state.config.ConfigurationID, p.state.sender.identity})
	defer clear(wire)
	if err != nil {
		return envelope.Context{}, err
	}
	digest := sha256.Sum256(wire)
	return envelope.NewContext(map[string]string{"profile": "identity-password-otp-completion-output-v1", "binding": hex.EncodeToString(digest[:])})
}

var _ kernel.MFAOTPAttemptContributor = (*passwordOTPCompletionPhase)(nil)
