package reference

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	policy "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

type passwordOTPSendPhase struct {
	state         *passwordOTPSendState
	request       mfa.OtpSendRequest
	input         *passwordOTPSendInput
	native        otppg.MFALoginSendInput
	command       identity.Command
	plan          kernel.CommandPlan
	counter       kernel.CommandCounterPlan
	registry      *kernel.ContributorRegistry
	coordinator   *kernel.Coordinator
	risk          risk.ProtectedProviderAdmission
	prepared      otppg.PreparedMFALoginSend
	observedUntil time.Time
	sourceChecked bool
}

func (*passwordOTPSendPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}
}
func (*passwordOTPSendPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{passwordOTPSendOperation()}
}
func (p *passwordOTPSendPhase) compose() error {
	auditing, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return err
	}
	life, err := lifecyclepg.NewContributor()
	if err != nil {
		return err
	}
	p.registry, err = kernel.NewContributorRegistry([]kernel.Contributor{p.state.directory, p.state.counters, auditing, life, p, p.state.config.Issuance.DeliveryContributor()})
	if err != nil {
		return err
	}
	p.coordinator, err = kernel.NewCoordinatorWithRequestKeys(p.state.pool, p.registry, p.state.config.Coordinator, p.state.config.RequestKeys)
	return err
}
func (p *passwordOTPSendPhase) buildCommand() error {
	if p.input == nil || p.registry == nil {
		return invalidPasswordOTPSend()
	}
	input := *p.input
	input.Root.Fields = nil
	wire, err := json.Marshal(input)
	if err != nil {
		return invalidPasswordOTPSend()
	}
	defer clear(wire)
	digest := sha256.Sum256(wire)
	root := p.input.Root
	meta := mfapg.OTPFactorMetadata(p.input.Factor)
	cont, err := p.native.Continuation.Bindings()
	if err != nil {
		return err
	}
	_, correlation, ok := cont.Authorization.MFAContinuation()
	if !ok {
		return identity.ForbiddenError{}
	}
	root.Fields = []identity.FeatureField{{Name: "factor.parent-command", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(correlation.PrimaryCommandID)}}, {Name: "factor.otp.input", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}}, {Name: "factor.otp.configuration", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: p.state.identity[:]}}, {Name: "factor.otp.issued-at", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: p.native.IssuedAt}}, {Name: "factor.otp.continuation", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(meta.ContinuationID)}}}
	original, err := identity.NewFeaturePreAuthCommand(root, p.request.Cookie)
	if err != nil {
		return err
	}
	p.command, p.counter, err = p.state.counters.PrepareMFALoginSendCommandCounters(original, risk.Subject{User: string(meta.UserID), Network: p.input.Network}, p.native.IssuedAt)
	if err != nil {
		return err
	}
	full, _ := p.command.Feature()
	retained := false
	for _, f := range p.input.Root.Fields {
		if strings.HasPrefix(f.Name, "counter.") {
			retained = true
			break
		}
	}
	if retained && !reflect.DeepEqual(full, p.input.Root) {
		return identity.ConflictError{}
	}
	b := full.Binding
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return err
	}
	actor := audit.ActorService
	if string(b.ActorKind) == "user" {
		actor = audit.ActorHuman
	}
	seed, err := builder.Build(audit.RecordInput{OccurredAt: p.native.IssuedAt, Action: b.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: actor, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "factor", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "factor", "aggregate.id": b.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "protected"}})
	if err != nil {
		return err
	}
	auditDigest, err := kernel.FeatureAuditBindingDigest(b, full.Operation, "factor", seed)
	if err != nil {
		return err
	}
	descriptors := p.registry.Descriptors()
	deliveryOwner := p.state.config.Issuance.DeliveryContributor().Descriptor()
	descriptors = slices.DeleteFunc(descriptors, func(d kernel.ContributorDescriptor) bool { return d == deliveryOwner })
	p.plan, err = p.coordinator.PrepareFeaturePreparationPlan(p.command, kernel.CommandPlan{Contributors: descriptors, Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: full.Operation}, SubjectType: "factor", CommandCounters: &p.counter, Lifecycle: &kernel.LifecyclePlan{EventType: "otp.sent.v1", AfterVersion: 1}, Audits: []kernel.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: auditDigest}}})
	return err
}
func (p *passwordOTPSendPhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if p.input == nil || c != p.command || plan.Feature == nil || *plan.Feature != (kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: passwordOTPSendOperation()}) || plan.SubjectType != "factor" || plan.CommandCounters == nil || *plan.CommandCounters != p.counter || plan.Lifecycle == nil || *plan.Lifecycle != (kernel.LifecyclePlan{EventType: "otp.sent.v1", AfterVersion: 1}) || plan.OTP != nil || plan.Capability != nil || plan.CapabilityIssuance != nil || plan.MFACompletion != nil || plan.MFAContinuation != nil || plan.RiskEvidence != nil || len(plan.Audits) != 1 {
		return invalidPasswordOTPSend()
	}
	if plan.Delivery != nil {
		delivery, err := p.prepared.Plan()
		if err != nil || !reflect.DeepEqual(delivery, *plan.Delivery) {
			return invalidPasswordOTPSend()
		}
	}
	return nil
}
func (p *passwordOTPSendPhase) ValidateFeaturePreparation(c identity.Command, plan kernel.CommandPlan) error {
	if plan.Delivery != nil {
		return invalidPasswordOTPSend()
	}
	return p.ValidateFeatureCommand(c, plan)
}
func (p *passwordOTPSendPhase) MFALoginSendCounterSubject(c identity.Command) (identity.UserID, error) {
	if p.input == nil || c != p.command {
		return "", invalidPasswordOTPSend()
	}
	return mfapg.OTPFactorMetadata(p.input.Factor).UserID, nil
}

func (p *passwordOTPSendPhase) browser(now time.Time) error {
	cont, err := p.native.Continuation.Bindings()
	if err != nil {
		return err
	}
	original, correlation, ok := cont.Authorization.MFAContinuation()
	if !ok || correlation.ContinuationID != identity.CommandID(p.request.ContinuationID) || correlation.ScopeDigest != p.input.Factor.ScopeDigest {
		return identity.ForbiddenError{}
	}
	f, err := original.Bindings()
	if err != nil {
		return err
	}
	if f.Binding.Intent.Origin != p.input.Origin || f.Binding.Intent.CallbackURL != p.input.Callback || f.Binding.ID != p.request.PreAuthID {
		return identity.ForbiddenError{}
	}
	if now.Before(p.input.ChildIssuedAt) || !now.Before(p.input.ChildExpiresAt) || now.Before(p.native.IssuedAt) || !now.Before(p.native.ExpiresAt) || p.observedUntil.IsZero() || !time.Now().Before(p.observedUntil) {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *passwordOTPSendPhase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p.input == nil || c != p.command {
		return invalidPasswordOTPSend()
	}
	if _, _, _, err := w.FeatureScope(p); err != nil {
		return err
	}
	// The first protected read precedes external admission. It starts the
	// invocation's validity budget; later restoration/reads must not renew it.
	if p.observedUntil.IsZero() {
		p.observedUntil = time.Now().Add(p.state.config.MaximumDuration)
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if err = p.browser(now); err != nil {
		return err
	}
	cont, err := p.native.Continuation.Bindings()
	if err != nil {
		return err
	}
	flow, correlation, ok := cont.Authorization.MFAContinuation()
	if !ok {
		return identity.ForbiddenError{}
	}
	if err = sessionpg.RequireMFAOTPConsumedPreAuth(ctx, w, p.input.Root.Binding, p.state.config.Session, flow, correlation.PrimaryCommandID); err != nil {
		return err
	}
	if err = w.RequireActiveDirectoryAuthority(ctx, p, p.native.Authority.Directory); err != nil {
		return err
	}
	primary := p.input.PrimaryRecipient.native()
	if err = w.RequireRecipient(ctx, p, primary); err != nil {
		return err
	}
	if _, err = w.RequireRecipientCredential(ctx, p, primary, kernel.CredentialAdmission(p.input.Credential)); err != nil {
		return err
	}
	recipient := p.native.Recipient
	recipient.Query.UserID = ""
	if err = w.RequireRecipient(ctx, p, recipient); err != nil {
		return err
	}
	if err = policy.RequireAuthority(ctx, w, p.state.policyScope(p.input), p.input.AuthorizationVersion, p.state.config.MaximumDuration); err != nil {
		return err
	}
	return mfapg.RequireOTPLoginSendFactor(ctx, w, p, c, mfapg.OTPFactorMetadata(p.input.Factor), correlation.PrimaryCommandID)
}
func (s *passwordOTPSendState) policyScope(input *passwordOTPSendInput) policy.AuthorityScope {
	return policy.AuthorityScope{TenantID: authorization.TenantID(input.Credential.Credential.TenantID), SubjectID: authorization.SubjectID(input.Credential.Credential.UserID), PolicyNamespace: s.config.Profile.PolicyNamespace}
}

type passwordOTPSendAdmission struct {
	phase *passwordOTPSendPhase
	risk  risk.ProtectedProviderAdmission
}
type passwordOTPSendOutput struct {
	Schema     uint32
	Generation uint64
	Risk       magicTOTPStoredAdmission
	OTP        []byte
}

func (p *passwordOTPSendPhase) PrepareFeatureAdmission(ctx context.Context, c identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if p.input == nil || c != p.command {
		return nil, invalidPasswordOTPSend()
	}
	if err := p.refreshSource(ctx); err != nil {
		return nil, err
	}
	scope := risk.Context{Tenant: string(p.input.Root.Binding.TenantID), Operation: "identity.mfa.otp-send", Attempt: string(p.input.Root.Binding.CommandID)}
	result, err := p.state.config.Risk.Evaluation.EvaluateProtectedProviders(ctx, risk.EvaluateRequest{Context: scope, Phase: risk.NonIssuing})
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	admission, err := p.state.custody.Prepare(ctx, result, scope)
	if err != nil {
		return nil, err
	}
	a := &passwordOTPSendAdmission{phase: p, risk: admission}
	return a, a.Check(ctx)
}
func (*passwordOTPSendPhase) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, invalidPasswordOTPSend()
}
func (a *passwordOTPSendAdmission) Check(ctx context.Context) error {
	if a == nil || a.phase == nil {
		return invalidPasswordOTPSend()
	}
	if err := a.phase.browser(time.Now().UTC()); err != nil {
		return err
	}
	return a.risk.Check(ctx)
}
func (p *passwordOTPSendPhase) outputAAD(generation uint64) (envelope.Context, error) {
	if p.input == nil || generation == 0 {
		return envelope.Context{}, invalidPasswordOTPSend()
	}
	wire, err := json.Marshal(struct {
		Input         passwordOTPSendInput
		Generation    uint64
		Configuration [32]byte
	}{*p.input, generation, p.state.identity})
	if err != nil {
		return envelope.Context{}, invalidPasswordOTPSend()
	}
	defer clear(wire)
	digest := sha256.Sum256(wire)
	return envelope.NewContext(map[string]string{"profile": "reference-password-otp-send-output-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}
func (a *passwordOTPSendAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	p := a.phase
	output, err := p.state.config.Issuance.GenerateLoginSend(ctx, p.command, p.input.NativeInput, generation)
	if err != nil {
		return nil, err
	}
	defer clear(output)
	wire, err := json.Marshal(passwordOTPSendOutput{Schema: 1, Generation: generation, Risk: magicTOTPStoredAdmission(a.risk.Prepared()), OTP: output})
	if err != nil {
		return nil, invalidPasswordOTPSend()
	}
	defer clear(wire)
	aad, err := p.outputAAD(generation)
	if err != nil {
		return nil, err
	}
	return p.seal(ctx, aad, wire)
}
func (p *passwordOTPSendPhase) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	bad := func(err error) (identity.Command, kernel.CommandPlan, error) {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	if p.input == nil || c != p.command {
		return bad(invalidPasswordOTPSend())
	}
	aad, err := p.outputAAD(generation)
	if err != nil {
		return bad(err)
	}
	plain, err := p.open(ctx, aad, wire)
	if err != nil {
		return bad(err)
	}
	defer clear(plain)
	var output passwordOTPSendOutput
	if decodePasswordOTPSendJSON(plain, &output) != nil || output.Schema != 1 || output.Generation != generation || len(output.OTP) == 0 {
		return bad(invalidPasswordOTPSend())
	}
	defer clear(output.OTP)
	scope := risk.Context{Tenant: string(p.input.Root.Binding.TenantID), Operation: "identity.mfa.otp-send", Attempt: string(p.input.Root.Binding.CommandID)}
	p.risk, err = p.state.custody.Restore(ctx, risk.PreparedProtectedProviderAdmission(output.Risk), scope)
	if err != nil {
		return bad(err)
	}
	p.prepared, err = p.state.config.Issuance.RestoreLoginSend(ctx, c, p.input.NativeInput, generation, output.OTP)
	if err != nil {
		return bad(err)
	}
	delivery, err := p.prepared.Plan()
	if err != nil {
		return bad(err)
	}
	plan := p.plan
	plan.Digest = [32]byte{}
	plan.Contributors = append(slices.Clone(plan.Contributors), delivery.Contributor)
	plan.Delivery = &delivery
	return p.command, plan, nil
}
func (p *passwordOTPSendPhase) RestoreFeatureAdmission(ctx context.Context, c identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if err := p.refreshSource(ctx); err != nil {
		return nil, err
	}
	if _, _, err := p.RestoreFeaturePreparation(ctx, c, generation, wire); err != nil {
		return nil, err
	}
	a := &passwordOTPSendAdmission{phase: p, risk: p.risk}
	return a, a.Check(ctx)
}
func (p *passwordOTPSendPhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if err := w.RequireFeatureCommand(ctx, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.CheckFeatureCommit(ctx, w, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.prepared.Persist(ctx, w, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	cont, err := p.native.Continuation.Bindings()
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	_, parent, ok := cont.Authorization.MFAContinuation()
	if !ok {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	if err := mfapg.RecordOTPLoginSendSource(ctx, w, p, c, mfapg.OTPFactorMetadata(p.input.Factor), parent.PrimaryCommandID); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.CheckFeatureCommit(ctx, w, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: passwordOTPSendOperation(), AfterVersion: 1}, nil
}
func (p *passwordOTPSendPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if err := p.AdmitFeaturePreparation(ctx, w, c); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	return p.risk.CheckAt(ctx, now)
}
func (p *passwordOTPSendPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return p.state.config.Issuance.RecoverLoginSend(ctx, w, p)
}
func (p *passwordOTPSendPhase) destroy() {
	if p != nil && p.input != nil {
		clear(p.input.NativeInput)
	}
}
