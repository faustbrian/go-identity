package anonymouspostgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	policy "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// Invocation-local custody, never shared between calls or retained as an
// alternative journal. Only the existing coordinator acknowledges generation.
type signinPhase struct {
	service           *SigninService
	request           anonymous.SigninRequest
	coordinator       *kernel.Coordinator
	registry          *kernel.ContributorRegistry
	input             signinInput
	flow              session.PreAuthTransaction
	original, command identity.Command
	issuer            *session.SessionIssuer
	prepared          session.PreparedIssuance
	record            session.Session
	admission         risk.AuthenticationAdmission
	authority         kernel.AnonymousAuthorityRecord
	generation        uint64
	outputDigest      [32]byte
	receipt           identity.CommandResult
	deliverable       bool
}

var _ kernel.FeatureAdmissionPreparationContributor = (*signinPhase)(nil)
var _ kernel.RequestKeyPreparationContributor = (*signinPhase)(nil)
var _ kernel.FeatureCommitContributor = (*signinPhase)(nil)
var _ session.IssueExecutor = (*signinPhase)(nil)

func (*signinPhase) Descriptor() kernel.ContributorDescriptor { return creationOwner() }
func (*signinPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{creationOperation()}
}
func (p *signinPhase) registration() kernel.FeatureRegistration {
	return kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: creationOperation()}
}

func (p *signinPhase) initialize() error {
	subject, err := anonymous.NewAnonymousSubject(anonymous.SubjectSpec(p.input.Subject))
	if err != nil {
		return err
	}
	fields, err := CreationFields(subject)
	if err != nil {
		return err
	}
	creation, err := kernel.AnonymousCreationFields(p.creationIntent())
	if err != nil {
		return err
	}
	fields = append(fields, creation...)
	for _, f := range p.input.Intent {
		f.Name = "anonymous.request." + f.Name
		fields = append(fields, f)
	}
	p.original, err = identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: p.input.Binding, Operation: creationOperation(), Fields: fields})
	return err
}
func (p *signinPhase) creationIntent() kernel.AnonymousCreationIntent {
	return kernel.AnonymousCreationIntent{Creation: identity.CreateUserCommand(p.input.Creation), Placeholder: p.input.Placeholder}
}

func (p *signinPhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.service == nil || p.original == (identity.Command{}) || plan.Feature == nil || *plan.Feature != p.registration() || plan.SubjectType != "anonymous_flow" || plan.Lifecycle == nil || *plan.Lifecycle != (kernel.LifecyclePlan{EventType: "anonymous.created.v1"}) || len(plan.Audits) != 1 || plan.Audits[0].EventType != "identity.anonymous.create" || !plan.Audits[0].Required || plan.OTP != nil || plan.Capability != nil || plan.Delivery != nil || plan.SignupAcceptance {
		return anonymous.ErrInvalidInput
	}
	if c == p.original || p.command != (identity.Command{}) && c == p.command {
		return nil
	}
	return anonymous.ErrInvalidInput
}
func (p *signinPhase) ValidateFeaturePreparation(c identity.Command, plan kernel.CommandPlan) error {
	if c != p.original {
		return anonymous.ErrInvalidInput
	}
	return p.ValidateFeatureCommand(c, plan)
}

func (p *signinPhase) plan(command identity.Command, original bool) (kernel.CommandPlan, error) {
	f, ok := command.Feature()
	if !ok || f.Operation != creationOperation() {
		return kernel.CommandPlan{}, anonymous.ErrInvalidInput
	}
	b := f.Binding
	actor := audit.ActorService
	if b.ActorKind == authorization.SubjectUser {
		actor = audit.ActorHuman
	}
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	a, err := builder.Build(audit.RecordInput{OccurredAt: p.input.Subject.CreatedAt, Action: "identity.anonymous.create", Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: actor, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "anonymous_flow", ID: b.AnonymousFlowID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "anonymous_flow", "aggregate.id": b.AnonymousFlowID, "aggregate.before_version": "0", "aggregate.after_version": "0", "retention.class": "protected"}})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, creationOperation(), "anonymous_flow", a)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	registration := p.registration()
	plan := kernel.CommandPlan{Contributors: p.registry.Descriptors(), SubjectType: "anonymous_flow", Feature: &registration, Lifecycle: &kernel.LifecyclePlan{EventType: "anonymous.created.v1"}, Audits: []kernel.AuditPlan{{EventType: "identity.anonymous.create", SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}}
	if original {
		return p.coordinator.PrepareFeaturePreparationPlan(command, plan)
	}
	return p.coordinator.PrepareCommandPlan(b, command, plan)
}

func (p *signinPhase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, c identity.Command) error {
	b, f, _, err := w.FeatureScope(p)
	if err != nil || c != p.original || b != p.input.Binding || f != p.registration() {
		return anonymous.ErrInvalidInput
	}
	if err = sessionpg.RequirePreAuth(ctx, w, p.service.config().Sessions, p.flow); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	_, err = p.admitFlow(p.flow, now, false)
	return err
}
func (*signinPhase) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, anonymous.ErrInvalidInput
}

type signinAdmission struct {
	owner     *signinPhase
	admission risk.AuthenticationAdmission
}

func (a *signinAdmission) Check(ctx context.Context) error {
	if a == nil || a.owner == nil {
		return anonymous.ErrInvalidInput
	}
	now := time.Now().UTC()
	if err := a.admission.CheckAt(ctx, now); err != nil {
		return err
	}
	_, err := a.owner.admitFlow(a.owner.flow, now, false)
	return err
}

func (p *signinPhase) riskSubject() risk.Subject {
	// Authentication's fixed counter vocabulary requires an identifier bucket.
	// Anonymous signin has no contact: one purpose-separated tenant-wide absence
	// bucket prevents new opaque flow/user IDs from manufacturing fresh budgets.
	key := p.service.config().IntentKey
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte("identity-anonymous-signin-no-contact-v1\x00" + string(p.input.Binding.TenantID)))
	return risk.Subject{Network: p.request.Network, Device: p.request.Device, IdentifierDigest: hex.EncodeToString(mac.Sum(nil))}
}
func (p *signinPhase) PrepareFeatureAdmission(ctx context.Context, c identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if c != p.original {
		return nil, anonymous.ErrInvalidInput
	}
	b := p.input.Binding
	scope := risk.Context{Tenant: string(b.TenantID), Operation: risk.Action(b.OperationID), Attempt: string(b.CommandID)}
	result, err := p.service.config().Risk.Evaluation.Evaluate(ctx, risk.EvaluateRequest{Context: scope, Phase: risk.NonIssuing, Subject: p.riskSubject(), Attribution: &risk.DecisionAttribution{CommandID: b.CommandID, CorrelationID: b.CommandID, Actor: audit.ActorInput{Kind: audit.ActorAnonymous}, Subject: identity.SecurityAuthenticationAttempt, SubjectID: string(b.CommandID)}})
	if err != nil {
		return nil, signinPublicError(ctx, err)
	}
	admission, err := p.service.custody.Prepare(ctx, result, scope, p.riskSubject())
	if err != nil {
		return nil, identity.ForbiddenError{}
	}
	a := &signinAdmission{owner: p, admission: admission}
	if err = a.Check(ctx); err != nil {
		return nil, err
	}
	return a, nil
}

type signinOutput struct {
	Schema    uint8
	Fields    []identity.FeatureField
	Admission signinStoredAdmission
}

func (p *signinPhase) outputAAD(generation uint64) (envelope.Context, error) {
	f, ok := p.original.Feature()
	if !ok || generation == 0 {
		return envelope.Context{}, anonymous.ErrInvalidInput
	}
	frame, err := json.Marshal(struct {
		Original   identity.FeatureCommandSpec
		Generation uint64
		Profile    [32]byte
	}{f, generation, p.service.profile})
	if err != nil {
		return envelope.Context{}, err
	}
	defer clear(frame)
	sum := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"profile": "identity-anonymous-signin-output-v1", "binding": base64.RawURLEncoding.EncodeToString(sum[:])})
}

func (a *signinAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	p, c := a.owner, a.owner.service.config()
	b := p.input.Binding
	s := anonymous.SubjectSpec(p.input.Subject)
	directory, err := p.service.directory.GetDirectoryAuthority(ctx, kernel.DirectoryAuthorityQuery{GlobalAuthorityID: c.Profile.GlobalAuthorityID, TenantID: b.TenantID})
	if err != nil {
		return nil, err
	}
	if !directory.Enabled {
		return nil, identity.ForbiddenError{}
	}
	family, err := identity.NewSubjectID()
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	id, err := identity.NewSubjectID()
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	keys, err := kernel.KernelAuthorityKeys(directory.Query, s.UserID)
	if err != nil {
		return nil, err
	}
	sk, err := sessionpg.SessionAuthorityKeys(b.TenantID, s.UserID, string(family), string(id))
	if err != nil {
		return nil, err
	}
	pk, err := (policy.AuthorityScope{TenantID: authorization.TenantID(b.TenantID), SubjectID: authorization.SubjectID(s.UserID), PolicyNamespace: c.Profile.PolicyNamespace}).Key()
	if err != nil {
		return nil, err
	}
	v := func(key string, n uint64) session.AuthorityBinding {
		return session.AuthorityBinding{ScopeKey: key, Version: n}
	}
	vector, err := session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: v(keys.Global, directory.GlobalVersion), Tenant: v(keys.Tenant, directory.TenantVersion), User: v(keys.User, 1), Identifier: v(keys.Identifier, 1), Credential: v(keys.Credential, 1), SessionFamily: v(sk.Family, 1), Session: v(sk.Session, 1), Authorization: v(pk, 1)})
	if err != nil {
		return nil, err
	}
	prepared, err := p.issuer.PrepareAnonymous(b, session.SessionSpec{SessionID: string(id), FamilyID: string(family), TenantID: b.TenantID, UserID: s.UserID, Audience: c.Profile.Audience, Version: 1, FamilyVersion: 1, Authority: vector, Remember: p.request.Remember, Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationAnonymous, AnonymousAt: s.CreatedAt}, IssuedAt: s.CreatedAt, LastActivityAt: s.CreatedAt})
	if err != nil {
		return nil, err
	}
	record, ok := prepared.Session()
	if !ok {
		return nil, anonymous.ErrInvalidInput
	}
	fields, err := sessionpg.AnonymousSigninSessionFields(record)
	if err != nil {
		return nil, err
	}
	original, _ := p.original.Feature()
	fields = append(original.Fields, fields...)
	aad, err := p.outputAAD(generation)
	if err != nil {
		return nil, err
	}
	wire, err := p.service.seal(ctx, aad, signinOutput{Schema: 1, Fields: fields, Admission: signinStoredAdmission(a.admission.Prepared())})
	if err != nil {
		return nil, err
	}
	p.prepared = prepared
	return wire, nil
}

func (p *signinPhase) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	if c != p.original {
		return identity.Command{}, kernel.CommandPlan{}, anonymous.ErrInvalidInput
	}
	aad, err := p.outputAAD(generation)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	var out signinOutput
	if err = p.service.open(ctx, aad, wire, &out); err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	if out.Schema != 1 {
		return identity.Command{}, kernel.CommandPlan{}, anonymous.ErrInvalidInput
	}
	original, _ := p.original.Feature()
	command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: original.Binding, Operation: original.Operation, Fields: out.Fields})
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	f, _ := command.Feature()
	var base []identity.FeatureField
	for _, field := range f.Fields {
		if !strings.HasPrefix(field.Name, "session.result.") {
			base = append(base, field)
		}
	}
	if !sameSigninFields(base, original.Fields) {
		return identity.Command{}, kernel.CommandPlan{}, anonymous.ErrInvalidInput
	}
	record, err := sessionpg.AnonymousSigninSession(command)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	r, _ := record.Bindings()
	s := anonymous.SubjectSpec(p.input.Subject)
	if r.UserID != s.UserID || r.TenantID != s.TenantID || !r.IssuedAt.Equal(s.CreatedAt) || r.Remember != p.request.Remember || r.Audience != p.service.config().Profile.Audience {
		return identity.Command{}, kernel.CommandPlan{}, anonymous.ErrInvalidInput
	}
	prepared := risk.PreparedAuthenticationAdmission(out.Admission)
	scope := risk.Context{Tenant: string(original.Binding.TenantID), Operation: risk.Action(original.Binding.OperationID), Attempt: string(original.Binding.CommandID)}
	admission, err := p.service.custody.Restore(ctx, prepared, scope, p.riskSubject())
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, identity.ForbiddenError{}
	}
	p.command, p.record, p.admission, p.generation, p.outputDigest = command, record, admission, generation, sha256.Sum256(wire)
	plan, err := p.plan(command, false)
	return command, plan, err
}
func (p *signinPhase) RestoreFeatureAdmission(ctx context.Context, c identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if _, _, err := p.RestoreFeaturePreparation(ctx, c, generation, wire); err != nil {
		return nil, err
	}
	a := &signinAdmission{owner: p, admission: p.admission}
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	return a, nil
}

func (p *signinPhase) checkFacts(ctx context.Context, w kernel.Work) error {
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if err = p.admission.CheckAt(ctx, now); err != nil {
		return identity.ForbiddenError{}
	}
	if _, err = p.admitFlow(p.flow, now, false); err != nil {
		return err
	}
	s, err := anonymous.NewAnonymousSubject(anonymous.SubjectSpec(p.input.Subject))
	if err != nil {
		return err
	}
	return s.RequireActive(p.input.Binding.TenantID, now)
}
func (p *signinPhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if c != p.command || c == p.original {
		return identity.FeatureReceipt{}, anonymous.ErrInvalidInput
	}
	if err := w.RequireFeatureCommand(ctx, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	wire, generation, err := w.FeaturePreparationOutput(p)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	digest := sha256.Sum256(wire)
	clear(wire)
	if digest != p.outputDigest || generation != p.generation {
		return identity.FeatureReceipt{}, anonymous.ErrInvalidInput
	}
	if err = p.checkFacts(ctx, w); err != nil {
		return identity.FeatureReceipt{}, err
	}
	b, fingerprint, generation, err := w.FeatureCommandIdentity(p)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	use := sessionpg.PreAuthUse{Command: b, Fingerprint: fingerprint, Generation: generation}
	if err = sessionpg.ReservePreAuth(ctx, w, p.service.config().Sessions, p.flow, use); err != nil {
		return identity.FeatureReceipt{}, err
	}
	u, err := p.service.domain.Apply(ctx, w, p, c, p.creationIntent())
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	p.authority = kernel.AnonymousAuthorityRecord{User: u, Placeholder: p.input.Placeholder, UserAuthorityVersion: 1, IdentifierAuthorityVersion: 1, CredentialAuthorityVersion: 1}
	if err = p.service.repository.StageCreation(ctx, w, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if _, err = policy.InitializeAuthority(ctx, w, policy.AuthorityScope{TenantID: authorization.TenantID(u.TenantID), SubjectID: authorization.SubjectID(u.ID), PolicyNamespace: p.service.config().Profile.PolicyNamespace}, p.service.config().Repository.MaximumDuration); err != nil {
		return identity.FeatureReceipt{}, err
	}
	receipt, err := p.service.effect.Apply(ctx, w, p, c, p.authority)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err = sessionpg.FinalizePreAuth(ctx, w, p.service.config().Sessions, p.flow, use); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return receipt, nil
}
func (p *signinPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.command {
		return anonymous.ErrInvalidInput
	}
	if err := p.checkFacts(ctx, w); err != nil {
		return err
	}
	if err := p.service.repository.RequireCreation(ctx, w, p, c); err != nil {
		return err
	}
	return p.service.effect.Check(ctx, w, p, c, p.authority)
}
func (p *signinPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	a, err := p.service.repository.RecoverCreation(ctx, w, p)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	b, err := p.service.effect.Recover(ctx, w, p)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	if a != b {
		return kernel.RecoveryUnknown, nil
	}
	return a, nil
}

// Lend only the actual newly committed receipt from this exact invocation to
// the session owner's existing reveal gate. No execution or recovery occurs.
func (p *signinPhase) ExecuteIssue(ctx context.Context, r session.IssueRequest) (session.IssueExecution, error) {
	if ctx == nil || ctx.Err() != nil || p == nil || !p.deliverable || p.receipt.Outcome != identity.CommitOutcomeCommitted || p.receipt.Validate() != nil {
		return session.IssueExecution{}, anonymous.ErrInvalidInput
	}
	c, record, ok := r.AnonymousCommand()
	if !ok || c != p.command {
		return session.IssueExecution{}, anonymous.ErrInvalidInput
	}
	actual, err := sessionpg.AnonymousSigninSessionFields(record)
	if err != nil {
		return session.IssueExecution{}, err
	}
	expected, err := sessionpg.AnonymousSigninSessionFields(p.record)
	if err != nil || !sameSigninFields(actual, expected) {
		return session.IssueExecution{}, anonymous.ErrInvalidInput
	}
	p.deliverable = false
	return session.IssueExecution{Receipt: p.receipt, Session: p.record}, nil
}
func (*signinPhase) RecoverIssue(context.Context, session.IssueRequest) (session.IssueExecution, error) {
	return session.IssueExecution{}, anonymous.ErrInvalidInput
}
func sameSigninFields(a, b []identity.FeatureField) bool {
	a = slices.Clone(a)
	b = slices.Clone(b)
	order := func(a, b identity.FeatureField) int { return strings.Compare(a.Name, b.Name) }
	slices.SortFunc(a, order)
	slices.SortFunc(b, order)
	return reflect.DeepEqual(a, b)
}
