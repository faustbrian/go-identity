package passwordpostgres

import (
	"context"
	"crypto/sha256"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

type signupExecutionPreparation struct {
	authorizationNamespace string
	owner                  kernel.FeaturePreparationContributor
	original               identity.Command
	selected               kernel.PasswordRegistrationIntent
	flow                   session.PreAuthTransaction
	flowKey                session.DigestKey
	storage                sessionpg.Config
	at                     time.Time
	request                password.SignupRequest
	domain                 *kernel.PasswordRegistrationDomain
	generation             signupGenerationPreparation
	risk                   risk.AuthenticationAdmissionCustodyConfig
	subject                risk.Subject
}

// Restored invocation-local custody borrows the existing journal and Work.
// It never generates credentials, opens a transaction or invokes a sender.
type signupExecution struct {
	command          identity.Command
	issuancePlan     kernel.CapabilityIssuancePlan
	deliveryPlan     kernel.DeliveryPlan
	repository       *Repository
	input            signupExecutionPreparation
	admission        risk.AuthenticationAdmission
	facts            []risk.Signal
	issuance         issuerpg.PreparedIssuance
	delivery         deliverypg.PreparedDelivery
	outputDigest     [32]byte
	outputGeneration uint64
}

// Authenticate original output outside SQL. Native owners restore their own
// checkpoints; successful restoration cannot reveal the original bearer again.
func (r *Repository) restoreSignupExecution(ctx context.Context, p signupExecutionPreparation, generation uint64, wire []byte) (*signupExecution, error) {
	if ctx == nil || !r.configuredWriter() || p.owner == nil || p.domain == nil || p.generation.codec == nil || p.generation.delivery.owner == nil {
		return nil, password.ErrPasswordWork
	}
	out, err := r.restoreSignupOutput(ctx, p.generation.crypto, p.original, generation, p.generation.profile, p.generation.verification.issuer, wire)
	if err != nil {
		return nil, err
	}
	defer clear(out.IssuanceWire)
	defer clear(out.DeliveryWire)
	spec, ok := p.original.PasswordSignupInputFeature()
	_, cookie, originalCustody := p.original.PasswordSignupInputCustody()
	if !ok || !originalCustody || cookie.Token() != p.request.Cookie.Token() {
		return nil, password.ErrPasswordWork
	}
	command, err := identity.NewFeaturePasswordSignupCommand(spec, out.Hash, cookie)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	if _, err := r.signupMaterial(command, p.selected); err != nil {
		return nil, err
	}
	custody, err := risk.NewAuthenticationAdmissionCustody(p.risk)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	prepared := risk.PreparedAuthenticationAdmission(out.Admission)
	if prepared.Scope.Tenant != string(spec.Binding.TenantID) || prepared.Scope.Operation != risk.Action(spec.Binding.OperationID) || prepared.Scope.Attempt != string(spec.Binding.CommandID) {
		return nil, password.ErrPasswordWork
	}
	admission, err := custody.Restore(ctx, prepared, prepared.Scope, p.subject)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	issuance, err := p.generation.codec.RestorePreparation(ctx, spec.Binding, generation, out.Issuance, out.IssuanceWire)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	delivery, err := p.generation.delivery.owner.RestorePreparation(ctx, spec.Binding, generation, out.DeliveryWire)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	deliveryPlan, err := delivery.Plan()
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	return &signupExecution{command: command, issuancePlan: out.Issuance, deliveryPlan: deliveryPlan, repository: r, input: p, admission: admission, facts: out.Facts, issuance: issuance, delivery: delivery, outputDigest: sha256.Sum256(wire), outputGeneration: generation}, nil
}

func (e *signupExecution) checkFacts(ctx context.Context, w kernel.Work) error {
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if err := e.admission.CheckAt(ctx, now); err != nil {
		return password.ErrPasswordWork
	}
	return checkSignupScreening(ctx, e.input.generation.screening.Policy, e.admission.Prepared().Scope, e.facts, now)
}

func (e *signupExecution) apply(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if ctx == nil || e == nil || c != e.command {
		return identity.FeatureReceipt{}, password.ErrPasswordWork
	}
	if err := w.RequireFeatureCommand(ctx, e.input.owner, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	wire, generation, err := w.FeaturePreparationOutput(e.input.owner)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	digest := sha256.Sum256(wire)
	clear(wire)
	if generation != e.outputGeneration || digest != e.outputDigest {
		return identity.FeatureReceipt{}, password.ErrPasswordWork
	}
	if err := e.checkFacts(ctx, w); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := e.repository.applySignupPreAuth(ctx, w, e.input.owner, c, e.input.request, e.input.flow, e.input.flowKey, e.input.storage); err != nil {
		return identity.FeatureReceipt{}, err
	}
	_, accepted, err := e.input.domain.ApplyOrAccept(ctx, w, e.input.owner, c, e.input.selected)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	spec, _ := c.PasswordSignupFeature()
	// The kernel owns neutral acceptance. No material, credential grant or
	// message may be staged for the occupied account or proposed replacement.
	if accepted {
		return identity.FeatureReceipt{Operation: spec.Operation}, nil
	}
	if err := e.repository.applySignupMaterial(ctx, w, e.input.owner, c, e.input.selected); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if e.input.authorizationNamespace != "" {
		scope := authoritypg.AuthorityScope{TenantID: authorization.TenantID(spec.Binding.TenantID), SubjectID: authorization.SubjectID(e.input.selected.Creation.Binding.UserID), PolicyNamespace: e.input.authorizationNamespace}
		if _, err := authoritypg.InitializeAuthority(ctx, w, scope, e.repository.maximumDuration); err != nil {
			return identity.FeatureReceipt{}, readerFailure(ctx)
		}
	}
	if err := e.input.generation.verification.issuer.Stage(ctx, w, e.issuance); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := e.input.generation.delivery.owner.Stage(ctx, w, e.delivery); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: spec.Operation}, nil
}

// Audit and outbox persistence may take time after Apply. Check the original
// facts and flow again at primary time without renewing admission or callbacks.
func (e *signupExecution) checkCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if ctx == nil || e == nil || c != e.command {
		return password.ErrPasswordWork
	}
	if err := e.repository.checkSignupPreAuthCommit(ctx, w, e.input.owner, c, e.input.request, e.input.flow, e.input.flowKey); err != nil {
		return err
	}
	return e.checkFacts(ctx, w)
}

func signupExecutionPlan(coordinator *kernel.Coordinator, registry *kernel.ContributorRegistry, owner kernel.FeatureExecutionContributor, command identity.Command, at time.Time, issuance kernel.CapabilityIssuancePlan, delivery kernel.DeliveryPlan) (kernel.CommandPlan, error) {
	if coordinator == nil || registry == nil || owner == nil {
		return kernel.CommandPlan{}, password.ErrPasswordWork
	}
	spec, ok := command.PasswordSignupInputFeature()
	original := ok
	if !ok {
		spec, ok = command.PasswordSignupFeature()
	}
	if !ok || !signupOperation(spec.Operation) {
		return kernel.CommandPlan{}, password.ErrPasswordWork
	}
	b, op := spec.Binding, spec.Operation
	actor := audit.ActorHuman
	switch b.ActorKind {
	case authorization.SubjectUser:
	case authorization.SubjectServiceAccount, authorization.SubjectAPIKey:
		actor = audit.ActorService
	default:
		return kernel.CommandPlan{}, password.ErrPasswordWork
	}
	target := b.AnonymousFlowID
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	seed, err := builder.Build(audit.RecordInput{OccurredAt: at, Action: op.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: actor, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "user", ID: target}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "user", "aggregate.id": target, "aggregate.before_version": "0", "aggregate.after_version": "0", "retention.class": "protected"}})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, op, "user", seed)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	plan := kernel.CommandPlan{Feature: &kernel.FeatureRegistration{Contributor: owner.Descriptor(), Operation: op}, SubjectType: "user", SignupAcceptance: true, Lifecycle: &kernel.LifecyclePlan{EventType: "user.created.v1"}, Audits: []kernel.AuditPlan{{EventType: op.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}}
	// The journal authenticates the unchanged declaration prefix. Generated
	// issuance and delivery contributors are appended only after restoration.
	for _, d := range registry.Descriptors() {
		if d.ContractID != "capability.issuance" && d.ContractID != "identity.delivery.effects" {
			plan.Contributors = append(plan.Contributors, d)
		}
	}
	if len(issuance.Grants) != 0 {
		plan.CapabilityIssuance = &issuance
		plan.Contributors = append(plan.Contributors, issuance.Contributor)
	}
	if len(delivery.Intents) != 0 {
		plan.Delivery = &delivery
		plan.Contributors = append(plan.Contributors, delivery.Contributor)
	}
	if original {
		return coordinator.PrepareFeaturePreparationPlan(command, plan)
	}
	return coordinator.PrepareCommandPlan(b, command, plan)
}
