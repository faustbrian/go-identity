package passwordpostgres

import (
	"context"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-capability"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	email "github.com/faustbrian/go-identity/email"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/v2/postgres/identity"
)

// ConfirmRegistrationVerification explicitly confirms the original delivered
// signup link. It authenticates original signed/encrypted intent and current
// policy, then consumes the proof atomically with the pending address transition,
// audit and lifecycle effects in the sole identity coordinator. Scanner Validate
// is not an execution ticket. This initial require-verified profile issues no
// session, sends no mail and never changes the original expiry or signup actor.
//
// Select Verification.Counters at startup and install its verification migration
// plus kernel EmailVerificationMigrationSource. caller is trusted transport
// policy context; network is trusted transport input, never a client override.
// An omitted user resource is derived only from the authenticated signed grant.
// Callback must exactly match original intent and contain no proof. CommandID is
// stable for retries; changed subject/actor/address scope never selects history.
// Same-command replay returns the retained receipt without consuming/charging
// again. Expired/revoked proofs cannot execute or select history through this
// method; separate currently authorized recovery is metadata-only.
//
// Every call owns an invocation-local phase and borrows immutable dependencies.
// Earlier cancellation wins over MaximumDuration. No callback or network work
// occurs under transaction locks. Errors/panics are redacted; ambiguity retains
// Unknown rather than inventing rollback. Returned receipts disclose no address,
// bearer or session and confer no current authority. No goroutines are owned.
func (s *SignupService) ConfirmRegistrationVerification(ctx context.Context, proof capability.Proof, callback string, commandID identity.CommandID, network string, caller authorization.DecisionContext) (result identity.CommandResult, err error) {
	return s.confirmRegistrationVerification(ctx, proof, callback, commandID, network, caller, nil)
}

func (s *SignupService) confirmRegistrationVerification(ctx context.Context, proof capability.Proof, callback string, commandID identity.CommandID, network string, caller authorization.DecisionContext, replayed *bool) (result identity.CommandResult, err error) {
	if ctx == nil || s == nil || s.config == nil || s.pool == nil || s.directory == nil || s.config().Verification.Counters == nil {
		return result, identity.InvalidInputError{Field: "email_verification"}
	}
	c := s.config()
	ctx, stop := context.WithTimeout(ctx, c.Repository.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
	}()
	if _, err := identity.ParseCommandID(string(commandID)); err != nil || callback == "" || len(callback) > 2048 || len(network) > 128 {
		return result, identity.InvalidInputError{Field: "email_verification"}
	}
	grant, origin, replay, err := c.Verification.Issuer.ReadRegistrationOrigin(ctx, s.pool, proof)
	if err != nil {
		return result, err
	}
	if caller.Request.Resource.ID == "" {
		caller.Request.Resource.ID = authorization.ResourceID(grant.Payload().Subject)
	}
	spec, version, err := s.ReadRegistrationVerification(ctx, proof, caller)
	if err != nil {
		return result, err
	}
	if spec.Binding.CommandID != origin || version != replay || spec.Payload.Redirect.String() != callback || commandID == origin {
		return result, identity.ForbiddenError{}
	}
	p := &registrationConfirmationPhase{service: s, grant: grant, spec: spec}
	coordinator, registry, err := s.confirmationCoordinator(p)
	if err != nil {
		return result, identity.UnavailableError{}
	}
	q := identity.RecoveryQuery{CommandID: commandID, TenantID: spec.Payload.TenantID, UserID: identity.UserID(spec.Payload.SubjectID), RecordID: string(spec.IdentifierID), ActorID: identity.ActorID(caller.Request.Subject.ID), ActorKind: caller.Request.Subject.Kind, OperationID: "identity.email.verification-confirm"}
	admission, err := coordinator.ObserveCommandAdmission(ctx, q, caller)
	if err != nil {
		return result, err
	}
	if !admission.Absent {
		if replayed != nil {
			*replayed = true
		}
		// Exact single original-signup issuance and callback were authenticated
		// above. History cannot select a different subject/identifier/actor.
		return coordinator.RecoverFeatureCommand(ctx, q, caller)
	}
	state, err := s.directory.GetIdentifierState(ctx, identity.IdentifierQuery{TenantID: q.TenantID, UserID: q.UserID, MaximumIdentifiers: 128})
	if err != nil {
		return result, err
	}
	var at time.Time
	if err := s.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		return result, identity.UnavailableError{}
	}
	at = at.UTC().Truncate(time.Microsecond)
	p.intent = kernel.EmailVerificationIntent{Change: identity.IdentifierChange{TenantID: q.TenantID, UserID: q.UserID, ID: spec.IdentifierID, Action: identity.IdentifierVerify, ExpectedUserVersion: state.User.Version, ExpectedAuthorityVersion: state.AuthorityVersion, ExpectedIdentifierVersion: spec.IdentifierVersion, ExpectedVerificationVersion: spec.VerificationVersion}, CanonicalAddress: spec.Payload.CanonicalAddress.Record().Value, ComparisonProfile: c.RegistrationDomain.ComparisonProfile, RegistrationCommandID: origin}
	fields, err := kernel.EmailVerificationFields(p.intent)
	if err != nil {
		return result, err
	}
	op := p.FeatureOperations()[0]
	b := identity.CommandBinding{CommandID: commandID, TenantID: q.TenantID, UserID: q.UserID, ActorID: q.ActorID, ActorKind: q.ActorKind, RecordID: q.RecordID, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: c.PolicyID, PolicyVersion: c.Coordinator.AdmissionPolicy.PolicyVersion, CorrelationID: caller.CorrelationID}
	command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields})
	if err != nil {
		return result, err
	}
	capPlan, err := c.Verification.Issuer.PrepareRegistrationVerificationConsumption(ctx, b, proof, grant.EnvelopeDigest(), replay)
	if err != nil {
		return result, err
	}
	command, counters, err := c.Verification.Counters.PrepareVerificationCommandCounters(command, risk.Subject{User: string(q.UserID), Network: network}, capPlan.CapabilityID, at)
	if err != nil {
		return result, err
	}
	p.command = command
	plan, err := registrationConfirmationPlan(coordinator, registry, p, b, at, capPlan, counters)
	if err != nil {
		return result, err
	}
	reservation, result, err := coordinator.ReserveCommand(ctx, b, command, plan)
	if err != nil || reservation == (kernel.Reservation{}) {
		// Another invocation can commit after admission but before reservation.
		// Retained outcomes never authorize a fresh disclosure on this invocation.
		if replayed != nil && confirmationReservationReplayed(reservation, result, err) {
			*replayed = true
		}
		return result, err
	}
	work, err := coordinator.Begin(ctx, reservation)
	if err != nil {
		return identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeUnknown, Feature: &identity.FeatureReceipt{Operation: op}}, err
	}
	defer coordinator.Abort(work, identity.UnavailableError{})
	result, err = coordinator.ApplyFeature(ctx, work, command)
	if err != nil {
		return coordinator.Abort(work, err)
	}
	return coordinator.Commit(work, result)
}

func confirmationReservationReplayed(reservation kernel.Reservation, result identity.CommandResult, err error) bool {
	// Only the coordinator's successful zero-ticket branch observes retained
	// busy/terminal history. Fresh denial, ambiguity and conflict also return no
	// ticket, but carry an error and do not prove a prior command invocation.
	return err == nil && reservation == (kernel.Reservation{}) && result.Outcome != identity.CommitOutcomeInvalid
}

// RecoverRegistrationVerification observes/reconciles only the exact original
// confirmation command through current query authorization. It accepts no
// bearer, callback, password or execution input; expired/consumed proof is not
// needed and cannot be renewed or replayed. The original actor, user, tenant,
// identifier and command scope must match. It returns retained metadata only,
// not an address/session or permission to execute. Unknown remains unknown.
// Dependencies and duration/cleanup/cancellation semantics match confirmation.
func (s *SignupService) RecoverRegistrationVerification(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (result identity.CommandResult, err error) {
	if ctx == nil || s == nil || s.config == nil || s.pool == nil || s.directory == nil || s.config().Verification.Counters == nil || q.OperationID != "identity.email.verification-confirm" || q.RecordID == "" || q.UserID == "" {
		return result, identity.InvalidInputError{Field: "email_verification_recovery"}
	}
	ctx, stop := context.WithTimeout(ctx, s.config().Repository.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
	}()
	coordinator, _, err := s.confirmationCoordinator(&registrationConfirmationPhase{service: s})
	if err != nil {
		return result, identity.UnavailableError{}
	}
	return coordinator.RecoverFeatureCommand(ctx, q, caller)
}

func (s *SignupService) confirmationCoordinator(p *registrationConfirmationPhase) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	c := s.config()
	audits, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, err
	}
	outbox, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, nil, err
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{s.directory, audits, outbox, p, c.Verification.Counters, issuerpg.NewParticipant()})
	if err != nil {
		return nil, nil, err
	}
	coordinator, err := kernel.NewCoordinator(s.pool, registry, c.Coordinator)
	return coordinator, registry, err
}

type registrationConfirmationPhase struct {
	service *SignupService
	grant   capability.Grant
	spec    email.RegistrationVerificationSpec
	intent  kernel.EmailVerificationIntent
	command identity.Command
}

func (*registrationConfirmationPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/email/postgres", ContractID: "identity.email", Version: 1}
}
func (*registrationConfirmationPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{{Owner: "identity/email", OperationID: "identity.email.verification-confirm", SchemaID: "identity.email.verification-confirm.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}}
}
func (p *registrationConfirmationPhase) EmailVerification(c identity.Command) (kernel.EmailVerificationIntent, error) {
	if c != p.command || p.command == (identity.Command{}) {
		return kernel.EmailVerificationIntent{}, identity.ForbiddenError{}
	}
	return p.intent, nil
}
func (p *registrationConfirmationPhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if c != p.command || p.command == (identity.Command{}) || plan.CommandCounters == nil || plan.Capability == nil || plan.Capability.CapabilityID != p.grant.Payload().ID || plan.Capability.ProofFingerprint != p.grant.EnvelopeDigest() {
		return identity.ForbiddenError{}
	}
	return p.service.config().Verification.Counters.ValidateCommandCounters(c, *plan.CommandCounters)
}
func (p *registrationConfirmationPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.command {
		return identity.ForbiddenError{}
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if p.service.config().Verification.Policy.Authorize(p.grant, p.spec, now) != nil {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *registrationConfirmationPhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if err := w.RequireFeatureCommand(ctx, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.CheckFeatureCommit(ctx, w, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: p.FeatureOperations()[0], BeforeVersion: 1, AfterVersion: 2}, nil
}
func (*registrationConfirmationPhase) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	// No independently durable native writes exist. Kernel, capability, audit,
	// outbox and counter owners supply their own retained recovery evidence.
	return kernel.RecoveryNotCommitted, nil
}

func registrationConfirmationPlan(coordinator *kernel.Coordinator, registry *kernel.ContributorRegistry, p *registrationConfirmationPhase, b identity.CommandBinding, at time.Time, capPlan kernel.CapabilityPlan, counters kernel.CommandCounterPlan) (kernel.CommandPlan, error) {
	actor := audit.ActorService
	if b.ActorKind == authorization.SubjectUser {
		actor = audit.ActorHuman
	}
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	op := p.FeatureOperations()[0]
	seed, err := builder.Build(audit.RecordInput{OccurredAt: at, Action: "email.verified", Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: actor, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "identifier", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "identifier", "aggregate.id": b.RecordID, "aggregate.before_version": "1", "aggregate.after_version": "2", "retention.class": "protected"}})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, op, "identifier", seed)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	return coordinator.PrepareCommandPlan(b, p.command, kernel.CommandPlan{Contributors: registry.Descriptors(), Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op}, SubjectType: "identifier", Capability: &capPlan, CommandCounters: &counters, Lifecycle: &kernel.LifecyclePlan{EventType: "identifier.verified.v1", BeforeVersion: 1, AfterVersion: 2}, Audits: []kernel.AuditPlan{{EventType: "email.verified", SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}})
}
