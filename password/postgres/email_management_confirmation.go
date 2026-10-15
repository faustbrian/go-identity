package passwordpostgres

import (
	"bytes"
	"context"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	email "github.com/faustbrian/go-identity/email"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// VerificationConfirm explicitly verifies the original managed pending address.
// It authenticates original signed/encrypted intent and current caller policy,
// then atomically consumes one-use proof with directory, audit and lifecycle
// effects. Original source credential/authorization, global/tenant authority and
// known-empty MFA remain required; the historical session need not remain live.
// This verification-only profile performs no primary swap, delivery or signin.
//
// Tenant/caller/network are trusted composition, never client authority. Stable
// CommandID retries bind the exact original proof/callback/request and return
// metadata only; changed intent conflicts. Existing verification-counter history
// is required. No callbacks/network IO execute under SQL locks. Calls borrow the
// proof/pool, own invocation phases, retain no Work/goroutines and are bounded by
// MaximumDuration/earlier cancellation. Unknown remains unknown; later disclosure
// errors preserve any known commit but return no address. Errors are redacted.
func (s *EmailManagementService) VerificationConfirm(ctx context.Context, r email.VerificationConfirmRequest) (out email.VerificationConfirmResult, err error) {
	if ctx == nil || s == nil || s.config == nil || s.primary == nil || s.primary.config.Action != "identity.email.verification-send" || r.Validate() != nil {
		return out, email.ErrInvalidVerification
	}
	result, err := s.confirmManaged(ctx, r)
	out = email.VerificationConfirmResult{Outcome: result.Outcome, Address: result.Address, Replayed: result.Replayed, RetryAfter: result.RetryAfter}
	if result.Recovery.CommandID != "" {
		var e error
		out.Recovery, e = email.NewVerificationRecovery(result.Recovery)
		if e != nil {
			return out, identity.UnavailableError{}
		}
		if out.Validate() != nil {
			out.Address = identity.IdentifierProjection{}
			return out, identity.UnavailableError{}
		}
	}
	return out, err
}

// ChangeConfirm authenticates original new-address possession and fresh
// password-change intent, then atomically verifies/promotes the candidate,
// invalidates old identifier-bound sessions and stages old-address notification.
// It issues no authentication cookie. Unknown/rollback do not imply success;
// exact replay returns metadata and never duplicates the notice. Scope, bounded
// cancellation, current MFA/risk admission and custody match VerificationConfirm.
func (s *EmailManagementService) ChangeConfirm(ctx context.Context, r email.ChangeConfirmRequest) (out email.ChangeConfirmResult, err error) {
	if ctx == nil || s == nil || s.config == nil || s.primary == nil || s.primary.config.Action != "identity.email.change-request" || r.Validate() != nil {
		return out, email.ErrInvalidVerification
	}
	result, err := s.confirmManaged(ctx, email.VerificationConfirmRequest(r))
	out = email.ChangeConfirmResult{Outcome: result.Outcome, Address: result.Address, Replayed: result.Replayed, RetryAfter: result.RetryAfter}
	if result.Recovery.CommandID != "" {
		var e error
		out.Recovery, e = email.NewChangeRecovery(result.Recovery)
		if e != nil {
			return out, identity.UnavailableError{}
		}
		if out.Validate() != nil {
			out.Address = identity.IdentifierProjection{}
			return out, identity.UnavailableError{}
		}
	}
	return out, err
}

type managedConfirmationResult struct {
	Outcome    identity.CommitOutcome
	Address    identity.IdentifierProjection
	Replayed   bool
	RetryAfter time.Duration
	Recovery   identity.RecoveryQuery
}

func (s *EmailManagementService) confirmManaged(ctx context.Context, r email.VerificationConfirmRequest) (out managedConfirmationResult, err error) {
	ctx, stop := context.WithTimeout(ctx, s.config().MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			out.Address = identity.IdentifierProjection{}
		}
	}()
	grant, origin, replay, err := s.issuer.ReadIssuanceOrigin(ctx, s.primary.source.pool, r.Token, "identity.identifier.verify")
	if err != nil {
		return out, err
	}
	caller := r.Caller.Clone()
	if caller.Request.Resource.ID == "" {
		caller.Request.Resource.ID = authorization.ResourceID(grant.Payload().Subject)
	}
	var original managedEmailOriginAdmission
	spec, version, err := s.readManagedVerification(ctx, r.Token, caller, &original)
	if err != nil {
		return out, err
	}
	if origin != spec.Binding.CommandID || version != replay || origin == r.CommandID || r.TenantID != spec.Binding.TenantID || r.Callback.String() != spec.Payload.Redirect.String() {
		return out, identity.ForbiddenError{}
	}
	op := s.confirmationOperation()
	b := identity.CommandBinding{CommandID: r.CommandID, TenantID: r.TenantID, UserID: spec.Binding.UserID, ActorID: identity.ActorID(caller.Request.Subject.ID), ActorKind: caller.Request.Subject.Kind, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, RecordID: string(spec.IdentifierID), PolicyID: s.config().PolicyID, PolicyVersion: s.primary.source.c.Coordinator.AdmissionPolicy.PolicyVersion, CorrelationID: caller.CorrelationID}
	q := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
	p := &managedEmailConfirmationPhase{service: s, grant: grant, spec: spec, original: original}
	coordinator, registry, err := s.managedConfirmationCoordinator(p)
	if err != nil {
		return out, identity.UnavailableError{}
	}
	observed, err := coordinator.ObserveCommandAdmission(ctx, q, caller)
	if err != nil {
		return out, err
	}
	if !observed.Absent {
		if observed.Record.Feature == nil || *observed.Record.Feature != op {
			return out, identity.ForbiddenError{}
		}
		// Transport correlation is fresh for each HTTP attempt, not new domain
		// intent. Preserve the first acknowledged command's correlation while
		// still rebuilding/comparing every original proof, callback and counter
		// field through Reserve; history is not a shortcut around that fence.
		b.CorrelationID = observed.Record.Binding.CorrelationID
	}
	if observed.Absent {
		valid, e := s.ValidateManagedVerification(ctx, r.Token, r.Callback.String(), caller)
		if e != nil {
			return out, e
		}
		if !valid {
			return out, identity.ForbiddenError{}
		}
	}
	// Freeze predecessors/timing from the original acknowledged attachment,
	// not today's state or retry clock. Reserve can therefore compare the full
	// same-command intent even after its successor and proof use committed.
	p.intent = kernel.ManagedEmailVerificationIntent{Change: identity.IdentifierChange{TenantID: b.TenantID, UserID: b.UserID, ID: spec.IdentifierID, Action: identity.IdentifierVerify, ExpectedUserVersion: original.UserVersion + 1, ExpectedAuthorityVersion: original.IdentifierVersion + 1, ExpectedIdentifierVersion: spec.IdentifierVersion, ExpectedVerificationVersion: spec.VerificationVersion}, CanonicalAddress: spec.Payload.CanonicalAddress.Record().Value, ComparisonProfile: s.config().Domain.ComparisonProfile, RequestCommandID: origin}
	if s.primary.config.Action == "identity.email.change-request" {
		p.intent.Change.Action = identity.IdentifierVerifyPrimary
		p.intent.Previous = kernelPrevious(spec.Previous, spec.ChangeProfile)
	}
	fields, err := kernel.ManagedEmailVerificationFields(p.intent)
	if err != nil {
		return out, err
	}
	fields = append(fields, identity.FeatureField{Name: "managed-email.factor-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: original.FactorVersion}}, identity.FeatureField{Name: "managed-email.profile", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: bytes.Clone(s.profile[:])}})
	if s.config().ResendInterval != 0 {
		family, e := issuerpg.ManagedEmailScopeFromPayload(grant.Payload())
		if e != nil {
			return out, e
		}
		digest := family.Digest()
		fields = append(fields, identity.FeatureField{Name: "email.management.family", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: bytes.Clone(digest[:])}})
	}
	command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields})
	if err != nil {
		return out, err
	}
	var proofPlan kernel.CapabilityPlan
	if s.primary.config.Action == "identity.email.change-request" {
		proofPlan, err = s.issuer.PrepareManagedChangeConsumption(ctx, b, r.Token, grant.EnvelopeDigest(), replay)
	} else {
		proofPlan, err = s.issuer.PrepareManagedVerificationConsumption(ctx, b, r.Token, grant.EnvelopeDigest(), replay)
	}
	if err != nil {
		return out, err
	}
	var counters kernel.CommandCounterPlan
	if s.primary.config.Action == "identity.email.change-request" {
		command, counters, err = s.config().Counters.PrepareEmailChangeCommandCounters(command, risk.Subject{User: string(b.UserID), Network: r.Network}, proofPlan.CapabilityID, spec.IssuedAt)
	} else {
		command, counters, err = s.config().Counters.PrepareVerificationCommandCounters(command, risk.Subject{User: string(b.UserID), Network: r.Network}, proofPlan.CapabilityID, spec.IssuedAt)
	}
	if err != nil {
		return out, err
	}
	p.command = command
	scope := risk.Context{Tenant: string(b.TenantID), Operation: risk.Action(b.OperationID), Attempt: string(b.CommandID)}
	providers, err := s.config().Risk.Evaluation.EvaluateProtectedProviders(ctx, risk.EvaluateRequest{Context: scope, Phase: risk.NonIssuing})
	if err != nil {
		return out, err
	}
	p.providers, err = s.custody.Prepare(ctx, providers, scope)
	if err != nil {
		return out, err
	}
	contributors := registry.Descriptors()
	var notificationPlan *kernel.DeliveryPlan
	if s.primary.config.Action == "identity.email.change-request" {
		p.notification, err = s.prepareChangeNotification(ctx, b, spec)
		if err != nil {
			return out, err
		}
		declaration, e := p.notification.Plan()
		if e != nil {
			return out, e
		}
		notificationPlan = &declaration
		filtered := make([]kernel.ContributorDescriptor, 0, len(contributors))
		for _, d := range contributors {
			if d != declaration.Contributor {
				filtered = append(filtered, d)
			}
		}
		contributors = append(filtered, declaration.Contributor)
	}
	plan, err := resetServiceAuditDeclaration(b, op, contributors, "identifier", spec.VerificationVersion, spec.VerificationVersion+1, spec.IssuedAt)
	if err != nil {
		return out, err
	}
	plan.Feature.Contributor = p.Descriptor()
	plan.Lifecycle.EventType = "identifier.verified.v1"
	if notificationPlan != nil {
		plan.Lifecycle.EventType = "identifier.primary-changed.v1"
		plan.Delivery = notificationPlan
	}
	plan.Capability = &proofPlan
	plan.CommandCounters = &counters
	plan, err = coordinator.PrepareCommandPlan(b, command, plan)
	if err != nil {
		return out, err
	}
	reservation, result, err := coordinator.ReserveCommand(ctx, b, command, plan)
	if err == nil && reservation != (kernel.Reservation{}) {
		work, e := coordinator.Begin(ctx, reservation)
		if e != nil {
			result = identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeUnknown, Feature: &identity.FeatureReceipt{Operation: op}}
			err = e
		} else {
			defer coordinator.Abort(work, identity.UnavailableError{})
			result, err = coordinator.ApplyFeature(ctx, work, command)
			if err != nil {
				result, err = coordinator.Abort(work, err)
			} else {
				result, err = coordinator.Commit(work, result)
			}
		}
	} else if confirmationReservationReplayed(reservation, result, err) {
		out.Replayed = true
	}
	out.Outcome, out.RetryAfter = result.Outcome, result.RetryAfter
	if result.Outcome == identity.CommitOutcomeInvalid {
		return out, err
	}
	out.Recovery = q
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted || out.Replayed {
		return out, err
	}
	state, err := s.directory.GetIdentifierState(ctx, identity.IdentifierQuery{TenantID: b.TenantID, UserID: b.UserID, MaximumIdentifiers: 128})
	if err != nil {
		return out, err
	}
	var at time.Time
	if err := s.primary.source.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		return out, identity.UnavailableError{}
	}
	out.Address, err = identity.NewIdentifierProjection(identity.IdentifierProjectionSpec{TenantID: b.TenantID, UserID: b.UserID, IdentifierID: spec.IdentifierID, State: state, ObservedAt: at.UTC().Truncate(time.Microsecond), Values: identity.IdentifierValuesIncluded})
	if err != nil {
		return out, identity.UnavailableError{}
	}
	return out, nil
}

func managedConfirmationRecovery(q identity.RecoveryQuery, executionErr error) (email.VerificationRecovery, error) {
	r, err := email.NewVerificationRecovery(q)
	if err != nil {
		return r, identity.UnavailableError{}
	}
	return r, executionErr
}

// VerificationRecover observes the exact original managed confirmation under
// current query policy. No expired/consumed proof, callback or original session
// is needed. It never re-executes, renews authority or discloses an address or
// session; unavailable reconciliation remains Unknown. Ownership, cancellation
// and error redaction match VerificationConfirm.
func (s *EmailManagementService) VerificationRecover(ctx context.Context, r email.VerificationRecoveryRequest) (out email.VerificationRecoveryResult, err error) {
	if ctx == nil || s == nil || s.config == nil || s.primary == nil || s.primary.config.Action != "identity.email.verification-send" || r.Validate() != nil {
		return out, email.ErrInvalidVerification
	}
	ctx, cancel := context.WithTimeout(ctx, s.config().MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
	}()
	q, _ := r.Recovery.Bindings()
	caller := r.Caller.Clone()
	if caller.Request.Resource.ID == "" {
		caller.Request.Resource.ID = authorization.ResourceID(q.UserID)
	}
	coordinator, _, err := s.managedConfirmationCoordinator(&managedEmailConfirmationPhase{service: s})
	if err != nil {
		return out, identity.UnavailableError{}
	}
	result, err := coordinator.RecoverFeatureCommand(ctx, q, caller)
	if result.Outcome == identity.CommitOutcomeInvalid {
		return out, err
	}
	out = email.VerificationRecoveryResult{Outcome: result.Outcome, RetryAfter: result.RetryAfter, Recovery: r.Recovery}
	if out.Validate() != nil {
		return out, identity.UnavailableError{}
	}
	return out, err
}

func managedConfirmationOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/email", OperationID: "identity.email.verification-confirm", SchemaID: "identity.email.verification-confirm.managed-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func (s *EmailManagementService) confirmationOperation() identity.FeatureOperation {
	if s.primary.config.Action == "identity.email.change-request" {
		return identity.FeatureOperation{Owner: "identity/email", OperationID: "identity.email.change-confirm", SchemaID: "identity.email.change-confirm.managed-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	}
	return managedConfirmationOperation()
}

func (s *EmailManagementService) managedConfirmationCoordinator(p *managedEmailConfirmationPhase) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	audits, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, err
	}
	lifecycle, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, nil, err
	}
	contributors := []kernel.Contributor{s.directory, audits, lifecycle, p, s.config().Counters, issuerpg.NewParticipant()}
	if s.primary.config.Action == "identity.email.change-request" {
		contributors = append(contributors, s.config().Delivery.Owner)
	}
	registry, err := kernel.NewContributorRegistry(contributors)
	if err != nil {
		return nil, nil, err
	}
	c, err := kernel.NewCoordinator(s.primary.source.pool, registry, s.primary.source.c.Coordinator)
	return c, registry, err
}

type managedEmailConfirmationPhase struct {
	service      *EmailManagementService
	grant        capability.Grant
	spec         email.ManagedVerificationSpec
	original     managedEmailOriginAdmission
	intent       kernel.ManagedEmailVerificationIntent
	command      identity.Command
	providers    risk.ProtectedProviderAdmission
	notification deliverypg.PreparedDelivery
}

func (*managedEmailConfirmationPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/email/postgres", ContractID: "identity.email", Version: 1}
}
func (p *managedEmailConfirmationPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{p.service.confirmationOperation()}
}
func (p *managedEmailConfirmationPhase) ManagedEmailVerification(c identity.Command) (kernel.ManagedEmailVerificationIntent, *kernel.EmailAttachmentDomain, error) {
	if c != p.command || c == (identity.Command{}) {
		return kernel.ManagedEmailVerificationIntent{}, nil, identity.ForbiddenError{}
	}
	return p.intent, p.service.domain, nil
}
func (p *managedEmailConfirmationPhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if c != p.command || c == (identity.Command{}) || plan.Capability == nil || plan.CommandCounters == nil || plan.Capability.CapabilityID != p.grant.Payload().ID || plan.Capability.ProofFingerprint != p.grant.EnvelopeDigest() {
		return identity.ForbiddenError{}
	}
	s, _ := c.Feature()
	var factor, profile bool
	for _, f := range s.Fields {
		if f.Name == "managed-email.factor-version" {
			factor = f.Value.Kind == identity.FeatureUint64 && f.Value.Uint64 == p.original.FactorVersion
		}
		if f.Name == "managed-email.profile" {
			profile = f.Value.Kind == identity.FeatureBytes && bytes.Equal(f.Value.Bytes, p.service.profile[:])
		}
	}
	if !factor || !profile {
		return identity.ForbiddenError{}
	}
	if p.service.config().ResendInterval != 0 {
		family, err := issuerpg.ManagedEmailScopeFromPayload(p.grant.Payload())
		digest := family.Digest()
		matched := false
		for _, f := range s.Fields {
			if f.Name == "email.management.family" {
				matched = f.Value.Kind == identity.FeatureBytes && bytes.Equal(f.Value.Bytes, digest[:])
			}
		}
		if err != nil || !matched {
			return identity.ForbiddenError{}
		}
	}
	return p.service.config().Counters.ValidateCommandCounters(c, *plan.CommandCounters)
}
func (p *managedEmailConfirmationPhase) check(ctx context.Context, w kernel.Work, c identity.Command, final bool) error {
	if c != p.command {
		return identity.ForbiddenError{}
	}
	if err := w.RequireActiveDirectoryAuthority(ctx, p, p.original.Directory); err != nil {
		return err
	}
	credential := p.original.Credential
	if final {
		credential.IdentifierAuthorityVersion++
	}
	if _, err := w.RequireActiveCredential(ctx, p, credential); err != nil {
		return err
	}
	if err := w.RequireActiveUserAuthorization(ctx, p, p.original.Authorization); err != nil {
		return err
	}
	if _, err := mfapg.RequireManagedEmailFactors(ctx, w, p, c, p.original.FactorVersion); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if p.service.policy.Authorize(p.grant, p.spec, now) != nil {
		return identity.ForbiddenError{}
	}
	return p.providers.CheckAt(ctx, now)
}
func (p *managedEmailConfirmationPhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if err := w.RequireFeatureCommand(ctx, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.check(ctx, w, c, false); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.service.primary.config.Action == "identity.email.change-request" {
		if err := p.service.config().Delivery.Owner.Stage(ctx, w, p.notification); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	return identity.FeatureReceipt{Operation: p.service.confirmationOperation(), BeforeVersion: p.spec.VerificationVersion, AfterVersion: p.spec.VerificationVersion + 1}, nil
}
func (p *managedEmailConfirmationPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	return p.check(ctx, w, c, true)
}
func (*managedEmailConfirmationPhase) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return kernel.RecoveryNotCommitted, nil
}
