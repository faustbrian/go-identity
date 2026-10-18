package passwordpostgres

import (
	"context"
	"encoding/base64"
	"errors"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/otp"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/phone"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
)

type phoneConfirmationPhase struct {
	service      *phoneVerificationService
	source       *phoneEnrollmentPhase
	confirmation otppg.PhoneEnrollmentConfirmation
	intent       kernel.PhoneVerificationIntent
	command      identity.Command
	attempt      kernel.OTPAttemptPlan
	admission    risk.AuthenticationAdmission
	csrf         session.CSRFToken
	coordinator  *kernel.Coordinator
	registry     *kernel.ContributorRegistry
}

var _ kernel.PhoneVerificationContributor = (*phoneConfirmationPhase)(nil)

func (*phoneConfirmationPhase) Descriptor() kernel.ContributorDescriptor {
	return phoneVerificationDescriptor()
}
func (*phoneConfirmationPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{phoneVerificationOperation()}
}
func (p *phoneConfirmationPhase) PhoneVerification(c identity.Command) (kernel.PhoneVerificationIntent, *kernel.PhoneEnrollmentDomain, error) {
	if p == nil || p.service == nil || c != p.command {
		return kernel.PhoneVerificationIntent{}, nil, password.ErrPasswordWork
	}
	return p.intent, p.service.domain, nil
}
func (p *phoneConfirmationPhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.service == nil || c != p.command {
		return password.ErrPasswordWork
	}
	spec, ok := c.Feature()
	if !ok || spec.Operation != phoneVerificationOperation() || plan.Feature == nil || plan.Feature.Contributor != p.Descriptor() || plan.Feature.Operation != spec.Operation || plan.SubjectType != "identifier" || plan.Lifecycle == nil || plan.Lifecycle.EventType != "identifier.verified.v1" || plan.Lifecycle.BeforeVersion != 1 || plan.Lifecycle.AfterVersion != 2 || plan.OTP == nil || *plan.OTP != p.attempt || plan.OTP.Mode != kernel.OTPConsume || plan.Capability != nil || plan.CapabilityIssuance != nil || plan.Delivery != nil || plan.RiskEvidence != nil || plan.CommandCounters != nil || len(plan.Audits) != 1 || !plan.Audits[0].Required || plan.Audits[0].RetentionClass != "protected" {
		return password.ErrPasswordWork
	}
	owner := p.confirmation.Contributor()
	if owner == nil {
		return password.ErrPasswordWork
	}
	return owner.ValidateOTPAttemptCommand(c, p.attempt)
}
func (p *phoneConfirmationPhase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.command {
		return password.ErrPasswordWork
	}
	// This kernel-owned exclusive target lock precedes every wrong-code debit
	// and consuming reservation in their actual coordinator transaction.
	if err := w.RequirePhoneVerificationTarget(ctx, p, c); err != nil {
		return err
	}
	return p.check(ctx, w, c, false)
}
func (p *phoneConfirmationPhase) check(ctx context.Context, w kernel.Work, c identity.Command, final bool) error {
	if p == nil || p.source == nil || c != p.command {
		return password.ErrPasswordWork
	}
	var err error
	if final {
		err = p.confirmation.Check(ctx, w, p, c)
	} else {
		err = p.confirmation.Admit(ctx, w, p, c)
	}
	if err != nil {
		return err
	}
	if _, err = mfapg.RequirePhoneFactors(ctx, w, p, c, p.source.factorVersion); err != nil {
		return err
	}
	original, err := p.source.primary.Original()
	if err != nil {
		return err
	}
	if err = p.service.requireCSRF(ctx, w, original, p.csrf); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if now.Before(p.source.at) || !now.Before(p.source.until) {
		return identity.ForbiddenError{}
	}
	return p.admission.CheckAt(ctx, now)
}
func (p *phoneConfirmationPhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if err := w.RequireFeatureCommand(ctx, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	checked, err := w.OTPConsumption(p)
	if err != nil || checked.Plan != p.attempt {
		return identity.FeatureReceipt{}, password.ErrPasswordWork
	}
	if err = p.check(ctx, w, c, false); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: phoneVerificationOperation(), BeforeVersion: 1, AfterVersion: 2}, nil
}
func (p *phoneConfirmationPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	return p.check(ctx, w, c, true)
}
func (p *phoneConfirmationPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	_, f, _, err := w.FeatureScope(p)
	if err != nil || f.Operation != phoneVerificationOperation() {
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	// This participant owns admission only. The kernel target and actual OTP
	// participant supply their separate durable recovery votes; no local marker
	// or current verified state is invented as evidence of historical success.
	return kernel.RecoveryNotCommitted, nil
}

// Verify creates one new server-owned logical attempt against the exact committed
// enrollment. Wrong-code denial, reservation, OTP use and identifier verification
// use the existing coordinator and actual owners. A repeat call is a new attempt;
// ambiguity must use RecoverVerification with the original returned custody.
func (s *PhoneVerificationService) Verify(ctx context.Context, r phone.VerificationRequest) (out phone.VerificationResult, err error) {
	state := s.state()
	if ctx == nil || state == nil {
		return out, password.ErrPasswordWork
	}
	request, err := r.Bindings()
	if err != nil {
		return out, err
	}
	ctx, stop := context.WithTimeout(ctx, state.config().MaximumDuration)
	defer stop()
	var result phone.VerificationResultSpec
	entered := false
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
			if entered {
				result.Outcome = identity.CommitOutcomeUnknown
				result.Identifier = identity.IdentifierProjection{}
			}
		}
		if result.Binding.CommandID != "" {
			mapped, e := phone.NewVerificationResult(result)
			if e != nil {
				err = identity.UnavailableError{}
			} else {
				out = mapped
			}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
	}()
	source, confirmation, err := state.restorePhoneSource(ctx, request.TenantID, request.UserID, request.Caller, request.Flow, request.SendCommandID, request.CSRFToken)
	if err != nil {
		return out, err
	}
	intent, err := confirmation.Intent()
	if err != nil {
		return out, err
	}
	if _, err = state.currentPhoneSource(ctx, request.Caller, source, true); err != nil {
		return out, err
	}
	original, err := source.primary.Original()
	if err != nil {
		return out, err
	}
	if err = state.checkCSRF(original, request.CSRFToken); err != nil {
		return out, err
	}
	b := sourceBinding(source.command)
	op := phoneVerificationOperation()
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	b.CommandID, err = identity.NewCommandID()
	if err != nil {
		return out, readerFailure(ctx)
	}
	b.CorrelationID = string(b.CommandID)
	fields, err := confirmation.Fields()
	if err != nil {
		return out, err
	}
	_, _, bearer, _ := request.Flow.Bindings()
	root, err := identity.NewFeatureSessionCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields}, bearer)
	if err != nil {
		return out, err
	}
	p := &phoneConfirmationPhase{service: state, source: source, confirmation: confirmation, intent: intent, csrf: request.CSRFToken}
	p.coordinator, p.registry, err = state.coordinator(p, confirmation.Contributor())
	if err != nil {
		return out, err
	}
	q := phoneRecoveryQuery(b)
	caller := state.phoneQueryCaller(request.Caller, q, false)
	observed, err := p.coordinator.ObserveCommandAdmission(ctx, q, caller)
	if err != nil || !observed.Absent {
		if err == nil {
			err = identity.ForbiddenError{}
		}
		return out, err
	}
	p.command, p.attempt, err = confirmation.Prepare(ctx, state.primary.primary.source.pool, root, request.Code, state.config().CurrentAttemptKeyVersion)
	if err != nil {
		return out, err
	}
	result = phone.VerificationResultSpec{Binding: b, Outcome: identity.CommitOutcomeNotCommitted}
	result.Recovery, err = phoneRecoveryFromPlan(b, request.SendCommandID, p.attempt)
	if err != nil {
		return out, err
	}
	p.admission, err = state.prepareRisk(ctx, b, source.subject)
	if err != nil {
		return out, err
	}
	plan, err := p.plan()
	if err != nil {
		return out, err
	}
	plan, err = p.coordinator.PrepareOTPReservationPlan(b, p.command, plan)
	if err != nil {
		return out, err
	}
	entered = true
	denied, err := p.coordinator.RecordOTPAttemptDenial(ctx, b, p.command, plan)
	var conflict identity.ConflictError
	if denied.Outcome != identity.CommitOutcomeConflict || !errors.As(err, &conflict) {
		result.Outcome, result.RetryAfter = denied.Outcome, denied.RetryAfter
		return out, err
	}
	reservation, receipt, err := p.coordinator.ReserveOTPCommand(ctx, b, p.command, plan)
	if err != nil || reservation == (kernel.Reservation{}) {
		result.Outcome, result.RetryAfter, result.Replayed = receipt.Outcome, receipt.RetryAfter, true
		return out, err
	}
	w, err := p.coordinator.Begin(ctx, reservation)
	if err != nil {
		result.Outcome = identity.CommitOutcomeUnknown
		return out, err
	}
	defer p.coordinator.Abort(w, identity.UnavailableError{})
	receipt, err = p.coordinator.ApplyFeature(ctx, w, p.command)
	if err == nil {
		receipt, err = p.coordinator.Commit(w, receipt)
	} else {
		receipt, err = p.coordinator.Abort(w, err)
	}
	result.Outcome, result.RetryAfter = receipt.Outcome, receipt.RetryAfter
	if err == nil && receipt.Outcome == identity.CommitOutcomeCommitted {
		result.Identifier, err = state.committedPhone(ctx, intent)
	}
	return out, err
}

func (p *phoneConfirmationPhase) plan() (kernel.CommandPlan, error) {
	spec, ok := p.command.Feature()
	if !ok || p.registry == nil {
		return kernel.CommandPlan{}, password.ErrPasswordWork
	}
	plan, err := resetServiceAuditDeclaration(spec.Binding, spec.Operation, p.registry.Descriptors(), "identifier", 1, 2, p.source.at)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	plan.Feature.Contributor = p.Descriptor()
	plan.Lifecycle.EventType = "identifier.verified.v1"
	plan.OTP = &p.attempt
	return plan, nil
}
func sourceBinding(c identity.Command) identity.CommandBinding {
	spec, _ := c.Feature()
	return spec.Binding
}

func (s *phoneVerificationService) committedPhone(ctx context.Context, i kernel.PhoneVerificationIntent) (identity.IdentifierProjection, error) {
	c := i.Change
	state, err := s.directory.GetIdentifierState(ctx, identity.IdentifierQuery{TenantID: c.TenantID, UserID: c.UserID, MaximumIdentifiers: 128})
	if err != nil {
		return identity.IdentifierProjection{}, err
	}
	if state.User.Status != identity.StatusActive || state.User.Version != c.ExpectedUserVersion+1 || state.AuthorityVersion != c.ExpectedAuthorityVersion+1 {
		return identity.IdentifierProjection{}, identity.ForbiddenError{}
	}
	now, err := s.now(ctx)
	if err != nil {
		return identity.IdentifierProjection{}, err
	}
	projection, err := identity.NewIdentifierProjection(identity.IdentifierProjectionSpec{TenantID: c.TenantID, UserID: c.UserID, IdentifierID: c.ID, State: state, Values: identity.IdentifierValuesOmitted, ObservedAt: now})
	b, e := projection.Bindings()
	if err != nil || e != nil || b.Kind != identity.IdentifierPhone || !b.Verified || b.Primary || b.IdentifierVersion != 2 || b.VerificationVersion != 2 {
		return identity.IdentifierProjection{}, identity.ForbiddenError{}
	}
	return projection, nil
}

func phoneRecoveryFromPlan(b identity.CommandBinding, send identity.CommandID, p kernel.OTPAttemptPlan) (phone.VerificationRecovery, error) {
	return phone.NewVerificationRecovery(otp.CheckRecoveryBindings{SendCommandID: send, Attempt: otp.AttemptRecoveryIdentity{TenantID: b.TenantID, CommandID: b.CommandID, AttemptID: otp.AttemptID(p.AttemptID), Fingerprint: otp.AttemptFingerprint(base64.RawURLEncoding.EncodeToString(p.AttemptFingerprint[:])), FingerprintKeyVersion: p.FingerprintKeyVersion}, ExpectedVersion: p.ExpectedVersion, DigestKeyVersion: p.DigestKeyVersion, ScopeDigest: p.ScopeDigest})
}
