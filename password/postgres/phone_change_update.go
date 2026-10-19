package passwordpostgres

import (
	"context"
	"errors"
	"fmt"
	"slices"

	identity "github.com/faustbrian/go-identity"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/phone"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

type phoneChangeUpdatePhase struct {
	service      *phoneChangeService
	source       *phoneChangeSendPhase
	request      phone.UpdateRequestSpec
	primary      ActionPrimaryAdmission
	confirmation otppg.PhoneChangeConfirmation
	intent       kernel.PhoneChangeIntent
	command      identity.Command
	attempt      kernel.OTPAttemptPlan
	counter      kernel.CommandCounterPlan
	admission    risk.ProtectedProviderAdmission
	notice       deliverypg.PreparedDelivery
	coordinator  *kernel.Coordinator
	registry     *kernel.ContributorRegistry
	// Per-invocation observation only, not durable authority. The coordinator
	// returns existing history before invoking fresh Work input admission.
	attemptAdmitted bool
}

var _ kernel.PhoneChangeContributor = (*phoneChangeUpdatePhase)(nil)

func (*phoneChangeUpdatePhase) Descriptor() kernel.ContributorDescriptor {
	return phoneVerificationDescriptor()
}
func (*phoneChangeUpdatePhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{actionPrimaryOperation("identity.phone.update")}
}
func (p *phoneChangeUpdatePhase) PhoneChange(c identity.Command) (kernel.PhoneChangeIntent, *kernel.PhoneChangeDomain, error) {
	if p == nil || p.service == nil || c != p.command {
		return kernel.PhoneChangeIntent{}, nil, password.ErrPasswordWork
	}
	return p.intent, p.service.domain, nil
}
func (p *phoneChangeUpdatePhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.service == nil || p.source == nil || c != p.command || !phoneCommandProfile(c, p.service.profile, p.source.factors) {
		return password.ErrPasswordWork
	}
	op := p.FeatureOperations()[0]
	before := p.intent.Change.ExpectedIdentifierVersion
	if plan.Feature == nil || plan.Feature.Contributor != p.Descriptor() || plan.Feature.Operation != op || plan.SubjectType != "identifier" || plan.Lifecycle == nil || *plan.Lifecycle != (kernel.LifecyclePlan{EventType: "identifier.changed.v1", BeforeVersion: before, AfterVersion: before + 1}) || plan.OTP == nil || *plan.OTP != p.attempt || plan.CommandCounters == nil || *plan.CommandCounters != p.counter || plan.Capability != nil || plan.CapabilityIssuance != nil || plan.RiskEvidence != nil || len(plan.Audits) != 1 || !plan.Audits[0].Required || plan.Audits[0].RetentionClass != "standard" || plan.Audits[0].EventType != "identity.identifier.change" {
		return password.ErrPasswordWork
	}
	notice, err := p.notice.Plan()
	if err != nil || plan.Delivery == nil || plan.Delivery.Contributor != notice.Contributor || !slices.Equal(plan.Delivery.Intents, notice.Intents) {
		return password.ErrPasswordWork
	}
	owner := p.confirmation.Contributor()
	if owner == nil {
		return password.ErrPasswordWork
	}
	return owner.ValidateOTPAttemptCommand(c, p.attempt)
}
func (p *phoneChangeUpdatePhase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, c identity.Command) error {
	// Lock the exact predecessor and both numbers before code comparison, debit
	// or reservation, in the sole coordinator transaction.
	if err := w.RequirePhoneChangeTarget(ctx, p, c); err != nil {
		return err
	}
	if err := p.check(ctx, w, c, false); err != nil {
		return err
	}
	p.attemptAdmitted = true
	return nil
}
func (p *phoneChangeUpdatePhase) check(ctx context.Context, w kernel.Work, c identity.Command, final bool) error {
	if p == nil || p.source == nil || c != p.command {
		return password.ErrPasswordWork
	}
	if final {
		if err := p.confirmation.Check(ctx, w, p, c); err != nil {
			return err
		}
	} else {
		if err := p.confirmation.Admit(ctx, w, p, c); err != nil {
			return err
		}
		if err := p.primary.Admit(ctx, w, p, c); err != nil {
			return err
		}
	}
	if err := p.primary.Check(ctx, w, p, c); err != nil {
		return err
	}
	original, err := p.primary.Original()
	if err != nil {
		return err
	}
	// The directory epoch advances exactly once. The OTP owner checks that
	// successor; still fence the original session/family and synchronizer here.
	if err = sessionpg.RequireSession(ctx, w, p.service.update.primary.source.c.Session, original); err != nil {
		return err
	}
	if err = p.service.common.requireCSRF(ctx, w, original, p.request.CSRFToken); err != nil {
		return err
	}
	if _, err = mfapg.RequirePhoneFactors(ctx, w, p, c, p.source.factors); err != nil {
		return err
	}
	if err = requireIndependentPhoneRecovery(ctx, w, p.primary, p.intent.Change.TenantID, p.intent.Change.UserID, p.service.signin, p.service.reset); err != nil {
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
func (p *phoneChangeUpdatePhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
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
	if err = p.primary.Consume(ctx, w, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err = p.service.notices.Stage(ctx, w, p.notice); err != nil {
		return identity.FeatureReceipt{}, err
	}
	before := p.intent.Change.ExpectedIdentifierVersion
	return identity.FeatureReceipt{Operation: p.FeatureOperations()[0], BeforeVersion: before, AfterVersion: before + 1}, nil
}
func (p *phoneChangeUpdatePhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	return p.check(ctx, w, c, true)
}
func (p *phoneChangeUpdatePhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return p.service.update.Recover(ctx, w, p)
}

// Update maps one retry key to one original logical consuming attempt, including
// wrong-code denials. Identical retries observe that attempt without comparing
// or charging the code again; changed intent under the key conflicts. A distinct current update
// proof and original new-number OTP possession are required; the sending proof
// cannot authorize this mutation. All proof/OTP use, replacement, retirement,
// notice and pending cascade share the existing coordinator Work. After an
// ambiguous result use the original keyed request or code-free RecoverUpdate,
// never a new key to identify history. Historical success grants no new session.
func (s *PhoneChangeService) Update(ctx context.Context, r phone.UpdateRequest) (out phone.UpdateResult, err error) {
	state := s.state()
	if ctx == nil || state == nil {
		return out, password.ErrPasswordWork
	}
	request, err := r.Bindings()
	if err != nil || request.Reason != state.config().Reason {
		return out, phone.ErrInvalidChange
	}
	ctx, stop := context.WithTimeout(ctx, state.config().MaximumDuration)
	defer stop()
	entered := false
	stage := "source admission"
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
			if entered {
				out.Result = identity.CommandResult{Binding: out.Result.Binding, Outcome: identity.CommitOutcomeUnknown, Feature: out.Result.Feature}
			}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			// Fixed stage names add no number, proof, code or correlated metadata.
			err = fmt.Errorf("phone update %s: %w", stage, err)
		}
	}()
	source, confirmation, err := state.restoreChangeSource(ctx, request.TenantID, request.UserID, request.Caller, request.Flow, request.SendCommandID, request.CSRFToken)
	if err != nil {
		return out, err
	}
	intent, err := confirmation.Intent()
	if err != nil || intent.Reason != string(request.Reason) {
		return out, phone.ErrInvalidChange
	}
	p := &phoneChangeUpdatePhase{service: state, source: source, request: request, confirmation: confirmation, intent: intent}
	p.coordinator, p.registry, err = state.coordinator(p, confirmation.Contributor())
	if err != nil {
		return out, err
	}
	input, err := state.updateIntent(request)
	if err != nil {
		return out, err
	}
	keyScope, caller, feature := p.updateScope()
	k, wire, err := p.coordinator.ResolvePreparedRequestKey(ctx, keyScope, request.IdempotencyKey, input, caller, feature, p)
	defer clear(wire)
	if err != nil {
		return out, err
	}
	if err = p.restoreUpdate(ctx, k, wire); err != nil {
		return out, err
	}
	b := sourceBinding(p.command)
	op := p.FeatureOperations()[0]
	out.Result = identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeNotCommitted, Feature: &identity.FeatureReceipt{Operation: op}}
	stage = "preparation"
	out.Recovery, err = phoneRecoveryFromPlan(b, request.SendCommandID, p.attempt)
	if err != nil {
		return out, err
	}
	q := phoneRecoveryQuery(b)
	observed, err := p.coordinator.ObserveCommandAdmission(ctx, q, state.common.phoneQueryCaller(request.Caller, q, false))
	if err != nil && observed.Validate() != nil {
		return out, err
	}
	if !observed.Absent {
		return s.recoverSubmittedUpdate(ctx, request, out.Recovery)
	}
	scope := risk.Context{Tenant: string(b.TenantID), Operation: risk.Action(b.OperationID), Attempt: string(b.CommandID)}
	evaluated, err := state.config().UpdateRisk.Evaluation.EvaluateProtectedProviders(ctx, risk.EvaluateRequest{Context: scope, Phase: risk.NonIssuing})
	if err != nil {
		return out, err
	}
	p.admission, err = state.protected.Prepare(ctx, evaluated, scope)
	if err != nil {
		return out, err
	}
	p.notice, err = state.prepareChangeNotice(ctx, b, intent, request.Proof.Proof.IssuedAt)
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
	stage = "attempt admission"
	denied, err := p.coordinator.RecordOTPAttemptDenial(ctx, b, p.command, plan)
	// Coordinator admission can return an empty receipt before a claim exists
	// or after successful rollback (failedReservation). Keep this attempt's
	// original correlation; ambiguous closure returns an explicit Unknown.
	if denied.Binding.CommandID == "" {
		return out, err
	}
	var conflict identity.ConflictError
	if denied.Outcome != identity.CommitOutcomeConflict || !errors.As(err, &conflict) {
		if !p.attemptAdmitted && denied.Outcome != identity.CommitOutcomeConflict {
			// Another same-key call can finish after our absence observation.
			// Terminal/busy journal paths precede input admission; possession
			// and plan equality do not authorize current history disclosure.
			return s.recoverSubmittedUpdate(ctx, request, out.Recovery)
		}
		out.Result = denied
		return out, err
	}
	stage = "reservation"
	reservation, receipt, err := p.coordinator.ReserveOTPCommand(ctx, b, p.command, plan)
	if err != nil || reservation == (kernel.Reservation{}) {
		if receipt.Binding.CommandID != "" {
			if receipt.Outcome != identity.CommitOutcomeConflict {
				return s.recoverSubmittedUpdate(ctx, request, out.Recovery)
			}
			out.Result = receipt
		}
		return out, err
	}
	stage = "begin"
	w, err := p.coordinator.Begin(ctx, reservation)
	if err != nil {
		out.Result.Outcome = identity.CommitOutcomeUnknown
		return out, err
	}
	defer p.coordinator.Abort(w, identity.UnavailableError{})
	stage = "protected mutation"
	receipt, err = p.coordinator.ApplyFeature(ctx, w, p.command)
	if err == nil {
		stage = "commit"
		receipt, err = p.coordinator.Commit(w, receipt)
	} else {
		receipt, err = p.coordinator.Abort(w, err)
	}
	out.Result = receipt
	return out, err
}

func (p *phoneChangeUpdatePhase) plan() (kernel.CommandPlan, error) {
	spec, ok := p.command.Feature()
	if !ok || p.registry == nil {
		return kernel.CommandPlan{}, password.ErrPasswordWork
	}
	before := p.intent.Change.ExpectedIdentifierVersion
	plan, err := resetServiceAuditDeclaration(spec.Binding, spec.Operation, p.registry.Descriptors(), "identifier", before, before+1, p.request.Proof.Proof.IssuedAt)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	plan.Feature.Contributor = p.Descriptor()
	plan.Lifecycle.EventType = "identifier.changed.v1"
	plan.OTP, plan.CommandCounters = &p.attempt, &p.counter
	notice, err := p.notice.Plan()
	plan.Delivery = &notice
	return plan, err
}
