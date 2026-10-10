package postgres

import (
	"context"
	"fmt"
	"strconv"

	identity "github.com/faustbrian/go-identity"
)

// RecoveryStatus is authoritative participant evidence, never a command
// receipt. Zero, missing, conflicting or unknown evidence cannot terminalize
// a command. Committed evidence beside a pending kernel journal is an atomicity
// conflict, not permission to reconstruct a success from current user state.
type RecoveryStatus uint8

const (
	// RecoveryUnknown supplies no conclusive participant outcome.
	RecoveryUnknown RecoveryStatus = iota
	// RecoveryNotCommitted proves no committed effect for the frozen input.
	RecoveryNotCommitted
	// RecoveryCommitted proves a committed participant effect, not a full receipt.
	RecoveryCommitted
)

// RecoveryContributor supplies local primary evidence for its exact frozen
// declaration. Only Coordinator calls this method. Implementations must inspect
// retained bindings, not merely prunable payloads, and own only their evidence.
// No network, hooks, private transactions, command-ledger changes or retained
// handles are allowed. A nil error is not commit proof. This interface grants
// evidence reads only. Identifier attachment's separate typed release phase is
// invoked only after every participant proves non-commit.
// Implementations must support concurrent invocations with independent handles.
type RecoveryContributor interface {
	Contributor
	RecoverParticipant(context.Context, RecoveryWork) (RecoveryStatus, error)
}

// RecoveryWork is a bounded, generation-bound primary evidence capability for
// one frozen contributor invocation. It has no constructor, mutation staging,
// transaction closure, reservation or raw driver API. Query admits trusted
// compile-time evidence SELECTs under Work's size/result/parameter limits;
// adapters must not issue SQL mutations or ownership-changing SQL functions.
// Copies share lifetime and expire when the invocation returns. Use serially;
// retaining this value or its rows is forbidden. Zero is invalid.
type RecoveryWork struct{ state *recoveryWorkState }

type recoveryWorkState struct {
	work   Work
	entry  registeredContributor
	plan   *admittedKernelPlan
	active bool
}

// Format hides runtime evidence scope and retained composition.
func (RecoveryWork) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.RecoveryWork(redacted)"))
}

// MarshalJSON rejects serialization of transaction evidence authority.
func (RecoveryWork) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

func (w RecoveryWork) usable() error {
	if w.state == nil || !w.state.active || w.state.plan == nil {
		return invalidWork()
	}
	return w.state.work.usable()
}

// Scope returns the original immutable command binding, not current authority.
func (w RecoveryWork) Scope() (identity.CommandBinding, error) {
	if err := w.usable(); err != nil {
		return identity.CommandBinding{}, err
	}
	return w.state.work.Scope()
}

// Query reads only this contributor's authoritative evidence using bounded
// coordinator-owned rows. Close/drain every cursor before returning; failures
// poison recovery and rows do not survive the invocation.
func (w RecoveryWork) Query(ctx context.Context, sql string, args ...any) (*WorkRows, error) {
	if err := w.usable(); err != nil {
		return nil, err
	}
	return w.state.work.Query(ctx, sql, args...)
}

// AuditPlan returns the owned frozen audit declaration only to audit/postgres.
func (w RecoveryWork) AuditPlan() (AuditPlan, error) {
	if err := w.usable(); err != nil {
		return AuditPlan{}, err
	}
	if w.state.entry.descriptor.Owner != "audit/postgres" || len(w.state.plan.audits) != 1 {
		return AuditPlan{}, invalidWork()
	}
	return w.state.plan.audits[0], nil
}

// AuditPlans returns an owned copy of every frozen audit slot, in event-index
// order, only during audit/postgres's recovery invocation. Native feature
// commands may require several slots; absence of any retained slot cannot
// prove their atomic persistence. Copies do not grant authority after return.
func (w RecoveryWork) AuditPlans() ([]AuditPlan, error) {
	if err := w.usable(); err != nil {
		return nil, err
	}
	if w.state.entry.descriptor.Owner != "audit/postgres" || len(w.state.plan.audits) == 0 {
		return nil, invalidWork()
	}
	return append([]AuditPlan(nil), w.state.plan.audits...), nil
}

// LifecyclePlan returns the owned frozen declaration only to outbox/postgres.
func (w RecoveryWork) LifecyclePlan() (LifecyclePlan, error) {
	if err := w.usable(); err != nil {
		return LifecyclePlan{}, err
	}
	if w.state.entry.descriptor.Owner != "outbox/postgres" || w.state.plan.lifecycle == nil {
		return LifecyclePlan{}, invalidWork()
	}
	return *w.state.plan.lifecycle, nil
}

// CapabilityBinding returns frozen participant input only to the exact
// registered capability instance. Generation is the recovery owner and
// PreviousGeneration is the reserved owner being reconciled. The handle grants
// evidence reads only: expiry or a negative capability observation alone cannot
// release it. Missing or mismatched retained bindings must remain unknown.
func (w RecoveryWork) CapabilityBinding(p CapabilityReleaseContributor) (CapabilityReservationBinding, error) {
	if w.usable() != nil || w.state.entry.descriptor.Owner != "capability/postgres" || w.state.work.state.execution == nil {
		return CapabilityReservationBinding{}, invalidWork()
	}
	r := w.state.work.state.execution.reservation
	if r == nil {
		return CapabilityReservationBinding{}, invalidWork()
	}
	s := &capabilityReservationState{coordinator: w.state.work.state.execution.coordinator, work: w.state.work, plan: w.state.plan, previousGeneration: r.journal.previousGeneration, active: true, releaseProof: capabilityReleaseRecovery}
	var ok bool
	s.contributor, ok = capabilityReservationParticipant(w.state.entry.contributor)
	if !ok {
		return CapabilityReservationBinding{}, invalidWork()
	}
	return (CapabilityReleaseWork{state: s}).Binding(p)
}

// RiskBinding returns frozen evidence custody only to the exact registered
// release participant during recovery. It grants reads, never release rights.
// Missing or mismatched native custody must remain unknown regardless of expiry.
func (w RecoveryWork) RiskBinding(p RiskReleaseContributor) (RiskReservationBinding, error) {
	if w.usable() != nil || w.state.entry.descriptor.Owner != "identity/risk/postgres" || w.state.work.state.execution == nil {
		return RiskReservationBinding{}, invalidWork()
	}
	r := w.state.work.state.execution.reservation
	if r == nil {
		return RiskReservationBinding{}, invalidWork()
	}
	participant, ok := riskReservationParticipant(w.state.entry.contributor)
	if !ok {
		return RiskReservationBinding{}, invalidWork()
	}
	s := &riskReservationState{coordinator: w.state.work.state.execution.coordinator, work: w.state.work, plan: w.state.plan, previousGeneration: r.journal.previousGeneration, active: true, contributor: participant, releaseProof: riskReleaseRecovery}
	return (RiskReleaseWork{state: s}).Binding(p)
}

// CaptchaBinding returns frozen consuming custody only to the exact native
// CAPTCHA owner during primary recovery. It grants evidence reads, never
// release authority; absent/divergent/terminal evidence cannot prove noncommit.
func (w RecoveryWork) CaptchaBinding(p CaptchaUseReservationContributor) (CaptchaUseReservationBinding, error) {
	if w.usable() != nil || w.state.entry.descriptor != (ContributorDescriptor{Owner: "identity/risk/postgres", ContractID: "identity.risk.store", Version: 1}) || w.state.work.state.execution == nil {
		return CaptchaUseReservationBinding{}, invalidWork()
	}
	r := w.state.work.state.execution.reservation
	owner, ok := captchaUseReservationParticipant(w.state.entry.contributor)
	if r == nil || !ok {
		return CaptchaUseReservationBinding{}, invalidWork()
	}
	s := &captchaExecutionState{reservation: captchaUseReservationState{coordinator: w.state.work.state.execution.coordinator, work: w.state.work, plan: w.state.plan, previous: r.journal.previousGeneration, contributor: owner, active: true}, phase: captchaRelease, proof: riskReleaseRecovery}
	return (CaptchaReleaseWork{state: s}).Binding(p)
}

// OTPBinding returns frozen consuming custody only to the exact registered OTP
// owner during primary recovery. It grants evidence reads, not release rights.
// Missing, divergent or terminal challenge evidence must remain unknown.
func (w RecoveryWork) OTPBinding(p OTPReservationContributor) (OTPReservationBinding, error) {
	if w.usable() != nil || w.state.entry.descriptor != otpDescriptor() || w.state.work.state.execution == nil {
		return OTPReservationBinding{}, invalidWork()
	}
	r := w.state.work.state.execution.reservation
	owner, ok := w.state.entry.contributor.(OTPReservationContributor)
	if r == nil || !ok {
		return OTPReservationBinding{}, invalidWork()
	}
	s := &otpExecutionState{reservation: otpReservationState{coordinator: w.state.work.state.execution.coordinator, work: w.state.work, plan: w.state.plan, previous: r.journal.previousGeneration, owner: owner, active: true}, phase: otpRelease, proof: riskReleaseRecovery}
	return (OTPReleaseWork{state: s}).Binding(p)
}

// RecoverParticipant proves absence of a creation target on the locked primary.
// An existing user is not evidence that this command committed; without an
// original command linkage that case conservatively remains unknown. No live
// user data or receipt is reconstructed. Only this exact enlisted instance may
// inspect its evidence. For field mutation, only the unchanged original
// aggregate version is negative evidence under the coordinator's journal and
// tenant fences. A changed/missing aggregate remains unknown; it is never
// treated as a committed receipt. Identifier attachment requires target absence
// plus the other participants' retained negative evidence; any existing target
// remains unknown. Other domain profiles remain unsupported.
func (r *Repository) RecoverParticipant(ctx context.Context, recovery RecoveryWork) (RecoveryStatus, error) {
	if r == nil || ctx == nil || recovery.usable() != nil || recovery.state.entry.contributor != r {
		return RecoveryUnknown, invalidWork()
	}
	b, err := recovery.Scope()
	if err == nil && recovery.state.plan.feature != nil {
		if passwordRegistrationOperation(recovery.state.plan.feature.Operation) {
			return recoverPasswordRegistration(ctx, recovery)
		}
		if authenticatedOperation(b) {
			return recoverSignInProofUse(ctx, recovery)
		}
		if credentialCompromiseOperation(recovery.state.plan.feature.Operation) {
			return recoverCredentialCompromise(ctx, recovery)
		}
		if credentialReplacementOperation(recovery.state.plan.feature.Operation) {
			return recoverCredentialReplacement(ctx, recovery)
		}
		// Native feature phases are forbidden from mutating kernel tables. This
		// participant supplies only the shared tenant/transaction fence; the
		// native owner must separately prove absence of its retained effects.
		return RecoveryNotCommitted, nil
	}
	if err != nil || b.OperationID != "identity.user.create" && b.OperationID != "identity.profile.update" && b.OperationID != "identity.user.update-admin" && b.OperationID != "identity.identifier.attach" && !statusOperation(b.OperationID) {
		return RecoveryUnknown, invalidWork()
	}
	if statusOperation(b.OperationID) {
		rows, e := recovery.Query(ctx, `SELECT EXISTS(SELECT 1 FROM identity.status_cascades WHERE command_id=$1 AND tenant_id=$2 AND user_id=$3 AND operation=$4)`, string(b.CommandID), string(b.TenantID), string(b.UserID), b.OperationID)
		if e != nil {
			return RecoveryUnknown, e
		}
		defer rows.Close()
		var exists bool
		if !rows.Next() || rows.Scan(&exists) != nil || rows.Next() || rows.Err() != nil {
			return RecoveryUnknown, identity.UnavailableError{}
		}
		if exists {
			return RecoveryUnknown, nil
		}
		return RecoveryNotCommitted, nil
	}
	if b.OperationID == "identity.identifier.attach" {
		rows, e := recovery.Query(ctx, `SELECT EXISTS(SELECT 1 FROM identity.identifiers WHERE tenant_id=$1 AND identifier_id=$2)`, string(b.TenantID), b.RecordID)
		if e != nil {
			return RecoveryUnknown, e
		}
		defer rows.Close()
		var exists bool
		if !rows.Next() || rows.Scan(&exists) != nil || rows.Next() || rows.Err() != nil {
			return RecoveryUnknown, identity.UnavailableError{}
		}
		if exists {
			return RecoveryUnknown, nil
		}
		return RecoveryNotCommitted, nil
	}
	if b.OperationID == "identity.profile.update" || b.OperationID == "identity.user.update-admin" {
		plan := recovery.state.plan.lifecycle
		if plan == nil || plan.BeforeVersion == 0 {
			return RecoveryUnknown, invalidWork()
		}
		rows, e := recovery.Query(ctx, `SELECT EXISTS(SELECT 1 FROM identity.users WHERE tenant_id=$1 AND user_id=$2 AND version=$3::numeric)`, string(b.TenantID), string(b.UserID), strconv.FormatUint(plan.BeforeVersion, 10))
		if e != nil {
			return RecoveryUnknown, e
		}
		defer rows.Close()
		var unchanged bool
		if !rows.Next() {
			return RecoveryUnknown, identity.UnavailableError{}
		}
		if e := rows.Scan(&unchanged); e != nil {
			return RecoveryUnknown, e
		}
		if rows.Next() || rows.Err() != nil {
			return RecoveryUnknown, identity.UnavailableError{}
		}
		if !unchanged {
			return RecoveryUnknown, nil
		}
		return RecoveryNotCommitted, nil
	}
	rows, err := recovery.Query(ctx, `SELECT EXISTS(SELECT 1 FROM identity.users WHERE tenant_id=$1 AND user_id=$2)`, string(b.TenantID), string(b.UserID))
	if err != nil {
		return RecoveryUnknown, err
	}
	defer rows.Close()
	var exists bool
	if !rows.Next() {
		return RecoveryUnknown, identity.UnavailableError{}
	}
	if err := rows.Scan(&exists); err != nil {
		return RecoveryUnknown, err
	}
	if rows.Next() || rows.Err() != nil {
		return RecoveryUnknown, identity.UnavailableError{}
	}
	if exists {
		return RecoveryUnknown, nil
	}
	return RecoveryNotCommitted, nil
}
