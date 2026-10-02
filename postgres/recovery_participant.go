package postgres

import (
	"context"
	"fmt"

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
// handles are allowed. A nil error is not commit proof. This kernel profile
// admits no one-time participants or participant transitions during recovery.
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

// RecoverParticipant proves absence of a creation target on the locked primary.
// An existing user is not evidence that this command committed; without an
// original command linkage that case conservatively remains unknown. No live
// user data or receipt is reconstructed. Only this exact enlisted instance may
// inspect its evidence. Other domain profiles remain unsupported.
func (r *Repository) RecoverParticipant(ctx context.Context, recovery RecoveryWork) (RecoveryStatus, error) {
	if r == nil || ctx == nil || recovery.usable() != nil || recovery.state.entry.contributor != r {
		return RecoveryUnknown, invalidWork()
	}
	b, err := recovery.Scope()
	if err != nil || b.OperationID != "identity.user.create" {
		return RecoveryUnknown, invalidWork()
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
