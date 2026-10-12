package postgres

import (
	"context"
	"fmt"
	"reflect"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// MFARecoveryAttemptContributor owns recovery-code comparison and shared-budget
// denial in the existing coordinator transaction. Original recovery/browser
// custody, current account/factor authority and policy must be fenced before
// comparison. Denied commits only the attempt, protected risk and denial audit;
// Unchanged rolls back and grants no factor proof. No code burn, child consumption,
// session issuance, external callback, transaction closure or retained Work is
// permitted here. Instances must be comparable and concurrency-safe.
type MFARecoveryAttemptContributor interface {
	MFACompletionContributor
	RecordMFARecoveryAttemptDenial(context.Context, MFARecoveryAttemptWork) (MFAAttemptDisposition, error)
}

// MFARecoveryAttemptBinding is immutable original correlation, not authority.
type MFARecoveryAttemptBinding struct {
	Command     identity.CommandBinding
	Plan        MFACompletionPlan
	Fingerprint [32]byte
	Generation  uint64
}

// Format redacts original credential and continuation correlation.
func (MFARecoveryAttemptBinding) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.MFARecoveryAttemptBinding(redacted)"))
}

// MarshalJSON rejects implicit correlation export.
func (MFARecoveryAttemptBinding) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// MarshalText rejects implicit correlation export.
func (MFARecoveryAttemptBinding) MarshalText() ([]byte, error) { return nil, invalidWork() }

// MFARecoveryAttemptWork borrows bounded SQL exclusively during the exact
// registered recovery callback. Copies share cancellation, budgets and lifetime;
// use serially and close rows. Zero, foreign and returned handles deny. It has
// no general Work, transaction, reservation, TOTP or session accessor.
type MFARecoveryAttemptWork struct{ recoveryState *mfaAttemptState }

// Format redacts borrowed callback authority.
func (MFARecoveryAttemptWork) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.MFARecoveryAttemptWork(redacted)"))
}

// MarshalJSON rejects borrowed custody export.
func (MFARecoveryAttemptWork) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// MarshalText rejects borrowed custody export.
func (MFARecoveryAttemptWork) MarshalText() ([]byte, error) { return nil, invalidWork() }

func (w MFARecoveryAttemptWork) usable() error {
	s := w.recoveryState
	if s == nil {
		return invalidWork()
	}
	f, ok := s.command.Feature()
	if _, code := s.command.RecoveryCode(); !ok || !code || f.Operation.OperationID != "identity.mfa.recovery-use" {
		return invalidWork()
	}
	return s.usable()
}

// Binding requires the exact live registered native recovery owner.
func (w MFARecoveryAttemptWork) Binding(owner MFARecoveryAttemptContributor) (MFARecoveryAttemptBinding, error) {
	if w.usable() != nil || nilContributor(owner) || !reflect.TypeOf(owner).Comparable() || owner != w.recoveryState.owner {
		return MFARecoveryAttemptBinding{}, invalidWork()
	}
	r := w.recoveryState.work.state.execution.reservation
	return MFARecoveryAttemptBinding{Command: r.plan.binding, Plan: *r.plan.mfaCompletion, Fingerprint: r.plan.fingerprint, Generation: r.journal.generation}, nil
}

// NativeCommand lends distinct original recovery/browser custody only here.
func (w MFARecoveryAttemptWork) NativeCommand(owner MFARecoveryAttemptContributor) (identity.Command, error) {
	if _, err := w.Binding(owner); err != nil {
		return identity.Command{}, err
	}
	return w.recoveryState.command, nil
}

// Exec executes bounded trusted factor/continuation SQL, not transaction control.
func (w MFARecoveryAttemptWork) Exec(ctx context.Context, sql string, args ...any) (int64, error) {
	if err := w.usable(); err != nil {
		return 0, err
	}
	return w.recoveryState.work.Exec(ctx, sql, args...)
}

// Query lends bounded rows that must close before the callback returns.
func (w MFARecoveryAttemptWork) Query(ctx context.Context, sql string, args ...any) (*WorkRows, error) {
	if err := w.usable(); err != nil {
		return nil, err
	}
	return w.recoveryState.work.Query(ctx, sql, args...)
}

// DatabaseTime samples primary UTC without renewing original validity.
func (w MFARecoveryAttemptWork) DatabaseTime(ctx context.Context) (time.Time, error) {
	if err := w.usable(); err != nil {
		return time.Time{}, err
	}
	return w.recoveryState.work.DatabaseTime(ctx)
}

// ReserveCommandCounters invokes the registered protected-risk owner once,
// before comparison. Denied forbids comparison; Unchanged rolls the charge back.
func (w MFARecoveryAttemptWork) ReserveCommandCounters(ctx context.Context, owner MFARecoveryAttemptContributor) (CommandCounterDisposition, error) {
	if _, err := w.Binding(owner); err != nil {
		return 0, err
	}
	return reserveMFAAttemptCounters(ctx, w.recoveryState)
}

// RequireActiveDirectoryAuthority fences original global/tenant epochs before
// factor locks. Every live failure poisons the sole transaction.
func (w MFARecoveryAttemptWork) RequireActiveDirectoryAuthority(ctx context.Context, owner MFARecoveryAttemptContributor, expected DirectoryAuthorityAdmission) error {
	if err := w.usable(); err != nil {
		return err
	}
	b, err := w.Binding(owner)
	return requireMFAAttemptDirectory(ctx, w.recoveryState, b.Command, err, expected)
}

// RequireRecipient fences the original selected user/identifier epochs. It
// grants no recovery proof or session and must precede factor locks.
func (w MFARecoveryAttemptWork) RequireRecipient(ctx context.Context, owner MFARecoveryAttemptContributor, expected RecipientRecord) error {
	if err := w.usable(); err != nil {
		return err
	}
	b, err := w.Binding(owner)
	return requireMFAAttemptRecipient(ctx, w.recoveryState, b.Command, err, expected)
}

// RequireRecipientCredential fences the original password credential and
// expiry without changing anonymous journal identity or renewing freshness.
// Versions must come from authenticated original primary custody; live errors
// poison the transaction even when a caller ignores them.
func (w MFARecoveryAttemptWork) RequireRecipientCredential(ctx context.Context, owner MFARecoveryAttemptContributor, recipient RecipientRecord, expected CredentialAdmission) (time.Time, error) {
	if err := w.usable(); err != nil {
		return time.Time{}, err
	}
	b, err := w.Binding(owner)
	return requireMFAAttemptCredential(ctx, w.recoveryState, b.Command, err, recipient, expected)
}

// PrepareMFARecoveryAttemptPlan freezes the closed recovery denial declaration.
// It performs no IO, comparison, reservation, burn or session issuance. The
// snapshot grants no authority and cannot enter ordinary structural execution.
func (c *Coordinator) PrepareMFARecoveryAttemptPlan(b identity.CommandBinding, command identity.Command, p CommandPlan) (CommandPlan, error) {
	_, snapshot, _, err := c.prepareMFAAttempt(b, command, p, "identity.mfa.recovery-use")
	return snapshot, err
}

// RecordMFARecoveryAttemptDenial uses the existing claim/journal transaction:
// exact replay precedes comparison, changed input conflicts, predecessor leases
// cannot be taken over, and ambiguous commit requires original recovery. No
// code, child or session is consumed here; correct comparison is not a proof.
func (c *Coordinator) RecordMFARecoveryAttemptDenial(ctx context.Context, b identity.CommandBinding, command identity.Command, p CommandPlan) (identity.CommandResult, error) {
	if b.OperationID != "identity.mfa.recovery-use" {
		return identity.CommandResult{}, invalidPlan()
	}
	return c.recordCountedAttemptCommand(ctx, b, command, p, false, true, nil)
}

// RecordMFARecoveryAttemptDenialWithOriginal uses original submitted custody
// for journal identity and validated counter-enriched custody for comparison.
// Exact replay does not charge again; substitution conflicts. Correct-code
// probing rolls back and grants no proof, code burn or session authority.
func (c *Coordinator) RecordMFARecoveryAttemptDenialWithOriginal(ctx context.Context, original, prepared identity.Command, p CommandPlan) (identity.CommandResult, error) {
	f, ok := prepared.Feature()
	if !ok || f.Operation.OperationID != "identity.mfa.recovery-use" {
		return identity.CommandResult{}, invalidPlan()
	}
	return c.recordCountedAttemptCommand(ctx, f.Binding, prepared, p, false, true, &original)
}
