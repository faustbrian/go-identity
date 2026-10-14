package postgres

import (
	"context"
	"fmt"
	"reflect"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// MFAOTPAttemptContributor couples the original shared MFA budget to the real
// OTP owner's counted denial in the sole coordinator transaction. Preparation
// authenticates consumed-primary/browser custody, locks current authority and
// the original continuation, then reserves protected risk before any comparison.
// Unchanged permits only that transaction's native OTP callback; it is not proof.
// Denied records risk denial without comparing or charging a factor attempt.
// RecordMFAOTPAttemptDenial runs only after actual native OTP denial and debits
// the same locked continuation once. Never compare OTP here, consume the child,
// create a session, invoke providers, retain Work or own a transaction. Errors
// roll back both owners. Instances are comparable and safe for concurrent calls.
type MFAOTPAttemptContributor interface {
	MFACompletionContributor
	PrepareMFAOTPAttempt(context.Context, MFAOTPAttemptWork) (MFAAttemptDisposition, error)
	RecordMFAOTPAttemptDenial(context.Context, MFAOTPAttemptWork) error
}

// MFAOTPAttemptBinding retains both exact frozen declarations and original
// command correlation. It is neither factor authority nor successful proof.
type MFAOTPAttemptBinding struct {
	Command     identity.CommandBinding
	Plan        MFACompletionPlan
	OTP         OTPAttemptPlan
	Fingerprint [32]byte
	Generation  uint64
}

// Format redacts original continuation/challenge correlation.
func (MFAOTPAttemptBinding) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.MFAOTPAttemptBinding(redacted)"))
}

// MarshalJSON rejects implicit correlation export.
func (MFAOTPAttemptBinding) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// MarshalText rejects implicit correlation export.
func (MFAOTPAttemptBinding) MarshalText() ([]byte, error) { return nil, invalidWork() }

// MFAOTPAttemptWork borrows bounded SQL only during the registered MFA owner's
// admission/denial callback. It has no OTP comparison, general Work, capability,
// session or transaction accessor. Copies share serial-use budgets and lifetime;
// zero, foreign and returned handles deny. Close query rows before returning.
type MFAOTPAttemptWork struct{ state *mfaAttemptState }

// Format redacts borrowed authority and credential custody.
func (MFAOTPAttemptWork) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.MFAOTPAttemptWork(redacted)"))
}

// MarshalJSON rejects callback export.
func (MFAOTPAttemptWork) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// MarshalText rejects callback export.
func (MFAOTPAttemptWork) MarshalText() ([]byte, error) { return nil, invalidWork() }

func (w MFAOTPAttemptWork) usable() error {
	if w.state == nil {
		return invalidWork()
	}
	f, ok := w.state.command.Feature()
	_, code := w.state.command.OneTimeCode()
	_, browser := w.state.command.PreAuthCookie()
	if !ok || !code || !browser || !mfaCompletionOperation(f.Operation) || f.Operation.OperationID != "identity.mfa.otp-verify" {
		return invalidWork()
	}
	return w.state.usable()
}

// Binding requires the exact registered instance and active callback lifetime.
func (w MFAOTPAttemptWork) Binding(owner MFAOTPAttemptContributor) (MFAOTPAttemptBinding, error) {
	if w.usable() != nil || nilContributor(owner) || !reflect.TypeOf(owner).Comparable() || owner != w.state.owner {
		return MFAOTPAttemptBinding{}, invalidWork()
	}
	r := w.state.work.state.execution.reservation
	if r.plan.otp == nil {
		return MFAOTPAttemptBinding{}, invalidWork()
	}
	return MFAOTPAttemptBinding{Command: r.plan.binding, Plan: *r.plan.mfaCompletion, OTP: *r.plan.otp, Fingerprint: r.plan.fingerprint, Generation: r.journal.generation}, nil
}

// NativeCommand borrows original code/browser custody, never persistence data.
func (w MFAOTPAttemptWork) NativeCommand(owner MFAOTPAttemptContributor) (identity.Command, error) {
	if _, err := w.Binding(owner); err != nil {
		return identity.Command{}, err
	}
	return w.state.command, nil
}

// RequireOTPDenial proves only that this callback follows the actual native OTP
// owner's Denied result. It cannot be invoked to fabricate or repeat a charge.
// The native MFA owner must also retain/check its exact locked continuation.
func (w MFAOTPAttemptWork) RequireOTPDenial(owner MFAOTPAttemptContributor) error {
	if _, err := w.Binding(owner); err != nil {
		return err
	}
	if !w.state.otpDenied {
		return invalidWork()
	}
	return nil
}

// Query returns callback-owned rows; close them before returning.
func (w MFAOTPAttemptWork) Query(ctx context.Context, sql string, args ...any) (*WorkRows, error) {
	if err := w.usable(); err != nil {
		return nil, err
	}
	return w.state.work.Query(ctx, sql, args...)
}

// Exec performs native continuation SQL without transaction closure.
func (w MFAOTPAttemptWork) Exec(ctx context.Context, sql string, args ...any) (int64, error) {
	if err := w.usable(); err != nil {
		return 0, err
	}
	return w.state.work.Exec(ctx, sql, args...)
}

// DatabaseTime samples primary UTC without extending original validity.
func (w MFAOTPAttemptWork) DatabaseTime(ctx context.Context) (time.Time, error) {
	if err := w.usable(); err != nil {
		return time.Time{}, err
	}
	return w.state.work.DatabaseTime(ctx)
}

// ReserveCommandCounters runs the original native protected-risk owner once,
// after current browser/authority admission and before the actual OTP comparison.
func (w MFAOTPAttemptWork) ReserveCommandCounters(ctx context.Context, owner MFAOTPAttemptContributor) (CommandCounterDisposition, error) {
	if _, err := w.Binding(owner); err != nil {
		return 0, err
	}
	return reserveMFAAttemptCounters(ctx, w.state)
}

// RequireActiveDirectoryAuthority fences original global/tenant observations.
func (w MFAOTPAttemptWork) RequireActiveDirectoryAuthority(ctx context.Context, owner MFAOTPAttemptContributor, expected DirectoryAuthorityAdmission) error {
	if err := w.usable(); err != nil {
		return err
	}
	b, err := w.Binding(owner)
	return requireMFAAttemptDirectory(ctx, w.state, b.Command, err, expected)
}

// RequireRecipient fences the original user's account/identifier authority.
func (w MFAOTPAttemptWork) RequireRecipient(ctx context.Context, owner MFAOTPAttemptContributor, expected RecipientRecord) error {
	if err := w.usable(); err != nil {
		return err
	}
	b, err := w.Binding(owner)
	return requireMFAAttemptRecipient(ctx, w.state, b.Command, err, expected)
}

// RequireRecipientCredential additionally fences the original password version
// and expiry without disclosing general Work or renewing primary freshness.
func (w MFAOTPAttemptWork) RequireRecipientCredential(ctx context.Context, owner MFAOTPAttemptContributor, recipient RecipientRecord, expected CredentialAdmission) (time.Time, error) {
	if err := w.usable(); err != nil {
		return time.Time{}, err
	}
	b, err := w.Binding(owner)
	return requireMFAAttemptCredential(ctx, w.state, b.Command, err, recipient, expected)
}
