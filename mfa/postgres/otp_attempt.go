package mfapostgres

import (
	"context"
	"fmt"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/jackc/pgx/v5"
)

// LockedOTPCompletionAttempt retains the original shared continuation lock in
// one counted native MFA callback. It is not OTP verification or successful
// factor proof. Copies share the single provisional debit and serial-use Work;
// returned/foreign handles deny. No private transaction or new budget is owned.
type LockedOTPCompletionAttempt struct {
	custody func() *lockedOTPCompletionAttempt
}
type lockedOTPCompletionAttempt struct {
	work         kernel.MFAOTPAttemptWork
	owner        kernel.MFAOTPAttemptContributor
	binding      kernel.MFAOTPAttemptBinding
	continuation mfa.PartialAuthContinuation
	spent        bool
}

// Format redacts original continuation identity and native callback authority.
func (LockedOTPCompletionAttempt) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.LockedOTPCompletionAttempt(redacted)"))
}

// MarshalJSON rejects callback custody export.
func (LockedOTPCompletionAttempt) MarshalJSON() ([]byte, error) { return nil, invalidAuthority() }

// MarshalText rejects callback custody export.
func (LockedOTPCompletionAttempt) MarshalText() ([]byte, error) { return nil, invalidAuthority() }

func nativeOTPCompletionAttemptSQL(w kernel.MFAOTPAttemptWork) totpAttemptSQL {
	return totpAttemptSQL{query: func(ctx context.Context, sql string, args []any, dest ...any) error {
		rows, err := w.Query(ctx, sql, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		if !rows.Next() {
			if err := rows.Err(); err != nil {
				return err
			}
			return pgx.ErrNoRows
		}
		if err := rows.Scan(dest...); err != nil {
			return err
		}
		if rows.Next() {
			return identity.UnavailableError{}
		}
		return rows.Err()
	}, exec: w.Exec}
}

// LockOTPCompletionAttempt fences the current account/factor generation and
// exact original pending continuation before the real OTP owner compares.
// It requires explicitly allowed "otp", original absolute expiry and remaining
// cross-method budget. The native MFA owner separately admits consumed-primary
// cookie/provenance, selected confirmed factor/recipient and current policy.
// Locks belong to the sole coordinator. No attempt, child or session is consumed.
func LockOTPCompletionAttempt(ctx context.Context, w kernel.MFAOTPAttemptWork, owner kernel.MFAOTPAttemptContributor) (LockedOTPCompletionAttempt, error) {
	if ctx == nil {
		return LockedOTPCompletionAttempt{}, invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return LockedOTPCompletionAttempt{}, err
	}
	b, err := w.Binding(owner)
	if err != nil {
		return LockedOTPCompletionAttempt{}, err
	}
	shared := kernel.MFATOTPAttemptBinding{Command: b.Command, Plan: b.Plan, Fingerprint: b.Fingerprint, Generation: b.Generation}
	c, _, err := lockMFAAttemptContinuation(ctx, nativeOTPCompletionAttemptSQL(w), shared, "otp")
	if err != nil {
		return LockedOTPCompletionAttempt{}, err
	}
	a := &lockedOTPCompletionAttempt{work: w, owner: owner, binding: b, continuation: c}
	return LockedOTPCompletionAttempt{custody: func() *lockedOTPCompletionAttempt { return a }}, nil
}

// RecordOTPCompletionAttemptDenial debits the same original shared MFA budget
// only after the coordinator reports an actual native OTP denial. OTP debit,
// this CAS, protected risk, audit and terminal command commit atomically there.
// Correct-code probing rolls both owners back. No OTP code is compared here.
// Copies cannot debit twice; propagate every error to abort the transaction.
func RecordOTPCompletionAttemptDenial(ctx context.Context, w kernel.MFAOTPAttemptWork, owner kernel.MFAOTPAttemptContributor, locked LockedOTPCompletionAttempt) error {
	if ctx == nil || locked.custody == nil {
		return invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	a := locked.custody()
	if a == nil || a.spent || a.work != w {
		return invalidAuthority()
	}
	b, err := w.Binding(owner)
	if err != nil || b != a.binding || a.owner != owner {
		return invalidAuthority()
	}
	if err := w.RequireOTPDenial(owner); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if err := spendMFAAttempt(ctx, nativeOTPCompletionAttemptSQL(w), a.continuation, now, "otp"); err != nil {
		return err
	}
	a.spent = true
	return nil
}
