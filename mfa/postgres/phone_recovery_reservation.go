package mfapostgres

import (
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/jackc/pgx/v5"
)

// RequirePhoneRecoveryTOTPReservation fences the original encrypted factor for
// the exact registered OTP reservation owner and unchanged generated joint
// command. Call BEFORE the OTP owner acquires lockout/exclusion/challenge locks:
// this locks current active user, aggregate and factor in canonical order until
// the parent coordinator closes its transaction. It checks original deadline,
// enrollment/aggregate/row/profile/ciphertext/replay without decrypting, comparing
// a code, advancing replay, charging a budget or granting factor proof. Errors
// must abort. Apply independently verifies the actual TOTP and replay CAS; no
// transaction, callback, renewal, successful-factor scalar or retry is created.
func RequirePhoneRecoveryTOTPReservation(ctx context.Context, w kernel.OTPReservationWork, owner kernel.OTPReservationContributor, command identity.Command, snapshot TOTPFactorSnapshot, until time.Time) error {
	if ctx == nil {
		return invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	b, err := w.Binding(owner)
	if err != nil {
		return err
	}
	original, err := w.NativeCommand(owner)
	if err != nil || command != original || b.Generation == 0 || b.Fingerprint == ([32]byte{}) || b.Plan.Mode != kernel.OTPConsume {
		return invalidAuthority()
	}
	m, err := snapshot.Metadata()
	if err != nil {
		return err
	}
	_, input, err := phoneRecoveryCommand(command, m)
	f, ok := command.PhonePasswordResetFeature()
	if err != nil || input || !ok || f.Binding != b.Command {
		return invalidAuthority()
	}
	_, err = lockPhoneRecoveryTOTP(ctx, phoneRecoveryReadSQL(w.Query), snapshot, until)
	return err
}

// RequirePhoneRecoveryTOTPApply reacquires the full original encrypted factor
// fence in the protected transaction BEFORE the OTP owner acquires its shared
// lockouts/challenge exclusions. Reservation's locks ended with its transaction.
// Only the exact registered owner's live consuming OTPApplyWork and closed
// code-free phone-reset scope are accepted. It locks active user, aggregate then
// factor, checking original enrollment/authority/ciphertext/profile/replay and
// current database time without decrypting, comparing, advancing replay, or
// granting factor proof. Errors must abort. The feature's later Apply must still
// independently verify the actual TOTP and CAS replay through its MFA owner.
func RequirePhoneRecoveryTOTPApply(ctx context.Context, w kernel.OTPApplyWork, owner kernel.OTPReservationContributor, snapshot TOTPFactorSnapshot, until time.Time) error {
	if ctx == nil {
		return invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	b, err := w.Binding(owner)
	if err != nil || b.Generation == 0 || b.PreviousGeneration != 0 || b.Fingerprint == ([32]byte{}) || b.Plan.Mode != kernel.OTPConsume {
		return invalidAuthority()
	}
	spec, err := w.CommandSpec(owner)
	if err != nil || spec.Binding != b.Command {
		return invalidAuthority()
	}
	m, err := snapshot.Metadata()
	if err != nil {
		return err
	}
	if !phoneRecoverySnapshot(m) {
		return invalidAuthority()
	}
	if err := phoneRecoveryFactorSpec(spec, m); err != nil {
		return err
	}
	_, err = lockPhoneRecoveryTOTP(ctx, phoneRecoveryReadSQL(w.Query), snapshot, until)
	return err
}

func phoneRecoveryReadSQL(query func(context.Context, string, ...any) (*kernel.WorkRows, error)) totpAttemptSQL {
	return totpAttemptSQL{query: func(ctx context.Context, q string, args []any, dest ...any) error {
		rows, err := query(ctx, q, args...)
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
			return invalidAuthority()
		}
		return rows.Err()
	}}
}
