package mfapostgres

import (
	"context"
	"errors"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/jackc/pgx/v5"
)

// RecordMissingTOTPAttemptDenial rechecks an authenticated absent/ineligible
// factor candidate under the exact registered live attempt owner. It locks the
// current account, factor authority and original continuation, then checks the
// submitted factor within that account. A now-confirmed factor, changed epoch,
// expired continuation, corrupt confirmed record or outage cannot be charged.
// One shared attempt is provisional; return MFAAttemptDenied to the coordinator
// so counters, denial audit and original journal commit atomically. No secret,
// successful replay, child use or session is read/created. No transaction starts.
func RecordMissingTOTPAttemptDenial(ctx context.Context, w kernel.MFATOTPAttemptWork, owner kernel.MFATOTPAttemptContributor, factorID string) error {
	if ctx == nil {
		return invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := identity.ParseCommandID(factorID); err != nil {
		return invalidAuthority()
	}
	b, err := w.Binding(owner)
	if err != nil {
		return err
	}
	return recordMissingTOTPAttempt(ctx, nativeTOTPAttemptSQL(w), b, factorID)
}

func recordMissingTOTPAttempt(ctx context.Context, sql totpAttemptSQL, b kernel.MFATOTPAttemptBinding, factorID string) error {
	c, _, err := lockTOTPAttemptContinuation(ctx, sql, b)
	if err != nil {
		return err
	}
	var state int16
	var confirmed, encrypted bool
	err = sql.query(ctx, `SELECT state,confirmed_at IS NOT NULL,encrypted_secret IS NOT NULL FROM identity_mfa.totp_factors WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3 FOR UPDATE`, []any{string(b.Command.TenantID), string(b.Plan.UserID), factorID}, &state, &confirmed, &encrypted)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return attemptStoreError(ctx, err)
	}
	if err == nil {
		if state == 2 {
			if !confirmed || !encrypted {
				return identity.UnavailableError{}
			}
			return identity.ForbiddenError{}
		}
		if state != 1 && state != 3 {
			return identity.UnavailableError{}
		}
	}
	var now time.Time
	if err := sql.query(ctx, `SELECT clock_timestamp()`, nil, &now); err != nil {
		return attemptStoreError(ctx, err)
	}
	return spendTOTPAttempt(ctx, sql, c, now)
}
