package mfapostgres

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strconv"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/jackc/pgx/v5"
)

// OTPLoginSendSource is exact committed send attribution under one original
// child, not OTP possession, verification, a validity lease or a session grant.
// The completion owner must authenticate the existing encrypted input/output,
// its generation and original browser/password/child/factor/recipient custody.
// IDs alone cannot select a destination, another factor or a newer primary.
type OTPLoginSendSource struct {
	CommandID      identity.CommandID
	FactorID       mfa.FactorID
	ContinuationID mfa.ContinuationID
}

// Format redacts original challenge and factor correlation.
func (OTPLoginSendSource) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.OTPLoginSendSource(redacted)"))
}

// MarshalJSON denies implicit source-custody export.
func (OTPLoginSendSource) MarshalJSON() ([]byte, error) { return nil, invalidAuthority() }

// MarshalText denies implicit textual source-custody export.
func (OTPLoginSendSource) MarshalText() ([]byte, error) { return nil, invalidAuthority() }

// ReadLoginSend restores the current committed send selected by the native MFA
// continuation, never by a client factor/challenge override or an account-wide
// latest-row search. Exact tenant/user, child scope/version, OTP policy and live
// shared budget remain required. Missing or retired/uncommitted attribution
// denies. It creates no attempt, generation, transaction or freshness renewal;
// original input/output authentication and protected checks still own authority.
func (r *OTPFactorReader) ReadLoginSend(ctx context.Context, grant capability.Grant, issuer string) (OTPLoginSendSource, error) {
	if ctx == nil || r == nil || r.continuation == nil || r.continuation.pool == nil {
		return OTPLoginSendSource{}, invalidAuthority()
	}
	ctx, stop := context.WithTimeout(ctx, r.continuation.maximumDuration)
	defer stop()
	c, err := r.continuation.Read(ctx, grant, issuer)
	if err != nil {
		return OTPLoginSendSource{}, err
	}
	s, err := c.Bindings()
	digest, derr := c.ScopeDigest()
	if err != nil || derr != nil || !slices.Contains(s.AllowedMethods, "otp") {
		return OTPLoginSendSource{}, identity.ForbiddenError{}
	}
	var id []byte
	var factor string
	err = r.continuation.pool.Raw().QueryRow(ctx, `SELECT c.otp_send_command_id,c.otp_send_factor_id
FROM identity_mfa.continuations c
JOIN identity.commands j ON j.tenant_id=c.tenant_id AND j.command_id=c.otp_send_command_id AND j.purpose=c.otp_send_purpose AND j.state='committed'
JOIN identity.identity_command_id_claims k ON k.command_id=j.command_id AND k.tenant_id=j.tenant_id AND k.purpose=j.purpose AND NOT k.retired
WHERE c.tenant_id=$1 AND c.user_id=$2 AND c.continuation_id=$3 AND c.scope_digest=$4 AND c.version=$5::numeric
AND c.state IN(1,2) AND c.attempts_remaining>0 AND c.expires_at>clock_timestamp()`, string(s.TenantID), string(s.SubjectID), string(s.ID), digest[:], strconv.FormatUint(s.Version, 10)).Scan(&id, &factor)
	if err != nil {
		if ctx.Err() != nil {
			return OTPLoginSendSource{}, ctx.Err()
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return OTPLoginSendSource{}, identity.ForbiddenError{}
		}
		return OTPLoginSendSource{}, identity.UnavailableError{}
	}
	command, err := identity.ParseCommandID(base64.RawURLEncoding.EncodeToString(id))
	if err != nil || command == identity.CommandID(s.ID) {
		return OTPLoginSendSource{}, identity.ForbiddenError{}
	}
	if _, err := r.Read(ctx, grant, issuer, factor); err != nil {
		return OTPLoginSendSource{}, err
	}
	return OTPLoginSendSource{CommandID: command, FactorID: mfa.FactorID(factor), ContinuationID: s.ID}, nil
}

// RecordOTPLoginSendSource attaches this send to its original child in the same
// protected Work as actual OTP/delivery persistence. The registered native owner
// must already have persisted those effects and admitted original primary,
// cookie, factor, recipient, policy and risk; this helper grants none of them.
// Exact current factor/child fences repeat before the write. No scope, version,
// deadline, primary, attempts, child uses or session is changed. Retry/recovery
// never writes attribution. Resends select a new committed send atomically.
func RecordOTPLoginSendSource(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, expected OTPFactorMetadata, primary identity.CommandID) error {
	if err := RequireOTPLoginSendFactor(ctx, w, owner, command, expected, primary); err != nil {
		return err
	}
	b, _, _, err := w.FeatureScope(owner)
	if err != nil {
		return err
	}
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil {
		return identity.ForbiddenError{}
	}
	n, err := w.Exec(ctx, `UPDATE identity_mfa.continuations SET otp_send_command_id=$4,otp_send_factor_id=$5
WHERE tenant_id=$1 AND user_id=$2 AND continuation_id=$3 AND scope_digest=$6 AND version=$7::numeric
AND state IN(1,2) AND attempts_remaining>0 AND expires_at>clock_timestamp()`, string(b.TenantID), string(expected.UserID), string(expected.ContinuationID), id, expected.FactorID, expected.ScopeDigest[:], strconv.FormatUint(expected.ContinuationVersion, 10))
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ForbiddenError{}
	}
	return ctx.Err()
}
