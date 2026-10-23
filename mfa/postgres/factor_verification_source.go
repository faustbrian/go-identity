package mfapostgres

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// FactorVerificationSource reads original signed active-factor evidence through
// authentication's existing method-neutral ReauthenticationSource contract.
// Only committed native issuance is visible. This source does not validate
// signatures, current session/factor authority or one-use status and cannot
// renew original proof timestamps. Those checks belong to the configured
// authentication validator and protected consuming workflow. It owns no
// transaction, cache, goroutine or pool lifetime; concurrent reads are safe.
type FactorVerificationSource struct {
	pool            *database.Pool
	maximumDuration time.Duration
	otp             bool
}

var _ auth.ReauthenticationSource = (*FactorVerificationSource)(nil)

// NewFactorVerificationSource borrows primary PostgreSQL with a read budget of
// at most five seconds. It performs no IO or schema initialization. Install the
// owned factor-verification history before use; missing storage fails closed.
func NewFactorVerificationSource(pool *database.Pool, maximumDuration time.Duration) (*FactorVerificationSource, error) {
	if pool == nil || pool.Raw() == nil || maximumDuration <= 0 || maximumDuration > 5*time.Second {
		return nil, invalidAuthority()
	}
	return &FactorVerificationSource{pool: pool, maximumDuration: maximumDuration}, nil
}

// NewOTPFactorVerificationSource selects only committed native active-OTP
// action evidence (factor-update or explicitly selected disable) in its distinct
// method-owned storage. Install
// OTPFactorVerificationMigrationSource first. It otherwise retains the existing
// source's bounded reads, errors, immutable signed history and borrowed pool
// lifetime. It grants no current authentication, permission or one-time use.
// It cannot read TOTP, pending enrollment or partial-login evidence as OTP.
func NewOTPFactorVerificationSource(pool *database.Pool, maximumDuration time.Duration) (*FactorVerificationSource, error) {
	source, err := NewFactorVerificationSource(pool, maximumDuration)
	if err != nil {
		return nil, err
	}
	source.otp = true
	return source, nil
}

// Reauthentication selects the immutable original proof by its globally unique
// random128 ID, which is also the native issuance command ID. Pending, aborted,
// absent and retired commands all return ErrInvalidProof without partial data.
// Corrupt or oversized evidence, missing schema and unavailable primary return
// redacted Unavailable; cancellation retains the original context error.
// Consumed evidence may still be read as history, but this never permits its
// reuse. Native consumers must exclusively lock/check its use marker together
// with current owners and apply their mutation in the same protected commit.
func (s *FactorVerificationSource) Reauthentication(ctx context.Context, id auth.ProofID) (auth.SignedReauthenticationRecord, error) {
	r, err := s.readRecord(ctx, id)
	return r.Original, err
}

func (s *FactorVerificationSource) readRecord(ctx context.Context, id auth.ProofID) (factorVerificationRecord, error) {
	zero := factorVerificationRecord{}
	if ctx == nil || s == nil || s.pool == nil || s.pool.Raw() == nil || s.maximumDuration <= 0 || s.maximumDuration > 5*time.Second {
		return zero, invalidAuthority()
	}
	if _, err := identity.ParseCommandID(string(id)); err != nil {
		return zero, auth.ErrInvalidProof
	}
	bounded, stop := context.WithTimeout(ctx, s.maximumDuration)
	defer stop()
	if err := bounded.Err(); err != nil {
		return zero, err
	}
	raw, _ := base64.RawURLEncoding.DecodeString(string(id))
	var tenant, user, factor, enrollment, authority string
	var payload []byte
	table, purpose := "identity_mfa.factor_verifications", "identity.mfa.totp-verify"
	if s.otp {
		table, purpose = "identity_mfa.otp_factor_verifications", "identity.mfa.otp-verify"
	}
	err := s.pool.Raw().QueryRow(bounded, `SELECT v.tenant_id,v.user_id,v.factor_id,v.enrollment_version::text,v.factor_authority_version::text,
CASE WHEN octet_length(v.record) BETWEEN 1 AND 32768 THEN v.record END
FROM `+table+` v
JOIN identity.commands j ON j.tenant_id=v.tenant_id AND j.command_id=v.command_id AND j.purpose=v.purpose
JOIN identity.identity_command_id_claims c ON c.tenant_id=j.tenant_id AND c.command_id=j.command_id AND c.purpose=j.purpose
WHERE v.proof_id=$1 AND v.command_id=$2 AND v.purpose=$3
AND j.state='committed' AND NOT c.retired`, string(id), raw, purpose).Scan(&tenant, &user, &factor, &enrollment, &authority, &payload)
	if bounded.Err() != nil {
		return zero, bounded.Err()
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return zero, auth.ErrInvalidProof
	}
	if err != nil {
		return zero, identity.UnavailableError{}
	}
	decode := decodeFactorVerificationRecord
	if s.otp {
		decode = decodeOTPFactorVerificationRecord
	}
	r, err := decode(id, tenant, user, payload)
	if err != nil || r.Original.CredentialID != factor || strconv.FormatUint(r.Original.CredentialVersion, 10) != enrollment || strconv.FormatUint(r.FactorAuthorityVersion, 10) != authority {
		return zero, identity.UnavailableError{}
	}
	return r, nil
}

// Format hides borrowed pool and deployment state.
func (*FactorVerificationSource) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.FactorVerificationSource(redacted)"))
}

// MarshalJSON rejects implicit runtime-resource export.
func (*FactorVerificationSource) MarshalJSON() ([]byte, error) { return nil, invalidAuthority() }

// MarshalText rejects implicit runtime-resource export.
func (*FactorVerificationSource) MarshalText() ([]byte, error) { return nil, invalidAuthority() }
