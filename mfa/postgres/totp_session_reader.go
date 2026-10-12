package mfapostgres

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// TOTP session authority is read independently of an expired or completed child.
// Session lifetime belongs to the session owner; child expiry is historical.
// This reader never decrypts the factor or treats replay counters as authority.

// TOTPSessionFactorState projects the current confirmed factor's enrollment and
// account-wide factor epoch from primary storage. It is not a proof or lease.
// The session owner must compare its exact original tenant/user/factor and
// enrollment, include AuthorityVersion in the complete current vector, and
// preserve the earliest contributing authoritative read's validity deadline.
type TOTPSessionFactorState struct {
	EnrollmentVersion, AuthorityVersion uint64
}

// TOTPSessionFactorReader borrows the primary pool and creates no transaction,
// cache, goroutine or factor secret. Concurrent reads are safe; the caller closes
// the pool only after calls finish. Unknown or unconfirmed factors fail closed.
type TOTPSessionFactorReader struct {
	pool            *database.Pool
	maximumDuration time.Duration
}

// NewTOTPSessionFactorReader freezes a bounded primary read budget (at most five
// seconds) without IO. Earlier caller deadlines win. Reading cannot enroll,
// complete, recover or authorize changing a factor.
func NewTOTPSessionFactorReader(pool *database.Pool, maximumDuration time.Duration) (*TOTPSessionFactorReader, error) {
	if pool == nil || pool.Raw() == nil || maximumDuration <= 0 || maximumDuration > 5*time.Second {
		return nil, invalidAuthority()
	}
	return &TOTPSessionFactorReader{pool: pool, maximumDuration: maximumDuration}, nil
}

// Read requires exact canonical stored identities and a canonical random128
// factor ID. It reads confirmed active factor and current account-wide epoch in
// one primary statement. Revoked, unconfirmed, missing or blocked state denies;
// corruption/outage returns a redacted unavailable error. No child lifetime,
// ciphertext, code, replay counter, cache expiry or authentication is returned.
func (r *TOTPSessionFactorReader) Read(ctx context.Context, tenant identity.TenantID, user identity.UserID, factorID string) (TOTPSessionFactorState, error) {
	if ctx == nil || r == nil || r.pool == nil || r.pool.Raw() == nil || r.maximumDuration <= 0 {
		return TOTPSessionFactorState{}, invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return TOTPSessionFactorState{}, err
	}
	if _, err := identity.ParseIdentifierID(string(tenant)); err != nil {
		return TOTPSessionFactorState{}, invalidAuthority()
	}
	if _, err := identity.ParseIdentifierID(string(user)); err != nil {
		return TOTPSessionFactorState{}, invalidAuthority()
	}
	if _, err := identity.ParseCommandID(factorID); err != nil {
		return TOTPSessionFactorState{}, invalidAuthority()
	}
	bounded, stop := context.WithTimeout(ctx, r.maximumDuration)
	defer stop()
	var enrollment, version string
	err := r.pool.Raw().QueryRow(bounded, `SELECT t.enrollment_version::text,f.version::text
FROM identity_mfa.totp_factors t
JOIN identity_mfa.factor_authorities f ON f.tenant_id=t.tenant_id AND f.user_id=t.user_id
JOIN identity.users u ON u.tenant_id=t.tenant_id AND u.user_id=t.user_id
WHERE t.tenant_id=$1 AND t.user_id=$2 AND t.factor_id=$3 AND t.state=2
AND t.confirmed_at IS NOT NULL AND t.encrypted_secret IS NOT NULL
AND f.active_factors BETWEEN 1 AND 64 AND u.status='active'`, string(tenant), string(user), factorID).Scan(&enrollment, &version)
	if err != nil {
		if bounded.Err() != nil {
			return TOTPSessionFactorState{}, bounded.Err()
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return TOTPSessionFactorState{}, identity.ForbiddenError{}
		}
		return TOTPSessionFactorState{}, identity.UnavailableError{}
	}
	e, err := strconv.ParseUint(enrollment, 10, 64)
	v, ve := strconv.ParseUint(version, 10, 64)
	if err != nil || ve != nil || e == 0 || v == 0 {
		return TOTPSessionFactorState{}, identity.UnavailableError{}
	}
	return TOTPSessionFactorState{EnrollmentVersion: e, AuthorityVersion: v}, nil
}

// Format prevents diagnostic traversal into pool/configuration state.
func (*TOTPSessionFactorReader) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.TOTPSessionFactorReader(redacted)"))
}

// MarshalJSON rejects implicit pool/configuration export.
func (*TOTPSessionFactorReader) MarshalJSON() ([]byte, error) { return nil, invalidAuthority() }

// MarshalText rejects implicit export and map-key disclosure.
func (*TOTPSessionFactorReader) MarshalText() ([]byte, error) { return nil, invalidAuthority() }
