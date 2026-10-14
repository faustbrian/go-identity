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

// OTPSessionFactorState is current confirmed enrollment/account epoch metadata,
// not a proof or renewable lease. Compare exact original factor/enrollment and
// retain the earliest authoritative-read deadline when validating a session.
type OTPSessionFactorState struct{ EnrollmentVersion, AuthorityVersion uint64 }

// OTPSessionFactorReader borrows the primary pool and bounded read budget. It
// owns no transaction, cache, goroutine, code or child. Concurrent reads are safe.
type OTPSessionFactorReader struct {
	pool            *database.Pool
	maximumDuration time.Duration
}

// NewOTPSessionFactorReader validates an at most five-second primary budget
// without IO. Pool remains caller-owned; close it only after calls finish.
func NewOTPSessionFactorReader(pool *database.Pool, maximum time.Duration) (*OTPSessionFactorReader, error) {
	if pool == nil || pool.Raw() == nil || maximum <= 0 || maximum > 5*time.Second {
		return nil, invalidAuthority()
	}
	return &OTPSessionFactorReader{pool: pool, maximumDuration: maximum}, nil
}

// Read resolves current confirmed OTP authority independently of a completed or
// expired login child. Exact active account, enrollment and verified current
// recipient are required; revoked/pending/foreign/stale recipients deny. Outage
// and corruption return redacted unavailable errors, never absence or fallback.
// Earlier deadlines win and no read renews authentication or evidence freshness.
func (r *OTPSessionFactorReader) Read(ctx context.Context, tenant identity.TenantID, user identity.UserID, factor string) (OTPSessionFactorState, error) {
	if ctx == nil || r == nil || r.pool == nil || r.pool.Raw() == nil || r.maximumDuration <= 0 {
		return OTPSessionFactorState{}, invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return OTPSessionFactorState{}, err
	}
	if _, err := identity.ParseIdentifierID(string(tenant)); err != nil {
		return OTPSessionFactorState{}, invalidAuthority()
	}
	if _, err := identity.ParseIdentifierID(string(user)); err != nil {
		return OTPSessionFactorState{}, invalidAuthority()
	}
	if _, err := identity.ParseCommandID(factor); err != nil {
		return OTPSessionFactorState{}, invalidAuthority()
	}
	ctx, stop := context.WithTimeout(ctx, r.maximumDuration)
	defer stop()
	var enrollment, epoch string
	err := r.pool.Raw().QueryRow(ctx, `SELECT f.enrollment_version::text,a.version::text
FROM identity_mfa.otp_factors f
JOIN identity_mfa.factor_authorities a ON a.tenant_id=f.tenant_id AND a.user_id=f.user_id
JOIN identity.users u ON u.tenant_id=f.tenant_id AND u.user_id=f.user_id
JOIN identity.identifiers i ON i.tenant_id=f.tenant_id AND i.user_id=f.user_id AND i.identifier_id=f.identifier_id
WHERE f.tenant_id=$1 AND f.user_id=$2 AND f.factor_id=$3 AND f.state=2 AND f.confirmed_at IS NOT NULL
AND a.active_factors BETWEEN 1 AND 64 AND u.status='active'
AND i.verified AND i.verification_state=2 AND i.verified_at IS NOT NULL
AND i.version=f.identifier_version AND i.verification_version=f.verification_version
AND ((f.channel='email' AND i.kind='email') OR (f.channel='sms' AND i.kind='phone'))`, string(tenant), string(user), factor).Scan(&enrollment, &epoch)
	if err != nil {
		if ctx.Err() != nil {
			return OTPSessionFactorState{}, ctx.Err()
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return OTPSessionFactorState{}, identity.ForbiddenError{}
		}
		return OTPSessionFactorState{}, identity.UnavailableError{}
	}
	e, err := strconv.ParseUint(enrollment, 10, 64)
	v, other := strconv.ParseUint(epoch, 10, 64)
	if err != nil || other != nil || e == 0 || v == 0 {
		return OTPSessionFactorState{}, identity.UnavailableError{}
	}
	return OTPSessionFactorState{EnrollmentVersion: e, AuthorityVersion: v}, nil
}

func (*OTPSessionFactorReader) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.OTPSessionFactorReader(redacted)"))
}
func (*OTPSessionFactorReader) MarshalJSON() ([]byte, error) { return nil, invalidAuthority() }
func (*OTPSessionFactorReader) MarshalText() ([]byte, error) { return nil, invalidAuthority() }
