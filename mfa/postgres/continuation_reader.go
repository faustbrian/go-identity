package mfapostgres

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// ContinuationReader restores original scope from primary PostgreSQL authority.
// It owns no connection, transaction or cache. Concurrent reads are safe; the
// caller owns the pool lifetime. A returned projection is not factor proof or
// permission to issue a session: protected execution must recheck authority and
// atomically consume the child and factor under the sole coordinator.
type ContinuationReader struct {
	pool            *database.Pool
	maximumDuration time.Duration
}

// NewContinuationReader borrows a primary pool and limits each read to at most
// five seconds. Earlier caller deadlines win. No database work occurs here.
func NewContinuationReader(pool *database.Pool, maximumDuration time.Duration) (*ContinuationReader, error) {
	if pool == nil || pool.Raw() == nil || maximumDuration <= 0 || maximumDuration > 5*time.Second {
		return nil, invalidAuthority()
	}
	return &ContinuationReader{pool: pool, maximumDuration: maximumDuration}, nil
}

// Read requires an already verified child grant and the configured issuer.
// It restores exact original scope and current attempt state without reserving,
// consuming or renewing anything. Missing, expired, inactive, uncommitted or
// changed factor authority denies. Storage failures fail closed; cancellation
// is preserved. No bearer or factor secret is returned.
func (r *ContinuationReader) Read(ctx context.Context, grant capability.Grant, issuer string) (mfa.PartialAuthContinuation, error) {
	deny := func() (mfa.PartialAuthContinuation, error) {
		return mfa.PartialAuthContinuation{}, identity.ForbiddenError{}
	}
	if ctx == nil || r == nil || r.pool == nil || r.pool.Raw() == nil || r.maximumDuration <= 0 || r.maximumDuration > 5*time.Second {
		return deny()
	}
	if err := ctx.Err(); err != nil {
		return mfa.PartialAuthContinuation{}, err
	}
	p := grant.Payload()
	if grant.EnvelopeDigest() == ([32]byte{}) || p.Operation != "identity.mfa.complete" || p.Issuer != issuer {
		return deny()
	}
	if _, err := identity.ParseCommandID(p.ID); err != nil {
		return deny()
	}
	if _, err := identity.ParseIdentifierID(p.Tenant); err != nil {
		return deny()
	}
	if _, err := identity.ParseIdentifierID(p.Subject); err != nil {
		return deny()
	}
	bounded, cancel := context.WithTimeout(ctx, r.maximumDuration)
	defer cancel()
	var wire, digestBytes []byte
	var state int16
	var version, factorVersion, source string
	var maximum, remaining, active int32
	var issued, expires, now time.Time
	err := r.pool.Raw().QueryRow(bounded, `SELECT c.original_scope,c.scope_digest,c.state,c.version::text,c.max_attempts,c.attempts_remaining,c.source_preauth_id,c.issued_at,c.expires_at,f.version::text,f.active_factors,clock_timestamp()
FROM identity_mfa.continuations c
JOIN identity.commands j ON j.tenant_id=c.tenant_id AND j.purpose=c.origin_purpose AND j.command_id=c.origin_command_id
JOIN identity.identity_command_id_claims k ON k.command_id=j.command_id AND k.tenant_id=j.tenant_id AND k.purpose=j.purpose
JOIN identity_mfa.factor_authorities f ON f.tenant_id=c.tenant_id AND f.user_id=c.user_id
JOIN identity.users u ON u.tenant_id=c.tenant_id AND u.user_id=c.user_id
WHERE c.tenant_id=$1 AND c.continuation_id=$2 AND c.user_id=$3
AND j.state='committed' AND NOT k.retired AND k.fingerprint=c.origin_fingerprint AND j.generation=c.origin_generation
AND u.status='active'`, p.Tenant, p.ID, p.Subject).Scan(&wire, &digestBytes, &state, &version, &maximum, &remaining, &source, &issued, &expires, &factorVersion, &active, &now)
	defer clear(wire)
	if err != nil {
		if bounded.Err() != nil {
			return mfa.PartialAuthContinuation{}, bounded.Err()
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return deny()
		}
		return mfa.PartialAuthContinuation{}, identity.UnavailableError{}
	}
	if len(digestBytes) != 32 || maximum <= 0 || remaining < 0 || active <= 0 || active > 64 {
		return deny()
	}
	v, err := strconv.ParseUint(version, 10, 64)
	if err != nil {
		return deny()
	}
	var digest [32]byte
	copy(digest[:], digestBytes)
	c, err := decodeContinuationScope(wire, digest, mfa.ContinuationState(state), v, uint32(remaining))
	if err != nil {
		return deny()
	}
	s, err := c.Bindings()
	if err != nil || string(s.ID) != p.ID || string(s.TenantID) != p.Tenant || string(s.SubjectID) != p.Subject || string(s.SourcePreAuthID) != source || s.MaxAttempts != uint32(maximum) || !s.IssuedAt.Equal(issued) || !s.ExpiresAt.Equal(expires) || strconv.FormatUint(s.FactorVersion, 10) != factorVersion {
		return deny()
	}
	if err := c.Authorize(grant, issuer, now); err != nil {
		return deny()
	}
	if err := bounded.Err(); err != nil {
		return mfa.PartialAuthContinuation{}, err
	}
	return c, nil
}
