package mfapostgres

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// ReadMagicLinkChallengeRequired selects a branch from primary factor state
// matching the verified original magic-link grant. Missing/stale state denies;
// absence never means no MFA. This bounded read grants no authentication and
// retains no freshness lease. Protected admission/execution must fence it again.
func ReadMagicLinkChallengeRequired(ctx context.Context, pool *database.Pool, grant capability.Grant, maximum time.Duration) (bool, error) {
	if ctx == nil || pool == nil || pool.Raw() == nil || maximum <= 0 || maximum > 5*time.Second {
		return false, invalidAuthority()
	}
	p := grant.Payload()
	v, err := strconv.ParseUint(p.Caveats["magiclink.factor-version"], 10, 64)
	if err != nil || v == 0 || strconv.FormatUint(v, 10) != p.Caveats["magiclink.factor-version"] || p.Operation != "identity.magic-link.consume" || p.Subject == "" || p.Tenant == "" {
		return false, invalidAuthority()
	}
	bounded, stop := context.WithTimeout(ctx, maximum)
	defer stop()
	var version string
	var active int32
	if err := pool.Raw().QueryRow(bounded, `SELECT version::text,active_factors FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id=$2`, p.Tenant, p.Subject).Scan(&version, &active); err != nil {
		if bounded.Err() != nil {
			return false, bounded.Err()
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return false, identity.ForbiddenError{}
		}
		return false, identity.UnavailableError{}
	}
	if version != strconv.FormatUint(v, 10) || active < 0 || active > 64 {
		return false, identity.ForbiddenError{}
	}
	return active > 0, bounded.Err()
}

// RequireMagicLinkTOTPChallenge fences enrolled authority and an actually
// confirmed TOTP method for the exact native challenge-only consuming owner.
// It is permitted in original preparation and protected final execution, never
// single-factor/session or request phases. Factor row locking stabilizes method
// state through Work. No secret, provider, proof, session or mutation is exposed.
func RequireMagicLinkTOTPChallenge(ctx context.Context, w kernel.Work, owner kernel.MagicLinkMFAChallengeContributor, c identity.Command, user identity.UserID, version uint64) error {
	if ctx == nil || owner == nil || version == 0 {
		return invalidAuthority()
	}
	s, ok := c.Feature()
	b, f, life, err := w.FeatureScope(owner)
	if err != nil || !ok || s.Binding != b || s.Operation != f.Operation || b.OperationID != "identity.magic-link.consume" || b.UserID != "" || b.AnonymousFlowID == "" || life.EventType != "mfa.challenge.created.v1" || f.Contributor != (kernel.ContributorDescriptor{Owner: "identity/magiclink/postgres", ContractID: "identity.magiclink", Version: 1}) {
		return invalidAuthority()
	}
	state, err := readFactorAuthority(ctx, w, b, user, version)
	if err != nil {
		return err
	}
	if state.RequireEmailRecovery(b.TenantID, user) == nil {
		return identity.ForbiddenError{}
	}
	rows, err := w.Query(ctx, `SELECT factor_id FROM identity_mfa.totp_factors WHERE tenant_id=$1 AND user_id=$2 AND state=2 AND confirmed_at IS NOT NULL AND encrypted_secret IS NOT NULL LIMIT 1`, string(b.TenantID), string(user))
	if err != nil {
		return identity.UnavailableError{}
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return identity.UnavailableError{}
		}
		return identity.ForbiddenError{}
	}
	var id string
	if rows.Scan(&id) != nil || rows.Next() || rows.Err() != nil {
		return identity.UnavailableError{}
	}
	return ctx.Err()
}
