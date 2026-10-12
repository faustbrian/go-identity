package mfapostgres

import (
	"context"
	"errors"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// ReadPasswordSigninFactors selects known primary factor state after password
// comparison. It grants no authentication or freshness lease; the native owner
// must fence the returned generation in its protected Work. Missing state denies
// rather than implying no MFA. The pool is borrowed and the read is bounded.
func ReadPasswordSigninFactors(ctx context.Context, pool *database.Pool, tenant identity.TenantID, user identity.UserID, maximum time.Duration) (uint64, bool, error) {
	if ctx == nil || pool == nil || pool.Raw() == nil || maximum <= 0 || maximum > 5*time.Second {
		return 0, false, invalidAuthority()
	}
	if _, err := identity.ParseIdentifierID(string(tenant)); err != nil {
		return 0, false, invalidAuthority()
	}
	if _, err := identity.ParseIdentifierID(string(user)); err != nil {
		return 0, false, invalidAuthority()
	}
	bounded, stop := context.WithTimeout(ctx, maximum)
	defer stop()
	var version string
	var active int32
	if err := pool.Raw().QueryRow(bounded, `SELECT version::text,active_factors FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id=$2`, string(tenant), string(user)).Scan(&version, &active); err != nil {
		if bounded.Err() != nil {
			return 0, false, bounded.Err()
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, false, identity.ForbiddenError{}
		}
		return 0, false, identity.UnavailableError{}
	}
	v, err := strconv.ParseUint(version, 10, 64)
	if err != nil || active < 0 {
		return 0, false, identity.UnavailableError{}
	}
	if _, err := mfa.NewFactorAuthority(mfa.AuthorityRecord{TenantID: tenant, UserID: user, Version: v, ActiveFactors: uint32(active)}); err != nil {
		return 0, false, invalidAuthority()
	}
	return v, active > 0, bounded.Err()
}

// RequirePasswordSigninFactors locks the exact current generation through the
// sole password transaction. A challenge requires its closed native owner and a
// confirmed TOTP method; SFA requires known empty state. No secret or session is
// returned and every error must abort Work. Original expectedVersion is never
// replaced by the latest generation. Both Apply and final commit checks may use
// this guard; it creates no transaction, callback, enrollment or factor attempt.
func RequirePasswordSigninFactors(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, user identity.UserID, version uint64, challenge bool) error {
	if ctx == nil || owner == nil || version == 0 {
		return invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s, ok := command.PasswordSigninFeature()
	b, f, life, err := w.FeatureScope(owner)
	if err != nil || !ok || s.Binding != b || s.Operation != f.Operation || b.OperationID != "identity.password.signin" || f.Contributor != (kernel.ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}) {
		return invalidAuthority()
	}
	if challenge {
		if _, ok := owner.(kernel.PasswordMFAChallengeContributor); !ok || life.EventType != "mfa.challenge.created.v1" {
			return invalidAuthority()
		}
	} else if life.EventType != "session.created.v1" {
		return invalidAuthority()
	}
	state, err := readFactorAuthority(ctx, w, b, user, version)
	if err != nil {
		return err
	}
	if !challenge {
		return state.RequireEmailRecovery(b.TenantID, user)
	}
	if state.RequireEmailRecovery(b.TenantID, user) == nil {
		return identity.ForbiddenError{}
	}
	rows, err := w.Query(ctx, `SELECT factor_id FROM identity_mfa.totp_factors WHERE tenant_id=$1 AND user_id=$2 AND state=2 AND confirmed_at IS NOT NULL AND encrypted_secret IS NOT NULL LIMIT 1`, string(b.TenantID), string(user))
	if err != nil {
		return identity.UnavailableError{}
	}
	defer rows.Close()
	var id string
	if !rows.Next() {
		if err := ctx.Err(); err != nil {
			return err
		}
		if rows.Err() != nil {
			return identity.UnavailableError{}
		}
		return identity.ForbiddenError{}
	}
	if rows.Scan(&id) != nil || rows.Next() || rows.Err() != nil {
		return identity.UnavailableError{}
	}
	if _, err := identity.ParseCommandID(id); err != nil {
		return identity.ForbiddenError{}
	}
	return ctx.Err()
}
