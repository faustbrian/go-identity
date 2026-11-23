package mfapostgres

import (
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

func ssoSAMLSessionFactors(record session.Session) (session.SessionSpec, uint64, error) {
	return ssoSessionFactors(record, "sso-saml")
}

// ReadSSOSAMLSessionFactors checks the actual enterprise session's original
// known-empty factor generation on the primary. Only single-factor sso-saml
// records with selected organization authority qualify; missing, enrolled or
// changed factor state denies without adopting another generation. Organization
// membership and its exact current authority remain separately owner-fenced.
// The pool is borrowed; maximum is 1ms..5s, bounded by earlier cancellation.
// Success creates no authentication, transaction or validity lease.
func ReadSSOSAMLSessionFactors(ctx context.Context, pool *database.Pool, record session.Session, maximum time.Duration) error {
	spec, version, err := ssoSAMLSessionFactors(record)
	if err != nil {
		return err
	}
	current, err := readKnownEmptyPrimary(ctx, pool, spec.TenantID, spec.UserID, maximum)
	if err != nil {
		return err
	}
	if current.Version() != version {
		return identity.ForbiddenError{}
	}
	return nil
}

// RequireSSOSAMLSessionFactors locks the original known-empty generation only
// for the exact registered same-user, same-tenant session revoke-one invocation.
// It accepts that original target or the caller's same-user source session;
// the session owner must bind both and independently fence session, directory,
// linked credential, policy and organization authority in the same Work.
// Call in Apply and final checks, propagating every error to abort. Locks stay
// with the sole coordinator until commit or rollback. No factor, session, proof,
// transaction, refreshed authority or competing organization owner is created.
func RequireSSOSAMLSessionFactors(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, record session.Session) error {
	if ctx == nil {
		return invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	spec, version, err := ssoSAMLSessionFactors(record)
	if err != nil {
		return err
	}
	return requireSSOSessionFactors(ctx, w, owner, spec, version)
}

// RequireSSOSAMLLogoutStartFactors locks the original known-empty factor
// generation in the exact SAML logout start Work. A sibling session cannot
// supply the factor authority. The caller must separately check the original
// session and other authority, propagate denials and retain the existing Work
// through commit or rollback. No factor or time window is created or renewed.
func RequireSSOSAMLLogoutStartFactors(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, record session.Session) error {
	if ctx == nil {
		return invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	spec, version, err := ssoSAMLSessionFactors(record)
	if err != nil {
		return err
	}
	if err := w.RequireSSOSAMLLogoutStartScope(ctx, owner, spec.TenantID, spec.UserID, spec.SessionID, spec.Version); err != nil {
		return err
	}
	binding, _, _, err := w.FeatureScope(owner)
	if err != nil {
		return err
	}
	_, err = readKnownEmptyFactors(ctx, w, binding, spec.UserID, version)
	return err
}
