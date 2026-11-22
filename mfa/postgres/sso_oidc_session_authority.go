package mfapostgres

import (
	"context"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

func ssoOIDCSessionFactors(record session.Session) (session.SessionSpec, uint64, error) {
	spec, err := record.Bindings()
	if err != nil || spec.Authentication.Kind != session.AuthenticationVerified || spec.Authentication.Proof.Method != "sso-oidc" || spec.Authentication.Proof.Purpose != "session-issue" || spec.Authentication.Proof.Assurance != auth.AssuranceSingleFactor || record.MFAAuthentication() != (session.MFAAuthentication{}) {
		return session.SessionSpec{}, 0, invalidAuthority()
	}
	vector, err := spec.Authority.Bindings()
	key, keyErr := FactorAuthorityKey(spec.TenantID, spec.UserID)
	if err != nil || keyErr != nil || !vector.Organization.Present || vector.Passkey.Present || !vector.Factor.Present || vector.Factor.Binding.ScopeKey != key || vector.Factor.Binding.Version == 0 {
		return session.SessionSpec{}, 0, invalidAuthority()
	}
	return spec, vector.Factor.Binding.Version, nil
}

// ReadSSOOIDCSessionFactors checks the actual enterprise session's original
// known-empty factor generation on the primary. Only single-factor sso-oidc
// records with selected organization authority qualify; missing, enrolled or
// changed factor state denies without adopting another generation. Organization
// membership and its exact current authority remain separately owner-fenced.
// The pool is borrowed; maximum is 1ms..5s, bounded by earlier cancellation.
// Success creates no authentication, transaction or validity lease.
func ReadSSOOIDCSessionFactors(ctx context.Context, pool *database.Pool, record session.Session, maximum time.Duration) error {
	spec, version, err := ssoOIDCSessionFactors(record)
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

// RequireSSOOIDCSessionFactors locks the original known-empty generation only
// for the exact registered same-user, same-tenant session revoke-one invocation.
// It accepts that original target or the caller's same-user source session;
// the session owner must bind both and independently fence session, directory,
// linked credential, policy and organization authority in the same Work.
// Call in Apply and final checks, propagating every error to abort. Locks stay
// with the sole coordinator until commit or rollback. No factor, session, proof,
// transaction, refreshed authority or competing organization owner is created.
func RequireSSOOIDCSessionFactors(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, record session.Session) error {
	if ctx == nil {
		return invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	spec, version, err := ssoOIDCSessionFactors(record)
	if err != nil {
		return err
	}
	binding, feature, life, err := w.FeatureScope(owner)
	if err != nil || binding.ValidateFor(feature.Operation) != nil || binding.TenantID != spec.TenantID || binding.UserID != spec.UserID || binding.ActorKind != authorization.SubjectUser || string(binding.ActorID) != string(spec.UserID) || binding.AnonymousFlowID != "" {
		return invalidAuthority()
	}
	if feature.Operation != session.RevokeOneOperation() || feature.Contributor != (kernel.ContributorDescriptor{Owner: "identity/session/postgres", ContractID: "identity.session.store", Version: 1}) || life.EventType != "session.revoked.v1" || life.EventIndex != 0 || life.BeforeVersion == 0 || life.BeforeVersion == ^uint64(0) || life.AfterVersion != life.BeforeVersion+1 || binding.RecordID == spec.SessionID && life.BeforeVersion != spec.Version {
		return invalidAuthority()
	}
	_, err = readKnownEmptyFactors(ctx, w, binding, spec.UserID, version)
	return err
}
