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

func oauthSessionFactors(record session.Session) (session.SessionSpec, uint64, error) {
	spec, err := record.Bindings()
	if err != nil || spec.Authentication.Kind != session.AuthenticationVerified || spec.Authentication.Proof.Method != "oauth" || spec.Authentication.Proof.Purpose != "session-issue" || spec.Authentication.Proof.Assurance != auth.AssuranceSingleFactor || record.MFAAuthentication() != (session.MFAAuthentication{}) {
		return session.SessionSpec{}, 0, invalidAuthority()
	}
	vector, err := spec.Authority.Bindings()
	key, e := FactorAuthorityKey(spec.TenantID, spec.UserID)
	if err != nil || e != nil || vector.Organization.Present || vector.Passkey.Present || !vector.Factor.Present || vector.Factor.Binding.ScopeKey != key || vector.Factor.Binding.Version == 0 {
		return session.SessionSpec{}, 0, invalidAuthority()
	}
	return spec, vector.Factor.Binding.Version, nil
}

// ReadOAuthSessionFactors checks the actual original known-empty generation for
// an existing OAuth session. Missing/enrolled/newer authority denies; it never
// replaces the record's generation. The borrowed primary pool and bounded
// maximum retain existing read ownership. Success is not a validity lease.
func ReadOAuthSessionFactors(ctx context.Context, pool *database.Pool, record session.Session, maximum time.Duration) error {
	spec, version, err := oauthSessionFactors(record)
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

// RequireOAuthSessionFactors retains the known-empty generation only for an
// exact native same-user session revoke-one invocation. It accepts the original
// target or its same-user caller session; the session owner binds both under
// its own transaction. Directory, linked credential, policy and session fences
// remain mandatory. Errors must abort Work. No factor, proof or lease is made.
func RequireOAuthSessionFactors(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, record session.Session) error {
	if ctx == nil {
		return invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	spec, version, err := oauthSessionFactors(record)
	if err != nil {
		return err
	}
	b, f, life, err := w.FeatureScope(owner)
	if err != nil || b.ValidateFor(f.Operation) != nil || b.TenantID != spec.TenantID || b.UserID != spec.UserID || b.ActorKind != authorization.SubjectUser || string(b.ActorID) != string(spec.UserID) || b.AnonymousFlowID != "" {
		return invalidAuthority()
	}
	if f.Operation != session.RevokeOneOperation() || f.Contributor != (kernel.ContributorDescriptor{Owner: "identity/session/postgres", ContractID: "identity.session.store", Version: 1}) || life.EventType != "session.revoked.v1" || life.EventIndex != 0 || life.BeforeVersion == 0 || life.BeforeVersion == ^uint64(0) || life.AfterVersion != life.BeforeVersion+1 || b.RecordID == spec.SessionID && life.BeforeVersion != spec.Version {
		return invalidAuthority()
	}
	_, err = readKnownEmptyFactors(ctx, w, b, spec.UserID, version)
	return err
}
