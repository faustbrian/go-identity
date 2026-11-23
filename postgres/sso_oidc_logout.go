package postgres

import (
	"context"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

const ssoOIDCLogoutPurpose = "identity.sso.oidc-logout"

// SSOOIDCLogoutOperation selects the authenticated enterprise OIDC logout
// start. The command targets the original local session, not the provider or
// a session family. This declaration grants no session or provider authority.
func SSOOIDCLogoutOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "sso/oidc", OperationID: ssoOIDCLogoutPurpose,
		SchemaID: "sso-enterprise-oidc-logout-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// SSOOIDCLogoutDescriptor identifies the native SSO logout contributor.
// Scope checks also require the coordinator's exact active instance.
func SSOOIDCLogoutDescriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.oidc-logout", Version: 1}
}

// RequireSSOOIDCLogoutScope admits the exact native logout start invocation and
// original self-user session transition. It does not read the session, extend
// evidence, or authorize any effect by itself. Denials poison live Work so
// ignoring this result cannot commit earlier effects.
func (w Work) RequireSSOOIDCLogoutScope(ctx context.Context, owner FeatureExecutionContributor, tenant identity.TenantID, user identity.UserID, sessionID string, version uint64) error {
	if err := w.usable(); err != nil {
		return err
	}
	if ctx == nil {
		return w.fail(w.state.ctx, invalidWork())
	}
	if err := ctx.Err(); err != nil {
		return w.fail(ctx, err)
	}
	b, feature, life, err := w.FeatureScope(owner)
	op := SSOOIDCLogoutOperation()
	if err != nil || feature.Operation != op || feature.Contributor != SSOOIDCLogoutDescriptor() || w.state.featurePreparationPlan != nil {
		return w.fail(ctx, invalidWork())
	}
	if b.ValidateFor(op) != nil || b.TenantID != tenant || b.UserID != user || b.ActorKind != authorization.SubjectUser || b.ActorID != identity.ActorID(user) {
		return w.fail(ctx, invalidWork())
	}
	if b.RecordID != sessionID || w.state.subjectType != "session" || life.EventType != "session.revoked.v1" || life.EventIndex != 0 || life.BeforeVersion != version || version == 0 || op.ValidateRecordVersions(version, life.AfterVersion) != nil {
		return w.fail(ctx, invalidWork())
	}
	return nil
}
