package postgres

import (
	"context"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// Enterprise and social provider ownership are intentionally separate. Keep the
// same current account association and epoch fences as the social query without
// making either evidence boundary accept an arbitrary credential owner.
const linkedSSOOIDCProviderCredentialSelect = `SELECT c.expires_at FROM identity.users u
 JOIN identity.credential_references c ON c.tenant_id=u.tenant_id AND c.user_id=u.user_id
 JOIN identity.account_credentials m ON m.tenant_id=c.tenant_id AND m.user_id=c.user_id AND m.credential_id=c.credential_id
 JOIN identity.accounts a ON a.tenant_id=m.tenant_id AND a.user_id=m.user_id AND a.account_id=m.account_id
 WHERE u.tenant_id=$1 AND u.user_id=$2 AND c.credential_id=$3 AND c.kind=3 AND c.owner='sso' AND c.version=$4::numeric AND c.enabled
 AND u.status='active' AND u.authority_version=$5::numeric AND u.identifier_version=$6::numeric AND u.credential_version=$7::numeric AND a.linked LIMIT 2`

func validSSOOIDCSessionCredential(a CredentialAdmission) bool {
	c := a.Credential
	return c.Validate(c.TenantID, c.UserID) == nil && c.Kind == identity.CredentialProvider && c.Owner == "sso" && a.UserAuthorityVersion != 0 && a.IdentifierAuthorityVersion != 0 && a.CredentialAuthorityVersion != 0
}

// CheckLinkedSSOOIDCProviderCredential performs bounded primary reads of the
// exact original SSO provider reference, independent user/security epochs and
// current linked account association. Missing, disabled, expired, foreign or
// stale authority denies; storage or ambiguous association is unavailable.
// Success grants neither authentication nor a lease. The session owner must
// separately fence directory, policy, factors, organization and session state,
// preserve the earliest read-start budget and repeat this check under Work.
func (r *Repository) CheckLinkedSSOOIDCProviderCredential(ctx context.Context, expected CredentialAdmission) error {
	if !r.validAccountRead(ctx) || !validSSOOIDCSessionCredential(expected) {
		return invalidAccountQuery()
	}
	bounded, stop := context.WithTimeout(ctx, r.maximumDuration)
	defer stop()
	rows, err := r.pool.Raw().Query(bounded, linkedSSOOIDCProviderCredentialSelect, providerSessionCredentialArgs(expected)...)
	if err != nil {
		return readFailure(bounded, err)
	}
	expires, err := linkedProviderExpiry(rows)
	if err != nil {
		return err
	}
	var now time.Time
	if err := r.pool.Raw().QueryRow(bounded, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return readFailure(bounded, err)
	}
	if expires != nil && !now.Before(*expires) {
		return identity.ForbiddenError{}
	}
	return bounded.Err()
}

// RequireLinkedSSOOIDCProviderCredential retains current user, credential and
// account-association locks only for the registered session store's native
// same-user, same-tenant revoke-one Apply or final invocation. The original
// credential may belong to its target or its caller's source session; this
// method does not bind or authorize either session. Every live denial poisons
// Work, including ignored errors. Exclusive expiry is sampled after acquiring
// account locks so waiting cannot preserve an expired credential. It creates
// no proof, refreshed authority, transaction or permission; the session owner
// must independently fence the complete original session authority in both
// phases. Callback/preparation authority cannot substitute for this profile.
func (w Work) RequireLinkedSSOOIDCProviderCredential(ctx context.Context, owner FeatureExecutionContributor, expected CredentialAdmission) error {
	if err := w.usable(); err != nil {
		return err
	}
	if ctx == nil {
		return w.fail(w.state.ctx, invalidWork())
	}
	if err := ctx.Err(); err != nil {
		return w.fail(ctx, err)
	}
	if !validSSOOIDCSessionCredential(expected) {
		return w.fail(ctx, invalidWork())
	}
	b, feature, life, err := w.FeatureScope(owner)
	if err != nil || b.ValidateFor(feature.Operation) != nil || b.TenantID != expected.Credential.TenantID || b.UserID != expected.Credential.UserID || b.ActorKind != authorization.SubjectUser || string(b.ActorID) != string(b.UserID) || b.AnonymousFlowID != "" {
		return w.fail(ctx, invalidWork())
	}
	// Match session.RevokeOneOperation without reversing the session -> kernel
	// dependency. MFA's RequireSSOOIDCSessionFactors uses this same profile.
	revokeOne := identity.FeatureOperation{Owner: "identity/session", OperationID: "identity.session.revoke-one", SchemaID: "session-revoke-one", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	store := ContributorDescriptor{Owner: "identity/session/postgres", ContractID: "identity.session.store", Version: 1}
	if feature.Operation != revokeOne || feature.Contributor != store || w.state.featurePreparationPlan != nil || life.EventType != "session.revoked.v1" || life.EventIndex != 0 || life.BeforeVersion == 0 || life.BeforeVersion == ^uint64(0) || life.AfterVersion != life.BeforeVersion+1 {
		return w.fail(ctx, invalidWork())
	}
	return w.lockLinkedSSOOIDCCredential(ctx, owner, expected)
}

// RequireLinkedSSOOIDCLogoutCredential retains the original linked provider
// credential and account only for the exact native self-logout session
// transition. The caller must match the linked account to the selected
// provider and independently fence the original session and organization.
// The locks and expiry check create no fresh evidence or provider authority.
func (w Work) RequireLinkedSSOOIDCLogoutCredential(ctx context.Context, owner FeatureExecutionContributor, expected CredentialAdmission, sessionID string, version uint64) error {
	c := expected.Credential
	if err := w.RequireSSOOIDCLogoutScope(ctx, owner, c.TenantID, c.UserID, sessionID, version); err != nil {
		return err
	}
	if !validSSOOIDCSessionCredential(expected) {
		return w.fail(ctx, invalidWork())
	}
	return w.lockLinkedSSOOIDCCredential(ctx, owner, expected)
}

func (w Work) lockLinkedSSOOIDCCredential(ctx context.Context, owner FeatureExecutionContributor, expected CredentialAdmission) error {
	// Preserve the kernel's user/credential-before-account lock ordering.
	if _, err := w.RequireActiveCredential(ctx, owner, expected); err != nil {
		return err
	}
	rows, err := w.Query(ctx, linkedSSOOIDCProviderCredentialSelect+` FOR SHARE OF a,m`, providerSessionCredentialArgs(expected)...)
	if err != nil {
		return err
	}
	expires, err := linkedProviderExpiry(rows)
	if err != nil {
		return w.fail(ctx, err)
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if expires != nil && !now.Before(*expires) {
		return w.fail(ctx, identity.ForbiddenError{})
	}
	return nil
}
