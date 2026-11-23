package postgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
)

const ssoSAMLLogoutStartPurpose = "identity.sso.saml-logout-start"

// SSOSAMLLogoutStartOperation selects the native transition to revoke the
// authenticated user's original local session. It grants no provider authority.
func SSOSAMLLogoutStartOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "sso/saml", OperationID: ssoSAMLLogoutStartPurpose,
		SchemaID: "sso-enterprise-saml-logout-start-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// SSOSAMLLogoutStartDescriptor identifies the native SAML logout contributor.
// Only the exact active invocation can use the scope in the coordinator's Work.
func SSOSAMLLogoutStartDescriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.saml-logout-start", Version: 1}
}

// RequireSSOSAMLLogoutStartScope binds the selected native logout invocation
// to its original self-user session and next revocation version. Denials poison
// live Work. No session, account or provider evidence is read or renewed here.
func (w Work) RequireSSOSAMLLogoutStartScope(ctx context.Context, owner FeatureExecutionContributor, tenant identity.TenantID, user identity.UserID, sessionID string, version uint64) error {
	return w.requireSSOSelfLogoutScope(ctx, owner, tenant, user, sessionID, version, SSOSAMLLogoutStartOperation(), SSOSAMLLogoutStartDescriptor())
}

// RequireLinkedSSOSAMLLogoutStartCredential retains the original enterprise
// provider reference and account locks in the selected SAML logout Work. The
// session owner must still match the selected provider and fence session,
// organization and factor authority. This creates no new evidence or lease.
func (w Work) RequireLinkedSSOSAMLLogoutStartCredential(ctx context.Context, owner FeatureExecutionContributor, expected CredentialAdmission, sessionID string, version uint64) error {
	c := expected.Credential
	if err := w.RequireSSOSAMLLogoutStartScope(ctx, owner, c.TenantID, c.UserID, sessionID, version); err != nil {
		return err
	}
	if !validSSOProviderSessionCredential(expected) {
		return w.fail(ctx, invalidWork())
	}
	return w.lockLinkedSSOProviderCredential(ctx, owner, expected)
}
