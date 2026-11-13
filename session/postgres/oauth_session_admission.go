package postgres

import (
	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func oauthSessionAdmissionBindings(profile IdentifierAdmissionConfig, record session.Session, b identity.CommandBinding) (kernel.DirectoryAuthorityAdmission, kernel.CredentialAdmission, kernel.UserAuthorizationAdmission, error) {
	deny := func() (kernel.DirectoryAuthorityAdmission, kernel.CredentialAdmission, kernel.UserAuthorizationAdmission, error) {
		return kernel.DirectoryAuthorityAdmission{}, kernel.CredentialAdmission{}, kernel.UserAuthorizationAdmission{}, identity.ForbiddenError{}
	}
	spec, err := record.Bindings()
	if err != nil || profile.AuthenticationMethod != "oauth" || profile.CredentialKind != identity.CredentialProvider || profile.CredentialOwner != "identity/oauth" || record.MFAAuthentication() != (session.MFAAuthentication{}) {
		return deny()
	}
	vector, err := spec.Authority.Bindings()
	key, e := mfapg.FactorAuthorityKey(spec.TenantID, spec.UserID)
	if err != nil || e != nil || !vector.Factor.Present || vector.Factor.Binding.ScopeKey != key || vector.Factor.Binding.Version == 0 {
		return deny()
	}
	return credentialSessionAdmissionBindings(profile, record, b, spec.SessionID, spec.Version, vector.Factor, session.OptionalAuthorityBinding{}, auth.AssuranceSingleFactor)
}
