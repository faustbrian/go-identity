package postgres

import (
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// NewMFAPasswordSessionService selects password-plus-confirmed-TOTP records.
// It uses native current directory, password credential, authorization and exact
// factor enrollment owners. Single-factor records deny rather than upgrading;
// the ordinary password factory continues to deny MFA. Configuration and pool
// ownership follow SessionServiceConfig. Install MFA and session histories first.
// No IO, cache, goroutine, proof issuance or migration occurs at construction.
func NewMFAPasswordSessionService(pool *database.Pool, c SessionServiceConfig) (*session.SessionService, error) {
	return newPasswordSessionService(pool, c, true)
}

func passwordMFASessionAdmission(c IdentifierAdmissionConfig, record session.Session, binding identity.CommandBinding, sessionID string, version uint64) (kernel.DirectoryAuthorityAdmission, kernel.CredentialAdmission, kernel.UserAuthorizationAdmission, error) {
	deny := func() (kernel.DirectoryAuthorityAdmission, kernel.CredentialAdmission, kernel.UserAuthorizationAdmission, error) {
		return kernel.DirectoryAuthorityAdmission{}, kernel.CredentialAdmission{}, kernel.UserAuthorizationAdmission{}, session.ErrUnauthenticated
	}
	s, err := record.Bindings()
	m, me := record.MFAAuthentication().Bindings()
	if err != nil || me != nil || c.AuthenticationMethod != "password" || c.CredentialKind != identity.CredentialPassword || c.CredentialOwner != "identity/password" || s.Authentication.Proof.Purpose != session.PasswordMFAPrimaryPurpose || m.Method != "totp" || string(m.PrimaryCommandID) != string(s.Authentication.Proof.ID) {
		return deny()
	}
	key, err := mfapg.FactorAuthorityKey(s.TenantID, s.UserID)
	if err != nil {
		return deny()
	}
	factor := session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: key, Version: m.FactorAuthorityVersion}}
	return passwordSessionAdmissionBindings(c, record, binding, sessionID, version, factor)
}
