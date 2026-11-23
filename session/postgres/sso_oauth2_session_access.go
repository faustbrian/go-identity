package postgres

import (
	"fmt"

	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// SSOOAuth2SessionAdmission selects the exact enterprise OAuth2 cookie
// profile. The trusted organization owner fences the original membership on
// the same primary, and in the original Work for strict cookie logout.
// This selects neither OIDC, social OAuth, nor provider logout.
type SSOOAuth2SessionAdmission struct {
	Profile   IdentifierAdmissionConfig
	Authority OrganizationSessionAuthority
}

func (p SSOOAuth2SessionAdmission) valid() bool {
	return validSSOSessionAdmission(p.Profile, p.Authority, "sso-oauth2")
}

// Format redacts deployment and borrowed authority details.
func (SSOOAuth2SessionAdmission) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.SSOOAuth2SessionAdmission(redacted)"))
}

// MarshalJSON denies implicit configuration export.
func (SSOOAuth2SessionAdmission) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

func selectedSSOOAuth2Admission(c SelectedSessionAdmissionConfig, selection SSOOAuth2SessionAdmission) ([]session.AuthenticationKind, string, error) {
	if !selection.valid() {
		return nil, "", session.ErrInvalidInput
	}
	return selectedSSOSessionAdmission(c, selection.Profile, "native-sso-oauth2-cookie-session-v1")
}

// NewSelectedSessionServiceWithSSOOAuth2 explicitly adds the OAuth2 native
// cookie reader to c. Set c.Admission.SSOOIDC separately to allow both. A
// denied or unavailable OAuth2 record never falls back to another profile.
// Construction performs no I/O and retains the original authority deadline.
func NewSelectedSessionServiceWithSSOOAuth2(pool *database.Pool, c SelectedSessionServiceConfig, selection SSOOAuth2SessionAdmission) (*session.SessionService, error) {
	methods, profile, err := selectedSSOOAuth2Admission(c.Admission, selection)
	if err != nil {
		return nil, err
	}
	return newSelectedSessionService(pool, c, enterpriseCookiePeers{oauth2: &selection}, methods, profile)
}

// NewCookieRevokeOneExecutorWithSSOOAuth2 opts the existing strict cookie
// executor into OAuth2 with its original CSRF keys and live authority. Use
// the identical profile in c.Sessions. Existing OIDC may also be selected
// separately, but neither provider session is admitted on bearer transport.
func NewCookieRevokeOneExecutorWithSSOOAuth2(pool *database.Pool, c RevokeOneExecutorConfig, keys []session.CSRFKey, selection SSOOAuth2SessionAdmission) (*CookieRevokeOneExecutor, error) {
	return newCookieRevokeOneExecutor(pool, c, keys, enterpriseCookiePeers{oauth2: &selection})
}
