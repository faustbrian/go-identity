package postgres

import (
	"fmt"

	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// SSOSAMLSessionAdmission selects the original linked-member SAML cookie profile.
// The borrowed organization owner checks the original active membership on
// the primary and in the strict local logout Work. This does not select SAML
// Single Logout, an IdP response validator, or a bearer session profile.
type SSOSAMLSessionAdmission struct {
	Profile   IdentifierAdmissionConfig
	Authority OrganizationSessionAuthority
}

func (p SSOSAMLSessionAdmission) valid() bool {
	return validSSOSessionAdmission(p.Profile, p.Authority, "sso-saml")
}

// Format redacts deployment and borrowed authority details.
func (SSOSAMLSessionAdmission) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.SSOSAMLSessionAdmission(redacted)"))
}

// MarshalJSON denies implicit configuration export.
func (SSOSAMLSessionAdmission) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// OAuth2 and SAML are selected by additive constructors so existing public
// config literals stay compatible. OIDC remains selected on the shared config.
type enterpriseCookiePeers struct {
	oauth2 *SSOOAuth2SessionAdmission
	saml   *SSOSAMLSessionAdmission
}

// NewSelectedSessionServiceWithSSOSAML adds the explicit SAML cookie reader.
// Set c.Admission.SSOOIDC or oauth2 to select additional enterprise methods on
// the same deployment, policy namespace and audience. A denied SAML read never
// falls back. Construction does not perform IO, and callers may release config
// values after construction; the primary pool and owner ports remain borrowed.
func NewSelectedSessionServiceWithSSOSAML(pool *database.Pool, c SelectedSessionServiceConfig, selection SSOSAMLSessionAdmission, oauth2 *SSOOAuth2SessionAdmission) (*session.SessionService, error) {
	if !selection.valid() {
		return nil, session.ErrInvalidInput
	}
	peers := enterpriseCookiePeers{saml: &selection}
	const domain = "native-sso-saml-cookie-session-v1"
	if oauth2 == nil {
		methods, profile, err := selectedSSOSessionAdmission(c.Admission, selection.Profile, domain)
		if err != nil {
			return nil, err
		}
		return newSelectedSessionService(pool, c, peers, methods, profile)
	}
	peer := *oauth2
	a, b := selection.Profile, peer.Profile
	if a.GlobalAuthorityID != b.GlobalAuthorityID || a.PolicyNamespace != b.PolicyNamespace || a.Audience != b.Audience {
		return nil, session.ErrInvalidInput
	}
	methods, profile, err := selectedSSOOAuth2Admission(c.Admission, peer)
	if err != nil {
		return nil, err
	}
	peers.oauth2 = &peer
	return newSelectedSessionService(pool, c, peers, methods, nativeAdmissionCacheProfile(domain, profile))
}

// NewCookieRevokeOneExecutorWithSSOSAML opts into strict local cookie logout
// for the exact SAML profile. Use the same SAML and optional OAuth2 selections
// as c.Sessions and the original synchronizer key set. A local logout never
// initiates an IdP protocol. The optional OAuth2 config is copied.
func NewCookieRevokeOneExecutorWithSSOSAML(pool *database.Pool, c RevokeOneExecutorConfig, keys []session.CSRFKey, selection SSOSAMLSessionAdmission, oauth2 *SSOOAuth2SessionAdmission) (*CookieRevokeOneExecutor, error) {
	peers := enterpriseCookiePeers{saml: &selection}
	if oauth2 != nil {
		peer := *oauth2
		peers.oauth2 = &peer
	}
	return newCookieRevokeOneExecutor(pool, c, keys, peers)
}
