package session

import (
	"fmt"
	"io"

	identity "github.com/faustbrian/go-identity"
)

// SSOSAMLIssuanceSpec binds a prospective SAML session to the exact SSO-owned
// linked provider credential and resolved original remember policy. It is not
// proof of a signed assertion, browser possession or current membership.
type SSOSAMLIssuanceSpec SSOOIDCIssuanceSpec

// Format redacts prospective authentication and organization linkage.
func (SSOSAMLIssuanceSpec) Format(s fmt.State, _ rune) {
	io.WriteString(s, "session.SSOSAMLIssuanceSpec(redacted)")
}

// MarshalJSON prevents implicit export of prospective authentication metadata.
func (SSOSAMLIssuanceSpec) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText prevents implicit export, including use as a map key.
func (SSOSAMLIssuanceSpec) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }

// NewSSOSAMLSessionIssuerWithCSRF selects only SP-initiated enterprise SAML
// issuance. The native executor must authenticate and consume the original
// frontchannel correlation, reserve the signed replay set, and fence the
// original linked account and current member/factor authority together with
// the protected session effects. Only a new acknowledged exact commit can
// reveal the normal session cookie and synchronizer. This installs no route.
func NewSSOSAMLSessionIssuerWithCSRF(executor IssueExecutor, config IssuerConfig, key CSRFKey) (*SessionIssuer, error) {
	return newEnterpriseSessionIssuerWithCSRF(executor, config, key, enterpriseSAMLSession)
}

// PrepareSSOSAML freezes a tokenless prospective session bound to the exact
// SAML callback, original pre-auth flow and verified linked credential. It
// performs no assertion, browser, replay or persistence checks of its own.
func (s *SessionIssuer) PrepareSSOSAML(binding identity.CommandBinding, input SSOSAMLIssuanceSpec) (PreparedIssuance, error) {
	return s.prepareEnterpriseSession(binding, input.Session, input.Credential, enterpriseSAMLSession)
}

// BindSSOSAML lends the exact original SAML callback and its frontchannel
// correlation to the native executor. Other protocol commands cannot bind it.
func (s *SessionIssuer) BindSSOSAML(prepared PreparedIssuance, command identity.Command) (PreparedIssuance, error) {
	return s.bindEnterpriseSession(prepared, command, enterpriseSAMLSession)
}

// SSOSAMLCommand exposes the original borrowed SAML callback and prospective
// session only to the selected native caller. Neither is historical recovery
// input or standalone authentication authority.
func (r IssueRequest) SSOSAMLCommand() (identity.Command, Session, bool) {
	return r.enterpriseSessionCommand(enterpriseSAMLSession)
}
