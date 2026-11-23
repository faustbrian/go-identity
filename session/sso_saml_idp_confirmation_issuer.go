package session

import identity "github.com/faustbrian/go-identity"

// NewSSOSAMLIDPConfirmationSessionIssuerWithCSRF selects only unsolicited SAML
// confirmation for an already linked user. The native executor must validate
// explicit same-browser intent, the exact original assertion and current
// authorities, then commit confirmation, replay and session effects together.
// Only an acknowledged new commit may disclose the normal session and CSRF.
// This selects no route, SP flow or persistent store by itself.
func NewSSOSAMLIDPConfirmationSessionIssuerWithCSRF(executor IssueExecutor, config IssuerConfig, key CSRFKey) (*SessionIssuer, error) {
	return newEnterpriseSessionIssuerWithCSRF(executor, config, key, enterpriseSAMLIDPConfirmationSession)
}

// PrepareSSOSAMLIDPConfirmation freezes the prospective tokenless session for
// the exact pending record and the verified linked user observed by the native
// owner. RecordID is the original arrival command, distinct from the completion
// command. The session retains the standard SAML method and original remember
// choice. Preparation neither checks possession nor establishes authority.
func (s *SessionIssuer) PrepareSSOSAMLIDPConfirmation(binding identity.CommandBinding, input SSOSAMLIssuanceSpec) (PreparedIssuance, error) {
	return s.prepareEnterpriseSession(binding, input.Session, input.Credential, enterpriseSAMLIDPConfirmationSession)
}

// BindSSOSAMLIDPConfirmation lends only the original paired cookie and form
// custody from the exact user-targeted command. It accepts neither SP pre-auth
// nor a plain structural projection. Copies share one binding and attempt.
func (s *SessionIssuer) BindSSOSAMLIDPConfirmation(prepared PreparedIssuance, command identity.Command) (PreparedIssuance, error) {
	return s.bindEnterpriseSession(prepared, command, enterpriseSAMLIDPConfirmationSession)
}

// SSOSAMLIDPConfirmationCommand lends the original confirmation command and
// prepared session during the selected native invocation. They are not proof
// of possession, historical recovery input or usable session credentials.
func (r IssueRequest) SSOSAMLIDPConfirmationCommand() (identity.Command, Session, bool) {
	return r.enterpriseSessionCommand(enterpriseSAMLIDPConfirmationSession)
}
