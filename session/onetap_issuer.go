package session

import identity "github.com/faustbrian/go-identity"

// NewOneTapSessionIssuerWithCSRF selects existing-account Google One Tap
// cookie issuance. The synchronous native executor authenticates the original
// provider and browser, and atomically commits the one-use capability, browser,
// session and required audit/lifecycle effects. Authority must be nil: this
// issuer does not create an authenticated proof. It exposes no cookie or CSRF
// token before an exact new committed result and owns no durable resources.
func NewOneTapSessionIssuerWithCSRF(executor IssueExecutor, config IssuerConfig, key CSRFKey) (*SessionIssuer, error) {
	if key.key.state == nil {
		return nil, ErrInvalidIssuer
	}
	issuer, err := newOAuthSessionIssuer(executor, config, oneTapIssuance)
	if err != nil {
		return nil, err
	}
	issuer.csrfKey = key
	return issuer, nil
}

// PrepareOneTap freezes a prospective single-factor provider session. It
// requires the exact anonymous One Tap callback and original flow ID, never
// ordinary OAuth, and performs no durable admission or provider verification.
func (s *SessionIssuer) PrepareOneTap(binding identity.CommandBinding, spec SessionSpec) (PreparedIssuance, error) {
	return s.prepareOAuth(binding, spec, oneTapIssuance)
}

// BindOneTap lends the exact callback command and its original pre-auth
// credential to the native executor. It cannot be used for recovery, and the
// command's cookie syntax proves no possession by itself.
func (s *SessionIssuer) BindOneTap(prepared PreparedIssuance, command identity.Command) (PreparedIssuance, error) {
	return s.bindOAuth(prepared, command, oneTapIssuance)
}

// OneTapCommand returns the borrowed native One Tap callback and prospective
// session without disclosing its bearer. Ordinary auth-code OAuth and all
// other issuance variants return false. This is not active authority.
func (r IssueRequest) OneTapCommand() (identity.Command, Session, bool) {
	return r.oauthCommand(oneTapIssuance)
}
