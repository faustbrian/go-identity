package session

import identity "github.com/faustbrian/go-identity"

// NewPasswordSignupSessionIssuer selects prospective native registration
// issuance without synchronizer custody. Authority must be nil; configuration
// bounds match NewPasswordSessionIssuer. Native registration owns policy-complete
// authentication and the atomic effects described by PrepareSignup. This profile
// enables neither proof issuance nor password signin. It owns no goroutines,
// stores or transactions, and borrows the concurrency-safe bounded executor.
func NewPasswordSignupSessionIssuer(executor IssueExecutor, c IssuerConfig) (*SessionIssuer, error) {
	s, err := NewPasswordSessionIssuer(executor, c)
	if err != nil {
		return nil, err
	}
	s.signup = true
	return s, nil
}

// NewPasswordSignupSessionIssuerWithCSRF selects prospective native registration
// issuance with original synchronizer custody. Authority must be nil; configuration
// bounds match NewPasswordSessionIssuerWithCSRF. Preparation is not authentication.
// The password owner must establish that verification and MFA policy are complete,
// reserve original pre-auth/risk custody and commit registration, password material,
// session and required audit/outbox in the same coordinator transaction. This
// issuer cannot grant that policy admission or persist those effects itself.
func NewPasswordSignupSessionIssuerWithCSRF(executor IssueExecutor, c IssuerConfig, key CSRFKey) (*SessionIssuer, error) {
	if key.key.state == nil {
		return nil, ErrInvalidIssuer
	}
	s, err := NewPasswordSignupSessionIssuer(executor, c)
	if err != nil {
		return nil, err
	}
	s.csrfKey = key
	return s, nil
}

// PrepareSignup freezes prospective single-factor password-session custody for
// the original signup command. Version, activity, authority and remember rules
// match PreparePassword, but this profile is disjoint from signin. The new user
// must be retained separately from anonymous command scope. No IO, authentication
// or flow consumption occurs; never prepare again to recover an unknown result.
// Map the complete Session/CSRF projection into native intent before BindSignup.
func (s *SessionIssuer) PrepareSignup(b identity.CommandBinding, spec SessionSpec) (PreparedIssuance, error) {
	if s == nil || !s.signup {
		return PreparedIssuance{}, ErrInvalidIssuance
	}
	return s.preparePassword(b, spec, passwordSignupOperation(b))
}

// BindSignup retains the exact paired prepared-verifier/pre-auth command under
// one shared bind claim. Invalid input does not claim the preparation. The native
// owner must bind all prepared session fields into keyed intent and admit their
// provenance in its protected transaction; this structural check grants neither
// hash-policy approval nor cookie possession. Copies share one issuance attempt.
// Keep verifier/cookie custody ephemeral; recovery uses separate safe correlation.
func (s *SessionIssuer) BindSignup(p PreparedIssuance, command identity.Command) (PreparedIssuance, error) {
	if s == nil || !s.password || !s.signup || p.state == nil || p.state.owner != s || p.state.password == nil {
		return PreparedIssuance{}, ErrInvalidIssuance
	}
	if p.state.request.state != nil {
		return PreparedIssuance{}, ErrIssuanceAlreadyBound
	}
	f, ok := command.PasswordSignupFeature()
	_, _, custody := command.PasswordSignupCustody()
	if !ok || !custody || f.Binding != p.state.password.binding || f.Operation != passwordSignupOperation(f.Binding) {
		return PreparedIssuance{}, ErrInvalidIssuance
	}
	if !p.state.password.bound.CompareAndSwap(false, true) {
		return PreparedIssuance{}, ErrIssuanceAlreadyBound
	}
	r := IssueRequest{state: &issueRequestState{password: &passwordIssueRequestState{command: command, binding: f.Binding, record: p.state.password.record, signup: true}}}
	return PreparedIssuance{state: &preparedIssuanceState{owner: s, request: r, token: p.state.token, csrf: p.state.csrf, password: p.state.password}}, nil
}

// PasswordSignupCommand lends original paired verifier/pre-auth custody and the
// prospective session only to the configured native executor. Zero, signin, OTP
// and proof variants deny. Success proves no authentication or policy completion.
// Do not persist, log or use this secret-bearing command for outcome recovery.
func (r IssueRequest) PasswordSignupCommand() (identity.Command, Session, bool) {
	if r.state == nil || r.state.password == nil || !r.state.password.signup {
		return identity.Command{}, Session{}, false
	}
	return r.state.password.command, r.state.password.record, true
}

func passwordSignupOperation(b identity.CommandBinding) identity.FeatureOperation {
	op := passwordSigninOperation(b)
	op.OperationID, op.SchemaID = "identity.password.signup", "password-signup"
	return op
}
