package session

import identity "github.com/faustbrian/go-identity"

// NewEmailVerificationSessionIssuer selects signin after a separately committed
// registration verification. It reuses the email-grant authentication record
// (AuthenticationMagicLink), not a password proof or ordinary magic-link command.
// The native executor must authenticate original signup/browser custody, require
// that exact committed verification, and fence current account, identifier,
// authorization, risk and factor policy while committing the session and audit.
// It must never issue from scanner inspection, replay or unknown verification.
// Configuration/resource bounds match NewMagicLinkSessionIssuer; Authority must
// be nil. The issuer owns no transaction, durable retry state or goroutine.
func NewEmailVerificationSessionIssuer(executor IssueExecutor, c IssuerConfig) (*SessionIssuer, error) {
	s, err := NewMagicLinkSessionIssuer(executor, c)
	if err != nil {
		return nil, err
	}
	s.verification = true
	return s, nil
}

// NewEmailVerificationSessionIssuerWithCSRF also retains the fresh synchronizer
// with the exact new session. Neither token is available before a new error-free
// committed issuance; metadata-only recovery cannot generate or redeliver them.
func NewEmailVerificationSessionIssuerWithCSRF(executor IssueExecutor, c IssuerConfig, key CSRFKey) (*SessionIssuer, error) {
	if key.key.state == nil {
		return nil, ErrInvalidIssuer
	}
	s, err := NewEmailVerificationSessionIssuer(executor, c)
	if err != nil {
		return nil, err
	}
	s.csrfKey = key
	return s, nil
}

// PrepareEmailVerification freezes original post-confirmation email-possession
// provenance before generating fresh token custody. The command is the closed
// identity.email.verification-signin v1 schema, with explicit user and the
// committed confirmation command as RecordID. This binds the parent transition
// independently of the newly allocated session ID. Remember must be recovered
// from the original signup intent, not resolved again. Lookup must be zero,
// versions initial and activity equal to
// issuance. This pure preparation proves no verification or current authority.
// The native owner must bind every session field before BindEmailVerification.
func (s *SessionIssuer) PrepareEmailVerification(b identity.CommandBinding, spec SessionSpec, metadata MagicLinkAuthentication) (PreparedIssuance, error) {
	if s == nil || !s.verification {
		return PreparedIssuance{}, ErrInvalidIssuance
	}
	if _, err := identity.ParseCommandID(b.RecordID); err != nil || b.UserID != spec.UserID || b.RecordID == string(b.CommandID) {
		return PreparedIssuance{}, ErrInvalidIssuance
	}
	p, err := metadata.Bindings()
	if err != nil || b.RecordID == string(p.RequestCommandID) {
		return PreparedIssuance{}, ErrInvalidIssuance
	}
	return s.prepareEmailGrant(b, spec, metadata, emailVerificationSigninOperation())
}

// BindEmailVerification lends the exact prepared session and original signup
// browser cookie only to its selected native executor. Copies share one bind
// and one attempt. Cookie presence is structural, not possession authentication;
// the native owner must validate the original digest and committed email grant.
// Ordinary magic-link, password, OTP and proof routes remain disjoint. Do not
// persist this borrowed input or use it as a restart/recovery credential.
func (s *SessionIssuer) BindEmailVerification(p PreparedIssuance, command identity.Command) (PreparedIssuance, error) {
	if s == nil || !s.verification {
		return PreparedIssuance{}, ErrInvalidIssuance
	}
	return s.bindEmailGrant(p, command, emailVerificationSigninOperation())
}

// EmailVerificationCommand returns the exact native post-verification command
// and tokenless prospective session, without authenticating either. Only the
// explicitly selected native executor may use it; all other profiles deny.
func (r IssueRequest) EmailVerificationCommand() (identity.Command, Session, bool) {
	if r.state == nil || r.state.magicLink == nil || !r.state.magicLink.verification {
		return identity.Command{}, Session{}, false
	}
	p := r.state.magicLink
	return p.command, p.record, true
}

func emailVerificationSigninOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/email", OperationID: "identity.email.verification-signin", SchemaID: "email-verification-signin", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}
