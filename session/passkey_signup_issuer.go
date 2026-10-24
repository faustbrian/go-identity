package session

import (
	"time"

	identity "github.com/faustbrian/go-identity"
)

// NewPasskeySignupSessionIssuer explicitly selects prospective passkey-only
// signup, not existing-account assertion issuance. Authority must be nil. The
// owned native executor must verify real WebAuthn, admit original pre-auth/risk,
// and commit account/credential/known-empty factor/policy/session effects and
// required lifecycles in the original transaction. Preparation grants none of
// those permissions. Borrowed dependencies retain IssuerConfig's bounded,
// concurrency-safe lifetime; construction performs no IO or background work.
func NewPasskeySignupSessionIssuer(executor IssueExecutor, c IssuerConfig) (*SessionIssuer, error) {
	s, err := NewPasskeySessionIssuer(executor, c)
	if err != nil {
		return nil, err
	}
	s.passkeySignup = true
	return s, nil
}

// NewPasskeySignupSessionIssuerWithCSRF retains the original synchronizer token
// until acknowledged new commit. Replay/unknown/recovery cannot reveal either
// credential; the native executor must persist the full original CSRF state.
func NewPasskeySignupSessionIssuerWithCSRF(executor IssueExecutor, c IssuerConfig, key CSRFKey) (*SessionIssuer, error) {
	if key.key.state == nil {
		return nil, ErrInvalidIssuer
	}
	s, err := NewPasskeySignupSessionIssuer(executor, c)
	if err != nil {
		return nil, err
	}
	s.csrfKey = key
	return s, nil
}

func passkeySignupOperation() identity.FeatureOperation {
	const id = "identity.passkey.register-verify"
	return identity.FeatureOperation{Owner: "passkey", OperationID: id, SchemaID: id + ".signup-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}

// PreparePasskeySignup freezes an initial prospective session and private token
// for the original anonymous signup command. RecordID names its new credential,
// not the separately allocated session. No durable user, authentication or
// authority is inferred. Initial account/credential/policy/factor/passkey epochs
// are one; original observed deployment epochs, remember and proof expiry stay
// unchanged. Map the complete session into native intent before binding once.
func (s *SessionIssuer) PreparePasskeySignup(b identity.CommandBinding, spec SessionSpec) (PreparedIssuance, error) {
	return s.preparePasskey(b, spec, true)
}

// BindPasskeySignup seals the exact original signup command under the shared
// one-bind claim. Native execution must compare the entire prepared session and
// actual opaque registration, not trust structural intent as authentication.
// Other issuance profiles deny. Recovery uses separate native metadata custody;
// this preparation never grants a right to execute again or reveal again.
func (s *SessionIssuer) BindPasskeySignup(p PreparedIssuance, c identity.Command) (PreparedIssuance, error) {
	return s.bindPasskey(p, c, true)
}

// PasskeySignupCommand lends only the original native anonymous signup command
// and prospective tokenless session to its configured durable executor. It is
// neither an assertion nor authenticated proof, current authority or signup
// permission. The native owner must establish all real cryptographic and
// transactional admission before returning a new committed result.
func (r IssueRequest) PasskeySignupCommand() (identity.Command, Session, bool) {
	if r.state == nil || r.state.passkey == nil || !r.state.passkey.signup {
		return identity.Command{}, Session{}, false
	}
	return r.state.passkey.command, r.state.passkey.record, true
}

func validatePasskeySignupIssuanceAt(record Session, now time.Time) error {
	if err := validatePasskeyIssuanceAt(record, now); err != nil {
		return err
	}
	s, _ := record.Bindings()
	v, _ := s.Authority.Bindings()
	_, continued := record.CredentialContinuation()
	if continued || s.Authentication.CredentialVersion != 1 || v.User.Version != 1 || v.Identifier.Version != 1 || v.Credential.Version != 1 || v.Authorization.Version != 1 || v.Factor.Binding.Version != 1 || v.Passkey.Binding.Version != 1 {
		return ErrInvalidIssuance
	}
	return nil
}
