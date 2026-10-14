package session

import identity "github.com/faustbrian/go-identity"

// CredentialContinuationSpec is the original password-change command and its
// independent credential-authority and credential-reference predecessors.
// Scope comes from the complete session. This projection is not authorization,
// a proof, a freshness lease or evidence that the command committed. A native
// adapter must compare all current owners and persist the transition in the
// same password-change transaction. Never derive it from a cache refresh.
type CredentialContinuationSpec struct {
	CommandID                                       identity.CommandID
	BeforeAuthorityVersion, BeforeCredentialVersion uint64
}

// ContinuePasswordSession structurally continues an exact password session over
// one credential successor without renewing authentication, activity, lifetime,
// assurance, remember policy, lookup, session/family versions or CSRF custody.
// The credential-authority dimension alone advances; user authority is distinct
// from the password command's user aggregate version. Both predecessors must
// match exactly and admit uint64 successors. This mapping performs no IO and
// grants no authority. The owning transaction must independently deny expired,
// revoked or otherwise stale rows and preserve every unrelated current owner.
func ContinuePasswordSession(source Session, c CredentialContinuationSpec) (Session, error) {
	spec, err := source.Bindings()
	if err != nil {
		return Session{}, ErrInvalidSession
	}
	a, err := spec.Authority.Bindings()
	if err != nil || a.Credential.Version != c.BeforeAuthorityVersion || source.EffectiveCredentialVersion() != c.BeforeCredentialVersion || !validContinuation(spec, c, false) {
		return Session{}, ErrInvalidSession
	}
	a.Credential.Version++
	spec.Authority, err = NewAuthoritySnapshot(a)
	if err != nil {
		return Session{}, ErrInvalidSession
	}
	return NewContinuedPasswordSession(spec, source.CSRFState(), c)
}

// NewContinuedPasswordSession reconstructs a complete trusted continued record.
// AuthenticationMetadata retains original login provenance, including original
// credential version and proof times. EffectiveCredentialVersion is its separate
// current linkage. Persist CredentialContinuation with Bindings and CSRFState;
// losing it is not equivalent serialization. Only verified password provenance
// is supported here; OTP/anonymous/provider histories are different profiles.
// Reconstruction certifies neither commitment nor current primary authority.
// Zero CSRF means explicitly tokenless; nonzero state must bind this session.
func NewContinuedPasswordSession(spec SessionSpec, csrf CSRFState, c CredentialContinuationSpec) (Session, error) {
	if !validContinuation(spec, c, true) {
		return Session{}, ErrInvalidSession
	}
	s, err := NewSession(spec)
	if err != nil {
		return Session{}, err
	}
	if csrf.state != nil {
		s, err = attachCSRF(s, csrf)
		if err != nil {
			return Session{}, err
		}
	}
	copy := c
	s.state.continuation = &copy
	return s, nil
}

func validContinuation(s SessionSpec, c CredentialContinuationSpec, successor bool) bool {
	_, idErr := identity.ParseCommandID(string(c.CommandID))
	if idErr != nil || c.BeforeAuthorityVersion == 0 || c.BeforeAuthorityVersion == ^uint64(0) || c.BeforeCredentialVersion == 0 || c.BeforeCredentialVersion == ^uint64(0) || s.Authentication.Kind != AuthenticationVerified || s.Authentication.Proof.Method != "password" || s.Authentication.CredentialVersion > c.BeforeCredentialVersion {
		return false
	}
	a, err := s.Authority.Bindings()
	if err != nil {
		return false
	}
	expected := c.BeforeAuthorityVersion
	if successor {
		expected++
	}
	return a.Credential.Version == expected
}

// CredentialContinuation returns an independent scalar trusted-storage
// projection. False means none, including zero session. It grants no current
// authority and must never be used alone to accept a credential.
func (s Session) CredentialContinuation() (CredentialContinuationSpec, bool) {
	if s.state == nil || s.state.continuation == nil {
		return CredentialContinuationSpec{}, false
	}
	return *s.state.continuation, true
}

// EffectiveCredentialVersion is the current credential-reference linkage while
// AuthenticationMetadata retains original login provenance. Zero/anonymous/OTP
// returns zero. This structural version is not current authority evidence.
func (s Session) EffectiveCredentialVersion() uint64 {
	if c, ok := s.CredentialContinuation(); ok {
		return c.BeforeCredentialVersion + 1
	}
	if s.state == nil || s.state.spec.Authentication.Kind != AuthenticationVerified {
		return 0
	}
	return s.state.spec.Authentication.CredentialVersion
}
