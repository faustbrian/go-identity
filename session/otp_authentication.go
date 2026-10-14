package session

import (
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
)

// OTPAuthenticationSpec is historical, non-secret authentication provenance for
// trusted storage. CommandID is the consuming signin, SendCommandID its original
// delivery, and AttemptID the original server-issued random128 attempt. The
// identifier must be the exact verified email or phone used by that challenge.
// Versions name those original records, not current eligibility. AuthenticatedAt
// and ValidUntil retain the original successful check and exclusive continuation
// expiry; neither is an authoritative validity lease. Persist this together with
// the complete SessionSpec. It contains no code, bearer, proof or replay grant.
type OTPAuthenticationSpec struct {
	CommandID, SendCommandID               identity.CommandID
	ChallengeID, AttemptID                 string
	IdentifierID                           identity.IdentifierID
	IdentifierKind                         identity.IdentifierKind
	IdentifierVersion, VerificationVersion uint64
	AuthenticatedAt, ValidUntil            time.Time
}

// OTPAuthentication freezes historical OTP metadata. Copies are concurrency-safe.
// Construction is not authentication, consumption, current authority or permission
// to issue a session. The native issuer must establish those in one transaction.
type OTPAuthentication struct{ state *OTPAuthenticationSpec }

// NewOTPAuthentication validates and copies a trusted projection without IO.
// IDs are bounded before parsing; challenge IDs retain up to256 UTF-8 bytes with
// no control runes. Command and attempt IDs are canonical nonzero random128 IDs.
// Only email/phone possession is supported; other methods must use their owner.
func NewOTPAuthentication(p OTPAuthenticationSpec) (OTPAuthentication, error) {
	if _, e := identity.ParseCommandID(string(p.CommandID)); e != nil {
		return OTPAuthentication{}, ErrInvalidSession
	}
	if _, e := identity.ParseCommandID(string(p.SendCommandID)); e != nil {
		return OTPAuthentication{}, ErrInvalidSession
	}
	if _, e := identity.ParseCommandID(p.AttemptID); e != nil {
		return OTPAuthentication{}, ErrInvalidSession
	}
	if _, e := identity.ParseIdentifierID(string(p.IdentifierID)); e != nil {
		return OTPAuthentication{}, ErrInvalidSession
	}
	if p.CommandID == p.SendCommandID || len(p.ChallengeID) == 0 || len(p.ChallengeID) > 256 || !utf8.ValidString(p.ChallengeID) ||
		(p.IdentifierKind != identity.IdentifierEmail && p.IdentifierKind != identity.IdentifierPhone) || p.IdentifierVersion == 0 || p.VerificationVersion == 0 ||
		!validTime(p.AuthenticatedAt) || !validTime(p.ValidUntil) || !p.ValidUntil.After(p.AuthenticatedAt) {
		return OTPAuthentication{}, ErrInvalidSession
	}
	for _, r := range p.ChallengeID {
		if unicode.IsControl(r) {
			return OTPAuthentication{}, ErrInvalidSession
		}
	}
	p.CommandID = identity.CommandID(strings.Clone(string(p.CommandID)))
	p.SendCommandID = identity.CommandID(strings.Clone(string(p.SendCommandID)))
	p.ChallengeID, p.AttemptID = strings.Clone(p.ChallengeID), strings.Clone(p.AttemptID)
	p.IdentifierID = identity.IdentifierID(strings.Clone(string(p.IdentifierID)))
	p.IdentifierKind = identity.IdentifierKind(strings.Clone(string(p.IdentifierKind)))
	p.AuthenticatedAt, p.ValidUntil = p.AuthenticatedAt.UTC().Round(0), p.ValidUntil.UTC().Round(0)
	return OTPAuthentication{&p}, nil
}

// Bindings returns a caller-owned historical projection. Zero returns only the
// redacted ErrInvalidSession. Correlated metadata must never enter logs.
func (p OTPAuthentication) Bindings() (OTPAuthenticationSpec, error) {
	if p.state == nil {
		return OTPAuthenticationSpec{}, ErrInvalidSession
	}
	return *p.state, nil
}

// NewSessionWithOTP reconstructs an OTP record with no synchronizer state.
// Authentication.Kind must be AuthenticationOTP and all legacy proof/credential
// fields zero. Issuance must precede original continuation expiry; later session
// activity is governed by Remember, never by renewing authentication. Factor,
// passkey and organization profiles currently fail closed, not silently omitted.
// This structural constructor grants no issuance or current acceptance authority.
func NewSessionWithOTP(spec SessionSpec, metadata OTPAuthentication) (Session, error) {
	if spec.Authentication.Kind != AuthenticationOTP {
		return Session{}, ErrInvalidSession
	}
	return newSession(spec, metadata)
}

// NewSessionWithOTPAndCSRF retains both explicit storage projections. The CSRF
// state must bind the exact tenant/session/version. Neither projection alone
// proves current authority; no code, token or transaction is created here.
func NewSessionWithOTPAndCSRF(spec SessionSpec, metadata OTPAuthentication, state CSRFState) (Session, error) {
	s, e := NewSessionWithOTP(spec, metadata)
	if e != nil {
		return Session{}, e
	}
	return attachCSRF(s, state)
}

// OTPAuthentication returns historical provenance; non-OTP and zero sessions
// return zero. Complete storage/equality must retain it together with Bindings
// and CSRFState. It is never a reusable proof or authority refresh.
func (s Session) OTPAuthentication() OTPAuthentication {
	if s.state == nil {
		return OTPAuthentication{}
	}
	return s.state.otp
}

func otpSpec(s Session) OTPAuthenticationSpec {
	p, _ := s.OTPAuthentication().Bindings()
	return p
}

func (s Session) authenticatedAt() time.Time {
	if s.state.magicLink.state != nil {
		return s.state.magicLink.state.AuthenticatedAt
	}
	if s.state.otp.state != nil {
		return s.state.otp.state.AuthenticatedAt
	}
	return s.state.spec.Authentication.at()
}

// rebuildSession retains method provenance while the caller explicitly selects
// synchronizer state. Version changes must never copy an obsolete CSRF binding.
func rebuildSession(spec SessionSpec, source Session, csrf CSRFState) (Session, error) {
	if c, ok := source.CredentialContinuation(); ok {
		return NewContinuedPasswordSession(spec, csrf, c)
	}
	s, e := newSessionWithMFA(spec, source.OTPAuthentication(), source.MagicLinkAuthentication(), source.MFAAuthentication())
	if e != nil {
		return Session{}, e
	}
	if csrf.state != nil {
		return attachCSRF(s, csrf)
	}
	return s, nil
}

// Format redacts correlated authentication metadata for every verb.
func (OTPAuthentication) Format(s fmt.State, _ rune) {
	io.WriteString(s, "session.OTPAuthentication(redacted)")
}

// MarshalJSON denies implicit export; trusted stores use explicit Bindings.
func (OTPAuthentication) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText denies implicit export and map-key disclosure.
func (OTPAuthentication) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }
