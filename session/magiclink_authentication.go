package session

import (
	"fmt"
	"io"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// MagicLinkAuthenticationSpec is historical, secret-free email-possession
// provenance. CommandID names consumption; RequestCommandID names original
// issuance. CapabilityID and identifier versions name that exact grant and
// verified address. AuthenticatedAt and exclusive ValidUntil retain the original
// consuming admission, not an authoritative validity lease. Complete trusted
// storage must retain this separately from SessionSpec; no token or proof is
// present. Construction cannot certify consumption, identity or factor policy.
type MagicLinkAuthenticationSpec struct {
	CommandID, RequestCommandID            identity.CommandID
	CapabilityID                           string
	IdentifierID                           identity.IdentifierID
	IdentifierVersion, VerificationVersion uint64
	AuthenticatedAt, ValidUntil            time.Time
}

// MagicLinkAuthentication freezes one original grant's historical projection.
// Copies are immutable and concurrency-safe; zero is invalid. Native issuance
// must establish cryptographic provenance, current authority and atomic one-use.
type MagicLinkAuthentication struct{ state *MagicLinkAuthenticationSpec }

// NewMagicLinkAuthentication validates and copies bounded projections without
// IO, proof verification, consumption or clock reads. Command IDs are canonical
// nonzero random128 IDs, identifier IDs use the kernel policy, capability IDs
// are 1..128 visible ASCII bytes, and both versions are positive. Times are
// normalized to UTC without changing instants; expiry must follow authentication.
func NewMagicLinkAuthentication(p MagicLinkAuthenticationSpec) (MagicLinkAuthentication, error) {
	if _, err := identity.ParseCommandID(string(p.CommandID)); err != nil {
		return MagicLinkAuthentication{}, ErrInvalidSession
	}
	if _, err := identity.ParseCommandID(string(p.RequestCommandID)); err != nil {
		return MagicLinkAuthentication{}, ErrInvalidSession
	}
	if _, err := identity.ParseIdentifierID(string(p.IdentifierID)); err != nil {
		return MagicLinkAuthentication{}, ErrInvalidSession
	}
	if p.CommandID == p.RequestCommandID || !authorityKey(p.CapabilityID, 128) || p.IdentifierVersion == 0 || p.VerificationVersion == 0 || !validTime(p.AuthenticatedAt) || !validTime(p.ValidUntil) || !p.ValidUntil.After(p.AuthenticatedAt) {
		return MagicLinkAuthentication{}, ErrInvalidSession
	}
	p.CommandID, p.RequestCommandID = identity.CommandID(strings.Clone(string(p.CommandID))), identity.CommandID(strings.Clone(string(p.RequestCommandID)))
	p.CapabilityID, p.IdentifierID = strings.Clone(p.CapabilityID), identity.IdentifierID(strings.Clone(string(p.IdentifierID)))
	p.AuthenticatedAt, p.ValidUntil = p.AuthenticatedAt.UTC().Round(0), p.ValidUntil.UTC().Round(0)
	return MagicLinkAuthentication{&p}, nil
}

// Bindings returns an owned historical projection, never proof or permission.
// Zero returns redacted ErrInvalidSession. Correlated metadata must not be logged.
func (p MagicLinkAuthentication) Bindings() (MagicLinkAuthenticationSpec, error) {
	if p.state == nil {
		return MagicLinkAuthenticationSpec{}, ErrInvalidSession
	}
	return *p.state, nil
}

// NewSessionWithMagicLink reconstructs complete magic-link session metadata
// without a synchronizer. Kind must be AuthenticationMagicLink; legacy proof
// and credential fields must be zero. Issuance precedes original admission
// expiry, but later session activity uses Remember and never renews provenance.
// Unsupported organization/factor/passkey projections fail closed. This is
// reconstruction only, not authentication or permission to issue a session.
func NewSessionWithMagicLink(s SessionSpec, p MagicLinkAuthentication) (Session, error) {
	if s.Authentication.Kind != AuthenticationMagicLink {
		return Session{}, ErrInvalidSession
	}
	return newSessionWithProvenance(s, OTPAuthentication{}, p)
}

// NewSessionWithMagicLinkAndCSRF retains both complete trusted projections.
// CSRF must bind the exact tenant/session/version; neither value proves current
// authority. No token, transaction, IO or consumption is created here.
func NewSessionWithMagicLinkAndCSRF(s SessionSpec, p MagicLinkAuthentication, c CSRFState) (Session, error) {
	r, err := NewSessionWithMagicLink(s, p)
	if err != nil {
		return Session{}, err
	}
	return attachCSRF(r, c)
}

// MagicLinkAuthentication returns historical metadata only for magic-link
// sessions. Zero/other methods return zero. Store/equality/rotation must retain
// it with Bindings and CSRFState; it is not a reusable authentication proof.
func (s Session) MagicLinkAuthentication() MagicLinkAuthentication {
	if s.state == nil {
		return MagicLinkAuthentication{}
	}
	return s.state.magicLink
}

func magicLinkSpec(s Session) MagicLinkAuthenticationSpec {
	p, _ := s.MagicLinkAuthentication().Bindings()
	return p
}

// Format redacts original command, grant and identifier for every verb.
func (MagicLinkAuthentication) Format(s fmt.State, _ rune) {
	io.WriteString(s, "session.MagicLinkAuthentication(redacted)")
}

// MarshalJSON rejects implicit metadata export; trusted stores use Bindings.
func (MagicLinkAuthentication) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText rejects implicit export and map-key disclosure.
func (MagicLinkAuthentication) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }
