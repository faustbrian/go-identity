package session

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	authentication "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
)

// ErrInvalidSession rejects malformed records without disclosing scope data.
var ErrInvalidSession = errors.New("session: invalid record")

// AuthenticationKind distinguishes completed authentication metadata from
// explicitly unprivileged anonymous state. Zero and unknown values are invalid.
type AuthenticationKind uint8

const (
	// AuthenticationVerified selects completed-authentication metadata only;
	// the discriminator itself proves no authentication.
	AuthenticationVerified AuthenticationKind = iota + 1
	// AuthenticationAnonymous selects explicitly unprivileged anonymous state.
	AuthenticationAnonymous
)

// AuthenticationMetadata preserves original authentication and credential
// linkage for trusted storage. Proof is authentication's caller-owned projection,
// NOT an authority-issued proof. Kind cannot certify successful authentication.
// Verified records require ProofVersion and a credential ID/version. Anonymous
// records require AnonymousAt and every verified field zero; they confer no
// authenticated assurance. The session issuer must independently validate final
// authority-issued proof, every applicable factor/passkey and live authority.
// CredentialVersion is the exact authenticating credential's version; it is not
// a substitute for the snapshot's aggregate credential invalidation dimension.
type AuthenticationMetadata struct {
	Kind              AuthenticationKind
	Proof             authentication.Proof
	ProofVersion      uint64
	CredentialID      string
	CredentialVersion uint64
	AnonymousAt       time.Time
}

// SessionSpec is a complete bounded persistence projection with no raw token.
// Remember must already be resolved; Authority is the sole complete vector.
// Session/family versions must equal that vector's corresponding versions.
// IDs are canonical 1..128 visible ASCII bytes, Audience at most256. Constructors
// do not normalize IDs or derive authority scope keys. The owner must derive
// those keys from these exact IDs and verify them against primary records.
// Times preserve original issuance, accepted activity and authentication. A
// completed proof may precede issuance; issuance must not renew its freshness.
// Reconstruction is not authentication, an active-state check or durable proof.
type SessionSpec struct {
	SessionID, FamilyID      string
	TenantID                 identity.TenantID
	UserID                   identity.UserID
	Audience                 string
	Version, FamilyVersion   uint64
	Remember                 RememberPolicy
	Authority                AuthoritySnapshot
	Lookup                   TokenDigest
	Authentication           AuthenticationMetadata
	IssuedAt, LastActivityAt time.Time
}

// Session owns immutable structural session state, safe to copy concurrently.
// Zero is invalid. NewSession reconstructs trusted storage projections; it does
// not issue a session. An attacker can construct structurally valid projections,
// so neither this value nor Lifetime authorizes credential acceptance. Primary
// adapters own active status, exact scope derivation, proof validation and live
// authority comparisons, including original bounded validity evidence.
type Session struct{ state *sessionState }
type sessionState struct{ spec SessionSpec }

// NewSession validates and freezes a complete record without IO or callbacks.
// Authentication proof expiry is historical metadata here; admission uses the
// issue command's separate temporal check. It rejects activity outside original
// absolute lifetime and mismatched record/family versions, returning only the
// redacted ErrInvalidSession. No token is created, revealed or persisted.
func NewSession(s SessionSpec) (Session, error) {
	if !authorityKey(s.SessionID, 128) || !authorityKey(s.FamilyID, 128) || !authorityKey(string(s.TenantID), 128) || !authorityKey(string(s.UserID), 128) || !authorityKey(s.Audience, 256) || s.Version == 0 || s.FamilyVersion == 0 || s.Lookup.KeyVersion == 0 || s.Lookup.Sum == ([32]byte{}) {
		return Session{}, ErrInvalidSession
	}
	a, err := s.Authority.Bindings()
	if err != nil || a.Session.Version != s.Version || a.SessionFamily.Version != s.FamilyVersion {
		return Session{}, ErrInvalidSession
	}
	switch s.Authentication.Kind {
	case AuthenticationVerified:
		m := s.Authentication
		if m.ProofVersion == 0 || !authorityKey(m.CredentialID, 128) || m.CredentialVersion == 0 || m.AnonymousAt != (time.Time{}) || !validTime(m.Proof.ExpiresAt) {
			return Session{}, ErrInvalidSession
		}
		use := authentication.ProofUse{Tenant: string(s.TenantID), Subject: string(s.UserID), Audience: s.Audience, Purpose: m.Proof.Purpose, Now: m.Proof.IssuedAt}
		proof, err := authentication.NewProof(authentication.ProofSpec(m.Proof))
		if err != nil || proof.Validate(use) != nil {
			return Session{}, ErrInvalidSession
		}
		s.Authentication.Proof = proof
		s.Authentication.CredentialID = strings.Clone(m.CredentialID)
	case AuthenticationAnonymous:
		m := s.Authentication
		if m.Proof != (authentication.Proof{}) || m.ProofVersion != 0 || m.CredentialID != "" || m.CredentialVersion != 0 || !validTime(m.AnonymousAt) || a.Factor.Present || a.Passkey.Present {
			return Session{}, ErrInvalidSession
		}
	default:
		return Session{}, ErrInvalidSession
	}
	if _, err = s.Remember.Evaluate(s.LastActivityAt, s.IssuedAt, s.LastActivityAt, s.Authentication.at()); err != nil {
		return Session{}, ErrInvalidSession
	}
	s.SessionID = strings.Clone(s.SessionID)
	s.FamilyID = strings.Clone(s.FamilyID)
	s.TenantID = identity.TenantID(strings.Clone(string(s.TenantID)))
	s.UserID = identity.UserID(strings.Clone(string(s.UserID)))
	s.Audience = strings.Clone(s.Audience)
	return Session{state: &sessionState{spec: s}}, nil
}

func (m AuthenticationMetadata) at() time.Time {
	if m.Kind == AuthenticationAnonymous {
		return m.AnonymousAt
	}
	return m.Proof.IssuedAt
}

// Bindings returns an owned non-secret scalar projection for trusted adapters.
// Scope and lookup values correlate people/activity; never log them. Returned
// Remember and Authority values retain immutable state, not renewed freshness.
func (s Session) Bindings() (SessionSpec, error) {
	if s.state == nil {
		return SessionSpec{}, ErrInvalidSession
	}
	return s.state.spec, nil
}

// Lifetime evaluates only recorded timestamps and immutable lifetime policy.
// It does not check active status, proof authority, revocation, versions or a
// store; positive output must never be used alone to authenticate a credential.
func (s Session) Lifetime(now time.Time) (Lifetime, error) {
	if s.state == nil {
		return Lifetime{}, ErrInvalidSession
	}
	p := s.state.spec
	return p.Remember.Evaluate(now, p.IssuedAt, p.LastActivityAt, p.Authentication.at())
}

// Format redacts identifiers, metadata and correlated lookup values.
func (s Session) Format(f fmt.State, _ rune) { io.WriteString(f, "session.Session(redacted)") }

// MarshalJSON denies implicit encoding; use explicit trusted Bindings instead.
func (s Session) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText denies implicit encoding and map-key disclosure.
func (s Session) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }
