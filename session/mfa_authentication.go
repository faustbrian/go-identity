package session

import (
	"fmt"
	"io"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// MFAAuthenticationSpec is historical, secret-free second-factor provenance.
// CommandID names completion, PrimaryCommandID the original primary admission,
// and ContinuationID/ScopeDigest the unchanged one-use child. ContinuationVersion
// is the version before completion. This initial native profile supports TOTP;
// it never treats a passkey sign-in as an enrolled factor. Remember is the exact
// original resolved policy, not a new default. VerifiedAt is factor time, never
// the session's primary-authentication freshness origin. ValidUntil is the
// original continuation expiry, not a positive-authority lease or session expiry.
// Filling these fields does not certify authentication or committed effects.
type MFAAuthenticationSpec struct {
	CommandID, PrimaryCommandID, ContinuationID identity.CommandID
	ContinuationScopeDigest                     [32]byte
	Method, FactorID                            string
	EnrollmentVersion, FactorAuthorityVersion   uint64
	ContinuationVersion                         uint64
	Remember                                    RememberPolicySpec
	VerifiedAt, ValidUntil                      time.Time
}

// MFAAuthentication freezes historical completion metadata. Zero is invalid;
// copies are immutable and concurrency-safe. Native issuance must independently
// authenticate the original primary, child and factor and commit their effects.
type MFAAuthentication struct{ state *MFAAuthenticationSpec }

// NewMFAAuthentication validates and copies bounded metadata without IO, clock
// reads or proof creation. All IDs are canonical random128 identities, versions
// positive and residual continuation lifetime at most five minutes. Rebuilding
// historical state does not recheck current authority or renew authentication.
func NewMFAAuthentication(p MFAAuthenticationSpec) (MFAAuthentication, error) {
	for _, id := range []identity.CommandID{p.CommandID, p.PrimaryCommandID, p.ContinuationID, identity.CommandID(p.FactorID)} {
		if _, err := identity.ParseCommandID(string(id)); err != nil {
			return MFAAuthentication{}, ErrInvalidSession
		}
	}
	if p.CommandID == p.PrimaryCommandID || p.CommandID == p.ContinuationID || p.PrimaryCommandID == p.ContinuationID || p.ContinuationScopeDigest == ([32]byte{}) || p.Method != "totp" || p.EnrollmentVersion == 0 || p.FactorAuthorityVersion == 0 || p.ContinuationVersion == 0 || !validTime(p.VerifiedAt) || !validTime(p.ValidUntil) || !p.ValidUntil.After(p.VerifiedAt) || p.ValidUntil.Sub(p.VerifiedAt) > 5*time.Minute {
		return MFAAuthentication{}, ErrInvalidSession
	}
	if _, err := NewRememberPolicy(p.Remember); err != nil {
		return MFAAuthentication{}, ErrInvalidSession
	}
	p.CommandID = identity.CommandID(strings.Clone(string(p.CommandID)))
	p.PrimaryCommandID = identity.CommandID(strings.Clone(string(p.PrimaryCommandID)))
	p.ContinuationID = identity.CommandID(strings.Clone(string(p.ContinuationID)))
	p.Method, p.FactorID = strings.Clone(p.Method), strings.Clone(p.FactorID)
	p.VerifiedAt, p.ValidUntil = p.VerifiedAt.UTC().Round(0), p.ValidUntil.UTC().Round(0)
	return MFAAuthentication{state: &p}, nil
}

// Bindings returns owned historical metadata, not proof or issuance permission.
func (m MFAAuthentication) Bindings() (MFAAuthenticationSpec, error) {
	if m.state == nil {
		return MFAAuthenticationSpec{}, ErrInvalidSession
	}
	return *m.state, nil
}

// NewSessionWithMagicLinkMFA reconstructs complete primary and factor metadata.
// Original primary time controls freshness; MFA cannot substitute its admission
// or upgrade Remember. Factor authority is required and must match this exact
// generation. Organization/passkey variants are not supported by this profile.
// This structural constructor grants no authentication or storage authority.
func NewSessionWithMagicLinkMFA(s SessionSpec, primary MagicLinkAuthentication, factor MFAAuthentication) (Session, error) {
	if primary.state == nil || factor.state == nil || s.Authentication.Kind != AuthenticationMagicLink {
		return Session{}, ErrInvalidSession
	}
	return newSessionWithMFA(s, OTPAuthentication{}, primary, factor)
}

// NewSessionWithMagicLinkMFAAndCSRF preserves all three trusted projections.
// Synchronizer state must bind the exact tenant/session/version. No token,
// transaction, factor verification or authority refresh occurs here.
func NewSessionWithMagicLinkMFAAndCSRF(s SessionSpec, primary MagicLinkAuthentication, factor MFAAuthentication, csrf CSRFState) (Session, error) {
	r, err := NewSessionWithMagicLinkMFA(s, primary, factor)
	if err != nil {
		return Session{}, err
	}
	return attachCSRF(r, csrf)
}

// MFAAuthentication returns historical factor metadata, never current proof.
// Complete stores, cache, equality, update and rotation must retain it together
// with the original primary provenance. Zero and single-factor sessions deny.
func (s Session) MFAAuthentication() MFAAuthentication {
	if s.state == nil {
		return MFAAuthentication{}
	}
	return s.state.mfa
}

func mfaSpec(s Session) MFAAuthenticationSpec {
	p, _ := s.MFAAuthentication().Bindings()
	return p
}

// Format redacts correlated factor and continuation metadata for every verb.
func (MFAAuthentication) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "session.MFAAuthentication(redacted)")
}

// MarshalJSON rejects implicit metadata export; trusted stores use Bindings.
func (MFAAuthentication) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText rejects implicit export and map-key disclosure.
func (MFAAuthentication) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }
