package postgres

import (
	"fmt"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

// SessionAdmissionConfig explicitly enables native original authenticated-
// session admission. Store borrows the original primary transaction; Profile
// selects the actual credential owner/method and audience. RetainedTokenKeys
// are copied, versioned 32..64-byte nonzero keys. FreshnessLimit is an explicit
// operation-policy cap, positive and at most24h; original remember freshness
// and lifetime remain additional earlier caps. No retry can renew either.
// Ordinary OTP selects the session owner's single-factor profile. The explicit
// native MFA active-action owner may preserve password/MFA provenance, provided
// that owner fences the actual original factor inside the same protected Work.
// Organization/passkey variants remain unsupported.
// Construction is bounded, performs no IO and proves no authentication/Allow.
type SessionAdmissionConfig struct {
	Store             sessionpg.Config
	Profile           sessionpg.IdentifierAdmissionConfig
	RetainedTokenKeys map[uint32][]byte
	FreshnessLimit    time.Duration
}

// NewContributorWithSession opts into native authenticated-session OTP without
// changing the existing ContributorConfig shape or NewContributor behavior.
// Base retains codec, deployment, namespace and lockout semantics. PreAuth and
// its keys may both be absent for session-only composition, or both installed
// to enable the distinct pre-auth profile too. Configuration is copied without
// IO; invalid profiles return nil and redacted ErrInvalidConfiguration.
// Session rows are never reserved/consumed; only OTP is one-time. Register the
// exact returned pointer with the existing coordinator and actual owner effects.
func NewContributorWithSession(base ContributorConfig, profile SessionAdmissionConfig) (*Contributor, error) {
	return newContributor(base, &profile)
}

// Format hides correlated profile and key material.
func (SessionAdmissionConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.SessionAdmissionConfig(redacted)"))
}

// MarshalJSON rejects secret configuration export.
func (SessionAdmissionConfig) MarshalJSON() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}

// MarshalText rejects secret configuration export.
func (SessionAdmissionConfig) MarshalText() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}

type sessionAdmissionProfile struct {
	store     sessionpg.Config
	profile   sessionpg.IdentifierAdmissionConfig
	keys      map[uint32]session.DigestKey
	freshness time.Duration
}

func newSessionAdmissionProfile(c *SessionAdmissionConfig, global, namespace string) (*sessionAdmissionProfile, error) {
	if c == nil {
		return nil, nil
	}
	if c.Profile.Validate() != nil || c.Profile.GlobalAuthorityID != global || c.Profile.PolicyNamespace != namespace || c.Profile.CredentialKind == identity.CredentialPasskey || c.FreshnessLimit <= 0 || c.FreshnessLimit > 24*time.Hour {
		return nil, ErrInvalidConfiguration
	}
	// Both profiles use the same session-owned bounded versioned lookup keys;
	// digest domains remain distinct in their actual token derivation.
	keys, err := newPreAuthProfile(c.Store, c.RetainedTokenKeys)
	if err != nil {
		return nil, err
	}
	profile := c.Profile
	profile.GlobalAuthorityID, profile.PolicyNamespace = strings.Clone(global), strings.Clone(namespace)
	profile.Audience, profile.AuthenticationMethod, profile.CredentialOwner = strings.Clone(profile.Audience), strings.Clone(profile.AuthenticationMethod), strings.Clone(profile.CredentialOwner)
	return &sessionAdmissionProfile{store: c.Store, profile: profile, keys: keys.keys, freshness: c.FreshnessLimit}, nil
}

func (p *Contributor) sessionAuthority(original session.Session, binding identity.CommandBinding, expected AttemptAuthority) error {
	if p == nil || p.session == nil {
		return ErrInvalidCommand
	}
	d, c, a, err := p.originalSessionAdmission(original, binding)
	if err != nil || expected.Directory != d || expected.Credential != c.Credential || expected.UserAuthorization != a || expected.UserAuthorityVersion != c.UserAuthorityVersion || expected.IdentifierAuthorityVersion != c.IdentifierAuthorityVersion || expected.CredentialAuthorityVersion != c.CredentialAuthorityVersion {
		return ErrInvalidCommand
	}
	return nil
}

// The explicit active-MFA profile may preserve a completed password/MFA
// session's original primary expectations. This does not omit its factor:
// native MFA must fence the exact original method/enrollment/account epoch in
// its own Work before OTP effect/consumption. Ordinary OTP/enrollment profiles
// retain their strict single-factor derivation and cannot select this arm.
func (p *Contributor) originalSessionAdmission(original session.Session, b identity.CommandBinding) (kernel.DirectoryAuthorityAdmission, kernel.CredentialAdmission, kernel.UserAuthorizationAdmission, error) {
	if p == nil || p.session == nil {
		return kernel.DirectoryAuthorityAdmission{}, kernel.CredentialAdmission{}, kernel.UserAuthorizationAdmission{}, ErrInvalidCommand
	}
	active := b.SchemaVersion == 1 && (b.OperationID == "identity.mfa.otp-send" && b.SchemaID == "mfa-otp-step-up-send" || b.OperationID == "identity.mfa.otp-verify" && b.SchemaID == "mfa-otp-step-up")
	if active && original.MFAAuthentication() != (session.MFAAuthentication{}) {
		return sessionpg.OriginalMFAPasswordSessionAdmission(p.session.profile, original, b)
	}
	return sessionpg.OriginalSessionAdmission(p.session.profile, original, b)
}

func (p *Contributor) sessionTime(original session.Session, now time.Time) error {
	if p == nil || p.session == nil {
		return ErrInvalidCommand
	}
	s, err := original.Bindings()
	if err != nil {
		return ErrInvalidCommand
	}
	lifetime, err := original.Lifetime(now)
	if err != nil || !lifetime.Fresh || !now.Before(s.Authentication.Proof.IssuedAt.Add(p.session.freshness)) {
		return ErrInvalidCommand
	}
	return nil
}
