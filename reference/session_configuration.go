package reference

import (
	"crypto/subtle"
	"fmt"
	"io"

	identity "github.com/faustbrian/go-identity"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

// SessionConfiguration selects native primary reads and self
// signout, without HTTP. Native freezes the authority profile, lookup keys,
// clock, policy and transaction bounds. Validation.Clock must be absent so the
// graph supplies Execution.Clock to both reading and mutation. CSRFKeys selects
// cookie signout; an empty slice disables it, never enables legacy cookie
// mutation. Bearer signout has no cookie fallback. Resources/callbacks remain
// borrowed, bounded and concurrent-safe. Construction performs no IO.
// The explicit verified profile remains selected; configured OTP and magic-link
// consuming issuers add their own native profiles to both read and revoke paths.
// Selected MagicLink.TOTP additionally composes current confirmed factor
// authority into both paths; MFA never falls back to a single-factor profile.
// Every selected issuer must use the same store, deployment, policy namespace,
// audience and cookie policy, with readable lookup and optional signout CSRF keys.
type SessionConfiguration struct {
	Native   sessionpg.SignOutServiceConfig
	CSRFKeys []session.CSRFKey
}

type sessionState struct {
	reader *session.SessionService
	bearer *session.SignOutService
	cookie *session.CookieSignOutService
	revoke *sessionpg.RevokeOneExecutor
	config sessionpg.SignOutServiceConfig
}

func composeSession(c StoreConfiguration, d ReferenceDependencies) (*sessionState, error) {
	if c.Session == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_session"}
	if c.OTP == nil || c.OTP.Signin == nil || d.PostgreSQL == nil {
		return nil, invalid
	}
	n, o := c.Session.Native, c.OTP
	e := n.Execution
	if n.Validation.Clock != nil || e.Profile.GlobalAuthorityID != o.Store.GlobalAuthorityID || e.Profile.PolicyNamespace != o.Store.UserPolicyNamespace || e.Repository.Schema != o.Signin.Session.Schema || e.Repository.MaximumDuration > o.Timeout || e.Coordinator.MaximumDuration > o.Timeout || n.MaximumDuration > o.Timeout || e.PolicyVersion != o.RequestKeys.Policy.PolicyVersion || !sameServerAuthorization(e.Authorization, o.RequestKeys.Policy.Authorization) {
		return nil, invalid
	}
	selection, err := sessionAdmissionSelection(c)
	if err != nil {
		return nil, invalid
	}
	validation := n.Validation
	validation.Clock = e.Clock
	var mfa *sessionpg.MagicLinkAdmissionConfig
	var passwordMFA *sessionpg.IdentifierAdmissionConfig
	if c.MagicLink != nil && c.MagicLink.TOTP != nil {
		if selection.MagicLink == nil || c.MagicLink.Consume == nil || c.MagicLink.Consume.MFA == nil || !c.MagicLink.Request.MFAContinuation {
			return nil, invalid
		}
		profile := *selection.MagicLink
		mfa = &profile
	}
	if c.PasswordSignin != nil && (c.PasswordSignin.TOTP != nil || c.PasswordSignin.Recovery != nil || c.PasswordSignin.OTP != nil) {
		if c.PasswordSignin.MFA == nil || selection.Verified == nil {
			return nil, invalid
		}
		profile := c.PasswordSignin.Native.Profile
		if profile != *selection.Verified {
			return nil, invalid
		}
		passwordMFA = &profile
	}
	reader, err := sessionpg.NewSelectedSessionService(d.PostgreSQL, sessionpg.SelectedSessionServiceConfig{Repository: e.Repository, Admission: sessionpg.SelectedSessionAdmissionConfig{SingleFactor: selection, MFAMagicLink: mfa, MFAPassword: passwordMFA}, Validation: validation})
	if err != nil {
		return nil, invalid
	}
	execution := sessionpg.RevokeOneExecutorConfig{Execution: e, Sessions: reader, Admission: &selection, MFAMagicLink: mfa, MFAPassword: passwordMFA}
	revoke, err := sessionpg.NewRevokeOneExecutor(d.PostgreSQL, execution)
	if err != nil {
		return nil, invalid
	}
	policy := session.SignOutConfig{Cookie: n.Cookie, PolicyID: e.PolicyID, PolicyVersion: e.PolicyVersion, MaximumDuration: n.MaximumDuration}
	bearer, err := session.NewSignOutService(reader, revoke, policy)
	if err != nil {
		return nil, invalid
	}
	state := &sessionState{reader: reader, bearer: bearer, revoke: revoke, config: n}
	if len(c.Session.CSRFKeys) > 0 {
		executor, err := sessionpg.NewCookieRevokeOneExecutor(d.PostgreSQL, execution, c.Session.CSRFKeys)
		if err != nil {
			return nil, invalid
		}
		base, err := session.NewSignOutService(reader, executor, policy)
		if err != nil {
			return nil, invalid
		}
		state.cookie, err = session.NewCookieSignOutService(base, c.Session.CSRFKeys)
		if err != nil {
			return nil, invalid
		}
	}
	// Runtime services own frozen configuration. Retain only the cookie and
	// duration needed by transport, never another caller-owned key/policy graph.
	state.config = sessionpg.SignOutServiceConfig{Cookie: n.Cookie, MaximumDuration: n.MaximumDuration}
	return state, nil
}

// Derive one explicit selection from actual consuming issuers. A request-only
// feature cannot enable authentication. Never try a second reader after denial,
// or give the revoker a broader method set than its primary reader.
func sessionAdmissionSelection(c StoreConfiguration) (sessionpg.SingleFactorSessionAdmissionConfig, error) {
	invalid := identity.InvalidInputError{Field: "reference_session"}
	deny := func() (sessionpg.SingleFactorSessionAdmissionConfig, error) {
		return sessionpg.SingleFactorSessionAdmissionConfig{}, invalid
	}
	if c.Session == nil || c.OTP == nil || c.OTP.Signin == nil {
		return deny()
	}
	n, e := *c.Session, c.Session.Native.Execution
	verified := sessionpg.IdentifierAdmissionConfig(e.Profile)
	common := sessionpg.OTPAdmissionConfig{GlobalAuthorityID: verified.GlobalAuthorityID, PolicyNamespace: verified.PolicyNamespace, Audience: verified.Audience}
	otp := c.OTP.Signin
	if otp.Profile != common || otp.Session != e.Repository || !sessionIssuanceMatches(n, otp.Issuer, otp.CSRFKey) {
		return deny()
	}
	selected := sessionpg.SingleFactorSessionAdmissionConfig{Verified: &verified, OTP: &common}
	if c.PasswordSignin != nil {
		p := c.PasswordSignin.Native
		if p.Profile != verified || p.Session != e.Repository || !sessionIssuanceMatches(n, p.Issuance, p.CSRFKey) {
			return deny()
		}
	}
	if m := c.MagicLink; m != nil && m.Consume != nil {
		profile := sessionpg.MagicLinkAdmissionConfig{GlobalAuthorityID: m.Request.GlobalAuthorityID, PolicyNamespace: m.Consume.PolicyNamespace, Audience: m.Request.Issuer.Audience}
		if sessionpg.OTPAdmissionConfig(profile) != common || m.Request.Session != e.Repository || !sessionIssuanceMatches(n, m.Consume.Issuer, m.Consume.CSRF) {
			return deny()
		}
		selected.MagicLink = &profile
	}
	return selected, nil
}

func sessionIssuanceMatches(n SessionConfiguration, issuer session.IssuerConfig, csrf session.CSRFKey) bool {
	selected, err := n.Native.Cookie.DeletionAttributes()
	issued, issueErr := issuer.Cookie.DeletionAttributes()
	return err == nil && issueErr == nil && selected.String() == issued.String() && sessionKeysMatch(n, issuer.LookupKey, csrf)
}

// Compare opaque keys through their owned domain-separated digest APIs, not
// pointer identity or exposed material. This fixed public probe is neither an
// issued credential nor persisted state. Retained rotation keys may be added,
// but the current issuer's exact version/material must remain readable.
func sessionIssuerKeysMatch(n SessionConfiguration, p passwordpg.SigninConfig) bool {
	return sessionKeysMatch(n, p.Issuance.LookupKey, p.CSRFKey)
}

func sessionKeysMatch(n SessionConfiguration, lookup session.DigestKey, csrfKey session.CSRFKey) bool {
	const probe = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"
	token, err := session.ParseToken(probe)
	if err != nil {
		return false
	}
	expected, err := token.Digest(lookup, "reference-key-profile")
	if err != nil {
		return false
	}
	matched := false
	for _, key := range n.Native.Validation.LookupKeys {
		actual, err := token.Digest(key, "reference-key-profile")
		if err == nil && actual.KeyVersion == expected.KeyVersion && subtle.ConstantTimeCompare(actual.Sum[:], expected.Sum[:]) == 1 {
			matched = true
		}
	}
	if !matched {
		return false
	}
	if len(n.CSRFKeys) == 0 {
		return true
	}
	csrf, err := session.ParseCSRFToken(probe)
	if err != nil {
		return false
	}
	binding := session.CSRFBinding{TenantID: "reference-key-profile", SessionID: "reference-key-profile", SessionVersion: 1}
	state, err := csrf.Digest(csrfKey, binding)
	if err != nil {
		return false
	}
	for _, key := range n.CSRFKeys {
		if state.Check(binding, csrf, key) == nil {
			return true
		}
	}
	return false
}

// Format redacts native key and authority configuration.
func (SessionConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.SessionConfiguration(redacted)")
}

// MarshalJSON denies implicit configuration export.
func (SessionConfiguration) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText denies implicit text/map-key export.
func (SessionConfiguration) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }
