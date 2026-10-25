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
// The retained deployment selects its verified profile; configured OTP and
// magic-link consuming issuers add their own native read and revoke profiles.
// Explicit passkey-only composition admits only its native passkey provenance.
// Selected MagicLink.TOTP additionally composes current confirmed factor
// authority into both paths; MFA never falls back to a single-factor profile.
// Every selected issuer must use the same store, deployment, policy namespace,
// audience and cookie policy, with readable lookup and optional signout CSRF keys.
type SessionConfiguration struct {
	Native   sessionpg.SignOutServiceConfig
	CSRFKeys []session.CSRFKey
	// Passkey admits the explicitly configured native passkey issuer into common
	// reads and signout. False retains the separate Passkeys handle only.
	Passkey bool
}

type sessionState struct {
	reader         *session.SessionService
	bearer         *session.SignOutService
	cookie         *session.CookieSignOutService
	revoke         *sessionpg.RevokeOneExecutor
	config         sessionpg.SignOutServiceConfig
	readerAudience string
}

func composeSession(c StoreConfiguration, d ReferenceDependencies, passkeyAuthority sessionpg.PasskeySessionAuthority) (*sessionState, error) {
	if c.Session == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_session"}
	if d.PostgreSQL == nil {
		return nil, invalid
	}
	n, o := c.Session.Native, c.OTP
	e := n.Execution
	if n.Validation.Clock != nil {
		return nil, invalid
	}
	if o == nil {
		if c.Passkey == nil || c.Passkey.Standalone == nil || !c.Session.Passkey || e.Repository.MaximumDuration > n.MaximumDuration || e.Coordinator.MaximumDuration > n.MaximumDuration {
			return nil, invalid
		}
	} else if e.Profile.GlobalAuthorityID != o.Store.GlobalAuthorityID || e.Profile.PolicyNamespace != o.Store.UserPolicyNamespace || o.Signin != nil && e.Repository.Schema != o.Signin.Session.Schema || e.Repository.MaximumDuration > o.Timeout || e.Coordinator.MaximumDuration > o.Timeout || n.MaximumDuration > o.Timeout || e.PolicyVersion != o.RequestKeys.Policy.PolicyVersion || !sameServerAuthorization(e.Authorization, o.RequestKeys.Policy.Authorization) {
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
	var passkey *sessionpg.PasskeySessionAdmission
	var mfaPasskey *sessionpg.MFAPasskeySessionAdmission
	if c.Session.Passkey {
		if c.Passkey == nil || passkeyAuthority == nil || !sessionIssuanceMatches(*c.Session, c.Passkey.Issuer, c.Passkey.CSRF) {
			return nil, invalid
		}
		passkey = &sessionpg.PasskeySessionAdmission{Profile: sessionpg.PasskeyAdmissionConfig{GlobalAuthorityID: e.Profile.GlobalAuthorityID, PolicyNamespace: e.Profile.PolicyNamespace, Audience: e.Profile.Audience, RPNamespace: c.Passkey.RPNamespace}, Authority: passkeyAuthority}
		if c.Passkey.TOTP != nil {
			mapping, ok := passkeyAuthority.(sessionpg.MFAPasskeySessionAuthority)
			if !ok {
				return nil, invalid
			}
			mfaPasskey = &sessionpg.MFAPasskeySessionAdmission{Profile: passkey.Profile, Authority: mapping}
		}
	}
	if c.MagicLink != nil && c.MagicLink.TOTP != nil {
		if selection.MagicLink == nil || c.MagicLink.Consume == nil || c.MagicLink.Consume.MFA == nil || !c.MagicLink.Request.MFAContinuation {
			return nil, invalid
		}
		profile := *selection.MagicLink
		mfa = &profile
	}
	if c.PasswordSignup != nil && c.PasswordSignup.VerificationTOTP != nil {
		if c.PasswordSignup.VerificationSignin == nil || c.PasswordSignup.VerificationSignin.TOTP == nil || selection.MagicLink == nil {
			return nil, invalid
		}
		// Both native origins retain verified-email-grant plus actual-factor
		// session vocabulary. This selects reading/revocation, not magic-link login.
		profile := c.PasswordSignup.VerificationSignin.Profile
		if mfa != nil && *mfa != profile || profile != *selection.MagicLink {
			return nil, invalid
		}
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
	if u := c.Username; u != nil && u.TOTP != nil {
		if !u.Signin || c.PasswordSignin == nil || selection.Verified == nil {
			return nil, invalid
		}
		// Username's original primary remains password authentication. Select
		// its actual MFA session reader/revoker without enabling email MFA login.
		profile := c.PasswordSignin.Native.Profile
		if profile != *selection.Verified || passwordMFA != nil && *passwordMFA != profile {
			return nil, invalid
		}
		passwordMFA = &profile
	}
	if p := c.PhoneSignin; p != nil && p.TOTP != nil {
		if c.PasswordSignin == nil || selection.Verified == nil {
			return nil, invalid
		}
		// Phone comparison retains password authentication plus actual TOTP.
		// Its sessions need native factor reads/revocation even when email MFA
		// login is deliberately unselected.
		profile := c.PasswordSignin.Native.Profile
		if profile != *selection.Verified || passwordMFA != nil && *passwordMFA != profile {
			return nil, invalid
		}
		passwordMFA = &profile
	}
	reader, err := sessionpg.NewSelectedSessionService(d.PostgreSQL, sessionpg.SelectedSessionServiceConfig{Repository: e.Repository, Admission: sessionpg.SelectedSessionAdmissionConfig{SingleFactor: selection, MFAMagicLink: mfa, MFAPassword: passwordMFA, Passkey: passkey, MFAPasskey: mfaPasskey}, Validation: validation})
	if err != nil {
		return nil, invalid
	}
	execution := sessionpg.RevokeOneExecutorConfig{Execution: e, Sessions: reader, Admission: &selection, MFAMagicLink: mfa, MFAPassword: passwordMFA, Passkey: passkey, MFAPasskey: mfaPasskey}
	if selection.Verified == nil && selection.OTP == nil && selection.MagicLink == nil {
		execution.Admission = nil
	}
	revoke, err := sessionpg.NewRevokeOneExecutor(d.PostgreSQL, execution)
	if err != nil {
		return nil, invalid
	}
	policy := session.SignOutConfig{Cookie: n.Cookie, PolicyID: e.PolicyID, PolicyVersion: e.PolicyVersion, MaximumDuration: n.MaximumDuration}
	bearer, err := session.NewSignOutService(reader, revoke, policy)
	if err != nil {
		return nil, invalid
	}
	state := &sessionState{reader: reader, bearer: bearer, revoke: revoke, config: n, readerAudience: n.Validation.Audience}
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
	if c.Session == nil {
		return deny()
	}
	if c.OTP == nil && c.PasswordSignin == nil {
		if !c.Session.Passkey || c.Passkey == nil || !sessionIssuanceMatches(*c.Session, c.Passkey.Issuer, c.Passkey.CSRF) {
			return deny()
		}
		// Passkey provenance has its own native admission owner. Selecting it
		// must not also admit an unconfigured password or email-OTP issuer.
		return sessionpg.SingleFactorSessionAdmissionConfig{}, nil
	}
	if c.OTP == nil || c.OTP.Signin == nil && c.PasswordSignin == nil {
		return deny()
	}
	n, e := *c.Session, c.Session.Native.Execution
	verified := sessionpg.IdentifierAdmissionConfig(e.Profile)
	common := sessionpg.OTPAdmissionConfig{GlobalAuthorityID: verified.GlobalAuthorityID, PolicyNamespace: verified.PolicyNamespace, Audience: verified.Audience}
	selected := sessionpg.SingleFactorSessionAdmissionConfig{Verified: &verified}
	if otp := c.OTP.Signin; otp != nil {
		if otp.Profile != common || otp.Session != e.Repository || !sessionIssuanceMatches(n, otp.Issuer, otp.CSRFKey) {
			return deny()
		}
		selected.OTP = &common
	}
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
	if p := c.PasswordSignup; p != nil && p.VerificationSignin != nil {
		v := *p.VerificationSignin
		if sessionpg.OTPAdmissionConfig(v.Profile) != common || p.Native.Session != e.Repository || !sessionIssuanceMatches(n, v.Issuance, v.CSRFKey) {
			return deny()
		}
		profile := v.Profile
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
