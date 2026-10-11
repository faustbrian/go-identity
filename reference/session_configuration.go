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

// SessionConfiguration selects native single-factor primary reads and self
// signout, without HTTP. Native freezes the authority profile, lookup keys,
// clock, policy and transaction bounds. Validation.Clock must be absent so the
// graph supplies Execution.Clock to both reading and mutation. CSRFKeys selects
// cookie signout; an empty slice disables it, never enables legacy cookie
// mutation. Bearer signout has no cookie fallback. Resources/callbacks remain
// borrowed, bounded and concurrent-safe. Construction performs no IO.
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
	if c.PasswordSignin != nil {
		p := c.PasswordSignin.Native
		if sessionpg.IdentifierAdmissionConfig(e.Profile) != p.Profile || e.Repository != p.Session || !sessionIssuerKeysMatch(*c.Session, p) {
			return nil, invalid
		}
		selected, err := n.Cookie.DeletionAttributes()
		issued, issueErr := p.Issuance.Cookie.DeletionAttributes()
		if err != nil || issueErr != nil || selected.String() != issued.String() {
			return nil, invalid
		}
	}
	validation := n.Validation
	validation.Clock = e.Clock
	reader, err := sessionpg.NewSessionService(d.PostgreSQL, sessionpg.SessionServiceConfig{Repository: e.Repository, Profile: sessionpg.IdentifierAdmissionConfig(e.Profile), Validation: validation})
	if err != nil {
		return nil, invalid
	}
	execution := sessionpg.RevokeOneExecutorConfig{Execution: e, Sessions: reader}
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

// Compare opaque keys through their owned domain-separated digest APIs, not
// pointer identity or exposed material. This fixed public probe is neither an
// issued credential nor persisted state. Retained rotation keys may be added,
// but the current issuer's exact version/material must remain readable.
func sessionIssuerKeysMatch(n SessionConfiguration, p passwordpg.SigninConfig) bool {
	const probe = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"
	token, err := session.ParseToken(probe)
	if err != nil {
		return false
	}
	expected, err := token.Digest(p.Issuance.LookupKey, "reference-key-profile")
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
	state, err := csrf.Digest(p.CSRFKey, binding)
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
