package reference

import (
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	database "github.com/faustbrian/go-postgres"
)

// PasswordPreAuthConfiguration selects a fixed password original-flow profile.
// Origin and CallbackURL must be allowed by the consuming native workflow owner.
// FlowKeyIndex selects its retained Native.FlowKeys, including original version;
// action, policy and revision come from that owner. ActorID is a service identity,
// not the future authenticated user. Lifetime, token size and secure cookie obey
// session.PreAuthIssuerConfig. Construction performs no IO or entropy; borrowed
// configuration must not be mutated concurrently.
type PasswordPreAuthConfiguration struct {
	ActorID               identity.ActorID
	Origin, CallbackURL   string
	FlowKeyIndex          uint32
	AuditRetentionVersion uint64
	FlowTTL               time.Duration
	TokenSize             int
	Cookie                session.CookiePolicy
}

// Format hides trusted deployment configuration.
func (PasswordPreAuthConfiguration) Format(s fmt.State, _ rune) {
	io.WriteString(s, "reference.PasswordPreAuthConfiguration(redacted)")
}

// MarshalJSON prevents implicit deployment custody export.
func (PasswordPreAuthConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText prevents implicit deployment custody export.
func (PasswordPreAuthConfiguration) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

func composePasswordPreAuth(pool *database.Pool, selected *PasswordSigninConfiguration) (*session.PreAuthIssuer, error) {
	if selected == nil || selected.PreAuth == nil {
		return nil, nil
	}
	p, n := *selected.PreAuth, selected.Native
	if uint64(p.FlowKeyIndex) >= uint64(len(n.FlowKeys)) || n.Coordinator.QueryPolicy == nil || n.Coordinator.AdmissionPolicy == nil || n.Coordinator.QueryPolicy.PolicyVersion != n.Coordinator.AdmissionPolicy.PolicyVersion || !slices.Contains(n.Origins, p.Origin) || !slices.Contains(n.CallbackURLs, p.CallbackURL) {
		return nil, identity.InvalidInputError{Field: "reference_password_preauth"}
	}
	action := "identity.password.signin"
	if n.Username != nil {
		action = "identity.username.signin"
	} else if n.Phone != nil {
		action = "identity.phone.password-signin"
	}
	executor, err := sessionpg.NewPreAuthIssueExecutor(pool, sessionpg.PreAuthIssueExecutorConfig{Repository: n.Session, Coordinator: n.Coordinator, Authorization: n.Coordinator.QueryPolicy.Authorization, Clock: clock.System{}, ActorID: p.ActorID, Action: action, Origin: p.Origin, CallbackURL: p.CallbackURL, PolicyID: n.PolicyID, PolicyVersion: n.Coordinator.AdmissionPolicy.PolicyVersion, AuditRetentionVersion: p.AuditRetentionVersion})
	if err != nil {
		return nil, err
	}
	return session.NewPreAuthIssuer(executor, session.PreAuthIssuerConfig{ActorID: p.ActorID, Action: action, Origin: p.Origin, CallbackURL: p.CallbackURL, PolicyID: n.PolicyID, PolicyVersion: n.Coordinator.AdmissionPolicy.PolicyVersion, Clock: clock.System{}, MaximumDuration: n.Session.MaximumDuration, FlowTTL: p.FlowTTL, LookupKey: n.FlowKeys[p.FlowKeyIndex], TokenSize: p.TokenSize, Cookie: p.Cookie})
}

// PasswordPreAuth returns the explicitly selected original password-flow owner.
// This does not select HTTP or change OTP's PreAuth profile. Native issuance owns
// original entropy, durable commitment and reveal-once delivery; recovery remains
// outcome-only. Every call retains initialized graph, tenant and shutdown guards.
func (f FeatureSet) PasswordPreAuth() (PreAuthService, error) {
	s := f.state
	if s == nil {
		return nil, identity.InvalidInputError{Field: "reference_password_preauth"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.passwordPreauth == nil {
		return nil, identity.UnavailableError{}
	}
	return composedPreAuth{state: s, issuer: s.features.passwordPreauth}, nil
}
