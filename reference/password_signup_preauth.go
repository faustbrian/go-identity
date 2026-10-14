package reference

import (
	"slices"

	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	database "github.com/faustbrian/go-postgres"
)

func composeSignupPreAuth(pool *database.Pool, selected *PasswordSignupConfiguration) (*session.PreAuthIssuer, error) {
	if selected == nil || selected.PreAuth == nil {
		return nil, nil
	}
	p, n := *selected.PreAuth, selected.Native
	if uint64(p.FlowKeyIndex) >= uint64(len(n.FlowKeys)) || n.Coordinator.QueryPolicy == nil || n.Coordinator.AdmissionPolicy == nil || n.Coordinator.QueryPolicy.PolicyVersion != n.Coordinator.AdmissionPolicy.PolicyVersion || !slices.Contains(n.Origins, p.Origin) || !slices.Contains(n.CallbackURLs, p.CallbackURL) {
		return nil, identity.InvalidInputError{Field: "reference_signup_preauth"}
	}
	const action = "identity.password.signup"
	executor, err := sessionpg.NewPreAuthIssueExecutor(pool, sessionpg.PreAuthIssueExecutorConfig{Repository: n.Session, Coordinator: n.Coordinator, Authorization: n.Coordinator.QueryPolicy.Authorization, Clock: clock.System{}, ActorID: p.ActorID, Action: action, Origin: p.Origin, CallbackURL: p.CallbackURL, PolicyID: n.PolicyID, PolicyVersion: n.Coordinator.AdmissionPolicy.PolicyVersion, AuditRetentionVersion: p.AuditRetentionVersion})
	if err != nil {
		return nil, err
	}
	return session.NewPreAuthIssuer(executor, session.PreAuthIssuerConfig{ActorID: p.ActorID, Action: action, Origin: p.Origin, CallbackURL: p.CallbackURL, PolicyID: n.PolicyID, PolicyVersion: n.Coordinator.AdmissionPolicy.PolicyVersion, Clock: clock.System{}, MaximumDuration: n.Session.MaximumDuration, FlowTTL: p.FlowTTL, LookupKey: n.FlowKeys[p.FlowKeyIndex], TokenSize: p.TokenSize, Cookie: p.Cookie})
}

// SignupPreAuth returns the selected original registration-flow issuer. It
// freezes signup, not signin, intent using the native registration profile.
// Issuance and recovery retain graph startup, tenant, lifetime and shutdown
// guards. Obtaining a handle performs no IO and exposes no configuration.
func (f FeatureSet) SignupPreAuth() (PreAuthService, error) {
	s := f.state
	if s == nil {
		return nil, identity.InvalidInputError{Field: "reference_signup_preauth"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.signupPreauth == nil {
		return nil, identity.UnavailableError{}
	}
	return composedPreAuth{state: s, issuer: s.features.signupPreauth}, nil
}
