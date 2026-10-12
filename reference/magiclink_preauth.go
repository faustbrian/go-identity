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

// MagicLinkPreAuthConfiguration selects an original magic-link flow. Its cookie
// key version must exist in Request.CookieKeys; action and policy come from that
// owner. Actor, origin and callback are fixed trusted deployment bindings.
// Cookie, FlowTTL and TokenSize obey session.PreAuthIssuerConfig. HTTP selection
// requires the canonical five-minute lifetime; direct issuance may use1..10m.
type MagicLinkPreAuthConfiguration struct {
	ActorID               identity.ActorID
	Origin, CallbackURL   string
	LookupKeyVersion      uint32
	AuditRetentionVersion uint64
	FlowTTL               time.Duration
	TokenSize             int
	Cookie                session.CookiePolicy
}

// Format redacts deployment custody.
func (MagicLinkPreAuthConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.MagicLinkPreAuthConfiguration(redacted)")
}

// MarshalJSON rejects implicit deployment export.
func (MagicLinkPreAuthConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText rejects implicit deployment export.
func (MagicLinkPreAuthConfiguration) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

func composeMagicLinkPreAuth(pool *database.Pool, selected *MagicLinkConfiguration) (*session.PreAuthIssuer, error) {
	if selected == nil || selected.PreAuth == nil {
		return nil, nil
	}
	p, n := *selected.PreAuth, selected.Request
	key, ok := n.CookieKeys[p.LookupKeyVersion]
	if !ok || n.Coordinator.QueryPolicy == nil || n.Coordinator.AdmissionPolicy == nil || n.Coordinator.QueryPolicy.PolicyVersion != n.Coordinator.AdmissionPolicy.PolicyVersion || !slices.Contains(n.Origins, p.Origin) || !slices.Contains(n.Callbacks, p.CallbackURL) {
		return nil, identity.InvalidInputError{Field: "reference_magic_link_preauth"}
	}
	executor, err := sessionpg.NewPreAuthIssueExecutor(pool, sessionpg.PreAuthIssueExecutorConfig{Repository: n.Session, Coordinator: n.Coordinator, Authorization: n.Coordinator.QueryPolicy.Authorization, Clock: clock.System{}, ActorID: p.ActorID, Action: "identity.magic-link.consume", Origin: p.Origin, CallbackURL: p.CallbackURL, PolicyID: n.PolicyID, PolicyVersion: n.Coordinator.AdmissionPolicy.PolicyVersion, AuditRetentionVersion: p.AuditRetentionVersion})
	if err != nil {
		return nil, err
	}
	return session.NewPreAuthIssuer(executor, session.PreAuthIssuerConfig{ActorID: p.ActorID, Action: "identity.magic-link.consume", Origin: p.Origin, CallbackURL: p.CallbackURL, PolicyID: n.PolicyID, PolicyVersion: n.Coordinator.AdmissionPolicy.PolicyVersion, Clock: clock.System{}, MaximumDuration: n.Session.MaximumDuration, FlowTTL: p.FlowTTL, LookupKey: key, TokenSize: p.TokenSize, Cookie: p.Cookie})
}

// MagicLinkPreAuth exposes selected original-flow preparation/issuance/recovery
// through the graph's existing lifetime and tenant guards. It selects no HTTP.
func (f FeatureSet) MagicLinkPreAuth() (PreAuthService, error) {
	s := f.state
	if s == nil {
		return nil, identity.InvalidInputError{Field: "reference_magic_link_preauth"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.magicPreauth == nil {
		return nil, identity.UnavailableError{}
	}
	return composedPreAuth{state: s, issuer: s.features.magicPreauth}, nil
}
