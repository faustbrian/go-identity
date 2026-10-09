package reference

import (
	"context"
	"fmt"
	"time"

	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	database "github.com/faustbrian/go-postgres"
)

// OTPPreAuthConfiguration selects one trusted original-flow profile. Action,
// policy and native namespace come from the selected OTP owner, not a second
// configuration. Origin/CallbackURL are fixed deployment allowlist values;
// empty callback disables redirect. LookupKeyVersion selects an exact retained
// OTP pre-auth cookie key. FlowTTL is 1..10 minutes, TokenSize 32..64 and Cookie
// must be the secure __Host-identity_flow policy. ActorID is a service identity,
// never the future authenticated user. No constructor performs IO.
type OTPPreAuthConfiguration struct {
	ActorID               identity.ActorID
	Origin, CallbackURL   string
	LookupKeyVersion      uint32
	AuditRetentionVersion uint64
	FlowTTL               time.Duration
	TokenSize             int
	Cookie                session.CookiePolicy
}

func composeOTPPreAuth(pool *database.Pool, o OTPSendConfiguration) (*session.PreAuthIssuer, error) {
	if o.PreAuth == nil {
		return nil, nil
	}
	c := *o.PreAuth
	if o.Store.PreAuth.Schema == "" || o.Store.PreAuth.MaximumDuration > o.Timeout {
		return nil, identity.InvalidInputError{Field: "reference_preauth"}
	}
	key, err := session.NewDigestKey(c.LookupKeyVersion, o.Store.PreAuthCookieKeys[c.LookupKeyVersion])
	if err != nil {
		return nil, identity.InvalidInputError{Field: "reference_preauth"}
	}
	executor, err := sessionpg.NewPreAuthIssueExecutor(pool, sessionpg.PreAuthIssueExecutorConfig{
		Repository: o.Store.PreAuth, Coordinator: o.Coordinator,
		Authorization: o.RequestKeys.Policy.Authorization, Clock: clock.System{},
		ActorID: c.ActorID, Action: o.PreAuthAction, Origin: c.Origin, CallbackURL: c.CallbackURL,
		PolicyID: o.PolicyID, PolicyVersion: o.PolicyVersion, AuditRetentionVersion: c.AuditRetentionVersion,
	})
	if err != nil {
		return nil, err
	}
	return session.NewPreAuthIssuer(executor, session.PreAuthIssuerConfig{
		ActorID: c.ActorID, Action: o.PreAuthAction, Origin: c.Origin, CallbackURL: c.CallbackURL,
		PolicyID: o.PolicyID, PolicyVersion: o.PolicyVersion, Clock: clock.System{},
		MaximumDuration: o.Timeout, FlowTTL: c.FlowTTL, LookupKey: key, TokenSize: c.TokenSize, Cookie: c.Cookie,
	})
}

// PreAuthService is the selected original-flow preparation, issuance and
// outcome-only recovery API. All calls require initialized graph and explicit
// tenant admission and deny after shutdown. Prepare performs no durable work;
// retain its unchanged Command after Issue ambiguity. Issue delivers a cookie
// only for the original new commitment. Recovery never reveals or renews one.
// Calls are concurrent-safe and bounded by the graph/caller lifetime. No HTTP
// route, listener or automatic retry is enabled. Remember is already resolved
// through the shared session policy before Prepare; action/origin/callback are
// trusted configuration, never request choices.
type PreAuthService interface {
	Prepare(context.Context, session.PreAuthPrepareInput) (session.PreparedPreAuthIssuance, error)
	Issue(context.Context, session.PreparedPreAuthIssuance) (session.PreAuthIssueResult, error)
	Recover(context.Context, session.PreAuthIssueCommand) (session.PreAuthIssueResult, error)
}

// PreAuth returns original-flow initiation only when explicitly selected in
// OTP.PreAuth. Handles share native owners and retain startup/shutdown guards.
// Obtaining a handle performs no entropy, IO or implicit initialization.
func (f FeatureSet) PreAuth() (PreAuthService, error) {
	s := f.state
	if s == nil {
		return nil, identity.InvalidInputError{Field: "reference_preauth"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.preauth == nil {
		return nil, identity.UnavailableError{}
	}
	return composedPreAuth{state: s}, nil
}

type composedPreAuth struct{ state *storeState }

func (f composedPreAuth) Prepare(ctx context.Context, i session.PreAuthPrepareInput) (session.PreparedPreAuthIssuance, error) {
	w, done, err := f.state.enterFeature(ctx, true)
	if err != nil {
		return session.PreparedPreAuthIssuance{}, err
	}
	defer done()
	if f.state.tenants[string(i.TenantID)] == nil {
		return session.PreparedPreAuthIssuance{}, identity.UnavailableError{}
	}
	if err := w.Err(); err != nil {
		return session.PreparedPreAuthIssuance{}, err
	}
	p, err := f.state.features.preauth.Prepare(i)
	if err != nil {
		return session.PreparedPreAuthIssuance{}, err
	}
	if err := w.Err(); err != nil {
		return session.PreparedPreAuthIssuance{}, err
	}
	return p, nil
}

func (f composedPreAuth) Issue(ctx context.Context, p session.PreparedPreAuthIssuance) (session.PreAuthIssueResult, error) {
	w, done, err := f.state.enterFeature(ctx, true)
	if err != nil {
		return session.PreAuthIssueResult{}, err
	}
	defer done()
	c, ok := p.Command()
	if !ok || !f.permits(c) {
		return session.PreAuthIssueResult{}, identity.UnavailableError{}
	}
	return f.state.features.preauth.Issue(w, p)
}

func (f composedPreAuth) Recover(ctx context.Context, c session.PreAuthIssueCommand) (session.PreAuthIssueResult, error) {
	w, done, err := f.state.enterFeature(ctx, true)
	if err != nil {
		return session.PreAuthIssueResult{}, err
	}
	defer done()
	if !f.permits(c) {
		return session.PreAuthIssueResult{}, identity.UnavailableError{}
	}
	return f.state.features.preauth.Recover(w, c)
}

func (f composedPreAuth) permits(c session.PreAuthIssueCommand) bool {
	spec, err := c.Record.Bindings()
	return err == nil && f.state.tenants[string(spec.Binding.Intent.TenantID)] != nil
}

// Format redacts trusted deployment profile values for every formatting verb.
func (OTPPreAuthConfiguration) Format(s fmt.State, _ rune) {
	s.Write([]byte("reference.OTPPreAuthConfiguration(redacted)"))
}

// MarshalJSON prevents implicit deployment configuration disclosure.
func (OTPPreAuthConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText prevents implicit configuration disclosure, including map keys.
func (OTPPreAuthConfiguration) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
