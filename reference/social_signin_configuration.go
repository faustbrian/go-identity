package reference

import (
	"fmt"
	"slices"
	"time"

	identity "github.com/faustbrian/go-identity"
	oauthpg "github.com/faustbrian/go-identity/oauth/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

// SocialOAuthSigninConfiguration selects native existing-account signin with
// original preauth and session completion, independently of HTTP selection.
// FlowKeyIndex selects PasswordSignin.Native.FlowKeys; no second key set, store
// or workflow is supplied. ActorID is the fixed login service, not a user.
// Origin/policy/provider/transaction custody come from SocialOAuth. Completion
// must match the common session namespace, audience, lookup and CSRF custody.
// The graph supplies its existing counted/audited risk evaluator and keys.
// CSRFCookie is needed only by the selected same-origin HTTP callback profile.
// Callers must not mutate borrowed configuration during construction.
type SocialOAuthSigninConfiguration struct {
	ActorID             identity.ActorID
	CallbackURL         string
	FlowKeyIndex        uint32
	FlowTTL             time.Duration
	TokenSize           int
	FlowCookie          session.CookiePolicy
	RiskConfigurationID string
	Completion          oauthpg.SigninCompletionConfig
	CSRFCookie          session.CSRFCookiePolicy
}

type socialSigninState struct {
	start         *oauthpg.SigninService
	complete      *oauthpg.SigninCompletionService
	preauth       *session.PreAuthIssuer
	actor         identity.ActorID
	callback      string
	flowCookie    session.CookiePolicy
	csrfCookie    session.CSRFCookiePolicy
	audience      string
	sessionSchema string
}

func composeSocialSignin(c StoreConfiguration, d ReferenceDependencies, evaluation risk.Evaluator) (*socialSigninState, error) {
	if c.SocialOAuth == nil || c.SocialOAuth.Signin == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_social_signin"}
	if c.OTP == nil || c.PasswordSignin == nil || c.PasswordSignup == nil || c.Session == nil || d.PostgreSQL == nil {
		return nil, invalid
	}
	n, p := c.SocialOAuth, *c.SocialOAuth.Signin
	sessions, password := c.Session.Native.Execution, c.PasswordSignin.Native
	if uint64(p.FlowKeyIndex) >= uint64(len(password.FlowKeys)) || !slices.Contains(n.CallbackAllowlist, p.CallbackURL) || password.Session != sessions.Repository {
		return nil, invalid
	}
	completion := p.Completion
	if completion.PolicyNamespace != sessions.Profile.PolicyNamespace || completion.Audience != sessions.Profile.Audience || !sessionIssuanceMatches(*c.Session, completion.Issuer, completion.CSRF) {
		return nil, invalid
	}
	start, err := oauthpg.NewSigninService(d.PostgreSQL, oauthpg.SigninServiceConfig{
		Schema: n.Schema, ConfigurationID: n.ConfigurationID, PolicyID: n.PolicyID, Origin: n.Origin,
		GlobalAuthorityID: sessions.Profile.GlobalAuthorityID, Providers: n.Providers, CallbackAllowlist: n.CallbackAllowlist,
		Session: sessions.Repository, FlowKeys: password.FlowKeys,
		Risk:        risk.AuthenticationAdmissionCustodyConfig{Evaluation: evaluation, ConfigurationID: p.RiskConfigurationID, Keys: c.OTP.RiskKeys},
		Coordinator: n.Coordinator, Capability: n.Issuer, CapabilityPreparation: c.PasswordSignup.Preparation,
		MaximumDuration: n.MaximumDuration, StateLifetime: n.StateLifetime, AuditRetentionPolicyVersion: sessions.AuditRetentionVersion,
		IntentKey: n.IntentKey, CurrentStateKeyVersion: n.CurrentStateKeyVersion, StateKeys: n.StateKeys,
		CurrentPKCEKeyVersion: n.CurrentPKCEKeyVersion, PKCECommitmentKeys: n.PKCECommitmentKeys,
		CurrentEnvelopeKey: n.CurrentEnvelopeKey, EnvelopeKeys: n.EnvelopeKeys,
	})
	if err != nil {
		return nil, err
	}
	complete, err := oauthpg.NewSigninCompletionService(start, completion)
	if err != nil {
		return nil, err
	}
	const action = "identity.oauth.callback"
	version := n.Coordinator.AdmissionPolicy.PolicyVersion
	executor, err := sessionpg.NewPreAuthIssueExecutor(d.PostgreSQL, sessionpg.PreAuthIssueExecutorConfig{Repository: sessions.Repository, Coordinator: n.Coordinator, Authorization: n.Coordinator.AdmissionPolicy.Authorization, Clock: sessions.Clock, ActorID: p.ActorID, Action: action, Origin: n.Origin, CallbackURL: p.CallbackURL, PolicyID: n.PolicyID, PolicyVersion: version, AuditRetentionVersion: sessions.AuditRetentionVersion})
	if err != nil {
		return nil, err
	}
	preauth, err := session.NewPreAuthIssuer(executor, session.PreAuthIssuerConfig{ActorID: p.ActorID, Action: action, Origin: n.Origin, CallbackURL: p.CallbackURL, PolicyID: n.PolicyID, PolicyVersion: version, Clock: sessions.Clock, MaximumDuration: sessions.Repository.MaximumDuration, FlowTTL: p.FlowTTL, LookupKey: password.FlowKeys[p.FlowKeyIndex], TokenSize: p.TokenSize, Cookie: p.FlowCookie})
	if err != nil {
		return nil, err
	}
	if c.HTTPSocialOAuth != nil && (c.HTTPSocialOAuth.SigninStart || c.HTTPSocialOAuth.Callback) {
		if c.HTTPPreAuth == nil || c.HTTPPreAuth.Device == nil || n.Origin != c.OTP.PreAuth.Origin || p.FlowTTL != 5*time.Minute {
			return nil, invalid
		}
		flow, e := p.FlowCookie.DeletionAttributes()
		base, b := c.OTP.PreAuth.Cookie.DeletionAttributes()
		if e != nil || b != nil || flow.String() != base.String() {
			return nil, invalid
		}
		if _, err := p.CSRFCookie.DeletionAttributes(); err != nil {
			return nil, invalid
		}
	}
	return &socialSigninState{start: start, complete: complete, preauth: preauth, actor: p.ActorID, callback: p.CallbackURL, flowCookie: p.FlowCookie, csrfCookie: p.CSRFCookie, audience: completion.Audience, sessionSchema: sessions.Repository.Schema}, nil
}

// Format redacts native configuration and borrowed secret custody.
func (SocialOAuthSigninConfiguration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.SocialOAuthSigninConfiguration(redacted)"))
}

// MarshalJSON rejects implicit runtime configuration export.
func (SocialOAuthSigninConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText rejects implicit runtime configuration export.
func (SocialOAuthSigninConfiguration) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
