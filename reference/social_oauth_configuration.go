package reference

import (
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	oauthpg "github.com/faustbrian/go-identity/oauth/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

// SocialOAuthConfiguration selects native explicit-self OIDC account linking.
// The existing verified password/session graph supplies current user, factor,
// session and issuance-preparation authority, never an application-authored
// workflow. Schema is a dedicated RP namespace. ConfigurationID and IntentKey
// are stable across state/PKCE/envelope key rotation; changing them requires
// retaining the original deployment for in-flight requests. Providers and all
// borrowed callbacks remain bounded, concurrency-safe and caller-owned.
// HTTP is independently opt-in. This profile enables no social signin or token
// refresh; those operations must be selected only with their actual owners.
type SocialOAuthConfiguration struct {
	Schema, ConfigurationID, Origin, PolicyID string
	Providers                                 []oauth.Provider
	Issuer                                    capabilitypg.IssuerConfig
	Coordinator                               kernel.CoordinatorConfig
	Counters                                  riskpg.Config
	IntentKey                                 [32]byte
	MaximumDuration, StateLifetime            time.Duration
	CallbackAllowlist                         []string
	CurrentStateKeyVersion                    uint32
	StateKeys                                 map[uint32][32]byte
	CurrentPKCEKeyVersion                     uint32
	PKCECommitmentKeys                        map[uint32][32]byte
	CurrentEnvelopeKey                        string
	EnvelopeKeys                              map[string][]byte
}

// HTTPSocialOAuthConfiguration independently selects initiation and callback.
// The current query-only HTTP profile binds one configured provider to its
// exact callback URL. SigninStart is rejected until the native signin owner is
// selected; it is never advertised as a placeholder or weaker login method.
type HTTPSocialOAuthConfiguration struct{ LinkStart, SigninStart, Callback bool }

type socialOAuthState struct {
	owner          *oauthpg.LinkService
	schema, origin string
	profile        oauth.ProviderProfile
	callbacks      []string
	version        authorization.Revision
	duration       time.Duration
	http           *HTTPSocialOAuthConfiguration
}

func composeSocialOAuth(c StoreConfiguration, d ReferenceDependencies, selectedSession *sessionState) (*socialOAuthState, error) {
	invalid := identity.InvalidInputError{Field: "reference_social_oauth"}
	if c.SocialOAuth == nil {
		if c.HTTPSocialOAuth != nil {
			return nil, invalid
		}
		return nil, nil
	}
	n := *c.SocialOAuth
	if c.OTP == nil || c.PasswordSignin == nil || c.PasswordSignup == nil || c.Session == nil || selectedSession == nil || d.PostgreSQL == nil || n.Coordinator.QueryPolicy == nil || n.Coordinator.AdmissionPolicy == nil || !slices.Contains(c.PasswordSignin.Native.Origins, n.Origin) || n.MaximumDuration > c.OTP.Timeout || n.Counters.Schema != c.Velocity.Schema {
		return nil, invalid
	}
	for _, p := range []*kernel.CommandQueryPolicy{n.Coordinator.QueryPolicy, n.Coordinator.AdmissionPolicy} {
		if p.PolicyVersion != c.OTP.RequestKeys.Policy.PolicyVersion || !sameServerAuthorization(p.Authorization, c.OTP.RequestKeys.Policy.Authorization) {
			return nil, invalid
		}
	}
	if c.HTTPSocialOAuth != nil {
		h := *c.HTTPSocialOAuth
		if h.SigninStart || !h.LinkStart && !h.Callback || len(n.Providers) != 1 || c.HTTPRate == nil {
			return nil, invalid
		}
	}
	validation := c.Session.Native.Validation
	validation.Clock = c.Session.Native.Execution.Clock
	owner, err := oauthpg.NewLinkService(d.PostgreSQL, oauthpg.LinkServiceConfig{
		Schema: n.Schema, ConfigurationID: n.ConfigurationID, PolicyID: n.PolicyID, Origin: n.Origin,
		Providers: n.Providers, CallbackAllowlist: n.CallbackAllowlist,
		Session:  sessionpg.SessionServiceConfig{Repository: c.Session.Native.Execution.Repository, Profile: c.PasswordSignin.Native.Profile, Validation: validation},
		CSRFKeys: c.Session.CSRFKeys, Coordinator: n.Coordinator, Counters: n.Counters,
		Capability: n.Issuer, CapabilityPreparation: c.PasswordSignup.Preparation,
		MaximumDuration: n.MaximumDuration, StateLifetime: n.StateLifetime,
		AuditRetentionPolicyVersion: c.Session.Native.Execution.AuditRetentionVersion,
		IntentKey:                   n.IntentKey, CurrentStateKeyVersion: n.CurrentStateKeyVersion, StateKeys: n.StateKeys,
		CurrentPKCEKeyVersion: n.CurrentPKCEKeyVersion, PKCECommitmentKeys: n.PKCECommitmentKeys,
		CurrentEnvelopeKey: n.CurrentEnvelopeKey, EnvelopeKeys: n.EnvelopeKeys,
	})
	if err != nil {
		return nil, err
	}
	s := &socialOAuthState{owner: owner, schema: n.Schema, origin: n.Origin, callbacks: slices.Clone(n.CallbackAllowlist), version: authorization.Revision(n.Coordinator.AdmissionPolicy.PolicyVersion), duration: n.MaximumDuration}
	if c.HTTPSocialOAuth != nil {
		h := *c.HTTPSocialOAuth
		s.http = &h
		s.profile = n.Providers[0].Profile()
		s.profile.Scopes = slices.Clone(s.profile.Scopes)
		s.profile.Algorithms = slices.Clone(s.profile.Algorithms)
	}
	return s, nil
}

func (SocialOAuthConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.SocialOAuthConfiguration(redacted)")
}
func (SocialOAuthConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (SocialOAuthConfiguration) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (HTTPSocialOAuthConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.HTTPSocialOAuthConfiguration(redacted)")
}
func (HTTPSocialOAuthConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (HTTPSocialOAuthConfiguration) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
