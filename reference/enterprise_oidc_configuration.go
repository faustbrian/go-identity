package reference

import (
	"fmt"
	"io"
	"slices"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

const enterpriseOIDCCallbackAction = "identity.sso.oidc-callback"

// EnterpriseOIDCConfiguration selects one installed static OIDC provider and
// existing active linked members. It borrows this graph's primary, organization,
// session, envelope, and evaluated risk owners. Leave Routing.Clock/Envelope,
// Login.Session/GlobalAuthorityID/Envelope/AuditRetentionPolicyVersion,
// Login.Risk.Evaluation/Keys, and Completion.Issuer.Clock unset; the graph
// supplies them. Constructors take no network or database actions. Profile
// callbacks and key providers are caller-owned, bounded, and concurrency-safe.
type EnterpriseOIDCConfiguration struct {
	Routing    ssopg.ProviderRouterConfig
	Login      ssopg.ProviderLoginConfig
	Completion ssopg.ProviderLoginCompletionConfig
	// RoleSync optionally replaces provider-owned custom role grants during
	// the existing callback. It requires this provider's exact pinned mapping
	// and a configured organization dynamic-role permission owner.
	RoleSync *ssopg.StaticOIDCRoleMapping
}

// Format redacts deployment and key custody.
func (EnterpriseOIDCConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.EnterpriseOIDCConfiguration(redacted)")
}

// MarshalJSON refuses implicit export of deployment and key custody.
func (EnterpriseOIDCConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText refuses implicit export of deployment and key custody.
func (EnterpriseOIDCConfiguration) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// HTTPEnterpriseOIDCConfiguration exposes the selected provider's browser start
// and callback. FlowKeyIndex selects an exact retained Login.FlowKeys entry.
// SuccessCallback is the exact allowlisted application landing URL bound into
// the original browser flow, not the protocol redirect registered with the IdP.
// It uses the deployment's existing Lax browser-device/flow cookie policy and
// the common strict cookie session routes; no social route is enabled.
type HTTPEnterpriseOIDCConfiguration struct {
	FlowKeyIndex    uint32
	SuccessCallback string
	CSRFCookie      session.CSRFCookiePolicy
}

type enterpriseOIDCState struct {
	start           *ssopg.ProviderLoginService
	completion      *ssopg.ProviderLoginCompletionService
	preauth         *session.PreAuthIssuer
	profile         ssopg.StaticOIDCLoginProfile
	tenant          identity.TenantID
	origin          string
	policy          string
	version         uint64
	audience        string
	sessionSchema   string
	successCallback string
	duration        time.Duration
	callbacks       []string
	csrfCookie      session.CSRFCookiePolicy
	roleSync        bool
}

func validateEnterpriseOIDCSelection(c StoreConfiguration) error {
	invalid := identity.InvalidInputError{Field: "reference_enterprise_oidc"}
	if c.EnterpriseOIDC == nil {
		if c.HTTPEnterpriseOIDC != nil {
			return invalid
		}
		return nil
	}
	if c.OAuthWorkload != nil || c.Passkey != nil && c.Passkey.Standalone != nil || c.Session == nil || c.Organization == nil || c.OTP == nil {
		return invalid
	}
	if c.EnterpriseOIDC.RoleSync != nil && c.Organization.Core.DynamicRoles.Version == 0 {
		return invalid
	}
	if c.HTTPEnterpriseOIDC != nil && (c.HTTPRate == nil || c.HTTPPreAuth == nil || c.HTTPPreAuth.Device == nil || c.OTP.PreAuth == nil ||
		c.HTTPSession == nil || c.HTTPSession.Transport != session.CredentialCookie || len(c.Session.CSRFKeys) == 0) {
		return invalid
	}
	return nil
}

func composeEnterpriseOIDC(c StoreConfiguration, d ReferenceDependencies, evaluator risk.Evaluator, crypto *envelope.Service) (*enterpriseOIDCState, error) {
	if c.EnterpriseOIDC == nil {
		return nil, nil
	}
	n := *c.EnterpriseOIDC
	selectedSession := c.Session.Native.Execution
	invalid := identity.InvalidInputError{Field: "reference_enterprise_oidc"}
	if n.Routing.Clock != nil || n.Routing.Envelope != nil || n.Login.Session != (sessionpg.Config{}) || n.Login.GlobalAuthorityID != "" ||
		n.Login.Envelope != nil || n.Login.AuditRetentionPolicyVersion != 0 || n.Login.Risk.Evaluation != (risk.Evaluator{}) || len(n.Login.Risk.Keys) != 0 ||
		n.Completion.Issuer.Clock != nil || len(n.Login.Profiles) != 1 || len(n.Completion.Profiles) != 1 {
		return nil, invalid
	}
	if n.Completion.PolicyNamespace != selectedSession.Profile.PolicyNamespace || n.Completion.Audience != selectedSession.Profile.Audience ||
		!sessionIssuanceMatches(*c.Session, n.Completion.Issuer, n.Completion.CSRFKey) || n.Login.Coordinator.MaximumDuration > c.OTP.Timeout {
		return nil, invalid
	}
	for _, policy := range []*kernel.CommandQueryPolicy{n.Login.Coordinator.AdmissionPolicy, n.Login.Coordinator.QueryPolicy, &n.Login.RequestKeys.Policy} {
		if policy == nil || policy.PolicyVersion != selectedSession.PolicyVersion || !sameServerAuthorization(policy.Authorization, selectedSession.Authorization) {
			return nil, invalid
		}
	}
	n.Routing.Clock, n.Routing.Envelope = selectedSession.Clock, crypto
	n.Login.Session, n.Login.GlobalAuthorityID = selectedSession.Repository, selectedSession.Profile.GlobalAuthorityID
	n.Login.Envelope, n.Login.AuditRetentionPolicyVersion = crypto, selectedSession.AuditRetentionVersion
	n.Login.Risk.Evaluation, n.Login.Risk.Keys = evaluator, c.OTP.RiskKeys
	router, err := ssopg.NewProviderRouter(d.PostgreSQL, n.Routing)
	if err != nil {
		return nil, err
	}
	start, err := ssopg.NewProviderLoginService(router, n.Login)
	if err != nil {
		return nil, err
	}
	var complete *ssopg.ProviderLoginCompletionService
	if n.RoleSync == nil {
		complete, err = ssopg.NewProviderLoginCompletionService(start, n.Completion)
	} else {
		complete, err = ssopg.NewProviderLoginCompletionServiceWithRoleSync(start, n.Completion, []ssopg.StaticOIDCRoleMapping{*n.RoleSync})
	}
	if err != nil {
		return nil, err
	}
	profile := n.Login.Profiles[0]
	profile.Scopes = slices.Clone(profile.Scopes)
	state := &enterpriseOIDCState{start: start, completion: complete, profile: profile, tenant: n.Login.TenantID, origin: n.Login.Origin,
		policy: n.Login.PolicyID, version: selectedSession.PolicyVersion, audience: n.Completion.Audience, duration: n.Login.Coordinator.MaximumDuration,
		sessionSchema: selectedSession.Repository.Schema, callbacks: slices.Clone(n.Login.CallbackAllowlist), roleSync: n.RoleSync != nil}
	if c.HTTPEnterpriseOIDC == nil {
		return state, nil
	}
	h, flow := c.HTTPEnterpriseOIDC, c.OTP.PreAuth
	if uint64(h.FlowKeyIndex) >= uint64(len(n.Login.FlowKeys)) || flow.FlowTTL != 5*time.Minute || flow.Origin != n.Login.Origin ||
		profile.ProtocolRedirectURI != n.Login.Origin+"/sso/oidc/callback" || !slices.Contains(c.HTTPSession.TrustedOrigins, identityhttp.Origin(n.Login.Origin)) ||
		!slices.Contains(n.Login.CallbackAllowlist, h.SuccessCallback) || h.SuccessCallback == profile.ProtocolRedirectURI {
		return nil, invalid
	}
	csrf, err := h.CSRFCookie.DeletionAttributes()
	if err != nil {
		return nil, invalid
	}
	if c.SocialOAuth != nil && c.SocialOAuth.Signin != nil && c.HTTPSocialOAuth != nil && c.HTTPSocialOAuth.Callback {
		social, err := c.SocialOAuth.Signin.CSRFCookie.DeletionAttributes()
		if err != nil || social.String() != csrf.String() {
			return nil, invalid
		}
	}
	issuerConfig := session.PreAuthIssuerConfig{ActorID: n.Login.ActorID, Action: enterpriseOIDCCallbackAction, Origin: n.Login.Origin, CallbackURL: h.SuccessCallback,
		PolicyID: n.Login.PolicyID, PolicyVersion: selectedSession.PolicyVersion, Clock: selectedSession.Clock, MaximumDuration: selectedSession.Repository.MaximumDuration,
		FlowTTL: flow.FlowTTL, LookupKey: n.Login.FlowKeys[h.FlowKeyIndex], TokenSize: flow.TokenSize, Cookie: flow.Cookie}
	executor, err := sessionpg.NewPreAuthIssueExecutor(d.PostgreSQL, sessionpg.PreAuthIssueExecutorConfig{Repository: selectedSession.Repository, Coordinator: n.Login.Coordinator,
		Authorization: selectedSession.Authorization, Clock: selectedSession.Clock, ActorID: issuerConfig.ActorID, Action: issuerConfig.Action, Origin: issuerConfig.Origin,
		CallbackURL: issuerConfig.CallbackURL, PolicyID: issuerConfig.PolicyID, PolicyVersion: issuerConfig.PolicyVersion, AuditRetentionVersion: selectedSession.AuditRetentionVersion})
	if err != nil {
		return nil, err
	}
	state.preauth, err = session.NewPreAuthIssuer(executor, issuerConfig)
	if err != nil {
		return nil, err
	}
	state.csrfCookie = h.CSRFCookie
	state.successCallback = h.SuccessCallback
	return state, nil
}
