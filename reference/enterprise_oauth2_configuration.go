package reference

import (
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/oauth"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

const enterpriseOAuth2CallbackAction = "identity.sso.oauth-callback"
const enterpriseOAuth2CallbackPath = "/sso/oauth2/callback"

// EnterpriseOAuth2Configuration selects one installed, existing-linked-member
// provider. It uses the graph's live session, authorization and organization
// authorities. Leave Routing.Clock/Envelope, Login.Session/GlobalAuthorityID/
// Envelope/AuditRetentionPolicyVersion, Login.Risk.Evaluation/Keys,
// Completion.Issuer.Clock and both OIDC Profiles slices unset. Exchange's
// Profile.ID is derived from the exact installed organization and provider.
// The trusted HTTPS client is borrowed; construction performs no network I/O.
type EnterpriseOAuth2Configuration struct {
	Routing    ssopg.ProviderRouterConfig
	Login      ssopg.ProviderLoginConfig
	Profile    ssopg.StaticOAuth2LoginProfile
	Completion ssopg.ProviderLoginCompletionConfig
	Exchange   oauth.OAuth2UserInfoProfile
	HTTPClient *http.Client
}

// Format redacts configuration, keys and external endpoints.
func (EnterpriseOAuth2Configuration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.EnterpriseOAuth2Configuration(redacted)")
}

// MarshalJSON refuses implicit export of deployment and key custody.
func (EnterpriseOAuth2Configuration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText refuses implicit export of deployment and key custody.
func (EnterpriseOAuth2Configuration) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// HTTPEnterpriseOAuth2Configuration explicitly selects pre-auth and the two
// browser routes. SuccessCallback is the original, allowlisted app landing
// URL, not the provider's registered protocol callback.
type HTTPEnterpriseOAuth2Configuration struct {
	FlowKeyIndex    uint32
	SuccessCallback string
	CSRFCookie      session.CSRFCookiePolicy
}

type enterpriseOAuth2State struct {
	start           *ssopg.ProviderLoginService
	completion      *ssopg.ProviderOAuth2LoginCompletionService
	preauth         *session.PreAuthIssuer
	profile         ssopg.StaticOAuth2LoginProfile
	tenant          identity.TenantID
	origin          string
	policy          string
	version         uint64
	audience        string
	sessionSchema   string
	authorization   string
	successCallback string
	duration        time.Duration
	callbacks       []string
	csrfCookie      session.CSRFCookiePolicy
}

func validateEnterpriseOAuth2Selection(c StoreConfiguration) error {
	invalid := identity.InvalidInputError{Field: "reference_enterprise_oauth2"}
	n, h := c.EnterpriseOAuth2, c.HTTPEnterpriseOAuth2
	if n == nil {
		if h != nil {
			return invalid
		}
		return nil
	}
	if c.OAuthWorkload != nil || c.Passkey != nil && c.Passkey.Standalone != nil ||
		c.Session == nil || c.Organization == nil || c.OTP == nil || len(c.Session.CSRFKeys) == 0 {
		return invalid
	}
	if h == nil {
		return nil
	}
	if c.HTTPRate == nil || c.HTTPPreAuth == nil || c.HTTPPreAuth.Device == nil || c.OTP.PreAuth == nil ||
		c.HTTPSession == nil || c.HTTPSession.Transport != session.CredentialCookie {
		return invalid
	}
	csrf, err := h.CSRFCookie.DeletionAttributes()
	if err != nil {
		return invalid
	}
	if both := c.HTTPEnterpriseOIDC; both != nil {
		oidc := c.EnterpriseOIDC
		oidcCSRF, err := both.CSRFCookie.DeletionAttributes()
		if err != nil || oidc == nil || len(oidc.Login.Profiles) != 1 || oidcCSRF.String() != csrf.String() ||
			oidc.Login.TenantID != n.Login.TenantID || oidc.Login.Origin != n.Login.Origin || oidc.Login.Profiles[0].ProviderID == n.Profile.ProviderID {
			return invalid
		}
	}
	if c.SocialOAuth != nil && c.SocialOAuth.Signin != nil && c.HTTPSocialOAuth != nil && c.HTTPSocialOAuth.Callback {
		socialCSRF, err := c.SocialOAuth.Signin.CSRFCookie.DeletionAttributes()
		if err != nil || socialCSRF.String() != csrf.String() {
			return invalid
		}
	}
	return nil
}

func composeEnterpriseOAuth2(c StoreConfiguration, d ReferenceDependencies, evaluator risk.Evaluator, crypto *envelope.Service) (*enterpriseOAuth2State, error) {
	if c.EnterpriseOAuth2 == nil {
		return nil, nil
	}
	n := *c.EnterpriseOAuth2
	selected := c.Session.Native.Execution
	invalid := identity.InvalidInputError{Field: "reference_enterprise_oauth2"}
	if n.Routing.Clock != nil || n.Routing.Envelope != nil || n.Login.Session != (sessionpg.Config{}) ||
		n.Login.GlobalAuthorityID != "" || n.Login.Envelope != nil || n.Login.AuditRetentionPolicyVersion != 0 ||
		n.Login.Risk.Evaluation != (risk.Evaluator{}) || len(n.Login.Risk.Keys) != 0 ||
		n.Completion.Issuer.Clock != nil || len(n.Login.Profiles) != 0 || len(n.Completion.Profiles) != 0 ||
		n.Exchange.Profile.ID != "" {
		return nil, invalid
	}
	if n.Completion.PolicyNamespace != selected.Profile.PolicyNamespace || n.Completion.Audience != selected.Profile.Audience ||
		!sessionIssuanceMatches(*c.Session, n.Completion.Issuer, n.Completion.CSRFKey) || n.Login.Coordinator.MaximumDuration > c.OTP.Timeout {
		return nil, invalid
	}
	for _, policy := range []*kernel.CommandQueryPolicy{n.Login.Coordinator.AdmissionPolicy, n.Login.Coordinator.QueryPolicy, &n.Login.RequestKeys.Policy} {
		if policy == nil || policy.PolicyVersion != selected.PolicyVersion || !sameServerAuthorization(policy.Authorization, selected.Authorization) {
			return nil, invalid
		}
	}
	n.Routing.Clock, n.Routing.Envelope = selected.Clock, crypto
	n.Login.Session, n.Login.GlobalAuthorityID = selected.Repository, selected.Profile.GlobalAuthorityID
	n.Login.Envelope, n.Login.AuditRetentionPolicyVersion = crypto, selected.AuditRetentionVersion
	n.Login.Risk.Evaluation, n.Login.Risk.Keys = evaluator, c.OTP.RiskKeys
	router, err := ssopg.NewProviderRouter(d.PostgreSQL, n.Routing)
	if err != nil {
		return nil, err
	}
	router, err = router.WithProtocolRegistry()
	if err != nil {
		return nil, err
	}
	profile := n.Profile
	profile.Scopes = slices.Clone(profile.Scopes)
	start, err := ssopg.NewProviderLoginServiceWithOAuth2(router, n.Login, []ssopg.StaticOAuth2LoginProfile{profile})
	if err != nil {
		return nil, err
	}
	namespace, err := ssopg.SSOOAuth2AccountProviderNamespace(profile.OrganizationID, profile.ProviderID)
	if err != nil {
		return nil, err
	}
	n.Exchange.Profile.ID = strings.ReplaceAll(namespace, ".", "-")
	completion, err := ssopg.NewProviderOAuth2LoginCompletionService(start, n.Completion, []ssopg.StaticOAuth2CompletionProfile{{
		OrganizationID: profile.OrganizationID, ProviderID: profile.ProviderID, Profile: n.Exchange, HTTPClient: n.HTTPClient,
	}})
	if err != nil {
		return nil, err
	}
	state := &enterpriseOAuth2State{start: start, completion: completion, profile: profile, tenant: n.Login.TenantID,
		origin: n.Login.Origin, policy: n.Login.PolicyID, version: selected.PolicyVersion, audience: n.Completion.Audience,
		sessionSchema: selected.Repository.Schema, authorization: n.Exchange.Profile.AuthorizationEndpoint,
		duration: n.Login.Coordinator.MaximumDuration, callbacks: slices.Clone(n.Login.CallbackAllowlist)}
	if c.HTTPEnterpriseOAuth2 == nil {
		return state, nil
	}
	h, flow := c.HTTPEnterpriseOAuth2, c.OTP.PreAuth
	if uint64(h.FlowKeyIndex) >= uint64(len(n.Login.FlowKeys)) || flow.FlowTTL != 5*time.Minute || flow.Origin != n.Login.Origin ||
		profile.ProtocolRedirectURI != n.Login.Origin+enterpriseOAuth2CallbackPath || !slices.Contains(c.HTTPSession.TrustedOrigins, identityhttp.Origin(n.Login.Origin)) ||
		!slices.Contains(n.Login.CallbackAllowlist, h.SuccessCallback) || h.SuccessCallback == profile.ProtocolRedirectURI {
		return nil, invalid
	}
	issuerConfig := session.PreAuthIssuerConfig{ActorID: n.Login.ActorID, Action: enterpriseOAuth2CallbackAction, Origin: n.Login.Origin,
		CallbackURL: h.SuccessCallback, PolicyID: n.Login.PolicyID, PolicyVersion: selected.PolicyVersion,
		Clock: selected.Clock, MaximumDuration: selected.Repository.MaximumDuration, FlowTTL: flow.FlowTTL,
		LookupKey: n.Login.FlowKeys[h.FlowKeyIndex], TokenSize: flow.TokenSize, Cookie: flow.Cookie}
	executor, err := sessionpg.NewPreAuthIssueExecutor(d.PostgreSQL, sessionpg.PreAuthIssueExecutorConfig{Repository: selected.Repository,
		Coordinator: n.Login.Coordinator, Authorization: selected.Authorization, Clock: selected.Clock, ActorID: issuerConfig.ActorID, Action: issuerConfig.Action,
		Origin: issuerConfig.Origin, CallbackURL: issuerConfig.CallbackURL, PolicyID: issuerConfig.PolicyID, PolicyVersion: issuerConfig.PolicyVersion,
		AuditRetentionVersion: selected.AuditRetentionVersion})
	if err != nil {
		return nil, err
	}
	state.preauth, err = session.NewPreAuthIssuer(executor, issuerConfig)
	state.csrfCookie, state.successCallback = h.CSRFCookie, h.SuccessCallback
	if err != nil {
		return nil, err
	}
	return state, nil
}
