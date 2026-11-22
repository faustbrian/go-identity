package reference

import (
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	identityhttp "github.com/faustbrian/go-identity/http"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organization "github.com/faustbrian/go-organization"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

const enterpriseOIDCCallbackAction = "identity.sso.oidc-callback"

// EnterpriseOIDCConfiguration selects one installed static OIDC provider and
// defaults to existing active linked members. It borrows this graph's primary, organization,
// session, envelope, and evaluated risk owners. Leave Routing.Clock/Envelope,
// Login.Session/GlobalAuthorityID/Envelope/AuditRetentionPolicyVersion,
// Login.Risk.Evaluation/Keys, and Completion.Issuer.Clock unset; the graph
// supplies them. Constructors take no network or database actions. Profile
// callbacks and key providers are caller-owned, bounded, and concurrency-safe.
type EnterpriseOIDCConfiguration struct {
	Routing    ssopg.ProviderRouterConfig
	Login      ssopg.ProviderLoginConfig
	Completion ssopg.ProviderLoginCompletionConfig
	// StandaloneStart selects the standalone OIDC renderer for the committed
	// authorization redirect. The callback and member policy remain native.
	// Leave false to retain the previous renderer for existing installations.
	StandaloneStart bool
	// StandaloneCallback selects the standalone OIDC adapter for the admitted,
	// already parsed callback. Native reservation, session, linking, JIT, and
	// role policy remain unchanged. Leave false to retain native completion.
	StandaloneCallback bool
	// RoleSync optionally replaces provider-owned custom role grants during
	// the existing callback. It requires this provider's exact pinned mapping
	// and a configured organization dynamic-role permission owner.
	RoleSync *ssopg.StaticOIDCRoleMapping
	// JIT optionally creates an ordinary member at first sign-in. It requires
	// the installed provider's exact verified mailbox claim mapping. Nil is
	// the linked-member-only profile and installs no JIT migrations.
	JIT *EnterpriseOIDCJITConfiguration
}

// EnterpriseOIDCJITConfiguration selects an explicit first-login policy and
// the tenant directory's existing mailbox comparison and retirement settings.
// The graph supplies the selected provider, organization membership version
// and limits; claims cannot choose an organization, policy or role.
type EnterpriseOIDCJITConfiguration struct {
	Address       email.AddressParser
	Directory     kernel.SSOOIDCJITDomainConfig
	PolicyVersion uint64
}

func (EnterpriseOIDCJITConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.EnterpriseOIDCJITConfiguration(redacted)")
}

func (EnterpriseOIDCJITConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

func (EnterpriseOIDCJITConfiguration) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
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
	// ExplicitLink permits a fresh local password session to grant same-origin
	// consent to link one enterprise account. The callback never issues another
	// session for that link. The existing anonymous start remains available.
	ExplicitLink bool
}

type enterpriseOIDCState struct {
	start              *ssopg.ProviderLoginService
	completion         *ssopg.ProviderLoginCompletionService
	preauth            *session.PreAuthIssuer
	profile            ssopg.StaticOIDCLoginProfile
	tenant             identity.TenantID
	origin             string
	policy             string
	version            uint64
	audience           string
	sessionSchema      string
	successCallback    string
	duration           time.Duration
	callbacks          []string
	csrfCookie         session.CSRFCookiePolicy
	roleSync           bool
	jit                bool
	memberLink         bool
	standaloneCallback bool
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
	if jit := c.EnterpriseOIDC.JIT; jit != nil {
		membership := c.Organization.Core
		if jit.PolicyVersion == 0 || membership.PolicyVersion == 0 || membership.MaximumMembers == 0 || membership.MaximumPerUser == 0 {
			return invalid
		}
	}
	if c.HTTPEnterpriseOIDC != nil && (c.HTTPRate == nil || c.HTTPPreAuth == nil || c.HTTPPreAuth.Device == nil || c.OTP.PreAuth == nil ||
		c.HTTPSession == nil || c.HTTPSession.Transport != session.CredentialCookie || len(c.Session.CSRFKeys) == 0) {
		return invalid
	}
	if c.HTTPEnterpriseOIDC != nil && c.HTTPEnterpriseOIDC.ExplicitLink {
		cookie, err := c.Session.Native.Cookie.DeletionAttributes()
		if c.PasswordSignin == nil || err != nil || cookie.SameSite != http.SameSiteLaxMode {
			return invalid
		}
	}
	return nil
}

func composeEnterpriseOIDCCompletion(start *ssopg.ProviderLoginService, config EnterpriseOIDCConfiguration, membership organization.Config, profile ssopg.StaticOIDCLoginProfile) (*ssopg.ProviderLoginCompletionService, error) {
	var roles []ssopg.StaticOIDCRoleMapping
	if config.RoleSync != nil {
		roles = []ssopg.StaticOIDCRoleMapping{*config.RoleSync}
	}
	if jit := config.JIT; jit != nil {
		return ssopg.NewProviderLoginCompletionServiceWithJIT(start, config.Completion, ssopg.ProviderLoginJITConfig{
			Address: jit.Address, Directory: jit.Directory, RoleSync: roles,
			Profiles: []ssopg.StaticOIDCJITPolicy{{OrganizationID: profile.OrganizationID, ProviderID: profile.ProviderID,
				Version: jit.PolicyVersion, MappingVersion: profile.MappingVersion, MembershipVersion: membership.PolicyVersion,
				MaximumMembers: membership.MaximumMembers, MaximumPerUser: membership.MaximumPerUser}},
		})
	}
	if len(roles) != 0 {
		return ssopg.NewProviderLoginCompletionServiceWithRoleSync(start, config.Completion, roles)
	}
	return ssopg.NewProviderLoginCompletionService(start, config.Completion)
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
	if c.EnterpriseOAuth2 != nil {
		router, err = router.WithProtocolRegistry()
		if err != nil {
			return nil, err
		}
	}
	memberLink := c.HTTPEnterpriseOIDC != nil && c.HTTPEnterpriseOIDC.ExplicitLink
	var start *ssopg.ProviderLoginService
	if memberLink {
		validation := c.Session.Native.Validation
		validation.Clock = selectedSession.Clock
		profile := c.PasswordSignin.Native.Profile
		sessions, err := sessionpg.NewSessionService(d.PostgreSQL, sessionpg.SessionServiceConfig{
			Repository: selectedSession.Repository, Profile: profile, Validation: validation,
		})
		if err != nil {
			return nil, err
		}
		start, err = ssopg.NewProviderLoginServiceWithLink(router, n.Login, ssopg.ProviderLinkConfig{
			ConfigurationID: n.Login.ConfigurationID, Sessions: *sessions, Profile: profile,
			LookupKeys: validation.LookupKeys, CSRFKeys: c.Session.CSRFKeys,
		})
		if err != nil {
			return nil, err
		}
	} else {
		start, err = ssopg.NewProviderLoginService(router, n.Login)
		if err != nil {
			return nil, err
		}
	}
	profile := n.Login.Profiles[0]
	complete, err := composeEnterpriseOIDCCompletion(start, n, c.Organization.Core, profile)
	if err != nil {
		return nil, err
	}
	if n.StandaloneStart {
		start, complete, err = complete.WithOIDCStartAdapter(newEnterpriseOIDCStartAdapter)
		if err != nil {
			return nil, err
		}
	}
	if n.StandaloneCallback {
		complete, err = complete.WithOIDCCallbackAdapter(newEnterpriseOIDCCallbackAdapter)
		if err != nil {
			return nil, err
		}
	}
	profile.Scopes = slices.Clone(profile.Scopes)
	state := &enterpriseOIDCState{start: start, completion: complete, profile: profile, tenant: n.Login.TenantID, origin: n.Login.Origin,
		policy: n.Login.PolicyID, version: selectedSession.PolicyVersion, audience: n.Completion.Audience, duration: n.Login.Coordinator.MaximumDuration,
		sessionSchema: selectedSession.Repository.Schema, callbacks: slices.Clone(n.Login.CallbackAllowlist), roleSync: n.RoleSync != nil, jit: n.JIT != nil, memberLink: memberLink,
		standaloneCallback: n.StandaloneCallback}
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
