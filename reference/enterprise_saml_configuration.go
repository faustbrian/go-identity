package reference

import (
	"fmt"
	"io"
	"net/http"
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
	"github.com/faustbrian/go-sso/saml"
)

const enterpriseSAMLACSAction = "identity.sso.saml-acs"

// EnterpriseSAMLConfiguration selects one installed, managed linked-member
// provider. Reference supplies the graph's clock, envelope, storage, policy
// and SAML signer/verifier. Leave Routing.Clock/Envelope, Login.Session/
// GlobalAuthorityID/Envelope/AuditRetentionPolicyVersion, Login.Risk.Evaluation/
// Keys, Login.Profiles, Completion.Issuer.Clock, and Completion.Verify unset.
// Login.RequestKeys uses a dedicated namespace for canonical SAML starts,
// never a password, OAuth2/OIDC, or provider-management request namespace.
type EnterpriseSAMLConfiguration struct {
	Routing    ssopg.ProviderRouterConfig
	Login      ssopg.ProviderLoginConfig
	Profile    ssopg.StaticSAMLLoginProfile
	Completion ssopg.ProviderSAMLLoginCompletionConfig
	ClockSkew  time.Duration
}

func (EnterpriseSAMLConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.EnterpriseSAMLConfiguration(redacted)")
}
func (EnterpriseSAMLConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (EnterpriseSAMLConfiguration) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// HTTPEnterpriseSAMLConfiguration opts into the exact login and POST ACS
// pair, without selecting a normal pre-auth or device endpoint. The flow key
// is a retained native lookup key; FlowSignalKey is dedicated transport risk
// correlation. Both application returns must be on Login.CallbackAllowlist.
type HTTPEnterpriseSAMLConfiguration struct {
	FlowKeyIndex                   uint32
	FlowSignalKey                  session.DigestKey
	IdentityProviderOrigin         identityhttp.Origin
	AuthorizationEndpoint          string
	SuccessCallback, ErrorCallback string
	CSRFCookie                     session.CSRFCookiePolicy
	Lifetime                       session.LifetimeConfig
}

type enterpriseSAMLState struct {
	start            *ssopg.ProviderLoginService
	completion       *ssopg.ProviderSAMLLoginCompletionService
	profile          ssopg.StaticSAMLLoginProfile
	preauth          *session.PreAuthIssuer
	http             *HTTPEnterpriseSAMLConfiguration
	tenant           identity.TenantID
	origin, audience string
	sessionSchema    string
	callbacks        []string
	duration         time.Duration
}

func validateEnterpriseSAMLSelection(c StoreConfiguration) error {
	invalid := identity.InvalidInputError{Field: "reference_enterprise_saml"}
	n, h := c.EnterpriseSAML, c.HTTPEnterpriseSAML
	if n == nil {
		if h != nil {
			return invalid
		}
		return nil
	}
	if c.OAuthWorkload != nil || c.Passkey != nil && c.Passkey.Standalone != nil || c.Session == nil || c.Organization == nil || c.OTP == nil || len(c.Session.CSRFKeys) == 0 ||
		n.ClockSkew < 0 || n.ClockSkew > 5*time.Minute {
		return invalid
	}
	startNamespace := n.Login.RequestKeys.Namespace
	if startNamespace == "" || startNamespace == c.OTP.RequestKeys.Namespace ||
		c.PasswordSignup != nil && startNamespace == c.PasswordSignup.Native.RequestKeys.Namespace ||
		c.EnterpriseOIDC != nil && startNamespace == c.EnterpriseOIDC.Login.RequestKeys.Namespace ||
		c.EnterpriseOAuth2 != nil && startNamespace == c.EnterpriseOAuth2.Login.RequestKeys.Namespace {
		return invalid
	}
	if h == nil {
		return nil
	}
	if c.HTTPRate == nil || c.HTTPSession == nil || c.HTTPSession.Transport != session.CredentialCookie ||
		!slices.Contains(c.HTTPSession.TrustedOrigins, identityhttp.Origin(n.Login.Origin)) ||
		uint64(h.FlowKeyIndex) >= uint64(len(n.Login.FlowKeys)) || h.FlowSignalKey == (session.DigestKey{}) ||
		!slices.Contains(n.Login.CallbackAllowlist, h.SuccessCallback) || !slices.Contains(n.Login.CallbackAllowlist, h.ErrorCallback) {
		return invalid
	}
	csrf, err := h.CSRFCookie.DeletionAttributes()
	if err != nil || csrf.SameSite != http.SameSiteLaxMode {
		return invalid
	}
	matchesCSRF := func(other session.CSRFCookiePolicy) bool {
		attributes, err := other.DeletionAttributes()
		return err == nil && attributes.String() == csrf.String()
	}
	if c.HTTPEnterpriseOIDC != nil && !matchesCSRF(c.HTTPEnterpriseOIDC.CSRFCookie) ||
		c.HTTPEnterpriseOAuth2 != nil && !matchesCSRF(c.HTTPEnterpriseOAuth2.CSRFCookie) ||
		c.SocialOAuth != nil && c.SocialOAuth.Signin != nil && c.HTTPSocialOAuth != nil && c.HTTPSocialOAuth.Callback && !matchesCSRF(c.SocialOAuth.Signin.CSRFCookie) {
		return invalid
	}
	return nil
}

func composeEnterpriseSAML(c StoreConfiguration, d ReferenceDependencies, evaluator risk.Evaluator, crypto *envelope.Service) (*enterpriseSAMLState, error) {
	if c.EnterpriseSAML == nil {
		return nil, nil
	}
	n := *c.EnterpriseSAML
	selected := c.Session.Native.Execution
	invalid := identity.InvalidInputError{Field: "reference_enterprise_saml"}
	if n.Routing.Clock != nil || n.Routing.Envelope != nil || n.Login.Session != (sessionpg.Config{}) || n.Login.GlobalAuthorityID != "" ||
		n.Login.Envelope != nil || n.Login.AuditRetentionPolicyVersion != 0 || n.Login.Risk.Evaluation != (risk.Evaluator{}) || len(n.Login.Risk.Keys) != 0 ||
		len(n.Login.Profiles) != 0 || n.Completion.Issuer.Clock != nil || n.Completion.Verify != nil {
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
	router, err = router.WithSAMLRouteValidation(saml.ValidateSPSigningCredential)
	if err != nil {
		return nil, err
	}
	start, err := ssopg.NewProviderLoginServiceWithSAML(router, n.Login, []ssopg.StaticSAMLLoginProfile{n.Profile}, enterpriseSAMLSignRedirect)
	if err != nil {
		return nil, err
	}
	n.Completion.Verify = enterpriseSAMLPOSTVerifier(n.ClockSkew)
	complete, err := ssopg.NewProviderSAMLLoginCompletionService(start, n.Completion)
	if err != nil {
		return nil, err
	}
	state := &enterpriseSAMLState{start: start, completion: complete, profile: n.Profile, tenant: n.Login.TenantID,
		origin: n.Login.Origin, audience: n.Completion.Audience, sessionSchema: selected.Repository.Schema,
		callbacks: slices.Clone(n.Login.CallbackAllowlist), duration: n.Login.Coordinator.MaximumDuration}
	if c.HTTPEnterpriseSAML == nil {
		return state, nil
	}
	h := *c.HTTPEnterpriseSAML
	selectedKey := n.Login.FlowKeys[h.FlowKeyIndex]
	if slices.Contains(n.Login.FlowKeys, h.FlowSignalKey) || h.FlowSignalKey == n.Completion.Issuer.LookupKey {
		return nil, invalid
	}
	issuer := session.PreAuthIssuerConfig{ActorID: n.Login.ActorID, Action: enterpriseSAMLACSAction, Origin: state.origin,
		CallbackURL: state.origin + "/saml2/" + string(state.profile.ProviderID) + "/acs", PolicyID: n.Login.PolicyID, PolicyVersion: selected.PolicyVersion,
		Clock: selected.Clock, MaximumDuration: selected.Repository.MaximumDuration, FlowTTL: 5 * time.Minute,
		LookupKey: selectedKey, TokenSize: 32, Purpose: session.PreAuthSessionIssuance}
	executor, err := sessionpg.NewPreAuthIssueExecutor(d.PostgreSQL, sessionpg.PreAuthIssueExecutorConfig{Repository: selected.Repository,
		Coordinator: n.Login.Coordinator, Authorization: selected.Authorization, Clock: selected.Clock, ActorID: issuer.ActorID,
		Action: issuer.Action, Origin: issuer.Origin, CallbackURL: issuer.CallbackURL, PolicyID: issuer.PolicyID, PolicyVersion: issuer.PolicyVersion,
		AuditRetentionVersion: selected.AuditRetentionVersion, Purpose: issuer.Purpose})
	if err != nil {
		return nil, err
	}
	state.preauth, err = session.NewSAMLFrontchannelIssuer(executor, issuer)
	if err != nil {
		return nil, err
	}
	state.http = &h
	return state, nil
}
