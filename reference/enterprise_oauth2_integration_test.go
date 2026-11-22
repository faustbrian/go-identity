//go:build integration

package reference_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestReferencePostgresEnterpriseOAuth2Journey(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, organization: true, enterpriseOAuth2: true})
}

func TestReferencePostgresEnterpriseOAuth2UpgradeFromOIDC(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, organization: true, enterpriseOIDC: true, enterpriseOAuth2Upgrade: true})
}

func proveReferenceEnterpriseOAuth2Upgrade(t *testing.T, ctx context.Context, c reference.StoreConfiguration, deps reference.ReferenceDependencies,
	serverConfig reference.ReferenceConfig, installed enterpriseProvisioned, workers []deliverypg.WorkerConfig, owners []reference.ModuleID, origin string,
) (*reference.Server, reference.FeatureSet) {
	t.Helper()
	before := readReferenceEnterpriseJITLegacyState(t, ctx, deps, installed)
	configureReferenceEnterpriseOAuth2(t, &c, origin)
	migrate := func(stores reference.StoreSet) {
		request := applyRequest(t, ctx, stores, owners)
		request.CommandID, request.IdempotencyKey = "migration_command_0002", enterpriseKey(t, "enterprise-oauth2-upgrade")
		count := map[reference.ModuleID]int{}
		for _, step := range request.Plan.Steps {
			count[step.Owner]++
		}
		if len(request.Plan.Steps) != 9 || count["sso/postgres"] != 6 ||
			count["identity/session/postgres"] != 2 || count["identity/postgres"] != 1 {
			t.Fatal("OAuth2 changed a populated predecessor instead of appending native migrations", count)
		}
		result, err := stores.ReferenceMigrationApply(ctx, request)
		if err != nil || result.Result.State() != reference.MigrationApplied {
			t.Fatal("apply OAuth2 suffix after populated OIDC", result.Result.State(), err)
		}
		again, err := stores.ReferenceMigrationPlan(ctx, reference.ReferenceMigrationPlanRequest{Modules: owners})
		if err != nil || len(again.Plan.Steps) != 0 {
			t.Fatal("OAuth2 startup did not recognize the exact installed history", err)
		}
	}
	server, features := selectProvisionedEnterprise(t, ctx, c, deps, serverConfig, installed, workers, migrate)
	if readReferenceEnterpriseJITLegacyState(t, ctx, deps, installed) != before {
		t.Fatal("installing OAuth2 rewrote existing OIDC directory, membership, factor, or account authority")
	}
	checkEnterpriseOAuth2Selection(t, server, true)
	// Keep the native profile and storage installed, but remove its independent
	// HTTP selection. This must remove both callback and pre-auth advertising
	// while the already-selected OIDC start remains.
	c.HTTPEnterpriseOAuth2 = nil
	nativeOnly, _ := selectProvisionedEnterprise(t, ctx, c, deps, serverConfig, installed, workers, nil)
	checkEnterpriseOAuth2Selection(t, nativeOnly, false)
	return server, features
}

func checkEnterpriseOAuth2Selection(t *testing.T, server *reference.Server, httpSelected bool) {
	t.Helper()
	seen := map[string]int{}
	for _, op := range server.OpenAPI().Operations() {
		seen[op.Record.OperationID]++
	}
	if (seen["identity.sso.oauth-callback"] == 1) != httpSelected ||
		seen["identity.sso.signin-start"] != 1 || seen["identity.sso.oidc-callback"] != 1 ||
		strings.Contains(string(server.OpenAPI().JSON()), "sso-oauth2") != httpSelected {
		t.Fatal("the selected graph did not advertise exactly one shared start and its selected callbacks")
	}
}

func configureReferenceEnterpriseOAuth2(t *testing.T, c *reference.StoreConfiguration, origin string) *referenceEnterpriseIssuer {
	t.Helper()
	previous, err := c.Session.Native.Cookie.DeletionAttributes()
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: previous.Name, SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	c.Session.Native.Cookie, c.OTP.Signin.Issuer.Cookie, c.PasswordSignin.Native.Issuance.Cookie = cookie, cookie, cookie
	csrf, err := session.NewCSRFCookiePolicy(session.CookieConfig{Name: "__Host-identity_csrf", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	profile := ssopg.StaticOAuth2LoginProfile{OrganizationID: "EnterpriseOrganization", ProviderID: "Enterprise_OAuth2-01", Domain: "enterprise.example",
		ClientID: enterpriseProviderClient, ProtocolRedirectURI: origin + "/sso/oauth2/callback", ProviderVersion: 3, CredentialGeneration: 1, MappingVersion: 1,
		Scopes: []string{"read:identity"}}
	provider := newReferenceEnterpriseIssuerForProtocol(t, profile.ProtocolRedirectURI, true)
	issuer := c.PasswordSignin.Native.Issuance
	issuer.Clock = nil
	grant := c.PasswordSignup.Issuer
	grant.Audience = "reference-enterprise"
	c.EnterpriseOAuth2 = &reference.EnterpriseOAuth2Configuration{
		Routing: ssopg.ProviderRouterConfig{MaximumDuration: time.Second, Lifetime: 8 * time.Second, PolicyVersion: 9, MaximumProviders: 4},
		Login: ssopg.ProviderLoginConfig{TenantID: otpTenant, ActorID: c.PasswordSignup.PreAuth.ActorID, PolicyID: "reference-enterprise", Origin: origin,
			ConfigurationID: "reference-enterprise-oauth2-v1", CallbackAllowlist: []string{origin + "/enterprise/complete", origin + "/enterprise/error"},
			FlowKeys: c.PasswordSignin.Native.FlowKeys, Coordinator: c.PasswordSignup.Native.Coordinator, RequestKeys: c.PasswordSignup.Native.RequestKeys,
			Risk: risk.AuthenticationAdmissionCustodyConfig{ConfigurationID: "reference-enterprise-oauth2-risk"}, Capability: grant, CapabilityPreparation: c.PasswordSignup.Preparation,
			KeyReference: "issue-envelope", StateKeys: map[uint32][32]byte{1: {0xe3}}, PKCEKeys: map[uint32][32]byte{1: {0xe4}}, CurrentStateKey: 1, CurrentPKCEKey: 1, StateLifetime: 5 * time.Minute},
		Profile: profile,
		Completion: ssopg.ProviderLoginCompletionConfig{Audience: c.Session.Native.Validation.Audience, PolicyNamespace: c.PasswordSignin.Native.Profile.PolicyNamespace,
			Issuer: issuer, CSRFKey: c.PasswordSignin.Native.CSRFKey},
		Exchange: oauth.OAuth2UserInfoProfile{Profile: oauth.ProviderProfile{Version: profile.ProviderVersion, Issuer: provider.server.URL,
			AuthorizationEndpoint: provider.server.URL + "/authorize", TokenEndpoint: provider.server.URL + "/token", RedirectURI: profile.ProtocolRedirectURI,
			ClientID: profile.ClientID, ClientAuthentication: oauth.ClientSecretPost, Scopes: profile.Scopes, ResponseMode: "query", PKCEMethod: "S256", StateBytes: 32,
			Timeout: time.Second, ClockSkew: time.Minute, MaxResponseBytes: 64 << 10, MaxTokenBytes: 16 << 10, MaxCodeBytes: 4096},
			Details: oauth.OAuth2UserInfoDetails{UserInfoEndpoint: provider.server.URL + "/identity", SubjectClaim: "sub", SubjectEncoding: oauth.OAuth2StringSubject, ProofLifetime: 20 * time.Second}},
		HTTPClient: provider.server.Client(),
	}
	c.HTTPEnterpriseOAuth2 = &reference.HTTPEnterpriseOAuth2Configuration{CSRFCookie: csrf, SuccessCallback: origin + "/enterprise/complete"}
	return provider
}
