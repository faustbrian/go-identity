//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestReferencePostgresEnterpriseOIDCJourney(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, organization: true, enterpriseOIDC: true})
}

type referenceEnterpriseOIDCPolicy struct {
	allowLink, allowOAuth2, allowSAML, allowSAMLLogout, allowSAMLLogoutStart bool
}

func (p referenceEnterpriseOIDCPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	if string(c.Request.Tenant) == otpTenant && c.PolicyRevision == 9 && c.Request.Subject.Kind == authorization.SubjectServiceAccount && c.Request.Subject.ID == "AAAAAAAAAAAAAAAAAAAAAw" {
		switch c.Request.Action {
		case "identity.sso.oidc-callback", "identity.sso.signin-start", "identity.sso.signin-start.recover", "identity.sso.oidc-callback.recover":
			return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
		case "identity.sso.oauth-callback", "identity.sso.oauth-callback.recover":
			if p.allowOAuth2 {
				return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
			}
		case "identity.sso.saml-start", "identity.sso.saml-start.recover", "identity.sso.saml-acs", "identity.sso.saml-acs.recover":
			if p.allowSAML {
				return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
			}
		case "identity.sso.saml-slo":
			res := c.Request.Resource
			if p.allowSAMLLogout && (res.Type == "identity.user" && res.ID != "" ||
				res.Type == "identity.request-admission" && res.ID == "identity.sso.saml-slo") {
				return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
			}
		}
	}
	if string(c.Request.Tenant) == otpTenant && c.PolicyRevision == 9 && c.Request.Subject.Kind == authorization.SubjectUser {
		if p.allowSAMLLogoutStart && c.Request.Action == "identity.sso.saml-logout-start" {
			res := c.Request.Resource
			if res.Type == "identity.user" && res.ID == authorization.ResourceID(c.Request.Subject.ID) ||
				res.Type == "identity.request-admission" && res.ID == "identity.sso.saml-logout-start" {
				return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
			}
		}
		if p.allowLink {
			switch c.Request.Action {
			case "identity.sso.oidc-callback", "identity.sso.signin-start", "identity.sso.signin-start.recover", "identity.sso.oidc-callback.recover":
				return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
			}
		}
		switch c.Request.Action {
		case "identity.sso.provider.register-saml", "identity.sso.provider.register-saml.recover":
			if p.allowSAML {
				return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
			}
		case "identity.sso.provider.register-oauth", "identity.sso.provider.register-oauth.recover":
			if p.allowOAuth2 {
				return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
			}
		case "org:sso-write", "org:sso-read", "org:sso-credentials", "identity.sso.provider.register-oidc", "identity.sso.provider.register-oidc.recover",
			"identity.sso.provider.credentials-rotate", "identity.sso.provider.credentials-rotate.recover", "identity.sso.provider.enable", "identity.sso.provider.enable.recover",
			"identity.organization.role.create", "identity.organization.role.create.recover", "identity.organization.permission-check":
			return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
		}
	}
	return (referenceOrganizationPolicy{}).Decide(ctx, c)
}

func (p referenceEnterpriseOIDCPolicy) ObserveProviderEnableAuthorization(ctx context.Context, d authorization.DecisionContext, version uint64) (ssopg.ProviderEnableAuthorizationEvidence, error) {
	decision, err := p.Decide(ctx, d)
	return ssopg.ProviderEnableAuthorizationEvidence{Context: d.Clone(), Decision: decision, ActorAuthorizationVersion: version, ValidUntil: d.Request.Environment.Time.Add(15 * time.Second)}, err
}

func (p referenceEnterpriseOIDCPolicy) ObserveProviderCredentialsAuthorization(ctx context.Context, d authorization.DecisionContext, version uint64) (ssopg.ProviderCredentialsAuthorizationEvidence, error) {
	decision, err := p.Decide(ctx, d)
	return ssopg.ProviderCredentialsAuthorizationEvidence{Context: d.Clone(), Decision: decision, ActorAuthorizationVersion: version, ValidUntil: d.Request.Environment.Time.Add(15 * time.Second)}, err
}

func (p referenceEnterpriseOIDCPolicy) ObserveProviderDisableAuthorization(ctx context.Context, d authorization.DecisionContext, version uint64) (ssopg.ProviderDisableAuthorizationEvidence, error) {
	decision, err := p.Decide(ctx, d)
	return ssopg.ProviderDisableAuthorizationEvidence{Context: d.Clone(), Decision: decision, ActorAuthorizationVersion: version, ValidUntil: d.Request.Environment.Time.Add(15 * time.Second)}, err
}

func configureReferenceEnterpriseOIDC(t *testing.T, c *reference.StoreConfiguration, origin string) *referenceEnterpriseIssuer {
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
	profile := ssopg.StaticOIDCLoginProfile{OrganizationID: "EnterpriseOrganization", ProviderID: "Enterprise_Provider-01", Domain: "enterprise.example",
		ClientID: enterpriseProviderClient, ProtocolRedirectURI: origin + "/sso/oidc/callback", ProviderVersion: 3, CredentialGeneration: 1, MappingVersion: 1, Scopes: []string{"openid"}}
	provider := newReferenceEnterpriseIssuer(t, profile.ProtocolRedirectURI)
	issuer := c.PasswordSignin.Native.Issuance
	issuer.Clock = nil
	grant := c.PasswordSignup.Issuer
	grant.Audience = "reference-enterprise"
	c.EnterpriseOIDC = &reference.EnterpriseOIDCConfiguration{
		StandaloneStart:    true,
		StandaloneCallback: true,
		Routing:            ssopg.ProviderRouterConfig{MaximumDuration: time.Second, Lifetime: 8 * time.Second, PolicyVersion: 9, MaximumProviders: 4},
		Login: ssopg.ProviderLoginConfig{TenantID: otpTenant, ActorID: c.PasswordSignup.PreAuth.ActorID, PolicyID: "reference-enterprise", Origin: origin,
			ConfigurationID: "reference-enterprise-v1", CallbackAllowlist: []string{origin + "/enterprise/complete", origin + "/enterprise/error"}, Profiles: []ssopg.StaticOIDCLoginProfile{profile},
			FlowKeys: c.PasswordSignin.Native.FlowKeys, Coordinator: c.PasswordSignup.Native.Coordinator, RequestKeys: c.PasswordSignup.Native.RequestKeys,
			Risk: risk.AuthenticationAdmissionCustodyConfig{ConfigurationID: "reference-enterprise-risk"}, Capability: grant, CapabilityPreparation: c.PasswordSignup.Preparation,
			KeyReference: "issue-envelope", StateKeys: map[uint32][32]byte{1: {0xe1}}, PKCEKeys: map[uint32][32]byte{1: {0xe2}}, CurrentStateKey: 1, CurrentPKCEKey: 1, StateLifetime: 5 * time.Minute},
		Completion: ssopg.ProviderLoginCompletionConfig{Audience: c.Session.Native.Validation.Audience, PolicyNamespace: c.PasswordSignin.Native.Profile.PolicyNamespace, Issuer: issuer,
			CSRFKey: c.PasswordSignin.Native.CSRFKey, Profiles: []ssopg.StaticOIDCCompletionProfile{{OrganizationID: profile.OrganizationID, ProviderID: profile.ProviderID,
				Metadata: provider.metadata(), ClientAuthentication: oauth.ClientSecretBasic, Algorithms: []string{"ES256"},
				Keys: &coreoidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&provider.key.PublicKey}}, HTTPClient: provider.server.Client()}}},
	}
	c.HTTPEnterpriseOIDC = &reference.HTTPEnterpriseOIDCConfiguration{CSRFCookie: csrf, SuccessCallback: origin + "/enterprise/complete"}
	return provider
}

const (
	enterpriseProviderClient  = "reference-enterprise-client"
	enterpriseProviderSubject = "reference-enterprise-linked-subject"
)

type referenceEnterpriseIssuer struct {
	server         *httptest.Server
	key            *ecdsa.PrivateKey
	secret         []byte
	returnURI      string
	mux            sync.Mutex
	grant          map[string]enterpriseGrant
	posts          atomic.Int32
	identities     atomic.Int32
	oauth2         bool
	unlinkedOAuth2 atomic.Bool
	accessToken    string
	roleClaim      string
	roleGrant      atomic.Bool
	jitMapping     bool
	assertedClaims map[string]any
}

type enterpriseGrant struct{ nonce, challenge string }

func newReferenceEnterpriseIssuer(t *testing.T, returnURI string) *referenceEnterpriseIssuer {
	t.Helper()
	return newReferenceEnterpriseIssuerForProtocol(t, returnURI, false)
}

func newReferenceEnterpriseIssuerForProtocol(t *testing.T, returnURI string, oauth2 bool) *referenceEnterpriseIssuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var entropy [32]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		t.Fatal(err)
	}
	secret := base64.RawURLEncoding.AppendEncode(nil, entropy[:])
	clear(entropy[:])
	access, err := session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	accessToken, err := access.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	p := &referenceEnterpriseIssuer{key: key, secret: secret, returnURI: returnURI, grant: make(map[string]enterpriseGrant),
		oauth2: oauth2, accessToken: accessToken}
	p.server = httptest.NewTLSServer(http.HandlerFunc(p.serve))
	t.Cleanup(func() { p.server.Close(); clear(secret) })
	return p
}

func (p *referenceEnterpriseIssuer) metadata() sso.OIDCStaticMetadataSpec {
	issuer := p.server.URL
	return sso.OIDCStaticMetadataSpec{Issuer: issuer, AuthorizationEndpoint: issuer + "/authorize", TokenEndpoint: issuer + "/token", JWKSURI: issuer + "/keys"}
}

func (p *referenceEnterpriseIssuer) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/authorize":
		q := r.URL.Query()
		validNonce := !p.oauth2 && len(q.Get("nonce")) == 43 || p.oauth2 && !q.Has("nonce")
		if q.Get("client_id") != enterpriseProviderClient || q.Get("redirect_uri") != p.returnURI || q.Get("response_type") != "code" || q.Get("response_mode") != "query" ||
			q.Get("code_challenge_method") != "S256" || len(q.Get("state")) != 43 || !validNonce || len(q.Get("code_challenge")) != 43 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		code, err := identity.NewCommandID()
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		p.mux.Lock()
		p.grant[string(code)] = enterpriseGrant{q.Get("nonce"), q.Get("code_challenge")}
		p.mux.Unlock()
		returnQuery := url.Values{"code": {string(code)}, "state": {q.Get("state")}, "iss": {p.server.URL}}
		http.Redirect(w, r, p.returnURI+"?"+returnQuery.Encode(), http.StatusSeeOther)
	case r.Method == http.MethodPost && r.URL.Path == "/token":
		p.tokenResponse(w, r)
	case p.oauth2 && r.Method == http.MethodGet && r.URL.Path == "/identity":
		p.identities.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+p.accessToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		subject := enterpriseProviderSubject
		if p.unlinkedOAuth2.Load() {
			subject = "reference-enterprise-unlinked-subject"
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"sub": subject})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (p *referenceEnterpriseIssuer) tokenResponse(w http.ResponseWriter, r *http.Request) {
	p.posts.Add(1)
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	if r.ParseForm() != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	clientID, escaped, authenticated := r.BasicAuth()
	secret, parseErr := url.QueryUnescape(escaped)
	if p.oauth2 {
		clientID, secret, parseErr, authenticated = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret"), nil, r.Header.Get("Authorization") == ""
	}
	if !authenticated || clientID != enterpriseProviderClient || parseErr != nil || !bytes.Equal([]byte(secret), p.secret) ||
		r.PostForm.Get("grant_type") != "authorization_code" || r.PostForm.Get("redirect_uri") != p.returnURI {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	code := r.PostForm.Get("code")
	challenge := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	p.mux.Lock()
	grant, ok := p.grant[code]
	if ok && base64.RawURLEncoding.EncodeToString(challenge[:]) == grant.challenge {
		delete(p.grant, code)
	} else {
		ok = false
	}
	roleClaim := p.roleClaim
	selectedClaims := make(map[string]any, len(p.assertedClaims))
	for name, value := range p.assertedClaims {
		selectedClaims[name] = value
	}
	p.mux.Unlock()
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if p.oauth2 {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": p.accessToken, "refresh_token": "fixture-enterprise-oauth-refresh",
			"token_type": "Bearer", "expires_in": 300, "scope": "read:identity"})
		return
	}
	now := time.Now().UTC()
	attributes := map[string]any{"iss": p.server.URL, "aud": enterpriseProviderClient, "sub": enterpriseProviderSubject,
		"nonce": grant.nonce, "iat": now.Unix(), "auth_time": now.Unix(), "exp": now.Add(5 * time.Minute).Unix()}
	if roleClaim != "" {
		attributes[roleClaim] = p.roleGrant.Load()
	}
	for name, value := range selectedClaims {
		attributes[name] = value
	}
	claims, err := json.Marshal(attributes)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","kid":"reference-enterprise-key"}`))
	input := header + "." + base64.RawURLEncoding.EncodeToString(claims)
	sum := sha256.Sum256([]byte(input))
	a, b, err := ecdsa.Sign(rand.Reader, p.key, sum[:])
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	var sig [64]byte
	a.FillBytes(sig[:32])
	b.FillBytes(sig[32:])
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "fixture-provider-access", "refresh_token": "fixture-provider-refresh",
		"token_type": "Bearer", "expires_in": 300, "scope": "openid", "id_token": input + "." + base64.RawURLEncoding.EncodeToString(sig[:])})
}

func proveReferenceEnterpriseOIDCBootstrapped(t *testing.T, ctx context.Context, underlying *http.Client, origin string, provider sso.ProviderID) {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := *underlying
	client.Jar = jar
	post := func(path string, body []byte, key string) *http.Response {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", origin)
		if key != "" {
			request.Header.Set("Idempotency-Key", key)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	preauth := post("/v1/session/preauth-issue", []byte(`{"method":"sso-oidc"}`), "")
	var flow struct{ FlowID string }
	err = json.NewDecoder(preauth.Body).Decode(&flow)
	_ = preauth.Body.Close()
	if preauth.StatusCode != http.StatusOK || err != nil || flow.FlowID == "" {
		t.Fatal("selected enterprise browser did not obtain an original native flow", preauth.StatusCode, err)
	}
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]string{"flowID": flow.FlowID, "commandID": string(command), "providerID": string(provider),
		"callback": origin + "/enterprise/complete", "errorCallback": origin + "/enterprise/error"})
	if err != nil {
		t.Fatal(err)
	}
	start := post("/v1/sso/signin-start", body, "enterprise-uninstalled-provider")
	_ = start.Body.Close()
	if start.StatusCode != http.StatusForbidden || start.Header.Get("Location") != "" || start.Header.Get("Set-Cookie") != "" || !strings.Contains(start.Header.Get("Cache-Control"), "no-store") {
		t.Fatal("configured but uninstalled provider was not denied without a redirect or credentials", start.StatusCode)
	}
}

func selectProvisionedEnterprise(t *testing.T, ctx context.Context, c reference.StoreConfiguration, deps reference.ReferenceDependencies, config reference.ReferenceConfig, selected enterpriseProvisioned, workers []deliverypg.WorkerConfig, migrate func(reference.StoreSet)) (*reference.Server, reference.FeatureSet) {
	t.Helper()
	if c.EnterpriseOIDC == nil && c.EnterpriseOAuth2 != nil {
		native := *c.EnterpriseOAuth2
		native.Profile.OrganizationID, native.Profile.ProviderID = selected.organization, selected.provider
		c.EnterpriseOAuth2 = &native
		return startProvisionedEnterprise(t, ctx, c, deps, config, workers, migrate)
	}
	native := *c.EnterpriseOIDC
	login := native.Login.Profiles[0]
	login.OrganizationID, login.ProviderID = selected.organization, selected.provider
	native.Login.Profiles = []ssopg.StaticOIDCLoginProfile{login}
	completion := native.Completion.Profiles[0]
	completion.OrganizationID, completion.ProviderID = selected.organization, selected.provider
	native.Completion.Profiles = []ssopg.StaticOIDCCompletionProfile{completion}
	if native.RoleSync != nil {
		mapping := *native.RoleSync
		mapping.OrganizationID, mapping.ProviderID = selected.organization, selected.provider
		mapping.Rules = append([]ssopg.StaticOIDCRoleRule(nil), mapping.Rules...)
		native.RoleSync = &mapping
	}
	c.EnterpriseOIDC = &native
	return startProvisionedEnterprise(t, ctx, c, deps, config, workers, migrate)
}

func startProvisionedEnterprise(t *testing.T, ctx context.Context, c reference.StoreConfiguration, deps reference.ReferenceDependencies, config reference.ReferenceConfig, workers []deliverypg.WorkerConfig, migrate func(reference.StoreSet)) (*reference.Server, reference.FeatureSet) {
	t.Helper()
	stores, err := reference.ComposeStores(c, deps)
	if err != nil {
		t.Fatal("compose installed enterprise graph", err)
	}
	t.Cleanup(func() {
		bounded, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := stores.Close(bounded); err != nil {
			t.Error("installed enterprise graph close", err)
		}
	})
	providers, err := reference.ComposeProviders(stores)
	if err != nil {
		t.Fatal(err)
	}
	workerSet, err := reference.ComposeWorkers(stores, providers, workers...)
	if err != nil {
		t.Fatal(err)
	}
	features, err := reference.ComposeFeatures(stores, providers, workerSet)
	if err != nil {
		t.Fatal(err)
	}
	if migrate != nil {
		migrate(stores)
	}
	if err := features.Initialize(ctx); err != nil {
		t.Fatal("initialize installed enterprise graph", err)
	}
	server, err := reference.NewServer(config, deps, features)
	if err != nil {
		t.Fatal(err)
	}
	if state := server.Readiness(ctx); !state.Ready {
		t.Fatal("restarted server did not recognize its existing migrations", state.Failures)
	}
	return server, features
}

func proveReferenceEnterpriseAllowsLaterSocialSelection(t *testing.T, ctx context.Context, c reference.StoreConfiguration, deps reference.ReferenceDependencies, config reference.ReferenceConfig, selected enterpriseProvisioned, workers []deliverypg.WorkerConfig, modules []reference.ModuleID, origin string) {
	t.Helper()
	configureReferenceSocialOIDC(t, &c, origin, true, false)
	configureReferenceSocialSigninHTTP(t, &c)
	owners := append(append([]reference.ModuleID(nil), modules...), "identity/oauth/postgres")
	server, _ := selectProvisionedEnterprise(t, ctx, c, deps, config, selected, workers, func(stores reference.StoreSet) {
		plan, err := stores.ReferenceMigrationPlan(ctx, reference.ReferenceMigrationPlanRequest{Modules: owners})
		if err != nil {
			t.Fatal("enterprise-first history cannot accept later social selection", err)
		}
		var socialSteps int
		for _, step := range plan.Plan.Steps {
			if step.Owner != "identity/oauth/postgres" {
				t.Fatal("social opt-in attempted to change an installed prerequisite", step.Owner)
			}
			socialSteps++
		}
		if socialSteps == 0 {
			t.Fatal("missing pending native social owner migration")
		}
		result, err := stores.ReferenceMigrationApply(ctx, reference.ReferenceMigrationApplyRequest{CommandID: "migration_command_0002", Plan: plan.Plan,
			IdempotencyKey: enterpriseKey(t, "enterprise-later-social-migration")})
		if err != nil || result.Result.State() != reference.MigrationApplied {
			t.Fatal("social enablement did not preserve enterprise history", err, result.Result.State())
		}
	})
	var social, enterprise bool
	for _, operation := range server.OpenAPI().Operations() {
		switch operation.Record.OperationID {
		case "identity.oauth.signin-start":
			social = true
		case "identity.sso.signin-start":
			enterprise = true
		}
	}
	if !social || !enterprise {
		t.Fatal("later social selection did not preserve independent enterprise HTTP routes")
	}
}

func proveReferenceEnterpriseOIDCJourney(t *testing.T, ctx context.Context, base *http.Client, origin string, features reference.FeatureSet, provider *referenceEnterpriseIssuer, selected enterpriseProvisioned) {
	t.Helper()
	proveReferenceEnterpriseOIDCCookieJourney(t, ctx, base, origin, features, provider, selected, nil)
}

func proveReferenceEnterpriseOIDCCookieJourney(t *testing.T, ctx context.Context, base *http.Client, origin string, features reference.FeatureSet, provider *referenceEnterpriseIssuer, selected enterpriseProvisioned, created func(identity.UserID)) {
	t.Helper()
	previousPosts := provider.posts.Load()
	method, callbackPath := "sso-oidc", "/sso/oidc/callback"
	if provider.oauth2 {
		method, callbackPath = "sso-oauth2", "/sso/oauth2/callback"
	}
	requestKey := "enterprise-original-signin"
	if created != nil {
		requestKey = "enterprise-jit-first-signin"
	}
	requestKey += "-" + string(enterpriseCommand(t))
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := *base
	client.Jar = jar
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	request := func(method, target string, body []byte, key, csrf string) *http.Response {
		t.Helper()
		r, err := http.NewRequestWithContext(ctx, method, origin+target, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if method == http.MethodPost {
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", origin)
		}
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}
		if csrf != "" {
			r.Header.Set("X-CSRF-Token", csrf)
		}
		out, err := client.Do(r)
		if err != nil {
			t.Fatal("enterprise Reference HTTPS request failed")
		}
		return out
	}
	const preauthPath = "/v1/session/preauth-issue"
	issueFlow := func() string {
		t.Helper()
		issued := request(http.MethodPost, preauthPath, []byte(`{"method":"`+method+`"}`), "", "")
		defer issued.Body.Close()
		var flow struct{ FlowID string }
		if issued.StatusCode != http.StatusOK || json.NewDecoder(issued.Body).Decode(&flow) != nil || flow.FlowID == "" {
			t.Fatal("installed provider pre-auth flow was not issued", issued.StatusCode)
		}
		return flow.FlowID
	}
	success := origin + "/enterprise/complete"
	startBody := map[string]string{"flowID": issueFlow(), "commandID": string(enterpriseCommand(t)), "providerID": string(selected.provider),
		"callback": success, "errorCallback": origin + "/enterprise/error"}
	if provider.oauth2 {
		startBody["domain"] = "enterprise.example"
	}
	input, err := json.Marshal(startBody)
	if err != nil {
		t.Fatal(err)
	}
	start := func() (out struct{ AuthorizationURL, TransactionID string }) {
		t.Helper()
		response := request(http.MethodPost, "/v1/sso/signin-start", input, requestKey, "")
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&out) != nil || out.AuthorizationURL == "" || out.TransactionID == "" {
			t.Fatal("native enterprise sign-in start did not commit", response.StatusCode)
		}
		return out
	}
	original := start()
	if retry := start(); retry != original || provider.posts.Load() != previousPosts {
		t.Fatal("keyed retry changed the original authorization or exchanged before callback")
	}
	external := *provider.server.Client()
	external.CheckRedirect = client.CheckRedirect
	authorizeCallback := func(authorizationURL string) string {
		t.Helper()
		authorize, err := external.Get(authorizationURL)
		if err != nil {
			t.Fatal("controlled provider authorization failed")
		}
		defer authorize.Body.Close()
		callback := authorize.Header.Get("Location")
		if authorize.StatusCode != http.StatusSeeOther || !strings.HasPrefix(callback, origin+callbackPath+"?") {
			t.Fatal("provider did not return to the exact configured callback", authorize.StatusCode)
		}
		return callback
	}
	callbackURL := authorizeCallback(original.AuthorizationURL)
	getCallback := func() *http.Response {
		t.Helper()
		response, err := client.Get(callbackURL)
		if err != nil {
			t.Fatal("enterprise provider callback request failed")
		}
		_ = response.Body.Close()
		return response
	}
	callback := getCallback()
	if callback.StatusCode != http.StatusSeeOther || callback.Header.Get("Location") != success || provider.posts.Load() != previousPosts+1 || len(callback.Cookies()) != 2 {
		t.Fatal("linked enterprise login did not deliver one committed browser session", callback.StatusCode, provider.posts.Load())
	}
	if provider.oauth2 && provider.identities.Load() != previousPosts+1 {
		t.Fatal("OAuth2 sign-in must authenticate the separate identity endpoint")
	}
	var csrf, token string
	for _, cookie := range callback.Cookies() {
		if !cookie.Secure || cookie.Domain != "" || cookie.Path != "/" || cookie.SameSite != http.SameSiteLaxMode || cookie.MaxAge != 0 || !cookie.Expires.IsZero() {
			t.Fatal("enterprise cookies lost original browser scope or lifetime")
		}
		switch {
		case cookie.Name == "__Host-identity_csrf" && !cookie.HttpOnly:
			csrf = cookie.Value
		case cookie.HttpOnly:
			token = cookie.Value
		}
	}
	if csrf == "" || token == "" {
		t.Fatal("enterprise response lost separate session/CSRF custody")
	}
	read := func(authenticated bool) sessionhttp.GetResponse {
		t.Helper()
		response := request(http.MethodGet, "/v1/session/get", nil, "", "")
		defer response.Body.Close()
		var result sessionhttp.GetResponse
		if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&result) != nil || result.Authenticated != authenticated {
			t.Fatal("common session route did not report expected enterprise session state", response.StatusCode)
		}
		if authenticated {
			if result.Principal == nil || result.Session == nil || result.Principal.TenantID != otpTenant || result.Principal.UserID == "" {
				t.Fatal("enterprise cookie did not authenticate an exact tenant identity")
			}
			if selected.user == "" && created != nil {
				selected.user = result.Principal.UserID
			}
			if result.Principal.UserID != selected.user {
				t.Fatal("enterprise cookie did not authenticate the exact linked identity")
			}
		}
		return result
	}
	public := read(true)
	if created != nil {
		created(selected.user)
	}
	checkReferenceEnterpriseOrganization(t, ctx, features, token, public.Session.ID, method, selected)
	wrong := request(http.MethodPost, "/v1/session/signout", []byte(`{}`), "", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	_ = wrong.Body.Close()
	if wrong.StatusCode != http.StatusForbidden || len(wrong.Cookies()) != 0 {
		t.Fatal("wrong CSRF changed enterprise cookie custody", wrong.StatusCode)
	}
	read(true)
	logout := request(http.MethodPost, "/v1/session/signout", []byte(`{}`), "", csrf)
	_ = logout.Body.Close()
	if logout.StatusCode != http.StatusOK || len(logout.Cookies()) != 2 {
		t.Fatal("strict logout did not clear both enterprise cookies", logout.StatusCode)
	}
	for _, removed := range logout.Cookies() {
		if removed.MaxAge >= 0 {
			t.Fatal("strict logout did not delete the returned cookie")
		}
	}
	read(false)
	// Restore the old session cookie in the test client to prove durable revoke,
	// not merely the absence of a browser credential after Set-Cookie deletion.
	appURL, err := url.Parse(origin)
	if err != nil {
		t.Fatal(err)
	}
	client.Jar.SetCookies(appURL, callback.Cookies())
	read(false)
	replay := getCallback()
	if replay.StatusCode == http.StatusSeeOther || len(replay.Cookies()) != 0 || replay.Header.Get("Location") != "" || provider.posts.Load() != previousPosts+1 {
		t.Fatal("historical enterprise callback re-exchanged or disclosed credentials", replay.StatusCode)
	}
	if provider.oauth2 {
		startBody["flowID"], startBody["commandID"] = issueFlow(), string(enterpriseCommand(t))
		requestKey = "enterprise-oauth2-refusal-" + startBody["commandID"]
		input, err = json.Marshal(startBody)
		if err != nil {
			t.Fatal(err)
		}
		good := authorizeCallback(start().AuthorizationURL)
		bad, err := url.Parse(good)
		if err != nil {
			t.Fatal(err)
		}
		query := bad.Query()
		query.Del("iss")
		bad.RawQuery = query.Encode() + "&iss=%ZZ"
		for _, target := range []string{bad.String(), good} {
			callbackURL = target
			denied := getCallback()
			if denied.StatusCode != http.StatusForbidden || len(denied.Cookies()) != 0 || denied.Header.Get("Location") != "" ||
				provider.posts.Load() != previousPosts+1 || provider.identities.Load() != previousPosts+1 {
				t.Fatal("definitive issuer refusal or its replay reached provider or exposed credentials", denied.StatusCode)
			}
		}
		provider.unlinkedOAuth2.Store(true)
		defer provider.unlinkedOAuth2.Store(false)
		startBody["flowID"], startBody["commandID"] = issueFlow(), string(enterpriseCommand(t))
		requestKey = "enterprise-oauth2-unlinked-" + startBody["commandID"]
		input, err = json.Marshal(startBody)
		if err != nil {
			t.Fatal(err)
		}
		callbackURL = authorizeCallback(start().AuthorizationURL)
		for range 2 {
			denied := getCallback()
			if denied.StatusCode != http.StatusForbidden || len(denied.Cookies()) != 0 || denied.Header.Get("Location") != "" ||
				provider.posts.Load() != previousPosts+2 || provider.identities.Load() != previousPosts+2 {
				t.Fatal("verified unlinked subject did not settle as one terminal refusal", denied.StatusCode)
			}
		}
	}
}

func checkReferenceEnterpriseOrganization(t *testing.T, ctx context.Context, features reference.FeatureSet, token, publicSession, method string, selected enterpriseProvisioned) {
	t.Helper()
	service, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := session.ParseToken(token)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, parsed)
	if err != nil {
		t.Fatal(err)
	}
	read, err := service.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
	if err != nil || !read.Authenticated {
		t.Fatal("common native reader rejected the browser's enterprise credential", err)
	}
	spec, err := read.Session.Bindings()
	if err != nil || spec.SessionID != publicSession || spec.UserID != selected.user || spec.Authentication.Kind != session.AuthenticationVerified || spec.Authentication.Proof.Method != method {
		t.Fatal("common native reader changed enterprise provenance")
	}
	authority, err := spec.Authority.Bindings()
	if err != nil || !authority.Organization.Present || authority.ActiveOrganizationID != string(selected.organization) {
		t.Fatal("enterprise session authority did not retain the exact selected organization")
	}
}
