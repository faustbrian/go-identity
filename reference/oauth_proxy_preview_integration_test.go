//go:build integration

package reference_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	oauthpg "github.com/faustbrian/go-identity/oauth/postgres"
	oauthproxy "github.com/faustbrian/go-identity/oauth/proxy"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

func TestReferencePostgresOAuthProxyPreviewSignin(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
		postgresBaseline: true, socialOIDC: true, socialOIDCLinkOnly: true, oauthProxyPreview: true,
	}, true)
}

const referenceOAuthProxyPreviewBodyLimit = 8192

type referenceOAuthProxyPreviewProof struct {
	production  reference.OAuthProxyProductionConfiguration
	provider    *referenceSocialOIDCIssuer
	previewPool *database.Pool
}

func configureReferenceOAuthProxyPreview(t *testing.T, c *reference.StoreConfiguration, origin string, p *referenceSocialOIDCIssuer) *referenceOAuthProxyPreviewProof {
	t.Helper()
	_, production := oauthProxyProductionConfiguration(t)
	profile := c.SocialOAuth.Providers[0].Profile()
	if p.proxyRedirect != "https://production.example/oauth2/callback/proxy" {
		t.Fatal("the remote issuer lacks its exact registered production callback")
	}
	provider, err := oauth.NewOIDCProvider(oauth.OIDCConfig{
		ID: profile.ID, Version: profile.Version, Issuer: profile.Issuer,
		AuthorizationEndpoint: profile.AuthorizationEndpoint, TokenEndpoint: profile.TokenEndpoint,
		RedirectURI: p.proxyRedirect, ClientID: profile.ClientID, ClientAuthentication: oauth.PublicClient,
		Scopes: profile.Scopes, Algorithms: profile.Algorithms, KeySet: p,
		Clock: clock.System{}, HTTPClient: p.server.Client(), Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal("configure the production profile of the linked external issuer", err)
	}
	t.Cleanup(provider.Close)
	production.Start.Provider = provider
	production.RevocationEndpoint = p.server.URL + "/revoke"
	production.Start.Preview.Target = oauthproxy.PreviewTarget{
		Deployment: "preview-a", Origin: origin, Redirect: origin + reference.OAuthProxyPreviewPath, Recipient: "preview-identity",
	}
	principal, err := authentication.NewPrincipal(authentication.PrincipalSpec{
		Subject: string(production.Start.Preview.ActorID), Method: "bearer", Issuer: production.Start.Preview.Issuer,
		Audiences: []string{production.Start.Preview.Audience}, Scopes: []string{"identity.oauth.proxy-start"}, AuthenticatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal("construct the authenticated preview deployment principal", err)
	}
	authenticated, err := authentication.NewAuthenticatedResult(principal)
	if err != nil {
		t.Fatal("construct the authenticated preview deployment result", err)
	}
	production.Start.Preview.Authentication = oauthProxyProductionPreviewAuthentication{authenticated: authenticated}
	c.HTTPSocialOAuth.SigninStart = false
	c.SocialOAuth.Signin.CallbackURL = production.Start.Preview.Target.Redirect
	c.SocialOAuth.CallbackAllowlist = append(c.SocialOAuth.CallbackAllowlist, production.Start.Preview.Target.Redirect)
	c.OAuthProxyPreview = &reference.OAuthProxyPreviewConfiguration{
		Native: oauthpg.ProxyPreviewConfig{
			TenantID: production.Start.Preview.TenantID, ActorID: production.Start.Preview.ActorID,
			ProductionDeployment: production.Native.ProductionDeployment, Target: production.Start.Preview.Target,
			Codec: production.Codec, Clock: production.Clock,
		},
		HTTP: &reference.HTTPOAuthProxyPreviewConfiguration{SuccessURL: origin + "/social/complete"},
	}
	return &referenceOAuthProxyPreviewProof{production: production, provider: p}
}

// The existing fixture has created, verified and password-authenticated the
// user, then explicitly linked this provider. Both deployments below use their
// public Reference owners and real PostgreSQL; only the remote issuer is fake.
// Go follows the relay's HTTP contract manually, not in a browser engine.
func (p *referenceOAuthProxyPreviewProof) prove(t *testing.T, ctx context.Context, c reference.StoreConfiguration, features reference.FeatureSet, app *http.Client, base, origin string, user identity.UserID) {
	t.Helper()
	f := newLiveStoresProfile(t, ctx, true, true)
	productionConfig := p.production
	installOAuthProxyProductionFixture(t, ctx, f, productionConfig, true)
	runtimePool := newOAuthProxyProductionRuntimePool(t, ctx, f)
	productionConfig.HTTP = oauthProxyProductionHTTPConfiguration(t, runtimePool)
	production, err := reference.NewOAuthProxyProduction(runtimePool, productionConfig)
	if err != nil {
		t.Fatal("construct the public production proxy owner", err)
	}
	productionServer := httptest.NewTLSServer(production.Handler())
	t.Cleanup(productionServer.Close)
	productionClient := productionServer.Client()
	productionClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	productionClient.Timeout = 5 * time.Second
	if p.previewPool == nil {
		t.Fatal("the preview fixture lacks its actual persistence owner")
	}
	var previewDB, productionDB string
	if err := p.previewPool.Raw().QueryRow(ctx, `SELECT current_database()`).Scan(&previewDB); err != nil {
		t.Fatal("read the preview database identity", err)
	}
	if err := f.pool.Raw().QueryRow(ctx, `SELECT current_database()`).Scan(&productionDB); err != nil || previewDB == productionDB {
		t.Fatal("production and preview did not own separate databases", err)
	}
	sessionTable := pgx.Identifier{c.Session.Native.Execution.Repository.Schema, "sessions"}.Sanitize()
	readSessionCount := func() int64 {
		t.Helper()
		var count int64
		if err := p.previewPool.Raw().QueryRow(ctx, "SELECT count(*) FROM "+sessionTable+" WHERE tenant_id=$1 AND user_id=$2", string(otpTenant), string(user)).Scan(&count); err != nil {
			t.Fatal("read actual linked-user session rows", err)
		}
		return count
	}
	beforeSessions := readSessionCount()

	newBrowser := func() *http.Client {
		t.Helper()
		jar, err := cookiejar.New(nil)
		if err != nil {
			t.Fatal("create an isolated preview browser", err)
		}
		client := *app
		client.Jar = jar
		client.CheckRedirect = productionClient.CheckRedirect
		return &client
	}
	call := func(client *http.Client, method, path, body, csrf string) (*http.Response, []byte) {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, method, base+path, strings.NewReader(body))
		if err != nil {
			t.Fatal("build a preview public request", err)
		}
		if method == http.MethodPost {
			request.Header.Set("Origin", origin)
			request.Header.Set("Content-Type", "application/json")
		}
		if csrf != "" {
			request.Header.Set("X-CSRF-Token", csrf)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("execute a preview public request", err)
		}
		wire, readErr := io.ReadAll(io.LimitReader(response.Body, 16385))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || len(wire) > 16384 {
			t.Fatal("read a bounded preview response")
		}
		return response, wire
	}
	readSession := func(client *http.Client, want bool) {
		t.Helper()
		response, wire := call(client, http.MethodGet, "/v1/session/get", "", "")
		var state struct {
			Authenticated bool `json:"authenticated"`
			Principal     struct {
				UserID string `json:"userID"`
			} `json:"principal"`
		}
		if response.StatusCode != http.StatusOK || json.Unmarshal(wire, &state) != nil || state.Authenticated != want || want && state.Principal.UserID != string(user) {
			t.Fatal("the shared native session owner did not preserve preview identity", response.StatusCode)
		}
	}
	issueFlow := func(client *http.Client) (identity.PreAuthTransactionID, []*http.Cookie) {
		t.Helper()
		response, wire := call(client, http.MethodPost, "/v1/session/preauth-issue", `{"method":"oauth-proxy","remember":false}`, "")
		var result struct {
			Issued bool   `json:"issued"`
			FlowID string `json:"flowID"`
		}
		if response.StatusCode != http.StatusOK || json.Unmarshal(wire, &result) != nil || !result.Issued {
			t.Fatal("issue the actual preview original browser flow", response.StatusCode)
		}
		flow, err := identity.ParsePreAuthTransactionID(result.FlowID)
		if err != nil {
			t.Fatal("parse the original public preview flow", err)
		}
		return flow, response.Cookies()
	}
	browser := newBrowser()
	readSession(browser, false)
	flow, originalCookies := issueFlow(browser)
	flowPolicy, err := c.SocialOAuth.Signin.FlowCookie.DeletionAttributes()
	if err != nil {
		t.Fatal(err)
	}
	devicePolicy, err := c.HTTPPreAuth.Device.Cookie.DeletionAttributes()
	if err != nil {
		t.Fatal(err)
	}
	deviceCodec, err := session.NewBrowserDeviceCodec(*c.HTTPPreAuth.Device)
	if err != nil {
		t.Fatal(err)
	}
	var flowCookie authentication.BearerCredential
	var deviceID string
	for _, cookie := range originalCookies {
		switch cookie.Name {
		case flowPolicy.Name:
			flowCookie = authentication.NewBearerCredential(cookie.Value)
		case devicePolicy.Name:
			device, err := deviceCodec.Resolve(ctx, time.Now(), otpTenant, origin, cookie.Value)
			if err != nil {
				t.Fatal("resolve the actually issued signed browser device", err)
			}
			deviceID = device.DeviceID()
		default:
			t.Fatal("original preview issuance unexpectedly supplied session or CSRF authority")
		}
	}
	if flowCookie.Token() == "" || deviceID == "" {
		t.Fatal("original preview flow lacks its actual browser custody")
	}
	remember, err := session.ResolveRememberPolicy(session.RememberDefault, c.HTTPPreAuth.Lifetime)
	if err != nil {
		t.Fatal(err)
	}
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	beforeExchanges := p.provider.exchanges.Load()
	beforeRevocations := p.provider.proxyRevocations.Load()
	authorization, err := features.StartOAuthProxyPreview(ctx, production, reference.OAuthProxyPreviewStartRequest{
		Initiation: oauthproxy.InitiationRequest{
			Credential: authentication.NewBearerCredential("synthetic-production-preview-invocation"),
			CommandID:  command, TransactionID: flow, RequestFingerprint: sha256.Sum256([]byte("reference-preview-original-request")), Remember: remember,
		},
		FlowCookie: flowCookie, Network: "127.0.0.1", Device: deviceID,
	})
	if err != nil {
		t.Fatal("the public preview owner did not acknowledge both native origin bindings", err)
	}
	providerClient := *p.provider.server.Client()
	providerClient.CheckRedirect = productionClient.CheckRedirect
	providerRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, authorization.URL(), nil)
	if err != nil {
		t.Fatal(err)
	}
	authorized, err := providerClient.Do(providerRequest)
	if err != nil {
		t.Fatal("authorize at the controlled remote issuer", err)
	}
	authorized.Body.Close()
	callback, err := url.Parse(authorized.Header.Get("Location"))
	if err != nil || authorized.StatusCode != http.StatusSeeOther || callback.Scheme+"://"+callback.Host+callback.Path != p.provider.proxyRedirect {
		t.Fatal("the issuer did not return the exact production callback")
	}
	productionRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, productionServer.URL+callback.RequestURI(), nil)
	if err != nil {
		t.Fatal(err)
	}
	productionRequest.Host = "production.example"
	forwarded, err := productionClient.Do(productionRequest)
	if err != nil {
		t.Fatal("invoke the real production TLS callback", err)
	}
	forwardBody, readErr := io.ReadAll(io.LimitReader(forwarded.Body, 1025))
	closeErr := forwarded.Body.Close()
	handoff, err := url.Parse(forwarded.Header.Get("Location"))
	if readErr != nil || closeErr != nil || err != nil || forwarded.StatusCode != http.StatusSeeOther || len(forwardBody) != 0 || len(forwarded.Cookies()) != 0 ||
		handoff.Scheme+"://"+handoff.Host+handoff.Path != origin+reference.OAuthProxyPreviewPath || handoff.RawQuery != "" ||
		forwarded.Header.Get("Cache-Control") != "no-store" || forwarded.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("production did not return a tokenless fragment-only preview handoff", forwarded.StatusCode)
	}
	parts := strings.Split(handoff.Fragment, ".")
	if len(parts) != 3 || parts[0] != "identity-proxy-v1" || parts[1] != string(flow) {
		t.Fatal("production changed the original preview handoff locator")
	}
	envelope, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(envelope) == 0 || len(envelope) > 8192 {
		t.Fatal("production supplied a malformed encrypted handoff")
	}
	defer clear(envelope)
	if p.provider.exchanges.Load() != beforeExchanges+1 || p.provider.proxyRevocations.Load() != beforeRevocations+1 {
		t.Fatal("production did not exchange once and acknowledge refresh-token disposal")
	}
	landing, page := call(browser, http.MethodGet, reference.OAuthProxyPreviewPath, "", "")
	if landing.StatusCode != http.StatusOK || len(landing.Cookies()) != 0 || landing.Header.Get("Cache-Control") != "no-store" ||
		landing.Header.Get("Referrer-Policy") != "no-referrer" || landing.Header.Get("Content-Security-Policy") == "" ||
		!strings.Contains(string(page), `data-success="/social/complete"`) ||
		!strings.Contains(string(page), `history.replaceState(null, "", location.pathname)`) || !strings.Contains(string(page), `fetch(location.pathname`) ||
		strings.Contains(string(page), parts[2]) {
		t.Fatal("the public preview GET did not serve the fixed private relay", landing.StatusCode)
	}
	readSession(browser, false)
	payload, err := json.Marshal(map[string]string{"flow": parts[1], "envelope": parts[2]})
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) >= referenceOAuthProxyPreviewBodyLimit {
		t.Fatal("fixture must fit the preview router's body limit before padding")
	}
	// The same complete original must be denied when its streamed body exceeds
	// the selected router limit, even though the native JSON profile permits more.
	padded := io.MultiReader(strings.NewReader(string(payload)), strings.NewReader(strings.Repeat(" ", referenceOAuthProxyPreviewBodyLimit-len(payload)+1)))
	oversize, err := http.NewRequestWithContext(ctx, http.MethodPost, base+reference.OAuthProxyPreviewPath, padded)
	if err != nil {
		t.Fatal("build streamed preview completion", err)
	}
	oversize.ContentLength = -1
	oversize.Header.Set("Origin", origin)
	oversize.Header.Set("Content-Type", "application/json")
	overflow, err := browser.Do(oversize)
	if err != nil {
		t.Fatal("send streamed preview completion", err)
	}
	overflow.Body.Close()
	if overflow.StatusCode != http.StatusBadRequest || len(overflow.Cookies()) != 0 || readSessionCount() != beforeSessions {
		t.Fatal("a body exceeding the Reference transport limit entered preview completion", overflow.StatusCode)
	}
	foreign := newBrowser()
	foreignFlow, foreignCookies := issueFlow(foreign)
	denied, _ := call(foreign, http.MethodPost, reference.OAuthProxyPreviewPath, string(payload), "")
	if denied.StatusCode < 400 || len(denied.Cookies()) != 0 {
		t.Fatal("another original browser acquired preview session authority", denied.StatusCode)
	}
	readSession(foreign, false)
	if readSessionCount() != beforeSessions {
		t.Fatal("initiation, relay GET or another browser created a native session")
	}
	completed, completeBody := call(browser, http.MethodPost, reference.OAuthProxyPreviewPath, string(payload), "")
	if completed.StatusCode != http.StatusNoContent || len(completeBody) != 0 || len(completed.Cookies()) != 3 || completed.Header.Get("Location") != "" {
		t.Fatal("the public preview POST did not deliver one committed native session", completed.StatusCode)
	}
	var csrf string
	var clearedFlow bool
	for _, cookie := range completed.Cookies() {
		if !cookie.Secure || cookie.Path != "/" || cookie.Domain != "" {
			t.Fatal("preview session delivery changed the native host-cookie scope")
		}
		if cookie.Name == flowPolicy.Name {
			clearedFlow = cookie.MaxAge < 0
			continue
		}
		if cookie.SameSite != http.SameSiteLaxMode || cookie.MaxAge != 0 || !cookie.Expires.IsZero() || cookie.Value == flowCookie.Token() {
			t.Fatal("preview changed the original browser Remember choice or reused its flow credential")
		}
		if cookie.Name == "__Host-identity_csrf" && !cookie.HttpOnly {
			csrf = cookie.Value
		} else if !cookie.HttpOnly {
			t.Fatal("preview exposed its authentication cookie to scripts")
		}
	}
	if csrf == "" || !clearedFlow {
		t.Fatal("preview omitted the strict-logout synchronizer or original-flow expiry")
	}
	readSession(browser, true)
	if readSessionCount() != beforeSessions+1 {
		t.Fatal("preview completion did not persist exactly one linked-user session")
	}
	wrongCSRF, _ := call(browser, http.MethodPost, "/v1/session/signout", `{}`, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if wrongCSRF.StatusCode != http.StatusForbidden || len(wrongCSRF.Cookies()) != 0 {
		t.Fatal("wrong CSRF revoked the linked preview session", wrongCSRF.StatusCode)
	}
	readSession(browser, true)
	logout, _ := call(browser, http.MethodPost, "/v1/session/signout", `{}`, csrf)
	if logout.StatusCode != http.StatusOK || len(logout.Cookies()) != 2 {
		t.Fatal("strict shared logout did not revoke the linked preview session", logout.StatusCode)
	}
	readSession(browser, false)
	// Restore only the original anonymous custody, not the delivered session.
	// A known handoff retry must never disclose a second session after logout.
	replayBrowser := newBrowser()
	baseURL, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	replayBrowser.Jar.SetCookies(baseURL, originalCookies)
	replay, _ := call(replayBrowser, http.MethodPost, reference.OAuthProxyPreviewPath, string(payload), "")
	if replay.StatusCode < 400 || len(replay.Cookies()) != 0 || p.provider.exchanges.Load() != beforeExchanges+1 || p.provider.proxyRevocations.Load() != beforeRevocations+1 {
		t.Fatal("known preview replay repeated provider work or redisclosed a session", replay.StatusCode)
	}
	readSession(replayBrowser, false)
	if readSessionCount() != beforeSessions+1 {
		t.Fatal("known preview replay created another native session")
	}
	var previewCommittedOnce bool
	bindingsTable := pgx.Identifier{c.SocialOAuth.Schema, "proxy_preview_bindings"}.Sanitize()
	flowsTable := pgx.Identifier{c.Session.Native.Execution.Repository.Schema, "preauth_transactions"}.Sanitize()
	err = p.previewPool.Raw().QueryRow(ctx, `SELECT b.version=2 AND b.proof_ciphertext IS NULL AND
 (SELECT state='consumed' FROM `+flowsTable+` WHERE tenant_id=$1 AND flow_id=$2) AND
 (SELECT count(*)=1 FROM audit.identity_command_bindings a WHERE a.command_id=b.callback_command_id) AND
 (SELECT count(*)=1 FROM public.identity_outbox_bindings o WHERE o.command_id=b.callback_command_id)
 FROM `+bindingsTable+` b WHERE b.tenant_id=$1 AND b.flow_id=$2`, string(otpTenant), string(flow)).Scan(&previewCommittedOnce)
	if err != nil || !previewCommittedOnce {
		t.Fatal("preview did not conserve one consumed browser, erased callback grant, audit and lifecycle binding", err)
	}
	var productionHasNoIdentity bool
	err = f.pool.Raw().QueryRow(ctx, `SELECT
 (SELECT count(*)=0 FROM identity.users) AND
 to_regclass('identity.accounts') IS NULL AND
 to_regclass($2) IS NULL AND
 (SELECT count(*)=1 AND bool_and(outcome=1 AND handoff_ciphertext=$1 AND state_proof_ciphertext IS NULL AND pkce_ciphertext IS NULL) FROM synthetic_oauth.proxy_transactions)`, envelope, sessionTable).Scan(&productionHasNoIdentity)
	if err != nil || !productionHasNoIdentity {
		t.Fatal("production lost its committed handoff, retained original provider custody or created identity/session authority", err)
	}

	// The trusted deployment can make a valid production Start while the
	// preview browser proof is wrong. That must never release a provider URL.
	var foreignDevice string
	for _, cookie := range foreignCookies {
		if cookie.Name == devicePolicy.Name {
			device, err := deviceCodec.Resolve(ctx, time.Now(), otpTenant, origin, cookie.Value)
			if err != nil {
				t.Fatal("resolve signed device of the second browser", err)
			}
			foreignDevice = device.DeviceID()
		}
	}
	failedCommand, err := identity.NewCommandID()
	if err != nil || foreignDevice == "" {
		t.Fatal("prepare the second real browser's Start", err)
	}
	withheld, err := features.StartOAuthProxyPreview(ctx, production, reference.OAuthProxyPreviewStartRequest{
		Initiation: oauthproxy.InitiationRequest{
			Credential: authentication.NewBearerCredential("synthetic-production-preview-invocation"),
			CommandID:  failedCommand, TransactionID: foreignFlow, RequestFingerprint: sha256.Sum256([]byte("reference-preview-wrong-original")), Remember: remember,
		},
		FlowCookie: flowCookie, Network: "127.0.0.1", Device: foreignDevice,
	})
	if err == nil || withheld.URL() != "" {
		t.Fatal("failed preview browser binding disclosed a production authorization", err)
	}
	var productionStartExists, previewBindingExists bool
	if err := f.pool.Raw().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM synthetic_oauth.proxy_transactions WHERE tenant_id=$1 AND transaction_id=$2 AND version=1 AND outcome IS NULL)`, otpTenant, string(foreignFlow)).Scan(&productionStartExists); err != nil || !productionStartExists {
		t.Fatal("withheld authorization did not exercise the post-Start binding failure", err)
	}
	if err := p.previewPool.Raw().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM `+bindingsTable+` WHERE tenant_id=$1 AND flow_id=$2)`, otpTenant, string(foreignFlow)).Scan(&previewBindingExists); err != nil || previewBindingExists {
		t.Fatal("wrong original browser unexpectedly committed a preview binding", err)
	}
}
