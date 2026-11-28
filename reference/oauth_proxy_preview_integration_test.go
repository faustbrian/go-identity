//go:build integration

package reference_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	oauthpg "github.com/faustbrian/go-identity/oauth/postgres"
	oauthproxy "github.com/faustbrian/go-identity/oauth/proxy"
	kernel "github.com/faustbrian/go-identity/postgres"
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

func TestReferencePostgresOAuthProxyPreviewLiveProviderAuthority(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
		postgresBaseline: true, socialOIDC: true, socialOIDCLinkOnly: true, oauthProxyPreview: true, oauthProxyProviderAuthority: true,
	}, true)
}

func TestReferencePostgresOAuthProxyPreviewRetiresDisabledOrigins(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
		postgresBaseline: true, socialOIDC: true, socialOIDCLinkOnly: true,
		oauthProxyPreview: true, oauthProxyProviderAuthority: true, oauthProxyRetirement: true,
	}, true)
}

const referenceOAuthProxyPreviewBodyLimit = 8192

type referenceOAuthProxyPreviewProof struct {
	production        reference.OAuthProxyProductionConfiguration
	provider          *referenceSocialOIDCIssuer
	previewPool       *database.Pool
	productionFixture *liveStores
	authority         *oauthpg.ProviderAuthority
	operator          *oauthpg.ProviderAuthorityOperator
	retirement        *oauthpg.ProxyRetirementAuthority
	maintenance       bool
	readerRole        string
	epoch             uint64
}

func (p *referenceOAuthProxyPreviewProof) prepareRetirementAuthority(t *testing.T) {
	t.Helper()
	if p.productionFixture == nil || p.authority == nil {
		t.Fatal("retirement requires the separately owned live production authority")
	}
	// The trusted operator reads retained production audit evidence through the
	// fixture-owner pool, never by widening the restricted callback login.
	reader, err := auditpg.New(p.productionFixture.pool.Raw(), auditpg.Config{})
	if err != nil {
		t.Fatal("construct the trusted production audit reader", err)
	}
	p.retirement, err = oauthpg.NewProxyRetirementAuthority(reader, p.production.Native.Actor)
	if err != nil {
		t.Fatal("select the original provider operator for both local retirements", err)
	}
}

func (p *referenceOAuthProxyPreviewProof) prepareProviderAuthority(t *testing.T, ctx context.Context) {
	t.Helper()
	f := newLiveStoresProfile(t, ctx, true, true)
	p.productionFixture = &f
	var databaseName string
	if err := f.pool.Raw().QueryRow(ctx, `SELECT current_database()`).Scan(&databaseName); err != nil {
		t.Fatal("identify the dedicated live-authority production primary", err)
	}
	p.readerRole = databaseName + "_provider_reader"
	quoted := pgx.Identifier{p.readerRole}.Sanitize()
	if _, err := f.pool.Raw().Exec(ctx, "CREATE ROLE "+quoted+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"); err != nil {
		t.Fatal("create the fixture-owned SELECT-only provider authority login", err)
	}
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := f.pool.Raw().Exec(bounded, "DROP OWNED BY "+quoted+"; DROP ROLE "+quoted); err != nil {
			t.Error("release the exact fixture-owned provider reader role", err)
		}
	})
	reader, err := database.New(ctx, database.Config{
		DSN: f.pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 2,
		Configure: func(c *database.PoolConfig) error {
			c.ConnConfig.User, c.ConnConfig.Password = p.readerRole, ""
			return nil
		},
	})
	if err != nil {
		t.Fatal("open the independent provider authority read pool", err)
	}
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := reader.Close(bounded); err != nil {
			t.Error("close the provider authority read pool", err)
		}
	})
	p.authority, err = oauthpg.NewProviderAuthority(reader, p.production.Native.Schema, time.Second)
	if err != nil {
		t.Fatal("select the shared current-primary reader before preview composition", err)
	}
}

func (p *referenceOAuthProxyPreviewProof) installProviderAuthority(t *testing.T, ctx context.Context, f liveStores) {
	t.Helper()
	history, err := (oauthpg.ProviderAuthorityMigrationSource{Schema: p.production.Native.Schema, Version: 43}).Load(ctx)
	if err != nil || len(history) != 1 {
		t.Fatal("load the native additive provider authority history", err)
	}
	tx, err := f.pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, history[0].UpSQL()); err != nil {
		t.Fatal("install provider authority after the existing production bootstrap", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	quotedRole := pgx.Identifier{p.readerRole}.Sanitize()
	quotedSchema := pgx.Identifier{p.production.Native.Schema}.Sanitize()
	table := pgx.Identifier{p.production.Native.Schema, "provider_authorities"}.Sanitize()
	if _, err := f.pool.Raw().Exec(ctx, "GRANT USAGE ON SCHEMA "+quotedSchema+" TO "+quotedRole+"; GRANT SELECT ON "+table+" TO "+quotedRole); err != nil {
		t.Fatal("grant only exact-table provider authority reads", err)
	}
	var selectOnly bool
	if err := f.pool.Raw().QueryRow(ctx, `SELECT has_table_privilege($1,$2,'SELECT') AND
 NOT has_table_privilege($1,$2,'INSERT,UPDATE,DELETE,TRUNCATE') AND
 NOT has_schema_privilege($1,$3,'CREATE') AND
 (SELECT NOT rolsuper AND NOT rolbypassrls AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication FROM pg_roles WHERE rolname=$1)`,
		p.readerRole, table, p.production.Native.Schema).Scan(&selectOnly); err != nil || !selectOnly {
		t.Fatal("the shared provider reader is not SELECT-only", err)
	}
	operatorAuthority, err := oauthpg.NewProviderAuthority(f.pool, p.production.Native.Schema, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	p.operator, err = oauthpg.NewProviderAuthorityOperator(operatorAuthority, p.production.Native.Actor)
	if err != nil {
		t.Fatal("construct the separately authorized native provider operator", err)
	}
	p.changeProviderAuthority(t, ctx, true)
	if p.retirement != nil {
		history, err := (oauthpg.ProxyRetirementMigrationSource{
			Schema: p.production.Native.Schema, Version: 44, Kind: kernel.OAuthProxyRetireProduction,
		}).Load(ctx)
		if err != nil || len(history) != 2 {
			t.Fatal("load the opt-in production retirement migration suffix", err)
		}
		for _, migration := range history {
			tx, err := f.pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal("begin production retirement migration", err)
			}
			if _, err := tx.Exec(ctx, migration.UpSQL()); err != nil {
				_ = tx.Rollback(ctx)
				t.Fatal("install production retirement migration", err)
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal("commit production retirement migration", err)
			}
		}
	}
}

func (p *referenceOAuthProxyPreviewProof) changeProviderAuthority(t *testing.T, ctx context.Context, enabled bool) oauthpg.ProviderAuthorityChange {
	t.Helper()
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	next := p.epoch + 1
	if p.epoch == 0 {
		next = 41
	}
	change := oauthpg.ProviderAuthorityChange{
		Key:             oauthpg.ProviderAuthorityKey{TenantID: p.production.Start.Preview.TenantID, ProviderID: p.production.Start.Provider.Profile().ID},
		ExpectedVersion: p.epoch, Next: oauthpg.ProviderAuthorityState{Version: next, ProfileVersion: p.production.Start.Provider.Profile().Version, Enabled: enabled},
		CommandID: command,
	}
	if state, err := p.operator.Apply(ctx, change); err != nil || state != change.Next {
		t.Fatal("commit the exact native provider authority transition", state, err)
	}
	p.epoch = next
	return change
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
	var f liveStores
	if p.productionFixture != nil {
		f = *p.productionFixture
	} else {
		f = newLiveStoresProfile(t, ctx, true, true)
	}
	productionConfig := p.production
	installOAuthProxyProductionFixture(t, ctx, f, productionConfig, true)
	if p.authority != nil {
		// This database was created before the preview graph's audit cleanup
		// was registered. Release its shared role grants before that cleanup.
		t.Cleanup(func() {
			bounded, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if _, err := f.pool.Raw().Exec(bounded, "DROP OWNED BY audit_writer,audit_reader,audit_retention"); err != nil {
				t.Error("release production grants on the preview-owned audit roles", err)
			}
		})
		p.installProviderAuthority(t, ctx, f)
	}
	runtimePool := newOAuthProxyProductionRuntimePool(t, ctx, f)
	if p.maintenance {
		p.installMaintenance(t, ctx, c, f, runtimePool)
	}
	productionConfig.HTTP = oauthProxyProductionHTTPConfiguration(t, runtimePool)
	var production *reference.OAuthProxyProduction
	var err error
	if p.maintenance {
		production, err = reference.NewOAuthProxyProductionWithMaintenance(runtimePool, productionConfig, p.authority)
	} else if p.retirement != nil {
		production, err = reference.NewOAuthProxyProductionWithRetirement(runtimePool, productionConfig, p.authority, p.retirement)
	} else if p.authority != nil {
		production, err = reference.NewOAuthProxyProductionWithProviderAuthority(runtimePool, productionConfig, p.authority)
	} else {
		production, err = reference.NewOAuthProxyProduction(runtimePool, productionConfig)
	}
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
	startRequest := reference.OAuthProxyPreviewStartRequest{
		Initiation: oauthproxy.InitiationRequest{
			Credential: authentication.NewBearerCredential("synthetic-production-preview-invocation"),
			CommandID:  command, TransactionID: flow, RequestFingerprint: sha256.Sum256([]byte("reference-preview-original-request")), Remember: remember,
		},
		FlowCookie: flowCookie, Network: "127.0.0.1", Device: deviceID,
	}
	if p.authority != nil {
		static, err := reference.NewOAuthProxyProduction(runtimePool, productionConfig)
		if err != nil {
			t.Fatal("construct the mismatched static production bridge", err)
		}
		withheld, err := features.StartOAuthProxyPreview(ctx, static, startRequest)
		if !errors.Is(err, oauthproxy.CompletionDenied) || withheld.URL() != "" || p.provider.exchanges.Load() != beforeExchanges {
			t.Fatal("a static production owner entered the live preview bridge", err)
		}
		var noOriginal bool
		if err := f.pool.Raw().QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM synthetic_oauth.proxy_transactions WHERE tenant_id=$1 AND transaction_id=$2)`,
			otpTenant, string(flow)).Scan(&noOriginal); err != nil || !noOriginal {
			t.Fatal("mismatched bridge mode consumed the original live Start input", err)
		}
	}
	authorization, err := features.StartOAuthProxyPreview(ctx, production, startRequest)
	if err != nil {
		t.Fatal("the public preview owner did not acknowledge both native origin bindings", err)
	}
	if p.maintenance {
		p.proveMaintenance(t, ctx, c, features, production, app, base, origin, startRequest, authorization.URL())
		return
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
	if p.authority == nil {
		return
	}

	type liveAttempt struct {
		browser  *http.Client
		flow     identity.PreAuthTransactionID
		command  identity.CommandID
		callback *url.URL
	}
	startLiveAttempt := func(label string) liveAttempt {
		t.Helper()
		client := newBrowser()
		flow, cookies := issueFlow(client)
		var credential authentication.BearerCredential
		var device string
		for _, cookie := range cookies {
			if cookie.Name == flowPolicy.Name {
				credential = authentication.NewBearerCredential(cookie.Value)
			}
			if cookie.Name == devicePolicy.Name {
				resolved, err := deviceCodec.Resolve(ctx, time.Now(), otpTenant, origin, cookie.Value)
				if err != nil {
					t.Fatal("resolve the new original browser device", err)
				}
				device = resolved.DeviceID()
			}
		}
		command, err := identity.NewCommandID()
		if err != nil || credential.Token() == "" || device == "" {
			t.Fatal("prepare a fresh live-provider original browser", err)
		}
		authorization, err := features.StartOAuthProxyPreview(ctx, production, reference.OAuthProxyPreviewStartRequest{
			Initiation: oauthproxy.InitiationRequest{
				Credential: authentication.NewBearerCredential("synthetic-production-preview-invocation"),
				CommandID:  command, TransactionID: flow, RequestFingerprint: sha256.Sum256([]byte(label)), Remember: remember,
			},
			FlowCookie: credential, Network: "127.0.0.1", Device: device,
		})
		if err != nil {
			t.Fatal("acknowledge a fresh original through both live Reference owners", err)
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, authorization.URL(), nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := providerClient.Do(request)
		if err != nil {
			t.Fatal("authorize the fresh original at the controlled issuer", err)
		}
		response.Body.Close()
		callback, err := url.Parse(response.Header.Get("Location"))
		if err != nil || response.StatusCode != http.StatusSeeOther || callback.Scheme+"://"+callback.Host+callback.Path != p.provider.proxyRedirect {
			t.Fatal("fresh original did not return the exact production callback", err)
		}
		return liveAttempt{browser: client, flow: flow, command: command, callback: callback}
	}
	invokeProductionCallback := func(callback *url.URL) (*http.Response, []byte) {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, productionServer.URL+callback.RequestURI(), nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Host = "production.example"
		response, err := productionClient.Do(request)
		if err != nil {
			t.Fatal("invoke the original callback through restricted live Reference production", err)
		}
		wire, readErr := io.ReadAll(io.LimitReader(response.Body, 1025))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || len(wire) > 1024 {
			t.Fatal("read the bounded production callback response")
		}
		return response, wire
	}
	old := startLiveAttempt("reference-live-before-disable")
	beforeDisabledExchanges := p.provider.exchanges.Load()
	beforeDisabledRevocations := p.provider.proxyRevocations.Load()
	disable := p.changeProviderAuthority(t, ctx, false)
	assertOldCallbackRefused := func() {
		t.Helper()
		response, _ := invokeProductionCallback(old.callback)
		if response.StatusCode < 400 || response.Header.Get("Location") != "" || len(response.Cookies()) != 0 ||
			p.provider.exchanges.Load() != beforeDisabledExchanges || p.provider.proxyRevocations.Load() != beforeDisabledRevocations {
			t.Fatal("invalidated live original exchanged with the provider or returned a handoff", response.StatusCode)
		}
		if readSessionCount() != beforeSessions+1 {
			t.Fatal("invalidated production original created a preview session")
		}
		readSession(old.browser, false)
	}
	assertOldCallbackRefused()
	p.changeProviderAuthority(t, ctx, true)
	assertOldCallbackRefused()

	fresh := startLiveAttempt("reference-live-after-reenable")
	if fresh.command == old.command || fresh.flow == old.flow || fresh.callback.Query().Get("state") == old.callback.Query().Get("state") {
		t.Fatal("fresh live Start reused the invalidated command, transaction or state")
	}
	if p.retirement != nil {
		p.proveRetirement(t, ctx, f, c, features, production, old.command, old.flow, fresh.command, fresh.flow, disable)
		assertOldCallbackRefused()
		return
	}
	freshForwarded, freshBody := invokeProductionCallback(fresh.callback)
	freshHandoff, err := url.Parse(freshForwarded.Header.Get("Location"))
	if err != nil || freshForwarded.StatusCode != http.StatusSeeOther || len(freshBody) != 0 || len(freshForwarded.Cookies()) != 0 ||
		freshHandoff.Scheme+"://"+freshHandoff.Host+freshHandoff.Path != origin+reference.OAuthProxyPreviewPath || freshHandoff.RawQuery != "" ||
		p.provider.exchanges.Load() != beforeDisabledExchanges+1 || p.provider.proxyRevocations.Load() != beforeDisabledRevocations+1 {
		t.Fatal("fresh live epoch did not forward one exact tokenless handoff", freshForwarded.StatusCode)
	}
	freshParts := strings.Split(freshHandoff.Fragment, ".")
	if len(freshParts) != 3 || freshParts[0] != "identity-proxy-v1" || freshParts[1] != string(fresh.flow) {
		t.Fatal("fresh live handoff lost its original preview transaction")
	}
	freshEnvelope, err := base64.RawURLEncoding.Strict().DecodeString(freshParts[2])
	if err != nil || len(freshEnvelope) == 0 || len(freshEnvelope) > 8192 {
		t.Fatal("fresh live handoff did not carry a bounded evidence envelope", err)
	}
	defer clear(freshEnvelope)
	freshPayload, err := json.Marshal(map[string]string{"flow": freshParts[1], "envelope": freshParts[2]})
	if err != nil {
		t.Fatal(err)
	}
	p.changeProviderAuthority(t, ctx, false)
	assertBoundHandoffRefused := func() {
		t.Helper()
		response, _ := call(fresh.browser, http.MethodPost, reference.OAuthProxyPreviewPath, string(freshPayload), "")
		if response.StatusCode < 400 || len(response.Cookies()) != 0 || response.Header.Get("Location") != "" || readSessionCount() != beforeSessions+1 {
			t.Fatal("shared provider invalidation disclosed a preview cookie or persisted a session", response.StatusCode)
		}
		readSession(fresh.browser, false)
		var unchanged bool
		if err := p.previewPool.Raw().QueryRow(ctx, `SELECT b.version=1 AND b.proof_ciphertext IS NOT NULL AND
 (SELECT state='issued' FROM `+flowsTable+` WHERE tenant_id=$1 AND flow_id=$2) AND
 NOT EXISTS(SELECT FROM audit.identity_command_bindings a WHERE a.command_id=b.callback_command_id) AND
 NOT EXISTS(SELECT FROM public.identity_outbox_bindings o WHERE o.command_id=b.callback_command_id)
 FROM `+bindingsTable+` b WHERE b.tenant_id=$1 AND b.flow_id=$2`, otpTenant, string(fresh.flow)).Scan(&unchanged); err != nil || !unchanged {
			t.Fatal("refused live handoff changed preview browser, grant, audit or lifecycle custody", err)
		}
		if p.provider.exchanges.Load() != beforeDisabledExchanges+1 || p.provider.proxyRevocations.Load() != beforeDisabledRevocations+1 {
			t.Fatal("refused live preview completion repeated provider work")
		}
	}
	assertBoundHandoffRefused()
	p.changeProviderAuthority(t, ctx, true)
	assertBoundHandoffRefused()
}

func (p *referenceOAuthProxyPreviewProof) proveRetirement(t *testing.T, ctx context.Context, productionFixture liveStores,
	c reference.StoreConfiguration, features reference.FeatureSet, production *reference.OAuthProxyProduction,
	oldCommand identity.CommandID, oldFlow identity.PreAuthTransactionID,
	newCommand identity.CommandID, newFlow identity.PreAuthTransactionID, disable oauthpg.ProviderAuthorityChange) {
	t.Helper()
	snapshot := func(pool *database.Pool, query string, args ...any) string {
		t.Helper()
		var value string
		if err := pool.Raw().QueryRow(ctx, query, args...).Scan(&value); err != nil {
			t.Fatal("snapshot exact local retirement custody", err)
		}
		return value
	}
	sessionSchema := c.Session.Native.Execution.Repository.Schema
	sessions := pgx.Identifier{sessionSchema, "sessions"}.Sanitize()
	families := pgx.Identifier{sessionSchema, "families"}.Sanitize()
	issuances := pgx.Identifier{sessionSchema, "session_issuances"}.Sanitize()
	flows := pgx.Identifier{sessionSchema, "preauth_transactions"}.Sanitize()
	browserSQL := `SELECT jsonb_build_array(
 (SELECT jsonb_agg(to_jsonb(s) ORDER BY to_jsonb(s)::text) FROM ` + sessions + ` s),
 (SELECT jsonb_agg(to_jsonb(f) ORDER BY to_jsonb(f)::text) FROM ` + families + ` f),
 (SELECT jsonb_agg(to_jsonb(i) ORDER BY to_jsonb(i)::text) FROM ` + issuances + ` i),
 (SELECT jsonb_agg(to_jsonb(p) ORDER BY flow_id) FROM ` + flows + ` p))::text`
	browsers := snapshot(p.previewPool, browserSQL)
	exchanges, revocations := p.provider.exchanges.Load(), p.provider.proxyRevocations.Load()
	productionTable := pgx.Identifier{p.production.Native.Schema, "proxy_transactions"}.Sanitize()
	previewTable := pgx.Identifier{c.SocialOAuth.Schema, "proxy_preview_bindings"}.Sanitize()

	for _, local := range []struct {
		name, table, flowColumn, purpose, erasedColumns string
		pool                                            *database.Pool
		retire                                          func(context.Context, oauthpg.ProxyOriginRetirementRequest) (identity.CommandResult, error)
	}{
		{"production", productionTable, "transaction_id", "identity.oauth.proxy-forward",
			"'state_proof_ciphertext','pkce_ciphertext','handoff_ciphertext'", productionFixture.pool, production.RetireDisabledProviderOrigin},
		{"preview", previewTable, "flow_id", "identity.oauth.callback",
			"'proof_ciphertext'", p.previewPool, features.RetireDisabledOAuthProxyPreviewOrigin},
	} {
		t.Run(local.name, func(t *testing.T) {
			var grantID, grantProvenance string
			if err := local.pool.Raw().QueryRow(ctx, `SELECT capability_id,(to_jsonb(g)-'state')::text
 FROM public.capability_identity_one_use g WHERE tenant_id=$1 AND origin_command_id=$2
 AND subject_id=$3 AND purpose=$4 AND state='issued' AND uses=0`, string(otpTenant), string(oldCommand),
				string(oldFlow), local.purpose).Scan(&grantID, &grantProvenance); err != nil {
				t.Fatal("read the exact old unused local grant", err)
			}
			custodySQL := `SELECT to_jsonb(p)::text FROM ` + local.table + ` p WHERE tenant_id=$1 AND ` + local.flowColumn + `=$2`
			stableSQL := `SELECT (to_jsonb(p)-ARRAY['version',` + local.erasedColumns + `,
 'retirement_source_command_id','retirement_source_version','retired_at'])::text
 FROM ` + local.table + ` p WHERE tenant_id=$1 AND ` + local.flowColumn + `=$2`
			journalSQL := `SELECT COALESCE(jsonb_agg(to_jsonb(c) ORDER BY c.command_id),'[]'::jsonb)::text
 FROM identity.commands c WHERE c.tenant_id=$1 AND c.command_id IN
 (SELECT callback_command_id FROM ` + local.table + ` WHERE tenant_id=$1)`
			otherGrantsSQL := `SELECT COALESCE(jsonb_agg(to_jsonb(g) ORDER BY capability_id),'[]'::jsonb)::text
 FROM public.capability_identity_one_use g WHERE capability_id<>$1`
			newGrantSQL := `SELECT to_jsonb(g)::text FROM public.capability_identity_one_use g
 WHERE tenant_id=$1 AND origin_command_id=$2 AND subject_id=$3 AND purpose=$4 AND state='issued' AND uses=0`
			oldCustody := snapshot(local.pool, stableSQL, string(otpTenant), string(oldFlow))
			newCustody := snapshot(local.pool, custodySQL, string(otpTenant), string(newFlow))
			newGrant := snapshot(local.pool, newGrantSQL, string(otpTenant), string(newCommand), string(newFlow), local.purpose)
			journal := snapshot(local.pool, journalSQL, string(otpTenant))
			otherGrants := snapshot(local.pool, otherGrantsSQL, grantID)
			command, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			request := oauthpg.ProxyOriginRetirementRequest{
				CommandID: command, OriginCommandID: oldCommand, FlowID: oldFlow, Disable: disable,
			}
			result, err := local.retire(ctx, request)
			if err != nil || result.Outcome != identity.CommitOutcomeCommitted || result.Validate() != nil ||
				result.Binding.CommandID != command || result.Feature == nil || result.Feature.Operation != kernel.OAuthProxyOriginRetirementOperation() {
				t.Fatal("public Reference owner did not commit exact disabled-origin retirement", result.Outcome, err)
			}
			assertEffects := func() {
				t.Helper()
				source, err := base64.RawURLEncoding.Strict().DecodeString(string(disable.CommandID))
				if err != nil {
					t.Fatal(err)
				}
				erased := "proof_ciphertext IS NULL"
				if local.name == "production" {
					erased = "state_proof_ciphertext IS NULL AND pkce_ciphertext IS NULL AND handoff_ciphertext IS NULL AND outcome IS NULL"
				}
				var retired bool
				if err := local.pool.Raw().QueryRow(ctx, `SELECT version=3 AND `+erased+`
 AND binding_ciphertext IS NOT NULL AND settled_at IS NULL AND retirement_source_command_id=$3
 AND retirement_source_version=$4::numeric AND retired_at IS NOT NULL AND retired_at>=issued_at
 FROM `+local.table+` WHERE tenant_id=$1 AND `+local.flowColumn+`=$2`, string(otpTenant), string(oldFlow),
					source, disable.Next.Version).Scan(&retired); err != nil || !retired {
					t.Fatal("local retirement retained bearer custody, lost disable provenance or fabricated callback settlement", err)
				}
				var state, provenance string
				if err := local.pool.Raw().QueryRow(ctx, `SELECT state,(to_jsonb(g)-'state')::text
 FROM public.capability_identity_one_use g WHERE capability_id=$1`, grantID).Scan(&state, &provenance); err != nil ||
					state != "revoked" || provenance != grantProvenance {
					t.Fatal("local retirement did not revoke only the exact unused original grant", err)
				}
				if snapshot(local.pool, stableSQL, string(otpTenant), string(oldFlow)) != oldCustody ||
					snapshot(local.pool, custodySQL, string(otpTenant), string(newFlow)) != newCustody ||
					snapshot(local.pool, newGrantSQL, string(otpTenant), string(newCommand), string(newFlow), local.purpose) != newGrant ||
					snapshot(local.pool, journalSQL, string(otpTenant)) != journal || snapshot(local.pool, otherGrantsSQL, grantID) != otherGrants ||
					snapshot(p.previewPool, browserSQL) != browsers {
					t.Fatal("retirement changed original binding, callback journal, session, browser or newer-epoch custody")
				}
				commandBytes, err := base64.RawURLEncoding.Strict().DecodeString(string(command))
				if err != nil {
					t.Fatal(err)
				}
				var audits, events int
				if err := local.pool.Raw().QueryRow(ctx, `SELECT
 (SELECT count(*) FROM audit.identity_command_bindings WHERE tenant_id=$1 AND command_id=$2),
 (SELECT count(*) FROM public.identity_outbox_bindings WHERE tenant_id=$1 AND command_id=$2)`,
					string(otpTenant), commandBytes).Scan(&audits, &events); err != nil || audits != 1 || events != 1 {
					t.Fatal("local retirement did not retain exactly one audit and lifecycle effect", audits, events, err)
				}
				if p.provider.exchanges.Load() != exchanges || p.provider.proxyRevocations.Load() != revocations {
					t.Fatal("local retirement performed external provider work")
				}
			}
			assertEffects()
			retiredCustody := snapshot(local.pool, custodySQL, string(otpTenant), string(oldFlow))
			replay, err := local.retire(ctx, request)
			if err != nil || !reflect.DeepEqual(replay, result) ||
				snapshot(local.pool, custodySQL, string(otpTenant), string(oldFlow)) != retiredCustody {
				t.Fatal("exact public retirement replay did not recover the same result and custody", err)
			}
			assertEffects()
		})
	}
}
