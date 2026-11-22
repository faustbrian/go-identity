//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	emailhttp "github.com/faustbrian/go-identity/http/email"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/reference"
)

func TestReferencePostgresEnterpriseOIDCLinkJourney(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
		postgresBaseline: true, organization: true, enterpriseOIDC: true, enterpriseOIDCLink: true,
	})
}

func referenceLinkPOST(t *testing.T, ctx context.Context, client *http.Client, origin, path, key, csrf string, body any) *http.Response {
	t.Helper()
	wire, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+path, bytes.NewReader(wire))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", origin)
	if key != "" {
		r.Header.Set("Idempotency-Key", key)
	}
	if csrf != "" {
		r.Header.Set("X-CSRF-Token", csrf)
	}
	out, err := client.Do(r)
	if err != nil {
		t.Fatal("enterprise link HTTPS request failed")
	}
	return out
}

func prepareReferenceEnterpriseLinkMember(t *testing.T, ctx context.Context, client *http.Client, origin string, workers reference.WorkerSet, messages <-chan string) (enterpriseProvisioned, *http.Client, string) {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	browser := *client
	browser.Jar = jar
	browser.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	post := func(path, key string, body any, out any) *http.Response {
		t.Helper()
		r := referenceLinkPOST(t, ctx, &browser, origin, path, key, "", body)
		defer r.Body.Close()
		if r.StatusCode != http.StatusOK || json.NewDecoder(r.Body).Decode(out) != nil {
			t.Fatalf("prepare actual enterprise member via %s: status %d", path, r.StatusCode)
		}
		return r
	}
	issue := func(method string) identity.PreAuthTransactionID {
		t.Helper()
		var out sessionhttp.PreAuthResponse
		post("/v1/session/preauth-issue", "", map[string]string{"method": method}, &out)
		return out.FlowID
	}
	const address, password = "enterprise-member@example.invalid", "synthetic-enterprise-member-password"
	var signup passwordhttp.SignupResponse
	post("/v1/password/signup", "enterprise-link-signup", map[string]any{
		"flowID": issue("signup"), "email": address, "password": password, "callbackURL": origin + "/confirm",
	}, &signup)
	if signup.CommitOutcome != "committed" || !signup.VerificationRequired {
		t.Fatal("actual member signup did not commit")
	}
	if _, err := workers.ProcessDeliveryOne(ctx, 0); err != nil {
		t.Fatal("actual enterprise member verification delivery", err)
	}
	var link *url.URL
	select {
	case delivered := <-messages:
		link, err = url.Parse(delivered)
	case <-ctx.Done():
		t.Fatal("enterprise member verification not delivered")
	}
	if err != nil || link == nil || link.Scheme != "https" || link.Query().Get("token") == "" {
		t.Fatal("malformed enterprise member verification")
	}
	var verified emailhttp.ConfirmationResponse
	post("/v1/email/verification-confirm", "", map[string]string{
		"token": link.Query().Get("token"), "callback": origin + "/confirm", "commandID": string(enterpriseCommand(t)),
	}, &verified)
	if !verified.Confirmed || verified.Replayed || verified.Recovery == nil {
		t.Fatal("actual member verification did not commit")
	}
	var signed passwordhttp.SigninResponse
	response := post("/v1/password/signin", "", map[string]any{
		"flowID": issue("password"), "identifier": address, "password": password, "callbackURL": origin + "/reset",
	}, &signed)
	if !signed.SignedIn || signed.CommitOutcome != "committed" || signed.SessionID == "" || response.Header.Get("X-CSRF-Token") == "" {
		t.Fatal("actual password sign-in did not issue the member's local credentials")
	}
	for _, cookie := range response.Cookies() {
		if cookie.HttpOnly && cookie.Secure && cookie.SameSite == http.SameSiteLaxMode && strings.HasPrefix(cookie.Name, "__Host-") {
			return enterpriseProvisioned{user: verified.Recovery.UserID, bearer: auth.NewBearerCredential(cookie.Value)}, &browser, response.Header.Get("X-CSRF-Token")
		}
	}
	t.Fatal("actual password sign-in did not issue a host-only Lax session")
	return enterpriseProvisioned{}, nil, ""
}

func proveReferenceEnterpriseLinkUpgrade(t *testing.T, ctx context.Context, c reference.StoreConfiguration, deps reference.ReferenceDependencies,
	config reference.ReferenceConfig, modules []reference.ModuleID, workers []deliverypg.WorkerConfig, selected enterpriseProvisioned,
	active *atomic.Pointer[http.Handler], base, browser *http.Client, csrf, origin string, provider *referenceEnterpriseIssuer,
) {
	t.Helper()
	use := func(server *reference.Server) {
		handler := server.Handler()
		active.Store(&handler)
	}
	ordinary, _ := selectProvisionedEnterprise(t, ctx, c, deps, config, selected, workers, nil)
	use(ordinary)
	input := map[string]any{"link": true, "commandID": string(enterpriseCommand(t)), "providerID": string(selected.provider),
		"callback": origin + "/enterprise/complete", "errorCallback": origin + "/enterprise/error"}
	start := func(csrf string) *http.Response {
		t.Helper()
		return referenceLinkPOST(t, ctx, browser, origin, "/v1/sso/signin-start", "enterprise-link-consent", csrf, input)
	}
	denied := func(r *http.Response) {
		t.Helper()
		defer r.Body.Close()
		if r.StatusCode < 400 || r.Header.Get("Location") != "" || r.Header.Get("Set-Cookie") != "" || r.Header.Get("X-CSRF-Token") != "" {
			t.Fatal("denied enterprise link disclosed a redirect or credentials", r.StatusCode)
		}
	}
	denied(start(csrf))
	selectedHTTP := *c.HTTPEnterpriseOIDC
	selectedHTTP.ExplicitLink = true
	c.HTTPEnterpriseOIDC = &selectedHTTP
	upgraded, features := selectProvisionedEnterprise(t, ctx, c, deps, config, selected, workers, func(stores reference.StoreSet) {
		request := applyRequest(t, ctx, stores, modules)
		request.CommandID, request.IdempotencyKey = "migration_command_0002", enterpriseKey(t, "enterprise-link-migration")
		result, err := stores.ReferenceMigrationApply(ctx, request)
		if err != nil || result.Result.State() != reference.MigrationApplied {
			t.Fatal("explicit link could not upgrade the populated ordinary enterprise graph", err, result.Result.State())
		}
	})
	use(upgraded)
	count := func(want int) {
		t.Helper()
		var count int
		if err := deps.PostgreSQL.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.accounts WHERE tenant_id=$1 AND user_id=$2 AND issuer=$3 AND subject=$4 AND linked`,
			otpTenant, string(selected.user), provider.server.URL, enterpriseProviderSubject).Scan(&count); err != nil || count != want {
			t.Fatal("unexpected durable enterprise association count", count, err)
		}
	}
	denied(start(""))
	count(0)
	r := start(csrf)
	var started struct{ AuthorizationURL, TransactionID string }
	err := json.NewDecoder(r.Body).Decode(&started)
	_ = r.Body.Close()
	if r.StatusCode != http.StatusOK || err != nil || started.AuthorizationURL == "" || started.TransactionID == "" || r.Header.Get("Set-Cookie") != "" {
		t.Fatal("opted-in enterprise member start did not commit", r.StatusCode)
	}
	external := *provider.server.Client()
	external.CheckRedirect = browser.CheckRedirect
	authorized, err := external.Get(started.AuthorizationURL)
	if err != nil {
		t.Fatal("signed enterprise verifier authorization failed")
	}
	_ = authorized.Body.Close()
	callback := authorized.Header.Get("Location")
	if authorized.StatusCode != http.StatusSeeOther || !strings.HasPrefix(callback, origin+"/sso/oidc/callback?") {
		t.Fatal("enterprise link did not select the configured shared callback")
	}
	get := func(client *http.Client) *http.Response {
		t.Helper()
		out, err := client.Get(callback)
		if err != nil {
			t.Fatal("enterprise member callback request failed")
		}
		return out
	}
	unbound := *base
	unbound.CheckRedirect = browser.CheckRedirect
	denied(get(&unbound))
	if provider.posts.Load() != 0 {
		t.Fatal("unbound browser caused an exchange")
	}
	linked := get(browser)
	_ = linked.Body.Close()
	if linked.StatusCode != http.StatusSeeOther || linked.Header.Get("Location") != origin+"/enterprise/complete" ||
		linked.Header.Get("Set-Cookie") != "" || linked.Header.Get("X-CSRF-Token") != "" || provider.posts.Load() != 1 {
		t.Fatal("enterprise link did not commit exactly once without delivering credentials", linked.StatusCode)
	}
	denied(get(browser))
	if provider.posts.Load() != 1 {
		t.Fatal("enterprise link replay exchanged again")
	}
	count(1)
	proveReferenceEnterpriseOIDCJourney(t, ctx, base, origin, features, provider, selected)
}
