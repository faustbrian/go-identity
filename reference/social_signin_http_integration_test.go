//go:build integration

package reference_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	oauthpg "github.com/faustbrian/go-identity/oauth/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
)

func TestReferencePostgresConfiguredOIDCSigninHTTP(t *testing.T) {
	for _, scenario := range []struct {
		name             string
		remember, denied bool
		postAuth         bool
	}{{"browser", false, false, false}, {"persistent", true, false, false}, {"provider-denial", false, true, false}, {"post-authentication", false, false, true}} {
		t.Run(scenario.name, func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, socialOIDC: true, socialOIDCLinkOnly: true, socialOIDCHTTPSignin: true, socialOIDCHTTPRemember: scenario.remember, socialOIDCHTTPDenial: scenario.denied, socialOIDCPostAuth: scenario.postAuth}, true)
		})
	}
}

func TestReferencePostgresConfiguredOIDCSigninHTTPRejectsForeignPreAuthOrigin(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
		postgresBaseline: true, socialOIDC: true, socialOIDCLinkOnly: true,
		socialOIDCHTTPSignin: true, socialOIDCHTTPForeignOrigin: true,
	}, true)
}

func configureReferenceSocialSigninHTTP(t *testing.T, c *reference.StoreConfiguration) {
	t.Helper()
	pc := registrationRiskPolicyConfig(3, false)
	for i, operation := range []risk.Action{"identity.password.signin", "identity.password.change", "identity.oauth-server.client-create", "identity.session.get"} {
		admitted, err := c.DurableAdmission.Policy.Admit(operation)
		if err != nil {
			t.Fatal(err)
		}
		pc.Profiles[i], pc.Version = admitted.Profile, admitted.PolicyVersion
	}
	pc.OAuthProviderDiscovery = true
	policy, err := risk.NewPolicy(pc)
	if err != nil {
		t.Fatal(err)
	}
	// This selected browser profile must carry the original session through a
	// cross-site provider GET. Existing strict-only fixtures inject cookies and
	// cannot establish that navigation contract.
	previous, err := c.PasswordSignin.Native.Issuance.Cookie.DeletionAttributes()
	if err != nil {
		t.Fatal(err)
	}
	authentication, err := session.NewCookiePolicy(session.CookieConfig{Name: previous.Name, SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	c.PasswordSignin.Native.Issuance.Cookie = authentication
	c.OTP.Signin.Issuer.Cookie = authentication
	c.Session.Native.Cookie = authentication
	c.DurableAdmission.Policy = policy
	p := c.PasswordSignup.PreAuth
	csrf, err := session.NewCSRFCookiePolicy(session.CookieConfig{Name: "__Host-identity_csrf", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	n := c.PasswordSignin.Native
	c.SocialOAuth.Signin = &reference.SocialOAuthSigninConfiguration{
		ActorID: p.ActorID, CallbackURL: c.SocialOAuth.CallbackAllowlist[0], FlowKeyIndex: p.FlowKeyIndex,
		FlowTTL: p.FlowTTL, TokenSize: p.TokenSize, FlowCookie: p.Cookie,
		RiskConfigurationID: "reference-social-authentication-v1", CSRFCookie: csrf,
		Completion: oauthpg.SigninCompletionConfig{ConfigurationID: "reference-social-signin-v1", PolicyNamespace: n.Profile.PolicyNamespace, Audience: n.Profile.Audience, Issuer: n.Issuance, CSRF: n.CSRFKey},
	}
	c.HTTPSocialOAuth.SigninStart = true
}

// The real configured graph creates and links the account before this call.
// A new cookie jar represents a browser with no authenticated session. Only the
// external issuer is controlled; preauth, exchange, persistence, reading and
// strict logout all enter the actual configured public HTTP server.
func proveReferenceSocialSigninHTTP(t *testing.T, ctx context.Context, base *http.Client, endpoint, origin string, provider *referenceSocialOIDCIssuer, user identity.UserID, remember, denied bool) {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := *base
	client.Jar = jar
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	post := func(path, body string, headers map[string]string) *http.Response {
		t.Helper()
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		for name, value := range headers {
			r.Header.Set(name, value)
		}
		out, err := client.Do(r)
		if err != nil {
			t.Fatal("configured OAuth public request", err)
		}
		return out
	}
	preauthBody, _ := json.Marshal(map[string]any{"method": "oauth", "remember": remember})
	preauth := post("/v1/session/preauth-issue", string(preauthBody), nil)
	var flow struct {
		FlowID string `json:"flowID"`
	}
	err = json.NewDecoder(preauth.Body).Decode(&flow)
	preauth.Body.Close()
	if preauth.StatusCode != 200 || err != nil || flow.FlowID == "" {
		t.Fatal("public OAuth original browser issuance failed", preauth.StatusCode, err)
	}
	body, _ := json.Marshal(map[string]any{"flowID": flow.FlowID, "provider": "reference-oidc", "callback": origin + "/social/complete", "errorCallback": origin + "/social/error", "scopes": []string{"openid", "profile"}, "signupDisabled": true, "remember": remember})
	initiate := func() (string, string) {
		t.Helper()
		out := post("/v1/oauth/signin-start", string(body), map[string]string{"Idempotency-Key": "reference-http-original"})
		var result struct{ RedirectURI, TransactionID string }
		err := json.NewDecoder(out.Body).Decode(&result)
		out.Body.Close()
		if out.StatusCode != 200 || err != nil || result.RedirectURI == "" || result.TransactionID == "" {
			t.Fatal("public original OAuth initiation failed", out.StatusCode, err)
		}
		return result.RedirectURI, result.TransactionID
	}
	authorize, transaction := initiate()
	if retried, id := initiate(); retried != authorize || id != transaction {
		t.Fatal("HTTP keyed retry renewed/replaced original authorization state")
	}
	before := provider.exchanges.Load()
	provider.denyAuthorization.Store(denied)
	authorization, err := client.Get(authorize)
	if err != nil {
		t.Fatal(err)
	}
	authorization.Body.Close()
	if authorization.StatusCode != http.StatusSeeOther {
		t.Fatal("controlled provider did not navigate back", authorization.StatusCode)
	}
	callbackURL := authorization.Header.Get("Location")
	callback, err := client.Get(callbackURL)
	if err != nil {
		t.Fatal(err)
	}
	callback.Body.Close()
	if denied {
		if callback.StatusCode != 303 || callback.Header.Get("Location") != origin+"/social/error" || len(callback.Cookies()) != 0 || provider.exchanges.Load() != before {
			t.Fatal("provider denial created credentials, exchanged or lost its original redirect", callback.StatusCode)
		}
		replay, err := client.Get(callbackURL)
		if err != nil {
			t.Fatal(err)
		}
		replay.Body.Close()
		if replay.StatusCode != 303 || replay.Header.Get("Location") != origin+"/social/error" || len(replay.Cookies()) != 0 || provider.exchanges.Load() != before {
			t.Fatal("denial replay changed the terminal outcome or created authority", replay.StatusCode)
		}
		out, err := client.Get(endpoint + "/v1/session/get")
		if err != nil {
			t.Fatal(err)
		}
		defer out.Body.Close()
		var state struct {
			Authenticated bool `json:"authenticated"`
		}
		if out.StatusCode != 200 || json.NewDecoder(out.Body).Decode(&state) != nil || state.Authenticated {
			t.Fatal("denied provider browser acquired a session", out.StatusCode)
		}
		return
	}
	if callback.StatusCode != 303 || callback.Header.Get("Location") != origin+"/social/complete" || provider.exchanges.Load() != before+1 || len(callback.Cookies()) != 2 {
		t.Fatal("configured callback did not deliver one committed browser session", callback.StatusCode)
	}
	csrf := ""
	for _, cookie := range callback.Cookies() {
		if !cookie.Secure || cookie.Path != "/" || cookie.Domain != "" || cookie.SameSite != http.SameSiteLaxMode {
			t.Fatal("OAuth cookie scope changed")
		}
		if remember && (cookie.MaxAge <= 0 || cookie.Expires.IsZero()) || !remember && (cookie.MaxAge != 0 || !cookie.Expires.IsZero()) {
			t.Fatal("OAuth did not retain its original resolved Remember choice")
		}
		if cookie.Name == "__Host-identity_csrf" {
			if cookie.HttpOnly {
				t.Fatal("provider redirect stranded the synchronizer token")
			}
			csrf = cookie.Value
		} else if !cookie.HttpOnly {
			t.Fatal("OAuth authentication cookie became browser-readable")
		}
	}
	if csrf == "" {
		t.Fatal("browser received no strict-logout synchronizer")
	}
	read := func(want bool) {
		t.Helper()
		out, err := client.Get(endpoint + "/v1/session/get")
		if err != nil {
			t.Fatal(err)
		}
		defer out.Body.Close()
		var state struct {
			Authenticated bool `json:"authenticated"`
			Principal     struct {
				UserID string `json:"userID"`
			} `json:"principal"`
		}
		if out.StatusCode != 200 || json.NewDecoder(out.Body).Decode(&state) != nil || state.Authenticated != want || want && state.Principal.UserID != string(user) {
			t.Fatal("common configured session owner did not read OAuth identity", out.StatusCode)
		}
	}
	read(true)
	wrong := post("/v1/session/signout", `{}`, map[string]string{"X-CSRF-Token": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"})
	io.Copy(io.Discard, wrong.Body)
	wrong.Body.Close()
	if wrong.StatusCode != 403 || len(wrong.Cookies()) != 0 {
		t.Fatal("wrong CSRF cleared or revoked OAuth browser session", wrong.StatusCode)
	}
	read(true)
	logout := post("/v1/session/signout", `{}`, map[string]string{"X-CSRF-Token": csrf})
	logout.Body.Close()
	if logout.StatusCode != 200 || len(logout.Cookies()) != 2 {
		t.Fatal("strict configured OAuth logout failed", logout.StatusCode)
	}
	read(false)
	// The original native callback is historical: replay never reveals either
	// credential or performs another provider exchange after logout.
	replay, err := client.Get(callbackURL)
	if err != nil {
		t.Fatal(err)
	}
	replay.Body.Close()
	if len(replay.Cookies()) != 0 || provider.exchanges.Load() != before+1 {
		t.Fatal("HTTP callback replay redisclosed credentials or exchanged again")
	}
}
