//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/oauth/onetap"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	"github.com/jackc/pgx/v5"
)

func TestReferencePostgresConfiguredOneTapRedirectHTTP(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, oneTapRedirect: true}, true)
}

func configureReferenceOneTapRedirect(t *testing.T, c *reference.StoreConfiguration, origin string) *rsa.PrivateKey {
	t.Helper()
	signing := configureReferenceOneTapPopup(t, c, origin)
	c.OneTap.Redirect = true
	c.OneTap.Start.Issuance.CallbackURL = origin + "/v1/oauth/onetap-callback"
	c.OneTap.Start.Issuance.Cookie = session.CookiePolicy{}
	return signing
}

// Only Google's remote signing keys are substituted. Original redirect start,
// callback proof, linked-account resolution and common session lifecycle run
// through the assembled Reference TLS server and its real PostgreSQL owners.
func proveReferenceOneTapRedirectTLS(t *testing.T, ctx context.Context, c reference.StoreConfiguration, deps reference.ReferenceDependencies, baseClient *http.Client, endpoint, origin string, signing *rsa.PrivateKey) {
	t.Helper()
	user, _ := seedEnterpriseAdministrator(t, ctx, deps.PostgreSQL, c)
	seedEnterpriseLinkedAccount(t, ctx, deps.PostgreSQL, user, "google", "https://accounts.google.com")
	execEnterpriseFixture(t, ctx, deps.PostgreSQL, `UPDATE identity.credential_references SET owner='identity/oauth' WHERE tenant_id=$1 AND user_id=$2 AND credential_id='enterprise-fixture-provider'`, otpTenant, string(user))
	client := *baseClient
	client.Jar = nil
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	call := func(method, path string, body any, sender, key, csrf string, cookies []*http.Cookie) (*http.Response, []byte) {
		t.Helper()
		var input io.Reader
		media := ""
		if fields, ok := body.(url.Values); ok {
			input = strings.NewReader(fields.Encode())
			media = "application/x-www-form-urlencoded"
		} else if body != nil {
			wire, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			input = bytes.NewReader(wire)
			media = "application/json"
		}
		request, err := http.NewRequestWithContext(ctx, method, endpoint+path, input)
		if err != nil {
			t.Fatal(err)
		}
		if sender != "" {
			request.Header.Set("Origin", sender)
		}
		if media != "" {
			request.Header.Set("Content-Type", media)
		}
		if key != "" {
			request.Header.Set("Idempotency-Key", key)
		}
		if csrf != "" {
			request.Header.Set("X-CSRF-Token", csrf)
		}
		for _, cookie := range cookies {
			request.AddCookie(cookie)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("configured One Tap redirect TLS request", err)
		}
		payload, readErr := io.ReadAll(io.LimitReader(response.Body, 16385))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || len(payload) > 16384 || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("One Tap redirect lost bounded no-store delivery")
		}
		return response, payload
	}
	readSession := func(cookies []*http.Cookie, authenticated bool) {
		t.Helper()
		response, payload := call(http.MethodGet, "/v1/session/get", nil, origin, "", "", cookies)
		var state struct {
			Authenticated bool `json:"authenticated"`
			Principal     struct {
				UserID string `json:"userID"`
			} `json:"principal"`
		}
		if response.StatusCode != http.StatusOK || json.Unmarshal(payload, &state) != nil || state.Authenticated != authenticated || authenticated && state.Principal.UserID != string(user) {
			t.Fatalf("common redirect session getter: status %d, authenticated %t (want %t), matching identity %t", response.StatusCode, state.Authenticated, authenticated, state.Principal.UserID == string(user))
		}
	}
	issuances := func(want int) {
		t.Helper()
		var actual int
		query := `SELECT count(*) FROM ` + pgx.Identifier{c.Session.Native.Execution.Repository.Schema}.Sanitize() + `.session_issuances WHERE tenant_id=$1 AND user_id=$2 AND purpose='identity.oauth.onetap-callback'`
		if err := deps.PostgreSQL.Raw().QueryRow(ctx, query, otpTenant, string(user)).Scan(&actual); err != nil || actual != want {
			t.Fatal("redirect denial or replay changed once-only session issuance", actual, want, err)
		}
	}
	preauth, _ := call(http.MethodPost, "/v1/session/preauth-issue", map[string]string{"method": "password"}, origin, "", "", nil)
	var device *http.Cookie
	for _, cookie := range preauth.Cookies() {
		if cookie.Name == "__Host-identity_device" {
			device = cookie
		}
	}
	if preauth.StatusCode != http.StatusOK || device == nil || !device.Secure || !device.HttpOnly || device.SameSite != http.SameSiteLaxMode {
		t.Fatal("original-flow issuer did not supply signed Lax browser device", preauth.StatusCode)
	}
	button := map[string]any{"button": map[string]string{"type": "standard", "theme": "outline", "size": "large"}, "remember": false}
	missingDevice, _ := call(http.MethodPost, "/v1/oauth/onetap-start", button, origin, "reference-redirect-no-device", "", nil)
	if missingDevice.StatusCode < 400 || len(missingDevice.Cookies()) != 0 || missingDevice.Header.Get("Location") != "" {
		t.Fatal("redirect start accepted absent signed initiating device", missingDevice.StatusCode)
	}
	start := func(key string) (onetap.BrowserRedirectStartProjection, *http.Cookie) {
		t.Helper()
		response, payload := call(http.MethodPost, "/v1/oauth/onetap-start", button, origin, key, "", []*http.Cookie{device})
		var flow onetap.BrowserRedirectStartProjection
		cookies := response.Cookies()
		if response.StatusCode != http.StatusOK || json.Unmarshal(payload, &flow) != nil || flow.ClientID != c.OneTap.Start.Provider.Profile().ClientID || len(flow.Nonce) != 43 || len(flow.State) != 22 || flow.Experience != onetap.BrowserStartRedirectButton || flow.Button.UXMode != onetap.ButtonRedirect || flow.LoginURI != origin+"/v1/oauth/onetap-callback" || flow.AllowedParentOrigin != origin || flow.ExpiresAt.Sub(flow.IssuedAt) != 5*time.Minute || !flow.ExpiresAt.After(time.Now()) || len(cookies) != 1 || response.Header.Get("Location") != "" {
			t.Fatal("real redirect Start did not deliver original GIS button projection", response.StatusCode)
		}
		cookie := cookies[0]
		if cookie.Name != "__Secure-identity_frontchannel" || !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/v1/oauth/onetap-callback" || cookie.Domain != "" || cookie.SameSite != http.SameSiteNoneMode || cookie.MaxAge <= 0 || cookie.MaxAge > 300 || !cookie.Expires.Equal(flow.ExpiresAt) || bytes.Contains(payload, []byte(cookie.Value)) || bytes.Contains(payload, []byte(device.Value)) {
			t.Fatal("redirect Start lost original exact-path frontchannel custody")
		}
		return flow, cookie
	}
	flow, original := start("reference-redirect-original")
	replayedStart, replayedProjection := call(http.MethodPost, "/v1/oauth/onetap-start", button, origin, "reference-redirect-original", "", []*http.Cookie{device})
	if replayedStart.StatusCode < 400 || len(replayedStart.Cookies()) != 0 || replayedStart.Header.Get("Location") != "" || bytes.Contains(replayedProjection, []byte(original.Value)) || bytes.Contains(replayedProjection, []byte(flow.Nonce)) || bytes.Contains(replayedProjection, []byte(flow.State)) {
		t.Fatal("redirect Start replay redelivered original browser custody", replayedStart.StatusCode)
	}
	foreignFlow, foreign := start("reference-redirect-foreign")
	google := &http.Cookie{Name: "g_csrf_token", Value: "reference-google-redirect-double-submit", Path: "/", Secure: true}
	credential := referenceOneTapPopupCredential(t, signing, referenceOneTapPopupStart{ClientID: flow.ClientID, Nonce: flow.Nonce})
	body := url.Values{"state": {flow.State}, "credential": {credential}, "g_csrf_token": {google.Value}}
	deny := func(input url.Values, sender string, cookies []*http.Cookie) {
		t.Helper()
		response, payload := call(http.MethodPost, "/v1/oauth/onetap-callback", input, sender, "", "", cookies)
		if response.StatusCode < 400 || len(response.Cookies()) != 0 || response.Header.Get("Location") != "" || response.Header.Get("X-CSRF-Token") != "" || response.Header.Get("Access-Control-Allow-Origin") != "" || response.Header.Get("Access-Control-Allow-Credentials") != "" || bytes.Contains(payload, []byte(input.Get("credential"))) || bytes.Contains(payload, []byte(original.Value)) || bytes.Contains(payload, []byte(foreign.Value)) {
			t.Fatal("denied redirect callback disclosed credentials or navigation authority", response.StatusCode)
		}
	}
	readSession([]*http.Cookie{device, original}, false)
	issuances(0)
	deny(body, origin, []*http.Cookie{device, google})
	deny(body, "null", []*http.Cookie{foreign, google})
	wrongGoogle := *google
	wrongGoogle.Value = "foreign-google-double-submit"
	deny(body, "https://foreign.example", []*http.Cookie{original, &wrongGoogle})
	missingState := url.Values{"credential": {credential}, "g_csrf_token": {google.Value}, "flowId": {flow.State}}
	deny(missingState, origin, []*http.Cookie{original, google})
	foreignSigning, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	// Native completion fixes a credential intent on its first admitted attempt;
	// invalid provider proof uses a separate original flow, not the success flow.
	invalid := url.Values{"state": {foreignFlow.State}, "credential": {referenceOneTapPopupCredential(t, foreignSigning, referenceOneTapPopupStart{ClientID: foreignFlow.ClientID, Nonce: foreignFlow.Nonce})}, "g_csrf_token": {google.Value}}
	deny(invalid, "", []*http.Cookie{foreign, google})
	issuances(0)
	readSession([]*http.Cookie{device, original}, false)
	authentication, err := c.OneTap.Completion.Issuer.Cookie.DeletionAttributes()
	if err != nil {
		t.Fatal("read common authentication cookie policy", err)
	}
	for index, sender := range []string{"", "null", "https://foreign.example"} {
		if index > 0 {
			flow, original = start("reference-redirect-sender-" + strconv.Itoa(index))
			credential = referenceOneTapPopupCredential(t, signing, referenceOneTapPopupStart{ClientID: flow.ClientID, Nonce: flow.Nonce})
			body = url.Values{"state": {flow.State}, "credential": {credential}, "g_csrf_token": {google.Value}}
		}
		if index == 2 {
			body.Set("client_id", "foreign-client")
			body.Set("redirect", "https://foreign.example/callback")
			body.Set("device", "replacement-device")
			body.Set("select_by", "untrusted")
		}
		// The signed device is retained by native Start. Neither it nor a sender
		// Origin is callback authority for a cross-site Google form POST.
		response, payload := call(http.MethodPost, "/v1/oauth/onetap-callback", body, sender, "", "", []*http.Cookie{original, google})
		var result struct {
			Status string `json:"status"`
		}
		issued := response.Cookies()
		if response.StatusCode != http.StatusOK || json.Unmarshal(payload, &result) != nil || result.Status != "signed_in" || len(issued) != 2 || response.Header.Get("Location") != "" || response.Header.Get("Access-Control-Allow-Origin") != "" || response.Header.Get("Access-Control-Allow-Credentials") != "" || bytes.Contains(payload, []byte(credential)) || bytes.Contains(payload, []byte(original.Value)) {
			t.Fatalf("redirect callback without device lost common session delivery for sender shape %d: status %d", index, response.StatusCode)
		}
		csrf := ""
		for _, cookie := range issued {
			if !cookie.Secure || cookie.Path != "/" || cookie.Domain != "" || cookie.MaxAge != 0 || !cookie.Expires.IsZero() || bytes.Contains(payload, []byte(cookie.Value)) {
				t.Fatal("redirect changed common browser-session policy or serialized credentials")
			}
			if cookie.Name == "__Host-identity_csrf" {
				if cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
					t.Fatal("redirect synchronizer is not browser-readable")
				}
				csrf = cookie.Value
			} else if !cookie.HttpOnly || cookie.Name != authentication.Name || cookie.SameSite != authentication.SameSite || cookie.Value == original.Value {
				t.Fatal("redirect did not issue an independent HttpOnly session")
			}
		}
		if csrf == "" {
			t.Fatal("redirect did not deliver common logout synchronizer")
		}
		readSession(issued, true)
		deny(body, sender, []*http.Cookie{original, google})
		issuances(index + 1)
		readSession(issued, true)
		wrongLogout, _ := call(http.MethodPost, "/v1/session/signout", map[string]any{}, origin, "", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", issued)
		if wrongLogout.StatusCode != http.StatusForbidden || len(wrongLogout.Cookies()) != 0 {
			t.Fatal("wrong synchronizer cleared or revoked redirect session", wrongLogout.StatusCode)
		}
		readSession(issued, true)
		logout, _ := call(http.MethodPost, "/v1/session/signout", map[string]any{}, origin, "", csrf, issued)
		if logout.StatusCode != http.StatusOK || len(logout.Cookies()) != 2 {
			t.Fatal("common strict logout rejected redirect session", logout.StatusCode)
		}
		readSession(issued, false)
		deny(body, sender, []*http.Cookie{original, google})
		issuances(index + 1)
		readSession([]*http.Cookie{device, original}, false)
	}
}
