//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-identity/oauth"
	oauthpg "github.com/faustbrian/go-identity/oauth/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	"github.com/jackc/pgx/v5"
)

func TestReferencePostgresConfiguredOneTapPopupHTTP(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, oneTapPopup: true}, true)
}

type referenceOneTapPopupPolicy struct{}

func (referenceOneTapPopupPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	r := c.Request
	if r.Tenant == otpTenant && c.PolicyRevision == 9 && r.Subject.Kind == authorization.SubjectServiceAccount && r.Subject.ID == "AAAAAAAAAAAAAAAAAAAAAw" &&
		(r.Action == "identity.oauth.onetap-start" || r.Action == "identity.oauth.onetap-callback") {
		admission := r.Resource.Type == "identity.request-admission" && r.Resource.ID == authorization.ResourceID(r.Action)
		originalFlow := r.Resource.Type == "identity.anonymous-flow" && r.Resource.ID != ""
		if admission || originalFlow {
			return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
		}
	}
	return (referenceRegistrationPolicy{}).Decide(ctx, c)
}

func configureReferenceOneTapPopup(t *testing.T, c *reference.StoreConfiguration, origin string) *rsa.PrivateKey {
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
	c.DurableAdmission.Policy = policy
	signing, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("create controlled Google signing key", err)
	}
	provider, err := oauth.NewGoogleAccountsProvider(oauth.OIDCConfig{
		ID: "google", Version: 7, Issuer: "https://accounts.google.com",
		AuthorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth", TokenEndpoint: "https://oauth2.googleapis.com/token",
		RedirectURI: origin + "/google/callback", ClientID: "reference-onetap-client",
		ClientAuthentication: oauth.ClientSecretPost, ClientSecret: []byte("reference-onetap-test-secret"),
		Scopes: []string{"openid", "email", "profile"}, Algorithms: []string{"RS256"},
		Clock: c.Session.Native.Execution.Clock, Timeout: time.Second,
		KeySet: &coreoidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&signing.PublicKey}},
	})
	if err != nil {
		t.Fatal("configure controlled Google profile", err)
	}
	t.Cleanup(provider.Close)
	p, native := c.PasswordSignup.PreAuth, c.PasswordSignin.Native
	flowKey := native.FlowKeys[p.FlowKeyIndex]
	probe, err := session.ParseToken("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE")
	if err != nil {
		t.Fatal(err)
	}
	digest, err := probe.Digest(flowKey, otpTenant)
	if err != nil {
		t.Fatal("identify selected browser-flow key version", err)
	}
	csrf, err := session.NewCSRFCookiePolicy(session.CookieConfig{Name: "__Host-identity_csrf", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	c.OneTap = &reference.OneTapConfiguration{
		Start: oauthpg.OneTapStartConfig{
			Schema: "identity_onetap", ConfigurationID: "reference-onetap-start-v1", TenantID: otpTenant, Provider: provider,
			Issuance: session.PreAuthIssuerConfig{ActorID: p.ActorID, Action: "identity.oauth.onetap-start", Origin: origin,
				PolicyID: "reference-onetap", PolicyVersion: c.OTP.RequestKeys.Policy.PolicyVersion,
				MaximumDuration: native.Session.MaximumDuration, FlowTTL: p.FlowTTL, LookupKey: flowKey, TokenSize: p.TokenSize, Cookie: p.Cookie},
			Risk:        risk.AuthenticationAdmissionCustodyConfig{ConfigurationID: "reference-onetap-authentication-v1"},
			Coordinator: c.PasswordSignup.Native.Coordinator, Capability: c.PasswordSignup.Issuer,
			MaximumDuration: 3 * time.Second, IntentKey: [32]byte{0xe1},
			CurrentEnvelopeKey: "reference-onetap", EnvelopeKeys: map[string][]byte{"reference-onetap": bytes.Repeat([]byte{0xe2}, 32)},
		},
		Completion: &oauthpg.OneTapCompletionConfig{ConfigurationID: "reference-onetap-completion-v1",
			PolicyNamespace: native.Profile.PolicyNamespace, Audience: native.Profile.Audience,
			FlowKeys: map[uint32]session.DigestKey{digest.KeyVersion: flowKey}, Issuer: native.Issuance, CSRF: native.CSRFKey},
	}
	c.HTTPOneTap = &reference.HTTPOneTapConfiguration{EnableStart: true, EnableCallback: true, CSRFCookie: csrf}
	return signing
}

type referenceOneTapPopupStart struct {
	ClientID  string    `json:"clientId"`
	Nonce     string    `json:"nonce"`
	FlowID    string    `json:"flowId"`
	ExpiresAt time.Time `json:"expiresAt"`
	Options   struct {
		Experience string `json:"experience"`
		Button     struct {
			UXMode string `json:"ux_mode"`
		} `json:"button"`
	} `json:"options"`
}

// Only Google's remote key distribution is substituted. The fixture seeds an
// existing linked human through the established account fixture; all browser
// issuance, provider validation, admission, persistence and session reads use
// the assembled Reference server over TLS.
func proveReferenceOneTapPopupTLS(t *testing.T, ctx context.Context, c reference.StoreConfiguration, deps reference.ReferenceDependencies, baseClient *http.Client, endpoint, origin string, signing *rsa.PrivateKey) {
	t.Helper()
	user, _ := seedEnterpriseAdministrator(t, ctx, deps.PostgreSQL, c)
	seedEnterpriseLinkedAccount(t, ctx, deps.PostgreSQL, user, "google", "https://accounts.google.com")
	execEnterpriseFixture(t, ctx, deps.PostgreSQL, `UPDATE identity.credential_references SET owner='identity/oauth' WHERE tenant_id=$1 AND user_id=$2 AND credential_id='enterprise-fixture-provider'`, otpTenant, string(user))
	client := *baseClient
	client.Jar = nil
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	call := func(method, path string, body any, key, csrf string, cookies []*http.Cookie) (*http.Response, []byte) {
		t.Helper()
		var input io.Reader
		if body != nil {
			wire, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			input = bytes.NewReader(wire)
		}
		request, err := http.NewRequestWithContext(ctx, method, endpoint+path, input)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Origin", origin)
		if body != nil {
			request.Header.Set("Content-Type", "application/json")
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
			t.Fatal("configured One Tap TLS request", err)
		}
		payload, readErr := io.ReadAll(io.LimitReader(response.Body, 16385))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || len(payload) > 16384 || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("One Tap response lost bounded no-store delivery")
		}
		return response, payload
	}
	readSession := func(cookies []*http.Cookie, authenticated bool) {
		t.Helper()
		response, payload := call(http.MethodGet, "/v1/session/get", nil, "", "", cookies)
		var state struct {
			Authenticated bool `json:"authenticated"`
			Principal     struct {
				UserID string `json:"userID"`
			} `json:"principal"`
		}
		if response.StatusCode != 200 || json.Unmarshal(payload, &state) != nil || state.Authenticated != authenticated || authenticated && state.Principal.UserID != string(user) {
			t.Fatalf("common session getter: status %d, authenticated %t (want %t), matching identity %t", response.StatusCode, state.Authenticated, authenticated, state.Principal.UserID == string(user))
		}
	}
	preauth, _ := call(http.MethodPost, "/v1/session/preauth-issue", map[string]string{"method": "password"}, "", "", nil)
	var device *http.Cookie
	for _, cookie := range preauth.Cookies() {
		if cookie.Name == "__Host-identity_device" {
			device = cookie
		}
	}
	if preauth.StatusCode != 200 || device == nil || !device.Secure || !device.HttpOnly || device.SameSite != http.SameSiteLaxMode {
		t.Fatal("public original-flow issuer did not supply signed browser device", preauth.StatusCode)
	}
	start := func(key string) (referenceOneTapPopupStart, *http.Cookie) {
		t.Helper()
		response, payload := call(http.MethodPost, "/v1/oauth/onetap-start", map[string]any{"button": map[string]string{"type": "standard", "theme": "outline", "size": "large"}}, key, "", []*http.Cookie{device})
		var flow referenceOneTapPopupStart
		cookies := response.Cookies()
		if response.StatusCode != 200 || json.Unmarshal(payload, &flow) != nil || flow.ClientID != c.OneTap.Start.Provider.Profile().ClientID || len(flow.Nonce) != 43 || len(flow.FlowID) != 22 || !flow.ExpiresAt.After(time.Now()) || flow.Options.Experience != "popup_button" || flow.Options.Button.UXMode != "popup" || len(cookies) != 1 {
			t.Fatal("real One Tap Start did not deliver original popup authority", response.StatusCode)
		}
		cookie := cookies[0]
		if cookie.Name != "__Host-identity_flow" || !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.Domain != "" || cookie.SameSite != http.SameSiteLaxMode || cookie.MaxAge <= 0 || bytes.Contains(payload, []byte(cookie.Value)) {
			t.Fatal("One Tap Start lost original flow-cookie custody")
		}
		return flow, cookie
	}
	flow, original := start("reference-onetap-original")
	foreignFlow, foreign := start("reference-onetap-foreign")
	credential := referenceOneTapPopupCredential(t, signing, flow)
	google := &http.Cookie{Name: "g_csrf_token", Value: "reference-google-double-submit", Path: "/", Secure: true}
	body := map[string]string{"flowId": flow.FlowID, "credential": credential, "g_csrf_token": google.Value, "client_id": flow.ClientID}
	deny := func(cookies []*http.Cookie, input map[string]string) {
		t.Helper()
		response, payload := call(http.MethodPost, "/v1/oauth/onetap-callback", input, "", "", cookies)
		if response.StatusCode == 200 || len(response.Cookies()) != 0 || response.Header.Get("Location") != "" || response.Header.Get("X-CSRF-Token") != "" || bytes.Contains(payload, []byte(input["credential"])) || bytes.Contains(payload, []byte(original.Value)) {
			t.Fatal("denied One Tap callback disclosed credentials or redirected", response.StatusCode)
		}
	}
	readSession([]*http.Cookie{device}, false)
	deny([]*http.Cookie{device, foreign, google}, body)
	wrongGoogle := *google
	wrongGoogle.Value = "foreign-google-double-submit"
	deny([]*http.Cookie{device, original, &wrongGoogle}, body)
	foreignSigning, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	// The first admitted callback command fixes the signed credential intent
	// for that flow. Verify signature rejection on a separate started flow;
	// submitting a different credential is not a retry of that command.
	invalid := map[string]string{"flowId": foreignFlow.FlowID, "credential": referenceOneTapPopupCredential(t, foreignSigning, foreignFlow), "g_csrf_token": google.Value, "client_id": foreignFlow.ClientID}
	deny([]*http.Cookie{device, foreign, google}, invalid)
	readSession([]*http.Cookie{device}, false)
	response, payload := call(http.MethodPost, "/v1/oauth/onetap-callback", body, "", "", []*http.Cookie{device, original, google})
	var result struct {
		Status string `json:"status"`
	}
	issued := response.Cookies()
	if response.StatusCode != 200 || json.Unmarshal(payload, &result) != nil || result.Status != "signed_in" || len(issued) != 2 || response.Header.Get("Location") != "" {
		t.Fatal("configured native One Tap callback did not deliver a signed-in session", response.StatusCode)
	}
	csrf := ""
	for _, cookie := range issued {
		if !cookie.Secure || cookie.Path != "/" || cookie.Domain != "" || cookie.MaxAge != 0 || !cookie.Expires.IsZero() || bytes.Contains(payload, []byte(cookie.Value)) {
			t.Fatal("One Tap changed shared browser-session policy or serialized credentials")
		}
		if cookie.Name == "__Host-identity_csrf" {
			if cookie.HttpOnly {
				t.Fatal("One Tap synchronizer is not browser-readable")
			}
			csrf = cookie.Value
		} else if !cookie.HttpOnly || cookie.Name == original.Name || cookie.Value == original.Value {
			t.Fatal("One Tap did not issue an independent HttpOnly session")
		}
	}
	if csrf == "" {
		t.Fatal("One Tap did not deliver its shared logout synchronizer")
	}
	readSession(issued, true)
	deny([]*http.Cookie{device, original, google}, body)
	readSession(issued, true)
	var issuances int
	query := `SELECT count(*) FROM ` + pgx.Identifier{c.Session.Native.Execution.Repository.Schema}.Sanitize() + `.session_issuances WHERE tenant_id=$1 AND user_id=$2 AND purpose='identity.oauth.onetap-callback'`
	if err := deps.PostgreSQL.Raw().QueryRow(ctx, query, otpTenant, string(user)).Scan(&issuances); err != nil || issuances != 1 {
		t.Fatal("One Tap denial or replay changed exact once-only session issuance", issuances, err)
	}
	wrongLogout, _ := call(http.MethodPost, "/v1/session/signout", map[string]any{}, "", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", issued)
	if wrongLogout.StatusCode != http.StatusForbidden || len(wrongLogout.Cookies()) != 0 {
		t.Fatal("wrong synchronizer cleared or revoked One Tap session", wrongLogout.StatusCode)
	}
	readSession(issued, true)
	logout, _ := call(http.MethodPost, "/v1/session/signout", map[string]any{}, "", csrf, issued)
	if logout.StatusCode != 200 || len(logout.Cookies()) != 2 {
		t.Fatal("shared strict logout rejected One Tap session", logout.StatusCode)
	}
	readSession(issued, false)
	deny([]*http.Cookie{device, original, google}, body)
	readSession([]*http.Cookie{device}, false)
}

func referenceOneTapPopupCredential(t *testing.T, signing *rsa.PrivateKey, flow referenceOneTapPopupStart) string {
	t.Helper()
	now := time.Now().UTC()
	claims, err := json.Marshal(map[string]any{"iss": "https://accounts.google.com", "sub": enterpriseProviderSubject,
		"aud": flow.ClientID, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "nonce": flow.Nonce})
	if err != nil {
		t.Fatal(err)
	}
	message := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT","kid":"reference-onetap"}`)) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(message))
	signature, err := rsa.SignPKCS1v15(rand.Reader, signing, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return message + "." + base64.RawURLEncoding.EncodeToString(signature)
}
