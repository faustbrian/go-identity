package oauth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	oauth "github.com/faustbrian/go-identity/oauth"
)

func requireProxyExchangeError(t *testing.T, err error, kind oauth.ErrorKind) {
	t.Helper()
	var failure *oauth.Error
	if !errors.As(err, &failure) || failure.Kind() != kind {
		t.Fatalf("wanted %s, got %v", kind, err)
	}
}

func TestOIDCProxyExchangeDisposesRefreshBeforeReturningIdentity(t *testing.T) {
	for _, method := range []oauth.ClientAuthentication{oauth.PublicClient, oauth.ClientSecretBasic, oauth.ClientSecretPost} {
		t.Run(string(method), func(t *testing.T) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			var exchanges, revocations atomic.Int32
			var issuer string
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || r.Header.Get("Accept") != "application/json" {
					t.Error("wrong form POST")
				}
				if err := r.ParseForm(); err != nil {
					t.Error(err)
				}
				form := r.PostForm
				expected := url.Values{}
				switch r.URL.Path {
				case "/token":
					exchanges.Add(1)
					expected = url.Values{"grant_type": {"authorization_code"}, "code": {" exact +/=: code "}, "code_verifier": {testVerifier}, "redirect_uri": {"https://application.example/callback"}}
				case "/revoke":
					revocations.Add(1)
					expected = url.Values{"token": {"refresh +/=: secret"}, "token_type_hint": {"refresh_token"}}
				default:
					t.Error("unexpected endpoint")
				}
				if method != oauth.ClientSecretBasic {
					expected.Set("client_id", "client:+ secret")
				}
				if method == oauth.ClientSecretPost {
					expected.Set("client_secret", "configuration-secret")
				}
				if !reflect.DeepEqual(form, expected) {
					t.Error("incorrect exact client-authentication or operation form")
				}
				user, password, hasBasic := r.BasicAuth()
				if method == oauth.ClientSecretBasic {
					if !hasBasic || user != url.QueryEscape("client:+ secret") || password != url.QueryEscape("configuration-secret") {
						t.Error("incorrect Basic credentials")
					}
				} else if hasBasic {
					t.Error("unexpected Basic credentials")
				}
				if r.URL.Path == "/revoke" {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("ignored acknowledgement body"))
					return
				}
				claims := oidcClaims()
				claims["iss"] = issuer
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access-secret", "refresh_token": "refresh +/=: secret", "id_token": esToken(t, key, claims), "token_type": "Bearer", "expires_in": 3600})
			}))
			defer server.Close()
			issuer = server.URL
			config := providerConfig(t, server.URL+"/token", server.Client(), key)
			config.Issuer, config.AuthorizationEndpoint, config.ClientAuthentication = issuer, issuer+"/authorize", method
			if method == oauth.PublicClient {
				config.ClientSecret = nil
			}
			provider, err := oauth.NewOIDCProvider(config)
			if err != nil {
				t.Fatal(err)
			}
			defer provider.Close()
			proxy, err := oauth.NewOIDCProxyExchange(provider, server.URL+"/revoke")
			if err != nil {
				t.Fatal(err)
			}
			if exchanges.Load() != 0 || revocations.Load() != 0 {
				t.Fatal("constructor performed I/O")
			}
			if !reflect.DeepEqual(proxy.Profile(), provider.Profile()) {
				t.Fatal("proxy changed bound profile")
			}
			profile, err := proxy.Exchange(context.Background(), callback(t), verifier(t), testNonce)
			if err != nil {
				t.Fatal(err)
			}
			if profile.Subject() != "provider-subject" || profile.Issuer() != issuer || exchanges.Load() != 1 || revocations.Load() != 1 {
				t.Fatal("identity returned without exactly one acknowledged disposal")
			}
			for _, verb := range []string{"%v", "%+v", "%#v"} {
				if strings.Contains(fmt.Sprintf(verb, proxy), "configuration-secret") {
					t.Fatal("proxy diagnostic leaked credentials")
				}
			}
			if _, err := json.Marshal(proxy); err == nil {
				t.Fatal("proxy serialized")
			}
		})
	}
}

func TestOIDCProxyExchangeCleanupAndFailureClassification(t *testing.T) {
	cases := []struct {
		name                            string
		refresh, endpoint, invalidProof bool
		status                          int
		body                            string
		dropConnection                  bool
		want                            oauth.ErrorKind
		wantRevocations                 int32
	}{
		{name: "no refresh needs no endpoint", status: 200},
		{name: "refresh without endpoint", refresh: true, status: 200, want: oauth.Unknown},
		{name: "acknowledged", refresh: true, endpoint: true, status: 200, wantRevocations: 1},
		{name: "refused disposal remains unknown", refresh: true, endpoint: true, status: 400, body: `{"error":"unsupported_token_type"}`, want: oauth.Unknown, wantRevocations: 1},
		{name: "unavailable disposal remains unknown", refresh: true, endpoint: true, status: 503, want: oauth.Unknown, wantRevocations: 1},
		{name: "lost disposal response remains unknown", refresh: true, endpoint: true, dropConnection: true, want: oauth.Unknown, wantRevocations: 1},
		{name: "redirect never followed", refresh: true, endpoint: true, status: 307, want: oauth.Unknown, wantRevocations: 1},
		{name: "invalid proof still disposes", refresh: true, endpoint: true, invalidProof: true, status: 200, want: oauth.InvalidProof, wantRevocations: 1},
		{name: "invalid proof with uncertain disposal", refresh: true, endpoint: true, invalidProof: true, status: 503, want: oauth.Unknown, wantRevocations: 1},
		{name: "invalid proof without disposal endpoint", refresh: true, invalidProof: true, status: 200, want: oauth.Unknown},
		{name: "invalid proof without refresh", invalidProof: true, status: 200, want: oauth.InvalidProof},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			var exchanges, revocations atomic.Int32
			var issuer string
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/revoke" {
					revocations.Add(1)
					if tc.dropConnection {
						connection, _, err := w.(http.Hijacker).Hijack()
						if err != nil {
							t.Error(err)
							return
						}
						_ = connection.Close()
						return
					}
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("Location", issuer+"/unexpected")
					w.WriteHeader(tc.status)
					_, _ = w.Write([]byte(tc.body))
					return
				}
				if r.URL.Path != "/token" {
					t.Error("followed redirect or used unexpected endpoint")
					w.WriteHeader(500)
					return
				}
				exchanges.Add(1)
				claims := oidcClaims()
				claims["iss"] = issuer
				if tc.invalidProof {
					claims["nonce"] = "wrong"
				}
				response := map[string]any{"access_token": "access-secret", "id_token": esToken(t, key, claims), "token_type": "Bearer", "expires_in": 3600}
				if tc.refresh {
					response["refresh_token"] = "refresh-secret"
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()
			issuer = server.URL
			config := providerConfig(t, issuer+"/token", server.Client(), key)
			config.Issuer = issuer
			provider, err := oauth.NewOIDCProvider(config)
			if err != nil {
				t.Fatal(err)
			}
			defer provider.Close()
			endpoint := ""
			if tc.endpoint {
				endpoint = issuer + "/revoke"
			}
			proxy, err := oauth.NewOIDCProxyExchange(provider, endpoint)
			if err != nil {
				t.Fatal(err)
			}
			profile, err := proxy.Exchange(context.Background(), callback(t), verifier(t), testNonce)
			if tc.want != "" {
				requireProxyExchangeError(t, err, tc.want)
				if profile.Subject() != "" {
					t.Fatal("failure exposed identity")
				}
			} else if err != nil || profile.Subject() != "provider-subject" {
				t.Fatalf("valid profile rejected: %v", err)
			}
			if exchanges.Load() != 1 || revocations.Load() != tc.wantRevocations {
				t.Fatal("exchange/disposal was skipped or retried")
			}
		})
	}
}

func TestOIDCProxyExchangeRejectsUntrustedEndpointsAndPreflight(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(500) }))
	defer server.Close()
	config := providerConfig(t, server.URL+"/token", server.Client(), key)
	config.Issuer = server.URL
	provider, err := oauth.NewOIDCProvider(config)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	for _, endpoint := range []string{"http://issuer.example/revoke", "https://other.example/revoke", server.URL + "/revoke?query=x", server.URL + "/revoke#fragment"} {
		_, err := oauth.NewOIDCProxyExchange(provider, endpoint)
		requireProxyExchangeError(t, err, oauth.InvalidInput)
	}
	_, err = oauth.NewOIDCProxyExchange(nil, "")
	requireProxyExchangeError(t, err, oauth.InvalidInput)
	proxy, err := oauth.NewOIDCProxyExchange(provider, server.URL+"/revoke")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = proxy.Exchange(ctx, callback(t), verifier(t), testNonce)
	requireProxyExchangeError(t, err, oauth.Unavailable)
	_, err = proxy.Exchange(context.Background(), callback(t), verifier(t), "bad nonce")
	requireProxyExchangeError(t, err, oauth.InvalidInput)
	provider.Close()
	_, err = proxy.Exchange(context.Background(), callback(t), verifier(t), testNonce)
	requireProxyExchangeError(t, err, oauth.InvalidInput)
	if calls.Load() != 0 {
		t.Fatal("preflight sent a request")
	}
}

func TestOIDCProxyExchangeMalformedResponsesRemainUnknownAndRefusalIsDefinitive(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   oauth.ErrorKind
	}{
		{"truncated success", 200, `{"refresh_token":"refresh-secret",`, oauth.Unknown},
		{"duplicate refresh custody", 200, `{"refresh_token":"first","refresh_token":"second"}`, oauth.Unknown},
		{"invalid refresh shape", 200, `{"access_token":"access-secret","refresh_token":false,"id_token":"invalid","token_type":"Bearer","expires_in":3600}`, oauth.Unknown},
		{"coherent token refusal", 400, `{"error":"invalid_grant"}`, oauth.Refused},
		{"contradictory token refusal", 400, `{"error":"invalid_grant","refresh_token":"refresh-secret"}`, oauth.Unknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.URL.Path != "/token" {
					t.Error("used ambiguous refresh credential")
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			config := providerConfig(t, server.URL+"/token", server.Client(), key)
			config.Issuer = server.URL
			provider, err := oauth.NewOIDCProvider(config)
			if err != nil {
				t.Fatal(err)
			}
			defer provider.Close()
			proxy, err := oauth.NewOIDCProxyExchange(provider, server.URL+"/revoke")
			if err != nil {
				t.Fatal(err)
			}
			profile, err := proxy.Exchange(context.Background(), callback(t), verifier(t), testNonce)
			requireProxyExchangeError(t, err, tc.want)
			if profile.Subject() != "" || calls.Load() != 1 {
				t.Fatal("malformed/refused response escaped fail-closed one-send boundary")
			}
		})
	}
}

func TestOIDCProxyExchangeDoesNotChangeOrdinaryTokenCustody(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var issuer string
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/token" {
			t.Error("ordinary exchange attempted proxy disposal")
		}
		claims := oidcClaims()
		claims["iss"] = issuer
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access-secret", "refresh_token": "refresh-secret", "id_token": esToken(t, key, claims), "token_type": "Bearer", "expires_in": 3600})
	}))
	defer server.Close()
	issuer = server.URL
	config := providerConfig(t, issuer+"/token", server.Client(), key)
	config.Issuer = issuer
	provider, err := oauth.NewOIDCProvider(config)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	if _, err := oauth.NewOIDCProxyExchange(provider, issuer+"/revoke"); err != nil {
		t.Fatal(err)
	}
	result, err := provider.Exchange(context.Background(), callback(t), verifier(t), testNonce)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Tokens.Destroy()
	err = result.Tokens.Use(context.Background(), func(_ context.Context, tokens oauth.TokenBytes) error {
		if string(tokens.RefreshToken) != "refresh-secret" || string(tokens.AccessToken) != "access-secret" {
			t.Fatal("ordinary custody was disposed or changed")
		}
		return nil
	})
	if err != nil || calls.Load() != 1 || result.Identity.Subject() != "provider-subject" {
		t.Fatal("ordinary exchange changed")
	}
}

func TestOIDCProxyExchangeDisposesUnambiguousRefreshFromInvalidTokenResponse(t *testing.T) {
	const invalidExpiry = `{"access_token":"access-secret","refresh_token":"refresh-secret","id_token":"invalid","token_type":"Bearer","expires_in":"invalid"}`
	for _, tc := range []struct {
		name              string
		status            int
		contentType, body string
		wantRevocations   int32
	}{
		{"invalid expiry", 200, "application/json", invalidExpiry, 1},
		{"invalid scope", 200, "application/json", `{"access_token":"access-secret","refresh_token":"refresh-secret","id_token":"invalid","token_type":"Bearer","expires_in":3600,"scope":"unrequested"}`, 1},
		{"missing ID token", 200, "application/json", `{"access_token":"access-secret","refresh_token":"refresh-secret","token_type":"Bearer","expires_in":3600}`, 1},
		{"truncated object", 200, "application/json", invalidExpiry[:len(invalidExpiry)-1], 0},
		{"duplicate unrelated field", 200, "application/json", strings.TrimSuffix(invalidExpiry, "}") + `,"expires_in":3600}`, 0},
		{"trailing object", 200, "application/json", invalidExpiry + `{}`, 0},
		{"non-success response", 400, "application/json", invalidExpiry, 0},
		{"wrong media type", 200, "text/plain", invalidExpiry, 0},
		{"invalid refresh token", 200, "application/json", strings.Replace(invalidExpiry, `"refresh-secret"`, `false`, 1), 0},
		{"error-bearing response", 200, "application/json", strings.TrimSuffix(invalidExpiry, "}") + `,"error":"invalid_grant"}`, 0},
		{"error-description-bearing response", 200, "application/json", strings.TrimSuffix(invalidExpiry, "}") + `,"error_description":"denied"}`, 0},
		{"error-URI-bearing response", 200, "application/json", strings.TrimSuffix(invalidExpiry, "}") + `,"error_uri":"https://issuer.example/error"}`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			var exchanges, revocations atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/revoke" {
					revocations.Add(1)
					if err := r.ParseForm(); err != nil {
						t.Error(err)
					}
					if r.PostForm.Get("token") != "refresh-secret" || r.PostForm.Get("token_type_hint") != "refresh_token" {
						t.Error("revoked incorrect refresh credential")
					}
					w.WriteHeader(http.StatusOK)
					return
				}
				exchanges.Add(1)
				if r.URL.Path != "/token" {
					t.Error("unexpected endpoint")
				}
				w.Header().Set("Content-Type", tc.contentType)
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			config := providerConfig(t, server.URL+"/token", server.Client(), key)
			config.Issuer = server.URL
			provider, err := oauth.NewOIDCProvider(config)
			if err != nil {
				t.Fatal(err)
			}
			defer provider.Close()
			proxy, err := oauth.NewOIDCProxyExchange(provider, server.URL+"/revoke")
			if err != nil {
				t.Fatal(err)
			}
			profile, err := proxy.Exchange(context.Background(), callback(t), verifier(t), testNonce)
			requireProxyExchangeError(t, err, oauth.Unknown)
			if profile.Subject() != "" {
				t.Fatal("invalid token response exposed identity")
			}
			if exchanges.Load() != 1 || revocations.Load() != tc.wantRevocations {
				t.Fatalf("exchange calls %d, revocation calls %d; want one exchange and %d revocation", exchanges.Load(), revocations.Load(), tc.wantRevocations)
			}
		})
	}
}
