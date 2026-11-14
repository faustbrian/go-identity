package providers_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/oauth/providers"
)

func keycloakMetadata() []byte {
	return []byte(`{"issuer":"https://keycloak.example/realms/selected","authorization_endpoint":"https://keycloak.example/realms/selected/protocol/openid-connect/auth","token_endpoint":"https://keycloak.example/realms/selected/protocol/openid-connect/token","userinfo_endpoint":"https://keycloak.example/realms/selected/protocol/openid-connect/userinfo","jwks_uri":"https://keycloak.example/realms/selected/protocol/openid-connect/certs","response_types_supported":["code"],"response_modes_supported":["query"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],"token_endpoint_auth_methods_supported":["client_secret_basic"],"code_challenge_methods_supported":["S256"],"scopes_supported":["openid","profile","email"],"authorization_response_iss_parameter_supported":true}`)
}

func keycloakConfig(t *testing.T) providers.KeycloakConfig {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	g := googleConfig(key)
	metadata := keycloakMetadata()
	return providers.KeycloakConfig{Version: g.Version, Issuer: "https://keycloak.example/realms/selected", ClientID: g.ClientID, ClientSecret: g.ClientSecret, RedirectURI: "https://application.example/keycloak/callback", Metadata: metadata, MetadataSHA256: sha256.Sum256(metadata), KeySet: g.KeySet, Clock: g.Clock, Timeout: g.Timeout}
}

func TestKeycloakPinnedProfileThroughExistingOAuthBoundary(t *testing.T) {
	c := keycloakConfig(t)
	p, err := providers.NewKeycloak(c)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	var existing *oauth.OIDCProvider = p
	profile := existing.Profile()
	if profile.ID != "keycloak" || profile.Issuer != c.Issuer || profile.ClientAuthentication != oauth.ClientSecretBasic || profile.ResponseMode != "query" || profile.PKCEMethod != "S256" || !profile.NonceRequired || profile.GoogleAccounts || !reflect.DeepEqual(profile.Scopes, []string{"openid", "profile", "email"}) || !reflect.DeepEqual(profile.Algorithms, []string{"RS256"}) {
		t.Fatal("Keycloak profile did not preserve the selected protocol")
	}
	state := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	verifier, err := oauth.NewPKCEVerifier([]byte(strings.Repeat("v", 64)))
	if err != nil {
		t.Fatal(err)
	}
	defer verifier.Destroy()
	request, err := p.Authorization(context.Background(), oauth.AuthorizationParameters{State: state, Nonce: state, PKCEChallenge: verifier.Challenge()})
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(request.URL())
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme+"://"+u.Host+u.Path != profile.AuthorizationEndpoint || u.Query().Get("scope") != "openid profile email" || u.Query().Get("response_type") != "code" || u.Query().Get("response_mode") != "query" || u.Query().Get("code_challenge_method") != "S256" {
		t.Fatal("authorization escaped the pinned Keycloak profile")
	}
	c.Metadata[0] = 'x'
	c.ClientSecret[0] = 'x'
	if p.Profile().Issuer != profile.Issuer {
		t.Fatal("caller mutated the constructed profile")
	}
}

func TestKeycloakRejectsWrongPinAndUnsupportedMetadata(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"foreign issuer":   func(m map[string]any) { m["issuer"] = "https://other.example/realms/selected" },
		"non HTTPS token":  func(m map[string]any) { m["token_endpoint"] = "http://keycloak.example/token" },
		"foreign endpoint": func(m map[string]any) { m["token_endpoint"] = "https://attacker.example/token" },
		"missing userinfo": func(m map[string]any) { delete(m, "userinfo_endpoint") },
		"missing JWKS":     func(m map[string]any) { delete(m, "jwks_uri") },
		"no S256":          func(m map[string]any) { m["code_challenge_methods_supported"] = []string{"plain"} },
		"no basic":         func(m map[string]any) { m["token_endpoint_auth_methods_supported"] = []string{"client_secret_post"} },
		"no code":          func(m map[string]any) { m["response_types_supported"] = []string{"id_token"} },
		"no query":         func(m map[string]any) { m["response_modes_supported"] = []string{"form_post"} },
		"no RS256":         func(m map[string]any) { m["id_token_signing_alg_values_supported"] = []string{"none"} },
		"issuer excluded":  func(m map[string]any) { m["authorization_response_iss_parameter_supported"] = false },
		"missing scope":    func(m map[string]any) { m["scopes_supported"] = []string{"openid"} },
	} {
		t.Run(name, func(t *testing.T) {
			c := keycloakConfig(t)
			var m map[string]any
			if err := json.Unmarshal(c.Metadata, &m); err != nil {
				t.Fatal(err)
			}
			mutate(m)
			c.Metadata, _ = json.Marshal(m)
			c.MetadataSHA256 = sha256.Sum256(c.Metadata)
			p, err := providers.NewKeycloak(c)
			if p != nil {
				p.Close()
			}
			if p != nil || !errors.Is(err, providers.ErrKeycloakConfiguration) {
				t.Fatal("unsupported metadata was admitted", err)
			}
		})
	}
	c := keycloakConfig(t)
	c.MetadataSHA256[0] ^= 1
	if p, err := providers.NewKeycloak(c); p != nil || !errors.Is(err, providers.ErrKeycloakConfiguration) {
		t.Fatal("wrong metadata pin admitted")
	}
}

func TestKeycloakMalformedAndAmbiguousMetadataFailsClosed(t *testing.T) {
	valid := string(keycloakMetadata())
	for name, raw := range map[string]string{
		"duplicate issuer":  strings.TrimSuffix(valid, "}") + `,"issuer":"https://keycloak.example/realms/selected"}`,
		"escaped duplicate": strings.TrimSuffix(valid, "}") + `,"\u0069ssuer":"https://keycloak.example/realms/selected"}`,
		"wrong root":        "[]", "null": "null", "truncated": "{", "trailing": valid + "{}",
		"oversized": strings.Repeat(" ", 65537), "invalid UTF8": valid + string([]byte{255}),
		"duplicate capability": strings.Replace(valid, `["S256"]`, `["S256","S256"]`, 1),
		"null capability":      strings.Replace(valid, `["S256"]`, `[null]`, 1),
		"realm traversal":      strings.ReplaceAll(valid, "/protocol/", "/../protocol/"),
		"encoded traversal":    strings.ReplaceAll(valid, "/protocol/", "/%2e%2e/protocol/"),
		"foreign realm":        strings.ReplaceAll(valid, "/selected/protocol/", "/other/protocol/"),
	} {
		t.Run(name, func(t *testing.T) {
			c := keycloakConfig(t)
			c.Metadata = []byte(raw)
			c.MetadataSHA256 = sha256.Sum256(c.Metadata)
			p, err := providers.NewKeycloak(c)
			if p != nil {
				p.Close()
			}
			if p != nil || !errors.Is(err, providers.ErrKeycloakConfiguration) {
				t.Fatal("malformed metadata admitted", err)
			}
		})
	}
}

func TestKeycloakConfigurationAndClosedScopes(t *testing.T) {
	for name, change := range map[string]func(*providers.KeycloakConfig){
		"empty scopes":      func(c *providers.KeycloakConfig) { c.Scopes = []string{} },
		"missing openid":    func(c *providers.KeycloakConfig) { c.Scopes = []string{"profile"} },
		"unlisted scope":    func(c *providers.KeycloakConfig) { c.Scopes = []string{"openid", "offline_access"} },
		"duplicate scopes":  func(c *providers.KeycloakConfig) { c.Scopes = []string{"openid", "openid"} },
		"no key":            func(c *providers.KeycloakConfig) { c.KeySet = nil },
		"no client":         func(c *providers.KeycloakConfig) { c.ClientID = "" },
		"no secret":         func(c *providers.KeycloakConfig) { c.ClientSecret = nil },
		"zero version":      func(c *providers.KeycloakConfig) { c.Version = 0 },
		"unsafe redirect":   func(c *providers.KeycloakConfig) { c.RedirectURI = "http://application.example/callback" },
		"zero pin":          func(c *providers.KeycloakConfig) { c.MetadataSHA256 = [32]byte{} },
		"unbounded timeout": func(c *providers.KeycloakConfig) { c.Timeout = time.Hour },
	} {
		t.Run(name, func(t *testing.T) {
			c := keycloakConfig(t)
			change(&c)
			p, err := providers.NewKeycloak(c)
			if p != nil {
				p.Close()
			}
			if p != nil || !errors.Is(err, providers.ErrKeycloakConfiguration) {
				t.Fatal("invalid configuration admitted", err)
			}
		})
	}
	c := keycloakConfig(t)
	c.Scopes = []string{"openid"}
	p, err := providers.NewKeycloak(c)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	c.Scopes[0] = "offline_access"
	if !reflect.DeepEqual(p.Profile().Scopes, []string{"openid"}) {
		t.Fatal("caller mutated selected scope")
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		text := fmt.Sprintf(format, struct{ Config *providers.KeycloakConfig }{&c})
		if strings.Contains(text, string(c.ClientSecret)) || strings.Contains(text, c.Issuer) {
			t.Fatal("configuration diagnostics exposed sensitive configuration")
		}
	}
	if _, err := json.Marshal(c); err == nil {
		t.Fatal("implicit credential serialization allowed")
	}
	if _, err := c.MarshalText(); err == nil {
		t.Fatal("implicit text serialization allowed")
	}
}

func TestKeycloakOriginalSignedProofRetainsStrictIssuerAudienceNonceAndSignature(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"valid", "wrong issuer", "wrong audience", "wrong azp", "missing multi audience azp", "wrong nonce", "wrong signature"} {
		t.Run(scenario, func(t *testing.T) {
			state := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
			var issuer string
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				user, password, basic := r.BasicAuth()
				if !basic || user != "registered-client" || password != "configured-secret" || r.URL.Path != "/realms/selected/protocol/openid-connect/token" || r.Method != http.MethodPost || r.ParseForm() != nil || len(r.PostForm) != 4 || r.PostForm.Get("code_verifier") != strings.Repeat("v", 64) || r.PostForm.Get("client_secret") != "" {
					t.Error("token request escaped Basic/S256 contract")
					w.WriteHeader(400)
					return
				}
				claims := map[string]any{"iss": issuer, "sub": "exact-keycloak-subject", "aud": "registered-client", "azp": "registered-client", "nonce": state, "iat": googleNow.Unix(), "exp": googleNow.Add(time.Minute).Unix()}
				signing := key
				switch scenario {
				case "wrong issuer":
					claims["iss"] = issuer + "/other"
				case "wrong audience":
					claims["aud"] = "other-client"
				case "wrong azp":
					claims["azp"] = "other-client"
				case "missing multi audience azp":
					claims["aud"] = []string{"registered-client", "other-client"}
					delete(claims, "azp")
				case "wrong nonce":
					claims["nonce"] = strings.Repeat("n", 43)
				case "wrong signature":
					signing = wrong
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "test-only-access", "id_token": googleSignedToken(t, signing, claims), "token_type": "Bearer", "expires_in": 300, "scope": "openid profile email"})
			}))
			defer server.Close()
			issuer = server.URL + "/realms/selected"
			c := keycloakConfig(t)
			g := googleConfig(key)
			c.Issuer = issuer
			c.KeySet = g.KeySet
			c.HTTPClient = server.Client()
			c.Metadata = []byte(strings.ReplaceAll(string(keycloakMetadata()), "https://keycloak.example", server.URL))
			c.MetadataSHA256 = sha256.Sum256(c.Metadata)
			p, err := providers.NewKeycloak(c)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			callback, err := oauth.ParseQueryCallback(context.Background(), (url.Values{"code": {"test-only-code"}, "state": {state}, "iss": {issuer}}).Encode(), p.Profile())
			if err != nil {
				t.Fatal(err)
			}
			defer callback.Destroy()
			input, _ := callback.Input()
			verifier, err := oauth.NewPKCEVerifier([]byte(strings.Repeat("v", 64)))
			if err != nil {
				t.Fatal(err)
			}
			defer verifier.Destroy()
			out, err := p.Exchange(context.Background(), input, verifier, state)
			defer out.Tokens.Destroy()
			if scenario == "valid" {
				if err != nil || out.Identity.Issuer() != issuer || out.Identity.Subject() != "exact-keycloak-subject" {
					t.Fatal("original provider proof rejected", err)
				}
			} else if err == nil || out.Identity.Subject() != "" {
				t.Fatal("invalid original provider proof admitted")
			}
		})
	}
}

func FuzzKeycloakPinnedMetadata(f *testing.F) {
	f.Add(keycloakMetadata())
	f.Add([]byte(`{"issuer":"first","issuer":"second"}`))
	f.Add([]byte("null"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		// Missing other startup inputs ensures no transport/secret owner can be
		// created; the parser must remain bounded for every hostile document.
		p, err := providers.NewKeycloak(providers.KeycloakConfig{Issuer: "https://keycloak.example/realms/selected", Metadata: raw, MetadataSHA256: sha256.Sum256(raw)})
		if p != nil {
			p.Close()
			t.Fatal("incomplete configuration created a provider")
		}
		if !errors.Is(err, providers.ErrKeycloakConfiguration) {
			t.Fatal("unstable metadata failure")
		}
	})
}
