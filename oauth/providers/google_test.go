package providers_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/oauth/providers"
)

var googleNow = time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)

type googleClock struct{}

func (googleClock) Now() time.Time { return googleNow }

func googleConfig(key *rsa.PrivateKey) providers.GoogleConfig {
	return providers.GoogleConfig{Version: 7, ClientID: "registered-client", ClientSecret: []byte("configured-secret"), RedirectURI: "https://application.example/google/callback", KeySet: &coreoidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}, Clock: googleClock{}, Timeout: time.Second}
}

func TestGoogleBuiltInFixedProfileAndAuthorization(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	c := googleConfig(key)
	p, err := providers.NewGoogle(c)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	profile := p.Profile()
	if profile.ID != "google" || profile.Version != c.Version || profile.Issuer != "https://accounts.google.com" || profile.AuthorizationEndpoint != "https://accounts.google.com/o/oauth2/v2/auth" || profile.TokenEndpoint != "https://oauth2.googleapis.com/token" || profile.RedirectURI != c.RedirectURI || profile.ClientAuthentication != oauth.ClientSecretPost || !profile.GoogleAccounts || !reflect.DeepEqual(profile.Scopes, []string{"openid", "email", "profile"}) || !reflect.DeepEqual(profile.Algorithms, []string{"RS256"}) {
		t.Fatal("built-in provider did not select the reviewed Google facts")
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
	q := u.Query()
	if u.Scheme != "https" || u.Host != "accounts.google.com" || u.Path != "/o/oauth2/v2/auth" || len(q) != 9 || q.Get("scope") != "openid email profile" || q.Get("client_id") != c.ClientID || q.Get("redirect_uri") != c.RedirectURI || q.Get("response_type") != "code" || q.Get("response_mode") != "query" || q.Get("code_challenge_method") != "S256" || q.Get("nonce") != state || q.Get("state") != state || q.Get("code_challenge") != verifier.Challenge() {
		t.Fatal("authorization escaped the fixed query/S256/nonce profile")
	}
	profile.Scopes[0], profile.Algorithms[0] = "changed", "none"
	if p.Profile().Scopes[0] != "openid" || p.Profile().Algorithms[0] != "RS256" {
		t.Fatal("public facts mutated the immutable provider")
	}
	registry, err := oauth.NewProviderRegistry(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, found := registry.Lookup("Google"); found {
		t.Fatal("unselected alias acquired a provider")
	}
	if _, found := registry.Lookup("github"); found {
		t.Fatal("unselected provider acquired a capability")
	}
}

func TestGoogleBuiltInClosedScopeAndConfigurationDenial(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*providers.GoogleConfig){
		"empty selected scope": func(c *providers.GoogleConfig) { c.Scopes = []string{} },
		"too many scopes":      func(c *providers.GoogleConfig) { c.Scopes = []string{"openid", "email", "profile", "email"} },
		"missing openid":       func(c *providers.GoogleConfig) { c.Scopes = []string{"email", "profile"} },
		"unlisted scope": func(c *providers.GoogleConfig) {
			c.Scopes = []string{"openid", "https://www.googleapis.com/auth/drive"}
		},
		"duplicate scope":    func(c *providers.GoogleConfig) { c.Scopes = []string{"openid", "openid"} },
		"wrong scope case":   func(c *providers.GoogleConfig) { c.Scopes = []string{"Openid"} },
		"missing key":        func(c *providers.GoogleConfig) { c.KeySet = nil },
		"missing credential": func(c *providers.GoogleConfig) { c.ClientSecret = nil },
		"missing client":     func(c *providers.GoogleConfig) { c.ClientID = "" },
		"untrusted callback": func(c *providers.GoogleConfig) { c.RedirectURI = "http://application.example/callback" },
		"callback fragment":  func(c *providers.GoogleConfig) { c.RedirectURI += "#fragment" },
		"zero version":       func(c *providers.GoogleConfig) { c.Version = 0 },
		"unbounded timeout":  func(c *providers.GoogleConfig) { c.Timeout = time.Hour },
	} {
		t.Run(name, func(t *testing.T) {
			c := googleConfig(key)
			change(&c)
			p, err := providers.NewGoogle(c)
			if p != nil {
				p.Close()
			}
			if p != nil || !errors.Is(err, providers.ErrGoogleConfiguration) {
				t.Fatal("invalid built-in configuration admitted", err)
			}
		})
	}
	for _, scopes := range [][]string{{"openid"}, {"email", "openid"}, {"openid", "email", "profile"}} {
		c := googleConfig(key)
		c.Scopes = slices.Clone(scopes)
		p, err := providers.NewGoogle(c)
		if err != nil {
			t.Fatal(err)
		}
		c.Scopes[0] = "changed"
		if !reflect.DeepEqual(p.Profile().Scopes, scopes) {
			t.Fatal("caller changed explicit scopes")
		}
		p.Close()
	}
}

func googleSignedToken(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	message := header + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(message))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return message + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// The only network stand-in is the external provider. Hostnames/paths remain
// the built-in facts; a real TLS certificate covers the fixed Google hosts and
// the caller-owned test transport maps only those hosts to isolated loopback.
func googleTLS(t *testing.T, handler http.Handler) *http.Client {
	t.Helper()
	tlsKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"accounts.google.com", "oauth2.googleapis.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &tlsKey.PublicKey, tlsKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: tlsKey}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "accounts.google.com:443" && address != "oauth2.googleapis.com:443" {
			return nil, errors.New("unexpected provider host")
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}}
	client := &http.Client{Transport: transport}
	t.Cleanup(client.CloseIdleConnections)
	return client
}

func TestGoogleBuiltInOriginalSignedProofThroughFixedTLSFacts(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for _, tc := range []struct {
		name, issuer string
		nonce        string
		key          *rsa.PrivateKey
		want         bool
	}{
		{"canonical", "https://accounts.google.com", nonce, key, true},
		{"legacy", "accounts.google.com", nonce, key, true},
		{"wrong issuer", "https://other.example", nonce, key, false},
		{"wrong nonce", "https://accounts.google.com", strings.Repeat("x", 43), key, false},
		{"wrong signature", "https://accounts.google.com", nonce, wrongKey, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			original := googleSignedToken(t, tc.key, map[string]any{"iss": tc.issuer, "sub": "exact-provider-subject", "aud": "registered-client", "nonce": tc.nonce, "iat": googleNow.Unix(), "exp": googleNow.Add(time.Minute).Unix()})
			client := googleTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.TLS == nil || r.Host != "oauth2.googleapis.com" || r.URL.Path != "/token" || r.Method != http.MethodPost || r.Header.Get("Authorization") != "" || r.URL.RawQuery != "" {
					t.Error("fixed authenticated token endpoint or credential channel changed")
				}
				if err := r.ParseForm(); err != nil || len(r.PostForm) != 6 || r.PostForm.Get("client_id") != "registered-client" || r.PostForm.Get("client_secret") != "configured-secret" || r.PostForm.Get("code") != "original-code" || r.PostForm.Get("code_verifier") != strings.Repeat("v", 64) || r.PostForm.Get("redirect_uri") != "https://application.example/google/callback" || r.PostForm.Get("grant_type") != "authorization_code" {
					t.Error("original POST credentials/code/PKCE/callback changed")
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "controlled-access", "id_token": original, "token_type": "Bearer", "expires_in": 3600, "scope": "openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile"})
			}))
			c := googleConfig(key)
			c.HTTPClient = client
			p, err := providers.NewGoogle(c)
			clear(c.ClientSecret)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			if calls.Load() != 0 {
				t.Fatal("builder performed network IO")
			}
			callback, err := identity.NewOAuthCallbackInput([]byte("original-code"), nonce, identity.OAuthCallbackLimits{MaxCodeBytes: 4096, StateBytes: 32})
			if err != nil {
				t.Fatal(err)
			}
			defer callback.Destroy()
			verifier, err := oauth.NewPKCEVerifier([]byte(strings.Repeat("v", 64)))
			if err != nil {
				t.Fatal(err)
			}
			defer verifier.Destroy()
			out, err := p.Exchange(context.Background(), callback, verifier, nonce)
			defer out.Tokens.Destroy()
			if !tc.want {
				var rejected *oauth.Error
				if !errors.As(err, &rejected) || rejected.Kind() != oauth.InvalidProof || out.Identity.Subject() != "" {
					t.Fatal("invalid provider proof admitted", err)
				}
				return
			}
			if err != nil || calls.Load() != 1 || out.Identity.Issuer() != "https://accounts.google.com" || out.Identity.Subject() != "exact-provider-subject" {
				t.Fatal("valid original Google proof lost canonical identity", err)
			}
			requested := []string{"openid", "email", "profile"}
			if !slices.Equal(out.Tokens.RequestedScopes(), requested) || !slices.Equal(out.Tokens.GrantedScopes(), requested) || !out.Tokens.ScopeReported() {
				t.Fatal("documented response aliases changed the requested selection or failed to project canonical granted scopes")
			}
			if err := out.Tokens.Use(context.Background(), func(_ context.Context, bytes oauth.TokenBytes) error {
				if string(bytes.IDToken) != original {
					t.Fatal("signed ID-token bytes rewritten")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			for _, issuer := range []string{"accounts.google.com", "https://wrong.example"} {
				parsed, err := oauth.ParseQueryCallback(context.Background(), (url.Values{"code": {"code"}, "state": {nonce}, "iss": {issuer}}).Encode(), p.Profile())
				parsed.Destroy()
				if err == nil {
					t.Fatal("signed-token compatibility widened raw query issuer")
				}
			}
		})
	}
}

func TestGoogleBuiltInConfigurationRedacts(t *testing.T) {
	c := providers.GoogleConfig{ClientID: "private-client", ClientSecret: []byte("never-disclose-this-secret")}
	for _, formatted := range []string{fmt.Sprintf("%v", c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", &c)} {
		if strings.Contains(formatted, "never-disclose") || strings.Contains(formatted, "private-client") {
			t.Fatal("configuration diagnostic disclosed credential facts")
		}
	}
	if b, err := json.Marshal(c); err == nil || len(b) != 0 {
		t.Fatal("configuration serialized")
	}
	if b, err := c.MarshalText(); !errors.Is(err, providers.ErrGoogleConfiguration) || len(b) != 0 {
		t.Fatal("configuration text serialized")
	}
	if p, err := providers.NewGoogle(c); p != nil || !errors.Is(err, providers.ErrGoogleConfiguration) || strings.Contains(err.Error(), "never-disclose") {
		t.Fatal("invalid configuration disclosed source", err)
	}
}
