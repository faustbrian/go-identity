//go:build integration

package providers_test

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/oauth/providers"
)

// This is an actual external Keycloak server, not a Golib protocol stand-in.
// The launcher owns its immutable image, realm, client/user and verified TLS.
func TestKeycloakActualAuthorizationCodeAndProof(t *testing.T) {
	address, caFile := os.Getenv("KEYCLOAK_TEST_ADDRESS"), os.Getenv("KEYCLOAK_TEST_CA")
	if address == "" || caFile == "" {
		t.Skip("isolated Keycloak fixture not selected")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client := keycloakFixtureClient(t, address, caFile)
	issuer := "https://keycloak.example/realms/golib-keycloak-test"
	metadata := keycloakFixtureRead(t, ctx, client, issuer+"/.well-known/openid-configuration")
	var endpoints struct {
		JWKS string `json:"jwks_uri"`
	}
	if json.Unmarshal(metadata, &endpoints) != nil || !strings.HasPrefix(endpoints.JWKS, issuer+"/") {
		t.Fatal("Keycloak discovery did not bind realm keys")
	}
	keys := coreoidc.NewRemoteKeySet(coreoidc.ClientContext(ctx, client), endpoints.JWKS)
	p, err := providers.NewKeycloak(providers.KeycloakConfig{Version: 1, Issuer: issuer, ClientID: "golib-keycloak-consumer", ClientSecret: []byte("test-only-keycloak-client-secret"), RedirectURI: "https://application.example/keycloak/callback", Metadata: metadata, MetadataSHA256: sha256.Sum256(metadata), KeySet: keys, HTTPClient: client, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal("pinned actual Keycloak discovery was rejected", err)
	}
	defer p.Close()
	t.Logf("Keycloak 26.4.0 discovery SHA-256 %x", sha256.Sum256(metadata))
	state := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	verifier, err := oauth.NewPKCEVerifier([]byte(strings.Repeat("v", 64)))
	if err != nil {
		t.Fatal(err)
	}
	defer verifier.Destroy()
	authorization, err := p.Authorization(ctx, oauth.AuthorizationParameters{State: state, Nonce: state, PKCEChallenge: verifier.Challenge()})
	if err != nil {
		t.Fatal(err)
	}
	callbackURL := keycloakFixtureAuthorize(t, ctx, client, authorization.URL())
	callback, err := oauth.ParseQueryCallback(ctx, callbackURL.RawQuery, p.Profile())
	if err != nil || callback.Denied() {
		t.Fatal("actual Keycloak callback was not selected code/query/iss", err)
	}
	defer callback.Destroy()
	input, success := callback.Input()
	if !success {
		t.Fatal("successful callback input absent")
	}
	out, err := p.Exchange(ctx, input, verifier, state)
	if err != nil {
		t.Fatal("actual Keycloak code exchange/proof failed", err)
	}
	defer out.Tokens.Destroy()
	if out.Identity.Issuer() != issuer || out.Identity.Subject() == "" {
		t.Fatal("actual Keycloak subject was lost")
	}
	if _, err := p.Exchange(ctx, input, verifier, state); err == nil {
		t.Fatal("Keycloak authorization code was reusable")
	}
}

func keycloakFixtureClient(t *testing.T, address, caFile string) *http.Client {
	t.Helper()
	certificate, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal("fixture CA unavailable")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificate) {
		t.Fatal("fixture CA invalid")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, DialContext: func(ctx context.Context, network, target string) (net.Conn, error) {
		if target != "keycloak.example:443" {
			return nil, &net.AddrError{Err: "unexpected fixture host"}
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}}
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Transport: transport, Jar: jar, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(client.CloseIdleConnections)
	return client
}

func keycloakFixtureRead(t *testing.T, ctx context.Context, client *http.Client, target string) []byte {
	t.Helper()
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		t.Fatal("invalid fixture request")
	}
	out, err := client.Do(r)
	if err != nil {
		t.Fatal("verified TLS provider request failed", err)
	}
	defer out.Body.Close()
	body, err := io.ReadAll(io.LimitReader(out.Body, 65537))
	if err != nil || len(body) > 65536 || out.StatusCode != 200 {
		t.Fatal("bounded provider response unavailable", out.StatusCode)
	}
	return body
}

func keycloakFixtureAuthorize(t *testing.T, ctx context.Context, client *http.Client, target string) *url.URL {
	t.Helper()
	body := keycloakFixtureRead(t, ctx, client, target)
	action := regexp.MustCompile(`<form[^>]+action="([^"]+)"`).FindSubmatch(body)
	if len(action) != 2 {
		t.Fatal("actual Keycloak login form absent")
	}
	login := html.UnescapeString(string(action[1]))
	u, err := url.Parse(login)
	if err != nil || u.Scheme != "https" || u.Host != "keycloak.example" {
		t.Fatal("login form escaped selected provider")
	}
	form := url.Values{"username": {"keycloak-test-user"}, "password": {"test-only-keycloak-user-password"}, "credentialId": {""}}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, login, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal("login request unavailable")
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	out, err := client.Do(r)
	if err != nil {
		t.Fatal("Keycloak browser login failed", err)
	}
	defer out.Body.Close()
	if out.StatusCode != 302 {
		t.Fatal("Keycloak did not return an authorization response", out.StatusCode)
	}
	callback, err := url.Parse(out.Header.Get("Location"))
	if err != nil || callback.Scheme != "https" || callback.Host != "application.example" || callback.Path != "/keycloak/callback" || callback.Query().Get("iss") != "https://keycloak.example/realms/golib-keycloak-test" || callback.Query().Get("code") == "" {
		t.Fatal("Keycloak callback escaped original redirect/issuer")
	}
	return callback
}
