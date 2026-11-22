package oauth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/oauth"
)

// This bounded TLS wire fixture tests our client only; it is not a live GitHub
// or independent OAuth authorization-server interoperability claim.
func githubTLSClient(t *testing.T, handler http.Handler) *http.Client {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"github.com", "api.github.com"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "github.com:443" && address != "api.github.com:443" {
			return nil, errors.New("unexpected test origin")
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport}
}

func TestGitHubNonExpiringTokenExchangeKeepsFreshEvidenceSeparate(t *testing.T) {
	now := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	var tokenCalls, userCalls atomic.Int32
	c := githubOAuth2Config()
	c.Clock = oauth2Clock{now}
	c.HTTPClient = githubTLSClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		switch r.Host {
		case "github.com":
			tokenCalls.Add(1)
			if r.URL.Path != "/login/oauth/access_token" || r.Method != "POST" || r.Header.Get("Authorization") != "" || r.ParseForm() != nil || r.PostForm.Get("client_secret") != "test-only-client-secret" || r.PostForm.Get("code_verifier") != strings.Repeat("v", 64) {
				t.Error("token request lost exact origin/credential/S256 binding")
			}
			fmt.Fprint(w, `{"access_token":"test-only-access","token_type":"Bearer","scope":"read:user,user:email"}`)
		case "api.github.com":
			userCalls.Add(1)
			body, _ := io.ReadAll(r.Body)
			if r.URL.Path != "/user" || r.Method != "GET" || r.Header.Get("Authorization") != "Bearer test-only-access" || len(body) != 0 || r.URL.RawQuery != "" || r.Header.Get("User-Agent") == "" {
				t.Error("resource request leaked credentials or lost bearer binding")
			}
			fmt.Fprint(w, `{"id":42,"login":"mutable-login","email":"not-identity@example.invalid"}`)
		default:
			t.Error("foreign host")
			w.WriteHeader(400)
		}
	}))
	p, err := oauth.NewOAuth2UserInfoProviderWithPolicy(c, oauth.OAuth2GitHubOAuthAppPolicy)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	state := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	callback, err := oauth.ParseOAuth2QueryCallbackWithPolicy(context.Background(), "code=test-only-code&state="+state, c.RedirectURI, p.OAuth2Profile(), p.OAuth2TokenPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer callback.Destroy()
	verifier, err := oauth.NewPKCEVerifier([]byte(strings.Repeat("v", 64)))
	if err != nil {
		t.Fatal(err)
	}
	defer verifier.Destroy()
	input, _ := callback.Input()
	result, err := p.Exchange(context.Background(), input, verifier, "")
	if err != nil {
		t.Fatal("ordinary GitHub token response denied", err)
	}
	defer result.Tokens.Destroy()
	if tokenCalls.Load() != 1 || userCalls.Load() != 1 || result.Identity.Subject() != "42" || !result.Tokens.ExpiresAt().IsZero() || !result.Tokens.ReceivedAt().Equal(now) || !result.Identity.EvidenceExpiresAt().Equal(now.Add(20*time.Second)) || !result.Identity.IDTokenExpiresAt().IsZero() {
		t.Fatal("token lifetime was fabricated or confused with fresh identity evidence")
	}
}
