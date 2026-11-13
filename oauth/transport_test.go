package oauth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	oauth "github.com/faustbrian/go-identity/oauth"
)

func TestOIDCCancelAfterSendIsUnknownAndNotRetried(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan struct{})
	handlerDone := make(chan struct{})
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(handlerDone)
		calls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		close(received)
		<-r.Context().Done()
	}))
	defer server.Close()
	provider, err := oauth.NewOIDCProvider(providerConfig(t, server.URL, server.Client(), key))
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	input, proof := callback(t), verifier(t)
	go func() {
		result, err := provider.Exchange(ctx, input, proof, testNonce)
		result.Tokens.Destroy()
		done <- err
	}()
	select {
	case <-received:
	case <-ctx.Done():
		t.Fatal("token endpoint never received original code")
	}
	cancel()
	err = <-done
	var failure *oauth.Error
	if !errors.As(err, &failure) || failure.Kind() != oauth.Unknown || !errors.Is(err, context.Canceled) {
		t.Fatalf("wrong sent-cancellation outcome: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatal("cancelled code exchange retried")
	}
	select {
	case <-handlerDone:
	case <-time.After(time.Second):
		t.Fatal("request cancellation did not close handler")
	}
}

func TestOIDCUnexpectedEOFAfterSendNeverRetries(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		connection, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_ = connection.Close()
	}))
	defer server.Close()
	provider, err := oauth.NewOIDCProvider(providerConfig(t, server.URL, server.Client(), key))
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	_, err = provider.Exchange(context.Background(), callback(t), verifier(t), testNonce)
	var failure *oauth.Error
	if !errors.As(err, &failure) || failure.Kind() != oauth.Unknown || calls.Load() != 1 {
		t.Fatalf("ambiguous exchange retried or misclassified: %v", err)
	}
}

func TestOIDCPublicClientHasExactlyOneCredentialChannel(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("public client sent authorization header")
		}
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if len(r.PostForm) != 5 || r.PostForm.Get("client_id") != "client:+ secret" || r.PostForm.Has("client_secret") {
			t.Error("wrong public client channel")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "id_token": esToken(t, key, oidcClaims()), "token_type": "Bearer", "expires_in": 1})
	}))
	defer server.Close()
	config := providerConfig(t, server.URL, server.Client(), key)
	config.ClientAuthentication = oauth.PublicClient
	config.ClientSecret = nil
	provider, err := oauth.NewOIDCProvider(config)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	result, err := provider.Exchange(context.Background(), callback(t), verifier(t), testNonce)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Tokens.Destroy()
}

func TestOIDCOwnedHTTP1TransportOverridesInheritedProtocol(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 1 {
			t.Error("owned code exchange inherited HTTP2 retry policy")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "id_token": esToken(t, key, oidcClaims()), "token_type": "Bearer", "expires_in": 1})
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	client := server.Client()
	transport := client.Transport.(*http.Transport)
	transport.Protocols = new(http.Protocols)
	transport.Protocols.SetHTTP1(true)
	transport.Protocols.SetHTTP2(true)
	transport.TLSClientConfig.NextProtos = []string{"h2", "http/1.1"}
	provider, err := oauth.NewOIDCProvider(providerConfig(t, server.URL, client, key))
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	result, err := provider.Exchange(context.Background(), callback(t), verifier(t), testNonce)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Tokens.Destroy()
	if !transport.Protocols.HTTP2() || transport.TLSClientConfig.NextProtos[0] != "h2" {
		t.Fatal("caller-owned transport was mutated")
	}
}

type panickingClock struct{}

func (panickingClock) Now() time.Time { panic("clock-secret") }

type panickingKeySet struct{}

func (panickingKeySet) VerifySignature(context.Context, string) ([]byte, error) {
	panic("keyset-secret")
}

func TestOIDCPostSendCollaboratorPanicRemainsUnknown(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, which := range []string{"clock", "keyset"} {
		t.Run(which, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "id_token": esToken(t, key, oidcClaims()), "token_type": "Bearer", "expires_in": 60})
			}))
			defer server.Close()
			config := providerConfig(t, server.URL, server.Client(), key)
			if which == "clock" {
				config.Clock = panickingClock{}
			} else {
				config.KeySet = panickingKeySet{}
			}
			provider, err := oauth.NewOIDCProvider(config)
			if err != nil {
				t.Fatal(err)
			}
			defer provider.Close()
			result, err := provider.Exchange(context.Background(), callback(t), verifier(t), testNonce)
			defer result.Tokens.Destroy()
			var failure *oauth.Error
			if !errors.As(err, &failure) || failure.Kind() != oauth.Unknown || calls.Load() != 1 {
				t.Fatalf("post-send panic reported a pre-send failure: %v", err)
			}
			if strings.Contains(fmt.Sprint(err), "-secret") {
				t.Fatal("panic diagnostic leaked")
			}
		})
	}
}

func TestOIDCConfigurationFailsClosed(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		alter func(*oauth.OIDCConfig)
	}{
		{"http", func(c *oauth.OIDCConfig) { c.TokenEndpoint = "http://issuer.example/token" }},
		{"query", func(c *oauth.OIDCConfig) { c.TokenEndpoint = "https://issuer.example/token?client_secret=hidden" }},
		{"userinfo", func(c *oauth.OIDCConfig) { c.RedirectURI = "https://user@application.example/callback" }},
		{"fragment", func(c *oauth.OIDCConfig) { c.RedirectURI += "#" }},
		{"wildcard", func(c *oauth.OIDCConfig) { c.RedirectURI = "https://*.example/callback" }},
		{"backslash", func(c *oauth.OIDCConfig) { c.RedirectURI = "https://application.example/\\callback" }},
		{"scope-duplicate", func(c *oauth.OIDCConfig) { c.Scopes = []string{"openid", "openid"} }},
		{"scope-missing-openid", func(c *oauth.OIDCConfig) { c.Scopes = []string{"profile"} }},
		{"scope-injection", func(c *oauth.OIDCConfig) { c.Scopes = []string{"openid profile"} }},
		{"algorithm-none", func(c *oauth.OIDCConfig) { c.Algorithms = []string{"none"} }},
		{"algorithm-duplicate", func(c *oauth.OIDCConfig) { c.Algorithms = []string{"ES256", "ES256"} }},
		{"client-auth-missing", func(c *oauth.OIDCConfig) { c.ClientAuthentication = "" }},
		{"client-auth-unknown", func(c *oauth.OIDCConfig) { c.ClientAuthentication = "client_secret_unknown" }},
		{"client-auth-post-empty", func(c *oauth.OIDCConfig) { c.ClientAuthentication = oauth.ClientSecretPost; c.ClientSecret = nil }},
		{"client-auth-post-control", func(c *oauth.OIDCConfig) {
			c.ClientAuthentication = oauth.ClientSecretPost
			c.ClientSecret = []byte("invalid\x00credential")
		}},
		{"client-auth-post-limit", func(c *oauth.OIDCConfig) {
			c.ClientAuthentication = oauth.ClientSecretPost
			c.ClientSecret = []byte(strings.Repeat("x", 4097))
		}},
		{"public-secret", func(c *oauth.OIDCConfig) { c.ClientAuthentication = oauth.PublicClient }},
		{"missing-keyset", func(c *oauth.OIDCConfig) { c.KeySet = nil }},
		{"timeout", func(c *oauth.OIDCConfig) { c.Timeout = 31 * time.Second }},
		{"skew", func(c *oauth.OIDCConfig) { c.ClockSkew = 6 * time.Minute }},
		{"body-limit", func(c *oauth.OIDCConfig) { c.MaxResponseBytes = 1<<20 + 1 }},
		{"token-limit", func(c *oauth.OIDCConfig) { c.MaxTokenBytes = 16<<10 + 1 }},
		{"code-limit", func(c *oauth.OIDCConfig) { c.MaxCodeBytes = 64<<10 + 1 }},
		{"insecure-tls", func(c *oauth.OIDCConfig) {
			c.HTTPClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
		}},
		{"tls-dial-bypass", func(c *oauth.OIDCConfig) {
			c.HTTPClient = &http.Client{Transport: &http.Transport{DialTLSContext: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("must not run") }}}
		}},
		{"legacy-tls-dial-bypass", func(c *oauth.OIDCConfig) {
			transport := &http.Transport{}
			//lint:ignore SA1019 Deliberately exercise the legacy TLS-verification bypass so its rejection cannot be removed merely to silence deprecation.
			transport.DialTLS = func(string, string) (net.Conn, error) { return nil, errors.New("must not run") } //nolint:staticcheck // SA1019: Deliberately exercise the legacy TLS-verification bypass rejection.
			c.HTTPClient = &http.Client{Transport: transport}
		}},
		{"tls-host-override", func(c *oauth.OIDCConfig) {
			c.HTTPClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{ServerName: "another.example"}}}
		}},
		{"obsolete-tls", func(c *oauth.OIDCConfig) {
			c.HTTPClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS10}}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := providerConfig(t, "https://issuer.example/token", nil, key)
			tc.alter(&config)
			provider, err := oauth.NewOIDCProvider(config)
			if err == nil {
				provider.Close()
				t.Fatal("invalid configuration admitted")
			}
			if strings.Contains(err.Error(), "hidden") {
				t.Fatal("configuration error leaked secret")
			}
		})
	}
}
