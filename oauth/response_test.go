package oauth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	identity "github.com/faustbrian/go-identity"
	oauth "github.com/faustbrian/go-identity/oauth"
)

func TestOIDCResponseFailuresAreNotRetried(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name              string
		status            int
		contentType, body string
		kind              oauth.ErrorKind
	}{
		{"refusal", 400, "application/json", `{"error":"invalid_grant","error_description":"provider-secret"}`, oauth.Refused},
		{"ambiguous-server", 500, "application/json", `{"error":"server_error"}`, oauth.Unknown},
		{"ambiguous-rate", 429, "application/json", `{"error":"temporarily_unavailable"}`, oauth.Unknown},
		{"redirect", 302, "application/json", `{}`, oauth.Unknown},
		{"duplicate-token", 200, "application/json", `{"access_token":"one","access_token":"two"}`, oauth.Unknown},
		{"duplicate-unknown", 200, "application/json", `{"extension":{"one":1,"one":2}}`, oauth.Unknown},
		{"trailing", 200, "application/json", `{} {}`, oauth.Unknown},
		{"malformed", 200, "application/json", `{"`, oauth.Unknown},
		{"wrong-content-type", 200, "text/html", `{}`, oauth.Unknown},
		{"oversize", 200, "application/json", strings.Repeat("x", 65537), oauth.Unknown},
		{"mixed-error", 400, "application/json", `{"error":"invalid_grant","access_token":"secret"}`, oauth.Unknown},
		{"unrecognized-error", 400, "application/json", `{"error":"provider-secret"}`, oauth.Unknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", tc.contentType)
				w.Header().Set("Location", "/redirected")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			provider, err := oauth.NewOIDCProvider(providerConfig(t, server.URL, server.Client(), key))
			if err != nil {
				t.Fatal(err)
			}
			defer provider.Close()
			_, err = provider.Exchange(context.Background(), callback(t), verifier(t), testNonce)
			var failure *oauth.Error
			if !errors.As(err, &failure) || failure.Kind() != tc.kind {
				t.Fatalf("wrong classification: %v", err)
			}
			if calls.Load() != 1 || strings.Contains(err.Error(), "provider-secret") {
				t.Fatal("retry or secret disclosure")
			}
		})
	}
}

func TestOIDCPreflightAndCancelledExchangeNeverSend(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer server.Close()
	provider, err := oauth.NewOIDCProvider(providerConfig(t, server.URL, server.Client(), key))
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := provider.Exchange(ctx, callback(t), verifier(t), testNonce); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled context not preserved")
	}
	for _, tc := range []struct {
		input    identity.OAuthCallbackInput
		verifier oauth.PKCEVerifier
		nonce    string
	}{{identity.OAuthCallbackInput{}, verifier(t), testNonce}, {callback(t), oauth.PKCEVerifier{}, testNonce}, {callback(t), verifier(t), "wrong"}} {
		if _, err := provider.Exchange(context.Background(), tc.input, tc.verifier, tc.nonce); err == nil {
			t.Fatal("invalid exchange admitted")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("preflight sent token request")
	}
}
