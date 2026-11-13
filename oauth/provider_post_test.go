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
	"strings"
	"sync/atomic"
	"testing"

	oauth "github.com/faustbrian/go-identity/oauth"
)

func TestOIDCProviderPostAuthentication(t *testing.T) {
	for _, outcome := range []string{"success", "invalid-nonce", "refused", "redirect", "canceled"} {
		t.Run(outcome, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			const credential = "configuration:+ & credential"
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != http.MethodPost || r.URL.RequestURI() != "/token" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || r.Header.Get("Authorization") != "" {
					t.Error("token request used an unexpected credential channel")
				}
				if err := r.ParseForm(); err != nil {
					t.Error("invalid token request form")
				}
				if len(r.PostForm) != 6 || r.PostForm.Get("client_id") != "client:+ secret" || r.PostForm.Get("client_secret") != credential || r.PostForm.Get("grant_type") != "authorization_code" || r.PostForm.Get("code") != " exact +/=: code " || r.PostForm.Get("code_verifier") != testVerifier || r.PostForm.Get("redirect_uri") != "https://application.example/callback" {
					t.Error("token form lost original credentials or code binding")
				}
				for _, values := range r.PostForm {
					if len(values) != 1 {
						t.Error("duplicate token form member")
					}
				}
				w.Header().Set("Content-Type", "application/json")
				if outcome == "refused" {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"configuration:+ & credential"}`))
					return
				}
				if outcome == "redirect" {
					w.Header().Set("Location", "/must-not-follow")
					w.WriteHeader(http.StatusTemporaryRedirect)
					return
				}
				claims := oidcClaims()
				if outcome == "invalid-nonce" {
					claims["nonce"] = "different-original-nonce"
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access-secret", "id_token": esToken(t, key, claims), "token_type": "Bearer", "expires_in": 3600})
			}))
			defer server.Close()
			config := providerConfig(t, server.URL+"/token", server.Client(), key)
			// Use the public wire value so RED proves runtime rejection, rather
			// than just failing to compile for the new named constant.
			config.ClientAuthentication = oauth.ClientAuthentication("client_secret_post")
			config.ClientSecret = []byte(credential)
			provider, err := oauth.NewOIDCProvider(config)
			if err != nil {
				t.Fatal("explicit post credential profile rejected:", err)
			}
			defer provider.Close()
			clear(config.ClientSecret)
			if err := provider.Profile().ValidateQueryCallback(); err != nil {
				t.Fatal("query callback rejected its configured credential profile:", err)
			}
			authorization, err := provider.Authorization(context.Background(), oauth.AuthorizationParameters{State: testNonce, Nonce: testNonce, PKCEChallenge: verifier(t).Challenge()})
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(authorization.URL(), "client_secret") || strings.Contains(fmt.Sprint(config, provider, provider.Profile()), credential) {
				t.Fatal("credential escaped token-request custody")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if outcome == "canceled" {
				cancel()
			}
			result, err := provider.Exchange(ctx, callback(t), verifier(t), testNonce)
			defer result.Tokens.Destroy()
			if outcome == "success" {
				if err != nil || result.Identity.Subject() != "provider-subject" || result.Identity.Issuer() != "https://issuer.example" || calls.Load() != 1 {
					t.Fatal("post-authenticated code did not produce the validated identity")
				}
				return
			}
			want := oauth.Unknown
			switch outcome {
			case "invalid-nonce":
				want = oauth.InvalidProof
			case "refused":
				want = oauth.Refused
			case "canceled":
				want = oauth.Unavailable
			}
			var failure *oauth.Error
			if !errors.As(err, &failure) || failure.Kind() != want || result.Identity.Subject() != "" {
				t.Fatal("failed post-authenticated exchange lost its closed outcome")
			}
			wantCalls := int32(1)
			if outcome == "canceled" {
				wantCalls = 0
			}
			if calls.Load() != wantCalls || strings.Contains(fmt.Sprint(err), credential) {
				t.Fatal("failed exchange retried or disclosed token credentials")
			}
		})
	}
}
