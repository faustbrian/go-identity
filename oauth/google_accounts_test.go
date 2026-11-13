package oauth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/oauth"
)

const googleIssuer = "https://accounts.google.com"

func TestGoogleAccountsProviderSignedIssuerForms(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, issuer := range []string{googleIssuer, "accounts.google.com"} {
		t.Run(issuer, func(t *testing.T) {
			claims := oidcClaims()
			claims["iss"] = issuer
			claims["sub"] = "same exact Google subject:+ /"
			claims["auth_time"] = testNow.Add(-time.Minute).Unix()
			claims["at_hash"] = googleHash("access-secret")
			claims["c_hash"] = googleHash(" exact +/=: code ")
			original := esToken(t, key, claims)
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if err := r.ParseForm(); err != nil || r.PostForm.Get("code") != " exact +/=: code " || r.PostForm.Get("code_verifier") != testVerifier {
					t.Error("original code/PKCE lost")
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access-secret", "id_token": original, "token_type": "Bearer", "expires_in": 3600})
			}))
			defer server.Close()
			config := providerConfig(t, server.URL+"/token", server.Client(), key)
			config.Issuer = googleIssuer
			provider, err := oauth.NewGoogleAccountsProvider(config)
			if err != nil {
				t.Fatal(err)
			}
			defer provider.Close()
			if calls.Load() != 0 || !provider.Profile().GoogleAccounts {
				t.Fatal("constructor performed IO or lost explicit policy")
			}
			result, err := provider.Exchange(context.Background(), callback(t), verifier(t), testNonce)
			if err != nil {
				t.Fatal(err)
			}
			defer result.Tokens.Destroy()
			when, present := result.Identity.AuthenticationTime()
			if calls.Load() != 1 || result.Identity.Issuer() != googleIssuer || result.Identity.Subject() != claims["sub"] || !present || !when.Equal(testNow.Add(-time.Minute)) || !result.Identity.IDTokenIssuedAt().Equal(testNow) || !result.Identity.IDTokenExpiresAt().Equal(testNow.Add(time.Minute)) {
				t.Fatal("verified identity, exact subject or source lifetime changed")
			}
			if err := result.Tokens.Use(context.Background(), func(_ context.Context, tokens oauth.TokenBytes) error {
				if string(tokens.IDToken) != original {
					t.Fatal("original signed token rewritten")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func googleHash(value string) string {
	digest := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(digest[:16])
}

func TestGoogleAccountsProviderSelectionAndProofDenial(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		strict bool
		change func(map[string]any)
		signer *ecdsa.PrivateKey
	}{
		{"strict rejects legacy", true, func(c map[string]any) { c["iss"] = "accounts.google.com" }, key},
		{"wrong issuer", false, func(c map[string]any) { c["iss"] = "https://accounts.google.com/" }, key},
		{"wrong key", false, func(map[string]any) {}, wrong},
		{"wrong audience", false, func(c map[string]any) { c["aud"] = "another-client" }, key},
		{"wrong azp", false, func(c map[string]any) { c["azp"] = "another-client" }, key},
		{"wrong nonce", false, func(c map[string]any) { c["nonce"] = strings.Repeat("x", 43) }, key},
		{"expired", false, func(c map[string]any) { c["exp"] = testNow.Add(-2 * time.Minute).Unix() }, key},
		{"future issued", false, func(c map[string]any) { c["iat"] = testNow.Add(2 * time.Minute).Unix() }, key},
		{"wrong access hash", false, func(c map[string]any) { c["at_hash"] = googleHash("different-access") }, key},
		{"wrong code hash", false, func(c map[string]any) { c["c_hash"] = googleHash("different-code") }, key},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := oidcClaims()
			claims["iss"] = googleIssuer
			tc.change(claims)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access-secret", "id_token": esToken(t, tc.signer, claims), "token_type": "Bearer", "expires_in": 3600})
			}))
			defer server.Close()
			config := providerConfig(t, server.URL+"/token", server.Client(), key)
			config.Issuer = googleIssuer
			var provider *oauth.OIDCProvider
			if tc.strict {
				provider, err = oauth.NewOIDCProvider(config)
			} else {
				provider, err = oauth.NewGoogleAccountsProvider(config)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer provider.Close()
			result, err := provider.Exchange(context.Background(), callback(t), verifier(t), testNonce)
			defer result.Tokens.Destroy()
			var rejected *oauth.Error
			if !errors.As(err, &rejected) || rejected.Kind() != oauth.InvalidProof || result.Identity.Issuer() != "" || result.Identity.Subject() != "" {
				t.Fatal("invalid signed proof admitted", err)
			}
		})
	}
}

func TestGoogleAccountsProfileRemainsCanonicalAndStrictByDefault(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	config := providerConfig(t, "https://token.example/token", nil, key)
	for _, issuer := range []string{"accounts.google.com", "https://other.example", googleIssuer + "/"} {
		config.Issuer = issuer
		if p, err := oauth.NewGoogleAccountsProvider(config); err == nil || p != nil {
			if p != nil {
				p.Close()
			}
			t.Fatal("Google selection admitted noncanonical configuration")
		}
	}
	config.Issuer = googleIssuer
	selected, err := oauth.NewGoogleAccountsProvider(config)
	if err != nil {
		t.Fatal(err)
	}
	defer selected.Close()
	strict, err := oauth.NewOIDCProvider(config)
	if err != nil {
		t.Fatal(err)
	}
	defer strict.Close()
	selectedBytes, err := json.Marshal(selected.Profile())
	if err != nil {
		t.Fatal(err)
	}
	strictBytes, err := json.Marshal(strict.Profile())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(strictBytes), "GoogleAccounts") || !strings.HasSuffix(string(selectedBytes), `,"GoogleAccounts":true}`) {
		t.Fatal("zero policy changed legacy JSON or selected policy absent")
	}
	if string(strictBytes[:len(strictBytes)-1])+`,"GoogleAccounts":true}` != string(selectedBytes) {
		t.Fatal("explicit selection changed unrelated profile fields")
	}
	for _, issuer := range []string{googleIssuer, "accounts.google.com"} {
		query := (url.Values{"code": {"code"}, "state": {testNonce}, "iss": {issuer}}).Encode()
		parsed, err := oauth.ParseQueryCallback(context.Background(), query, selected.Profile())
		if issuer == googleIssuer {
			if err != nil || !parsed.Profile().GoogleAccounts {
				t.Fatal("canonical callback lost policy", err)
			}
			parsed.Destroy()
		} else if err == nil {
			parsed.Destroy()
			t.Fatal("Google signed-token policy widened raw callback issuer")
		}
	}
	malformed := selected.Profile()
	malformed.Issuer = "https://other.example"
	if malformed.ValidateQueryCallback() == nil {
		t.Fatal("Google profile admitted unrelated issuer")
	}
}

func FuzzGoogleAccountsQueryIssuer(f *testing.F) {
	for _, issuer := range []string{googleIssuer, "accounts.google.com", googleIssuer + "/", "https://other.example", "", "\x00"} {
		f.Add(issuer, true)
		f.Add(issuer, false)
	}
	f.Fuzz(func(t *testing.T, issuer string, selected bool) {
		profile := queryProfile()
		profile.Issuer, profile.GoogleAccounts = googleIssuer, selected
		query := (url.Values{"code": {"original-code"}, "state": {testNonce}, "iss": {issuer}}).Encode()
		parsed, err := oauth.ParseQueryCallback(context.Background(), query, profile)
		defer parsed.Destroy()
		if issuer != googleIssuer {
			if err == nil {
				t.Fatal("signed-token selection admitted a noncanonical raw issuer")
			}
			return
		}
		if err != nil || parsed.Profile().GoogleAccounts != selected {
			t.Fatal("canonical query lost exact selected policy", err)
		}
	})
}
