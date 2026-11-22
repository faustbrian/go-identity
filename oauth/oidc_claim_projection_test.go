package oauth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	oauth "github.com/faustbrian/go-identity/oauth"
)

func projectionFixture(t *testing.T, claims map[string]any, mutate func(string) string) oauth.OIDCConfig {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	token := esToken(t, key, claims)
	if mutate != nil {
		token = mutate(token)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access-secret", "refresh_token": "refresh-secret", "id_token": token, "token_type": "Bearer", "expires_in": 60})
	}))
	t.Cleanup(server.Close)
	return providerConfig(t, server.URL, server.Client(), key)
}

func TestOIDCClaimProjectionPreservesSelectedStatesAndOwnership(t *testing.T) {
	claims := oidcClaims()
	claims["null_value"] = nil
	claims["empty"] = ""
	claims["name"] = " exact é value "
	claims["disabled"] = false
	claims["enabled"] = true
	claims["Name"] = "case-sensitive, not selected"
	claims["unselected"] = []string{"not projected"}
	names := []string{"absent", "null_value", "empty", "name", "disabled", "enabled"}
	provider, err := oauth.NewOIDCProviderWithClaims(projectionFixture(t, claims, nil), oauth.OIDCClaimProjectionConfig{Names: names})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(provider.Close)
	names[0] = "unselected"
	result, err := provider.Exchange(context.Background(), callback(t), verifier(t), testNonce)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Tokens.Destroy()
	got := result.VerifiedOIDCClaims()
	if len(got) != 6 {
		t.Fatal("selected claims missing")
	}
	for index, want := range []struct {
		name string
		kind oauth.OIDCClaimKind
		text string
		flag bool
	}{
		{"absent", oauth.OIDCClaimAbsent, "", false},
		{"null_value", oauth.OIDCClaimNull, "", false},
		{"empty", oauth.OIDCClaimString, "", false},
		{"name", oauth.OIDCClaimString, " exact é value ", false},
		{"disabled", oauth.OIDCClaimBool, "", false},
		{"enabled", oauth.OIDCClaimBool, "", true},
	} {
		claim := got[index]
		text, hasString := claim.StringValue()
		flag, hasBool := claim.BoolValue()
		if claim.Name() != want.name || claim.Kind() != want.kind || text != want.text || flag != want.flag || hasString != (want.kind == oauth.OIDCClaimString) || hasBool != (want.kind == oauth.OIDCClaimBool) {
			t.Fatalf("selected claim %d lost its exact state", index)
		}
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if strings.Contains(fmt.Sprintf(verb, claim), " exact é value ") {
				t.Fatal("claim diagnostics disclosed its value")
			}
		}
	}
	got[0] = oauth.VerifiedOIDCClaim{}
	if fresh := result.VerifiedOIDCClaims(); fresh[0].Name() != "absent" || fresh[0].Kind() != oauth.OIDCClaimAbsent {
		t.Fatal("caller mutated retained projection")
	}
	for _, value := range []any{result.Identity, result} {
		for _, verb := range []string{"%v", "%+v", "%#v"} {
			if strings.Contains(fmt.Sprintf(verb, value), " exact é value ") {
				t.Fatal("nested diagnostics disclosed a selected claim")
			}
		}
	}
	result.Tokens.Destroy()
	if text, ok := result.VerifiedOIDCClaims()[3].StringValue(); !ok || text != " exact é value " {
		t.Fatal("claim projection borrowed token custody")
	}
}

func TestOIDCClaimProjectionIsOptIn(t *testing.T) {
	for _, google := range []bool{false, true} {
		t.Run(fmt.Sprint("google=", google), func(t *testing.T) {
			claims := oidcClaims()
			claims["name"] = "not selected"
			if google {
				claims["iss"] = "https://accounts.google.com"
			}
			config := projectionFixture(t, claims, nil)
			var provider *oauth.OIDCProvider
			var err error
			if google {
				config.Issuer = "https://accounts.google.com"
				provider, err = oauth.NewGoogleAccountsProvider(config)
			} else {
				provider, err = oauth.NewOIDCProvider(config)
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(provider.Close)
			result, err := provider.Exchange(context.Background(), callback(t), verifier(t), testNonce)
			if err != nil {
				t.Fatal(err)
			}
			defer result.Tokens.Destroy()
			if len(result.VerifiedOIDCClaims()) != 0 {
				t.Fatal("default path projected claims")
			}
		})
	}
	if len((oauth.ExchangeResult{}).VerifiedOIDCClaims()) != 0 {
		t.Fatal("zero result projected claims")
	}
}

func TestOIDCClaimProjectionConfigurationBounds(t *testing.T) {
	config := projectionFixture(t, oidcClaims(), nil)
	for _, names := range [][]string{nil, {""}, {"same", "same"}, {"with space"}, {"a/b"}, {"a:b"}, {"é"}, {"1name"}, {"nonce"}, {"at_hash"}, {"c_hash"}, {"access_token"}, {"refresh_token"}, {"id_token"}, {strings.Repeat("a", 129)}, make([]string, 129)} {
		provider, err := oauth.NewOIDCProviderWithClaims(config, oauth.OIDCClaimProjectionConfig{Names: names})
		if provider != nil {
			provider.Close()
		}
		var failure *oauth.Error
		if !errors.As(err, &failure) || failure.Kind() != oauth.InvalidInput || provider != nil {
			t.Fatal("invalid projection configuration accepted")
		}
	}
	names := make([]string, 128)
	for index := range names {
		names[index] = fmt.Sprintf("Claim_%d.ext-name", index)
	}
	names[0] = strings.Repeat("a", 128)
	provider, err := oauth.NewOIDCProviderWithClaims(config, oauth.OIDCClaimProjectionConfig{Names: names})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(provider.Close)
	result, err := provider.Exchange(context.Background(), callback(t), verifier(t), testNonce)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Tokens.Destroy()
	if len(result.VerifiedOIDCClaims()) != 128 {
		t.Fatal("valid configuration boundary lost selected absent claims")
	}
}

func TestOIDCClaimProjectionScalarBounds(t *testing.T) {
	for _, test := range []struct {
		name  string
		value any
		valid bool
	}{
		{"ascii-at-limit", strings.Repeat("a", 4096), true},
		{"utf8-at-limit", strings.Repeat("é", 2048), true},
		{"ascii-over-limit", strings.Repeat("a", 4097), false},
		{"utf8-over-limit", strings.Repeat("é", 2049), false},
		{"number", 1, false},
		{"array", []string{"value"}, false},
		{"object", map[string]any{"value": true}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			claims := oidcClaims()
			claims["selected"] = test.value
			provider, err := oauth.NewOIDCProviderWithClaims(projectionFixture(t, claims, nil), oauth.OIDCClaimProjectionConfig{Names: []string{"selected"}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(provider.Close)
			result, err := provider.Exchange(context.Background(), callback(t), verifier(t), testNonce)
			defer result.Tokens.Destroy()
			if !test.valid {
				assertProjectionRefused(t, result, err, oauth.InvalidProof)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := result.VerifiedOIDCClaims(); len(got) != 1 {
				t.Fatal("bounded string was not projected")
			} else if value, ok := got[0].StringValue(); !ok || value != test.value {
				t.Fatal("bounded string was altered")
			}
		})
	}
}

func TestOIDCClaimProjectionRequiresCompleteProof(t *testing.T) {
	for _, field := range []string{"iss", "aud", "azp", "nonce", "iat", "exp", "sub", "at_hash", "c_hash", "mutated-payload", "signature"} {
		t.Run(field, func(t *testing.T) {
			claims := oidcClaims()
			claims["selected"] = "must not escape"
			var mutate func(string) string
			switch field {
			case "iat":
				claims[field] = testNow.Add(time.Hour).Unix()
			case "exp":
				claims[field] = testNow.Add(-time.Hour).Unix()
			case "sub":
				claims[field] = ""
			case "mutated-payload":
				mutate = func(token string) string {
					parts := strings.Split(token, ".")
					claims["selected"] = "substituted"
					payload, err := json.Marshal(claims)
					if err != nil {
						t.Fatal(err)
					}
					parts[1] = base64.RawURLEncoding.EncodeToString(payload)
					return strings.Join(parts, ".")
				}
			case "signature":
				mutate = func(token string) string { return token[:len(token)-4] + "AAAA" }
			default:
				claims[field] = "wrong"
			}
			provider, err := oauth.NewOIDCProviderWithClaims(projectionFixture(t, claims, mutate), oauth.OIDCClaimProjectionConfig{Names: []string{"selected"}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(provider.Close)
			result, err := provider.Exchange(context.Background(), callback(t), verifier(t), testNonce)
			assertProjectionRefused(t, result, err, oauth.InvalidProof)
		})
	}
}

func TestOIDCClaimProjectionPreservesExchangeDispositions(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		status int
		body   string
		kind   oauth.ErrorKind
	}{
		{"refused", http.StatusBadRequest, `{"error":"invalid_grant"}`, oauth.Refused},
		{"unavailable-response", http.StatusServiceUnavailable, `{"error":"temporarily_unavailable"}`, oauth.Unknown},
		{"malformed-success", http.StatusOK, `{"access_token":`, oauth.Unknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			t.Cleanup(server.Close)
			provider, err := oauth.NewOIDCProviderWithClaims(providerConfig(t, server.URL, server.Client(), key), oauth.OIDCClaimProjectionConfig{Names: []string{"selected"}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(provider.Close)
			result, err := provider.Exchange(context.Background(), callback(t), verifier(t), testNonce)
			assertProjectionRefused(t, result, err, test.kind)
		})
	}
}

func assertProjectionRefused(t *testing.T, result oauth.ExchangeResult, err error, kind oauth.ErrorKind) {
	t.Helper()
	defer result.Tokens.Destroy()
	var failure *oauth.Error
	if !errors.As(err, &failure) || failure.Kind() != kind {
		t.Fatalf("wrong refusal: %v", err)
	}
	if result.Identity != (oauth.ProviderIdentity{}) || len(result.VerifiedOIDCClaims()) != 0 || result.Tokens.Use(context.Background(), func(context.Context, oauth.TokenBytes) error { return nil }) == nil {
		t.Fatal("refused proof returned identity, claims or token custody")
	}
}
