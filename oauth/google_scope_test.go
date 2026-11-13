package oauth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/faustbrian/go-identity/oauth"
)

func TestGoogleAccountsReturnedScopeAliases(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const emailURI = "https://www.googleapis.com/auth/userinfo.email"
	const profileURI = "https://www.googleapis.com/auth/userinfo.profile"
	requested := []string{"openid", "email", "profile"}
	for _, tc := range []struct {
		name, returned string
		configured     []string
		generic        bool
		want           []string
		kind           oauth.ErrorKind
	}{
		{name: "documented URI scopes", returned: "openid " + emailURI + " " + profileURI, want: requested},
		{name: "short scopes", returned: "openid email profile", want: requested},
		{name: "equivalent spellings collapse", returned: "openid " + emailURI + " email profile " + profileURI, want: requested},
		{name: "reported subset stays narrow", returned: "openid " + emailURI, want: []string{"openid", "email"}},
		{name: "unrequested alias denied", returned: "openid " + emailURI, configured: []string{"openid"}, kind: oauth.Unknown},
		{name: "unknown scope denied", returned: "openid https://www.googleapis.com/auth/drive", kind: oauth.Unknown},
		{name: "lookalike URI denied", returned: "openid " + emailURI + "/", kind: oauth.Unknown},
		{name: "duplicate raw scope denied", returned: "openid " + emailURI + " " + emailURI, kind: oauth.Unknown},
		{name: "generic remains strict", returned: "openid " + emailURI + " " + profileURI, generic: true, kind: oauth.Unknown},
		{name: "explicit URI configuration preserved", returned: "openid " + emailURI, configured: []string{"openid", emailURI}, want: []string{"openid", emailURI}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := oidcClaims()
			claims["iss"] = googleIssuer
			original := esToken(t, key, claims)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access-secret", "refresh_token": "refresh-secret", "id_token": original, "token_type": "Bearer", "expires_in": 3600, "scope": tc.returned})
			}))
			defer server.Close()
			config := providerConfig(t, server.URL+"/token", server.Client(), key)
			config.Issuer = googleIssuer
			config.Scopes = slices.Clone(requested)
			if tc.configured != nil {
				config.Scopes = slices.Clone(tc.configured)
			}
			var provider *oauth.OIDCProvider
			if tc.generic {
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
			if tc.kind != "" {
				var denied *oauth.Error
				if !errors.As(err, &denied) || denied.Kind() != tc.kind || result.Identity.Subject() != "" {
					t.Fatal("invalid returned scope was not denied", err)
				}
				return
			}
			if err != nil {
				t.Fatal("equivalent requested scope was rejected", err)
			}
			if !slices.Equal(result.Tokens.GrantedScopes(), tc.want) || !slices.Equal(result.Tokens.RequestedScopes(), config.Scopes) || !result.Tokens.ScopeReported() {
				t.Fatal("reported permission set expanded or exact request changed")
			}
			if err := result.Tokens.Use(context.Background(), func(_ context.Context, tokens oauth.TokenBytes) error {
				if string(tokens.IDToken) != original || string(tokens.AccessToken) != "access-secret" || string(tokens.RefreshToken) != "refresh-secret" {
					t.Fatal("scope normalization rewrote original token bytes")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
