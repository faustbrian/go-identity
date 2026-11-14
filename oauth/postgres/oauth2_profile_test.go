package postgres

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/oauth"
)

func nativeOAuth2Profile() oauth.ProviderProfile {
	p := nativeGoogleProfile()
	p.ID = "gitlab"
	p.Issuer = "https://gitlab.example"
	p.AuthorizationEndpoint = p.Issuer + "/oauth/authorize"
	p.TokenEndpoint = p.Issuer + "/oauth/token"
	p.RedirectURI = "https://application.example/gitlab/callback"
	p.ClientAuthentication = oauth.ClientSecretPost
	p.Scopes = []string{"read_user"}
	p.Algorithms = nil
	p.NonceRequired = false
	p.NonceBytes = 0
	return p
}

func TestOAuth2NativeTokenVaultAcceptsAbsentIDTokenOnlyForBoundVariant(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/oauth/token" {
			fmt.Fprint(w, `{"access_token":"test-only-vault-token","token_type":"Bearer","expires_in":60,"scope":"read_user"}`)
			return
		}
		fmt.Fprint(w, `{"id":42}`)
	}))
	defer server.Close()
	provider, err := oauth.NewOAuth2UserInfoProvider(oauth.OAuth2UserInfoConfig{ID: "gitlab", Version: 1, Issuer: server.URL, ClientID: "client", ClientSecret: []byte("test-only-client-secret"), RedirectURI: "https://app.example/gitlab", AuthorizationEndpoint: server.URL + "/oauth/authorize", TokenEndpoint: server.URL + "/oauth/token", UserInfoEndpoint: server.URL + "/api/v4/user", Scopes: []string{"read_user"}, SubjectClaim: "id", SubjectEncoding: oauth.OAuth2PositiveIntegerSubject, ClientAuthentication: oauth.ClientSecretPost, HTTPClient: server.Client(), Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	profile := provider.OAuth2Profile()
	query := (url.Values{"code": {"vault-code"}, "state": {base64.RawURLEncoding.EncodeToString(make([]byte, 32))}}).Encode()
	callback, err := oauth.ParseOAuth2QueryCallback(context.Background(), query, profile.Profile.RedirectURI, profile)
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
	result, err := provider.Exchange(context.Background(), input, verifier, "")
	if err != nil {
		t.Fatal(err)
	}
	defer result.Tokens.Destroy()
	s, b, oldTokens := rpVaultFixture(t, true)
	oldTokens.Destroy()
	s.profiles = map[string]oauth.ProviderProfile{profile.Profile.ID: profile.Profile}
	s.oauth2Profiles = map[string]oauth.OAuth2UserInfoDetails{profile.Profile.ID: profile.Details}
	b.ProviderID = profile.Profile.ID
	b.Issuer = profile.Profile.Issuer
	b.ClientID = profile.Profile.ClientID
	b.ConfigurationVersion = profile.Profile.Version
	prepared, err := s.sealProviderTokens(context.Background(), b, result.Tokens)
	if err != nil {
		t.Fatal("native OAuth2 vault required an invented ID token", err)
	}
	if err := s.validatePreparedProviderTokens(context.Background(), prepared); err != nil {
		t.Fatal("native OAuth2 vault restoration", err)
	}
	s.oauth2Profiles = nil
	if err := s.validatePreparedProviderTokens(context.Background(), prepared); err == nil {
		t.Fatal("OIDC accepted absent ID token without authenticated variant")
	}
}

func TestOAuth2NativeBindingWithoutProviderNonceRetainsExistingAAD(t *testing.T) {
	p := nativeOAuth2Profile()
	b := verifierBinding(t)
	selected, err := newRPVerifierBinding(b.tenant, p, b.transactionID, b.stateDigest, b.operation)
	if err != nil {
		t.Fatal("native state rejected real OAuth2/S256 shape", err)
	}
	aad, err := selected.aad()
	if err != nil {
		t.Fatal(err)
	}
	values := aad.Values()
	if len(values) != 10 || values["provider"] != p.ID || values["issuer"] != p.Issuer || values["redirect_uri"] != p.RedirectURI {
		t.Fatal("OAuth2 replaced the established verifier AAD binding")
	}
}

func TestOAuth2NativeCallbackBindsFullUserInfoFacts(t *testing.T) {
	p, _, request, clock := rpCallbackInputFixture(t)
	profile := nativeOAuth2Profile()
	profile.ID = p.input.Provider
	details := oauth.OAuth2UserInfoDetails{UserInfoEndpoint: profile.Issuer + "/api/v4/user", SubjectClaim: "id", SubjectEncoding: oauth.OAuth2PositiveIntegerSubject, ProofLifetime: 20 * time.Second}
	p.service.profiles[profile.ID] = profile
	p.service.oauth2Profiles = map[string]oauth.OAuth2UserInfoDetails{profile.ID: details}
	wire, err := p.generateOutput(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	out, _, _, err := p.restoreOutput(context.Background(), 1, wire)
	if err != nil {
		t.Fatal(err)
	}
	if out.Binding.OAuth2 == nil || *out.Binding.OAuth2 != details {
		t.Fatal("native state omitted UserInfo proof facts")
	}
	query := (url.Values{"code": {"test-code"}, "state": {out.Binding.State}}).Encode()
	parsed, err := oauth.ParseOAuth2QueryCallback(context.Background(), query, profile.RedirectURI, oauth.OAuth2UserInfoProfile{Profile: profile, Details: details})
	if err != nil {
		t.Fatal(err)
	}
	defer parsed.Destroy()
	request.Callback = parsed
	flow, err := p.service.authenticateRPCallback(context.Background(), request, out.Binding, out.StateProofCiphertext, *clock)
	if err != nil {
		t.Fatal("original OAuth2 transaction rejected", err)
	}
	flow.destroy()
	changed := details
	changed.UserInfoEndpoint = profile.Issuer + "/another-userinfo"
	p.service.oauth2Profiles[profile.ID] = changed
	flow, err = p.service.authenticateRPCallback(context.Background(), request, out.Binding, out.StateProofCiphertext, *clock)
	flow.destroy()
	if err == nil {
		t.Fatal("same configuration version changed bound UserInfo authority")
	}
}
