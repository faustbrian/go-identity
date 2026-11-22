package oauth_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	oauth "github.com/faustbrian/go-identity/oauth"
)

func sharedOAuth2UserInfoConfig(server *httptest.Server, clock oauth.Clock) oauth.OAuth2UserInfoConfig {
	return oauth.OAuth2UserInfoConfig{
		ID: "enterprise", Version: 7, Issuer: server.URL,
		AuthorizationEndpoint: server.URL + "/authorize", TokenEndpoint: server.URL + "/token",
		UserInfoEndpoint: server.URL + "/userinfo", RedirectURI: "https://application.example/shared/callback",
		ClientID: "registered-client", ClientSecret: []byte("test-only-client-secret"),
		ClientAuthentication: oauth.ClientSecretPost, Scopes: []string{"profile", "email"},
		SubjectClaim: "sub", SubjectEncoding: oauth.OAuth2StringSubject, ProofLifetime: 10 * time.Second,
		Clock: clock, HTTPClient: server.Client(), Timeout: time.Second,
	}
}

func sharedOAuth2UserInfoVerifier(t *testing.T) oauth.PKCEVerifier {
	t.Helper()
	verifier, err := oauth.NewPKCEVerifier([]byte(strings.Repeat("v", 64)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(verifier.Destroy)
	return verifier
}

func sharedOAuth2UserInfoParameters(verifier oauth.PKCEVerifier) oauth.AuthorizationParameters {
	return oauth.AuthorizationParameters{
		State: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), PKCEChallenge: verifier.Challenge(),
	}
}

func sharedOAuth2UserInfoCallback(t *testing.T, profile oauth.ProviderProfile, state string) oauth.QueryCallback {
	t.Helper()
	raw := (url.Values{"code": {"exact +/=: code"}, "state": {state}, "iss": {profile.Issuer}}).Encode()
	callback, err := oauth.ParseSharedOAuth2QueryCallback(t.Context(), raw, profile.RedirectURI, profile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(callback.Destroy)
	return callback
}

func requireSharedOAuth2UserInfoEmpty(t *testing.T, result oauth.ExchangeResult) {
	t.Helper()
	defer result.Tokens.Destroy()
	if result.Identity.Subject() != "" || result.Identity.ProviderID() != "" || result.Identity.Issuer() != "" || len(result.ObservedOAuth2Claims()) != 0 || len(result.VerifiedOIDCClaims()) != 0 {
		t.Fatal("refused exchange retained identity or claim observations")
	}
	borrowed := false
	err := result.Tokens.Use(t.Context(), func(context.Context, oauth.TokenBytes) error {
		borrowed = true
		return nil
	})
	if err == nil || borrowed {
		t.Fatal("refused exchange retained usable token custody")
	}
}

func TestSharedOAuth2UserInfoConfigurationIsExplicitAndBounded(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("provider configuration caused a network request")
	}))
	defer server.Close()
	config := sharedOAuth2UserInfoConfig(server, oauth2Clock{time.Date(2026, 11, 22, 8, 0, 0, 0, time.UTC)})
	foreign := config
	foreign.UserInfoEndpoint = "https://foreign.example.invalid/identity"
	if provider, err := oauth.NewSharedOAuth2UserInfoProvider(foreign, nil); err == nil || provider != nil {
		t.Fatal("unbound identity endpoint configuration was accepted")
	}
	for _, names := range [][]string{{"email", "email"}, {"Access_Token"}, {"client_secret"}, {"*"}, make([]string, 129)} {
		if provider, err := oauth.NewSharedOAuth2UserInfoProvider(config, names); err == nil || provider != nil {
			t.Fatal("unbounded, duplicate or credential claim selection was accepted")
		}
	}
	if provider, err := oauth.NewOAuth2UserInfoProvider(config); err == nil || provider != nil {
		t.Fatal("shared-only string identity silently changed the social provider contract")
	}
	shared, err := oauth.NewSharedOAuth2UserInfoProvider(config, nil)
	if err != nil {
		t.Fatal("explicit subject-only mode was rejected", err)
	}
	defer shared.Close()
	if _, implementsSocial := any(shared).(oauth.Provider); implementsSocial {
		t.Fatal("shared redirect client implements the distinct-route Provider contract")
	}
}

func TestSharedOAuth2UserInfoTLSRetainsOriginalEvidenceAndDetachedScalarClaims(t *testing.T) {
	now := time.Date(2026, 11, 22, 8, 0, 0, 0, time.UTC)
	subject := " " + strings.Repeat("ü", 255) + " "
	clock := &oauth2ObservationClock{points: []time.Time{now, now.Add(time.Second), now.Add(3 * time.Second)}}
	var tokenCalls, userCalls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token":
			tokenCalls.Add(1)
			want := url.Values{
				"grant_type": {"authorization_code"}, "code": {"exact +/=: code"}, "code_verifier": {strings.Repeat("v", 64)},
				"redirect_uri": {"https://application.example/shared/callback"}, "client_id": {"registered-client"}, "client_secret": {"test-only-client-secret"},
			}
			if r.TLS == nil || r.Method != http.MethodPost || r.Header.Get("Authorization") != "" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || r.URL.RawQuery != "" || r.ParseForm() != nil || !reflect.DeepEqual(r.PostForm, want) {
				t.Error("token request lost exact HTTPS POST code/verifier/client binding")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			fmt.Fprint(w, `{"access_token":"test-only-access-token","refresh_token":"test-only-refresh-token","token_type":"Bearer","expires_in":60,"scope":"profile email"}`)
		case "/userinfo":
			userCalls.Add(1)
			if r.TLS == nil || r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer test-only-access-token" || r.URL.RawQuery != "" {
				t.Error("UserInfo request lost its exact bearer HTTPS binding")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			fmt.Fprintf(w, `{"sub":%q,"display":"","email":null,"verified":false,"enabled":true,"unselected":["ignored"]}`, subject)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	names := []string{"missing", "email", "display", "verified", "enabled"}
	provider, err := oauth.NewSharedOAuth2UserInfoProvider(sharedOAuth2UserInfoConfig(server, clock), names)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	names[0] = "unselected"
	verifier := sharedOAuth2UserInfoVerifier(t)
	original := sharedOAuth2UserInfoParameters(verifier)
	authorization, err := provider.Authorization(t.Context(), original)
	if err != nil {
		t.Fatal(err)
	}
	parsedURL, err := url.Parse(authorization.URL())
	if err != nil {
		t.Fatal(err)
	}
	wantAuthorization := url.Values{
		"response_type": {"code"}, "response_mode": {"query"}, "client_id": {"registered-client"},
		"redirect_uri": {"https://application.example/shared/callback"}, "scope": {"profile email"},
		"state": {original.State}, "code_challenge": {verifier.Challenge()}, "code_challenge_method": {"S256"},
	}
	if !reflect.DeepEqual(parsedURL.Query(), wantAuthorization) || clock.reads.Load() != 0 || tokenCalls.Load() != 0 || userCalls.Load() != 0 {
		t.Fatal("authorization invented nonce/OIDC parameters, observed time or performed IO")
	}
	callback := sharedOAuth2UserInfoCallback(t, provider.Profile(), original.State)
	out, err := provider.Exchange(t.Context(), callback, verifier, original)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Tokens.Destroy()
	if tokenCalls.Load() != 1 || userCalls.Load() != 1 || out.Identity.Subject() != subject || len(out.Identity.Subject()) != 512 || out.Identity.ProviderID() != "enterprise" || out.Identity.Issuer() != server.URL {
		t.Fatal("shared OAuth2 exchange changed exact subject/provider or sent more than once")
	}
	if !out.Identity.EvidenceExpiresAt().Equal(now.Add(11*time.Second)) || out.Identity.EvidenceExpiresAt().Location() != time.UTC {
		t.Fatal("UserInfo completion renewed the original observation lifetime")
	}
	if authenticated, present := out.Identity.AuthenticationTime(); present || !authenticated.IsZero() || !out.Identity.IDTokenIssuedAt().IsZero() || !out.Identity.IDTokenExpiresAt().IsZero() || len(out.VerifiedOIDCClaims()) != 0 {
		t.Fatal("bearer UserInfo observations invented OIDC authentication or signed claims")
	}
	if !out.Tokens.ReceivedAt().Equal(now) || !out.Tokens.ExpiresAt().Equal(now.Add(time.Minute)) || !out.Tokens.ScopeReported() || !reflect.DeepEqual(out.Tokens.RequestedScopes(), []string{"profile", "email"}) || !reflect.DeepEqual(out.Tokens.GrantedScopes(), []string{"profile", "email"}) {
		t.Fatal("shared exchange lost original token lifetime or scopes")
	}
	var borrowed oauth.TokenBytes
	if err := out.Tokens.Use(t.Context(), func(_ context.Context, tokens oauth.TokenBytes) error {
		borrowed = tokens
		if string(tokens.AccessToken) != "test-only-access-token" || string(tokens.RefreshToken) != "test-only-refresh-token" || len(tokens.IDToken) != 0 || cap(tokens.AccessToken) != len(tokens.AccessToken) || cap(tokens.RefreshToken) != len(tokens.RefreshToken) {
			t.Fatal("retained OAuth2 token custody changed bytes, bounds or token kind")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, value := range [][]byte{borrowed.AccessToken, borrowed.RefreshToken} {
		for _, b := range value {
			if b != 0 {
				t.Fatal("token borrow survived synchronous cleanup")
			}
		}
	}
	claims := out.ObservedOAuth2Claims()
	wantNames := []string{"missing", "email", "display", "verified", "enabled"}
	wantKinds := []oauth.OAuth2ClaimKind{oauth.OAuth2ClaimAbsent, oauth.OAuth2ClaimNull, oauth.OAuth2ClaimString, oauth.OAuth2ClaimBool, oauth.OAuth2ClaimBool}
	if len(claims) != len(wantNames) {
		t.Fatal("selected scalar projection lost order, absence or null")
	}
	for index, claim := range claims {
		if claim.Name() != wantNames[index] || claim.Kind() != wantKinds[index] {
			t.Fatal("selected observation changed name, kind or configuration order")
		}
		text, isString := claim.StringValue()
		flag, isBool := claim.BoolValue()
		if isString != (index == 2) || text != "" || isBool != (index >= 3) || flag != (index == 4) {
			t.Fatal("selected observation conflated absent/null with empty string/false")
		}
	}
	claims[0] = claims[4]
	if again := out.ObservedOAuth2Claims(); again[0].Name() != "missing" || again[0].Kind() != oauth.OAuth2ClaimAbsent {
		t.Fatal("caller mutation changed the retained observation projection")
	}
}

func TestSharedOAuth2UserInfoRejectsUnboundReservationsBeforePOST(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()
	config := sharedOAuth2UserInfoConfig(server, oauth2Clock{time.Date(2026, 11, 22, 8, 0, 0, 0, time.UTC)})
	provider, err := oauth.NewSharedOAuth2UserInfoProvider(config, []string{"email"})
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	verifier := sharedOAuth2UserInfoVerifier(t)
	original := sharedOAuth2UserInfoParameters(verifier)
	callback := sharedOAuth2UserInfoCallback(t, provider.Profile(), original.State)
	for _, name := range []string{"wrong state", "wrong challenge", "wrong verifier", "destroyed verifier", "unsupported nonce", "wrong profile", "distinct callback strategy", "destroyed callback", "zero callback", "provider denial"} {
		t.Run(name, func(t *testing.T) {
			reservation, received := original, callback
			selectedVerifier := verifier
			switch name {
			case "wrong state":
				reservation.State = base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("s", 32)))
			case "wrong challenge":
				reservation.PKCEChallenge = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
			case "wrong verifier":
				selectedVerifier, err = oauth.NewPKCEVerifier([]byte(strings.Repeat("w", 64)))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(selectedVerifier.Destroy)
			case "destroyed verifier":
				selectedVerifier = sharedOAuth2UserInfoVerifier(t)
				selectedVerifier.Destroy()
			case "unsupported nonce":
				reservation.Nonce = reservation.State
			case "wrong profile":
				profile := provider.Profile()
				profile.Version++
				received = sharedOAuth2UserInfoCallback(t, profile, original.State)
			case "distinct callback strategy":
				facts := oauth.OAuth2UserInfoProfile{Profile: provider.Profile(), Details: oauth.OAuth2UserInfoDetails{
					UserInfoEndpoint: config.UserInfoEndpoint, SubjectClaim: "id", SubjectEncoding: oauth.OAuth2PositiveIntegerSubject, ProofLifetime: config.ProofLifetime,
				}}
				raw := (url.Values{"code": {"exact +/=: code"}, "state": {original.State}}).Encode()
				received, err = oauth.ParseOAuth2QueryCallback(t.Context(), raw, facts.Profile.RedirectURI, facts)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(received.Destroy)
			case "destroyed callback":
				received = sharedOAuth2UserInfoCallback(t, provider.Profile(), original.State)
				received.Destroy()
			case "zero callback":
				received = oauth.QueryCallback{}
			case "provider denial":
				profile := provider.Profile()
				raw := (url.Values{"error": {"access_denied"}, "state": {original.State}, "iss": {profile.Issuer}}).Encode()
				received, err = oauth.ParseSharedOAuth2QueryCallback(t.Context(), raw, profile.RedirectURI, profile)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(received.Destroy)
			}
			out, err := provider.Exchange(t.Context(), received, selectedVerifier, reservation)
			if err == nil || calls.Load() != 0 {
				t.Fatal("unbound callback or reservation reached the token endpoint")
			}
			requireSharedOAuth2UserInfoEmpty(t, out)
		})
	}
}

func TestSharedOAuth2UserInfoRefusesInvalidIdentityAndSelectedClaimsWithoutTokens(t *testing.T) {
	for _, tc := range []struct {
		name, user string
		status     int
	}{
		{"missing subject", `{"email":"selected"}`, http.StatusOK},
		{"empty subject", `{"sub":"","email":"selected"}`, http.StatusOK},
		{"numeric subject", `{"sub":42,"email":"selected"}`, http.StatusOK},
		{"null subject", `{"sub":null,"email":"selected"}`, http.StatusOK},
		{"subject over byte bound", `{"sub":"` + strings.Repeat("ü", 256) + `x","email":"selected"}`, http.StatusOK},
		{"subject contains control", `{"sub":"a\u0000b","email":"selected"}`, http.StatusOK},
		{"subject contains replacement rune", `{"sub":"a\ufffdb","email":"selected"}`, http.StatusOK},
		{"subject contains unpaired surrogate", `{"sub":"a\ud800b","email":"selected"}`, http.StatusOK},
		{"selected array", `{"sub":"valid","email":["not a scalar"]}`, http.StatusOK},
		{"duplicate subject", `{"sub":"first","sub":"second","email":"selected"}`, http.StatusOK},
		{"duplicate selected claim", `{"sub":"valid","email":"first","email":"second"}`, http.StatusOK},
		{"identity refusal", `{}`, http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var tokenCalls, userCalls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/token":
					tokenCalls.Add(1)
					fmt.Fprint(w, `{"access_token":"test-only-access-token","refresh_token":"test-only-refresh-token","token_type":"Bearer","expires_in":60,"scope":"profile email"}`)
				case "/userinfo":
					userCalls.Add(1)
					w.WriteHeader(tc.status)
					fmt.Fprint(w, tc.user)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()
			provider, err := oauth.NewSharedOAuth2UserInfoProvider(sharedOAuth2UserInfoConfig(server, oauth2Clock{time.Date(2026, 11, 22, 8, 0, 0, 0, time.UTC)}), []string{"email"})
			if err != nil {
				t.Fatal(err)
			}
			defer provider.Close()
			verifier := sharedOAuth2UserInfoVerifier(t)
			original := sharedOAuth2UserInfoParameters(verifier)
			callback := sharedOAuth2UserInfoCallback(t, provider.Profile(), original.State)
			out, err := provider.Exchange(t.Context(), callback, verifier, original)
			var classified *oauth.Error
			if !errors.As(err, &classified) || classified.Kind() != oauth.InvalidProof || tokenCalls.Load() != 1 || userCalls.Load() != 1 {
				t.Fatal("invalid UserInfo was accepted, misclassified or retried")
			}
			requireSharedOAuth2UserInfoEmpty(t, out)
		})
	}
}

func TestSharedOAuth2UserInfoCannotRenewObservationOrOutliveBearer(t *testing.T) {
	now := time.Date(2026, 11, 22, 8, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name         string
		tokenSeconds int
		finished     time.Duration
		wantExpiry   time.Duration
		refused      bool
	}{
		{"original observation", 60, 3 * time.Second, 11 * time.Second, false},
		{"bearer expiry caps evidence", 5, 3 * time.Second, 5 * time.Second, false},
		{"observation expired during read", 60, 11 * time.Second, 0, true},
		{"bearer expired during read", 3, 3 * time.Second, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var tokenCalls, userCalls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/token":
					tokenCalls.Add(1)
					fmt.Fprintf(w, `{"access_token":"test-only-access-token","token_type":"Bearer","expires_in":%d,"scope":"profile email"}`, tc.tokenSeconds)
				case "/userinfo":
					userCalls.Add(1)
					fmt.Fprint(w, `{"sub":"stable-subject","email":"observed-only"}`)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()
			clock := &oauth2ObservationClock{points: []time.Time{now, now.Add(time.Second), now.Add(tc.finished)}}
			provider, err := oauth.NewSharedOAuth2UserInfoProvider(sharedOAuth2UserInfoConfig(server, clock), []string{"email"})
			if err != nil {
				t.Fatal(err)
			}
			defer provider.Close()
			verifier := sharedOAuth2UserInfoVerifier(t)
			original := sharedOAuth2UserInfoParameters(verifier)
			callback := sharedOAuth2UserInfoCallback(t, provider.Profile(), original.State)
			out, err := provider.Exchange(t.Context(), callback, verifier, original)
			defer out.Tokens.Destroy()
			if tokenCalls.Load() != 1 || userCalls.Load() != 1 {
				t.Fatal("bounded observation changed the one-send token/UserInfo exchange")
			}
			if tc.refused {
				var classified *oauth.Error
				if !errors.As(err, &classified) || classified.Kind() != oauth.InvalidProof {
					t.Fatal("expired original evidence was renewed or misclassified")
				}
				requireSharedOAuth2UserInfoEmpty(t, out)
				return
			}
			if err != nil || out.Identity.Subject() != "stable-subject" || !out.Identity.EvidenceExpiresAt().Equal(now.Add(tc.wantExpiry)) {
				t.Fatal("observation expiry changed from the original read/bearer minimum", err)
			}
		})
	}
}
