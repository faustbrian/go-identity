package oauth_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/oauth"
)

func refreshFixture(t *testing.T, handler http.HandlerFunc) (*oauth.OAuth2UserInfoProvider, *oauth.OAuth2RefreshProvider) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	p, err := oauth.NewOAuth2UserInfoProvider(oauth.OAuth2UserInfoConfig{
		ID: "ordinary", Version: 3, Issuer: server.URL, AuthorizationEndpoint: server.URL + "/authorize",
		TokenEndpoint: server.URL + "/token", UserInfoEndpoint: server.URL + "/userinfo", RedirectURI: "https://app.example/callback",
		ClientID: "registered-client", ClientSecret: []byte("fixture-client-secret"), ClientAuthentication: oauth.ClientSecretPost,
		Scopes: []string{"read", "write"}, SubjectClaim: "id", SubjectEncoding: oauth.OAuth2PositiveIntegerSubject,
		HTTPClient: server.Client(), Clock: oauth2Clock{testNow}, Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	adapter, err := oauth.NewOAuth2RefreshProvider(p)
	if err != nil {
		t.Fatal(err)
	}
	return p, adapter
}

func storedRefresh(t *testing.T, p *oauth.OAuth2UserInfoProvider) oauth.RefreshToken {
	t.Helper()
	input, err := oauth.NewRefreshToken([]byte("fixture-original-refresh"), p.Profile(), []string{"read"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(input.Destroy)
	return input
}

func refreshKind(t *testing.T, err error, kind oauth.ErrorKind) {
	t.Helper()
	var classified *oauth.Error
	if !errors.As(err, &classified) || classified.Kind() != kind {
		t.Fatalf("expected %s, got %v", kind, err)
	}
}

func TestOAuth2RefreshOnePOSTAndActualGrantMetadata(t *testing.T) {
	for _, rotated := range []bool{false, true} {
		t.Run(fmt.Sprint("rotated=", rotated), func(t *testing.T) {
			var calls atomic.Int32
			p, adapter := refreshFixture(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != http.MethodPost || r.URL.RequestURI() != "/token" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || r.ParseForm() != nil || len(r.PostForm) != 4 || r.PostForm.Get("grant_type") != "refresh_token" || r.PostForm.Get("refresh_token") != "fixture-original-refresh" || r.PostForm.Get("client_id") != "registered-client" || r.PostForm.Get("client_secret") != "fixture-client-secret" {
					t.Error("refresh escaped exact configured endpoint or credential channel")
				}
				w.Header().Set("Content-Type", "application/json")
				response := map[string]any{"access_token": "fixture-new-access", "token_type": "Bearer", "expires_in": 60}
				if rotated {
					response["refresh_token"] = "fixture-new-refresh"
				}
				_ = json.NewEncoder(w).Encode(response)
			})
			result, err := adapter.Refresh(context.Background(), storedRefresh(t, p))
			if err != nil {
				t.Fatal(err)
			}
			defer result.Tokens.Destroy()
			if calls.Load() != 1 || !reflect.DeepEqual(result.Tokens.GrantedScopes(), []string{"read"}) || !reflect.DeepEqual(result.Tokens.RequestedScopes(), []string{"read"}) || result.Tokens.ScopeReported() || !result.Tokens.ReceivedAt().Equal(testNow) || !result.Tokens.ExpiresAt().Equal(testNow.Add(time.Minute)) {
				t.Fatal("refresh broadened stored scope, invented metadata, or performed additional I/O")
			}
			wantRotation := oauth.RetainOriginalRefreshToken
			if rotated {
				wantRotation = oauth.RotatedRefreshToken
			}
			if result.Rotation != wantRotation {
				t.Fatal("replacement disposition lost")
			}
			var borrow oauth.TokenBytes
			err = result.Tokens.Use(context.Background(), func(_ context.Context, value oauth.TokenBytes) error {
				borrow = value
				wantRefresh := ""
				if rotated {
					wantRefresh = "fixture-new-refresh"
				}
				if string(value.AccessToken) != "fixture-new-access" || string(value.RefreshToken) != wantRefresh || len(value.IDToken) != 0 {
					t.Error("refresh returned invented or wrong token custody")
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if strings.Trim(string(borrow.AccessToken), "\x00") != "" || strings.Trim(string(borrow.RefreshToken), "\x00") != "" {
				t.Fatal("token borrow was not cleared")
			}
		})
	}
}

func TestOAuth2RefreshOutcomesNeverRetry(t *testing.T) {
	cases := []struct {
		name, body string
		status     int
		kind       oauth.ErrorKind
	}{
		{"invalid grant", `{"error":"invalid_grant"}`, 400, oauth.RefreshGrantRejected},
		{"empty optional refusal text", `{"error":"invalid_grant","error_description":"","error_uri":""}`, 400, oauth.RefreshGrantRejected},
		{"valid refusal text and URI", `{"error":"invalid_grant","error_description":"Grant unavailable","error_uri":"https://provider.example/help"}`, 400, oauth.RefreshGrantRejected},
		{"other definitive refusal", `{"error":"invalid_client"}`, 401, oauth.Refused},
		{"invalid scope preserves grant", `{"error":"invalid_scope"}`, 400, oauth.Refused},
		{"wrong refusal status", `{"error":"invalid_grant"}`, 401, oauth.Unknown},
		{"unknown refusal", `{"error":"new_extension"}`, 400, oauth.Unknown},
		{"ambiguous refusal", `{"error":"invalid_grant","refresh_token":"fixture-rotated"}`, 400, oauth.Unknown},
		{"malformed refusal text", `{"error":"invalid_grant","error_description":"bad\ntext"}`, 400, oauth.Unknown},
		{"malformed success", `{"access_token":`, 200, oauth.Unknown},
		{"duplicate success", `{"access_token":"a","access_token":"b","token_type":"Bearer","expires_in":60}`, 200, oauth.Unknown},
		{"scope broadening", `{"access_token":"a","token_type":"Bearer","expires_in":60,"scope":"read write"}`, 200, oauth.Unknown},
		{"ID token not selected", `{"access_token":"a","token_type":"Bearer","expires_in":60,"id_token":"not-selected"}`, 200, oauth.Unknown},
		{"expiry missing", `{"access_token":"a","token_type":"Bearer"}`, 200, oauth.Unknown},
		{"bad rotation", `{"access_token":"a","token_type":"Bearer","expires_in":60,"refresh_token":""}`, 200, oauth.Unknown},
		{"redirect", `{}`, 302, oauth.Unknown},
		{"provider unavailable", `{}`, 503, oauth.Unknown},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			p, adapter := refreshFixture(t, func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Location", "/userinfo")
				w.WriteHeader(test.status)
				fmt.Fprint(w, test.body)
			})
			result, err := adapter.Refresh(context.Background(), storedRefresh(t, p))
			defer result.Tokens.Destroy()
			refreshKind(t, err, test.kind)
			if calls.Load() != 1 || result.Rotation != "" || result.Tokens.Use(context.Background(), func(context.Context, oauth.TokenBytes) error { t.Error("failure exposed tokens"); return nil }) == nil {
				t.Fatal("failure retried or exposed success custody")
			}
		})
	}
}

func TestOAuth2RefreshPreflightBindingAndRedaction(t *testing.T) {
	var calls atomic.Int32
	p, adapter := refreshFixture(t, func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(500) })
	for _, mutate := range []func(*oauth.ProviderProfile){
		func(p *oauth.ProviderProfile) { p.ID = "foreign" },
		func(p *oauth.ProviderProfile) { p.Version++ },
		func(p *oauth.ProviderProfile) { p.ClientID = "foreign-client" },
		func(p *oauth.ProviderProfile) {
			p.Issuer = "https://foreign.example"
			p.AuthorizationEndpoint = p.Issuer + "/authorize"
			p.TokenEndpoint = p.Issuer + "/token"
		},
		func(p *oauth.ProviderProfile) { p.TokenEndpoint += "/foreign" },
	} {
		profile := p.Profile()
		mutate(&profile)
		input, err := oauth.NewRefreshToken([]byte("fixture-original-refresh"), profile, []string{"read"})
		if err != nil {
			t.Fatal(err)
		}
		_, err = adapter.Refresh(context.Background(), input)
		input.Destroy()
		refreshKind(t, err, oauth.InvalidInput)
	}
	input := storedRefresh(t, p)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := adapter.Refresh(ctx, input)
	refreshKind(t, err, oauth.Unavailable)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation classification lost")
	}
	if _, err := oauth.NewRefreshToken([]byte("fixture-original-refresh"), p.Profile(), []string{"admin"}); err == nil {
		t.Fatal("unconfigured stored scope admitted")
	}
	if _, err := json.Marshal(input); err == nil {
		t.Fatal("secret custody serialized")
	}
	if strings.Contains(fmt.Sprintf("%+v %#v", input, adapter), "fixture-original-refresh") {
		t.Fatal("secret diagnostic disclosure")
	}
	alias := input
	input.Destroy()
	_, err = adapter.Refresh(context.Background(), alias)
	refreshKind(t, err, oauth.InvalidInput)
	p.Close()
	if _, err := oauth.NewOAuth2RefreshProvider(p); err == nil {
		t.Fatal("closed provider gained capability")
	}
	_, err = adapter.Refresh(context.Background(), storedRefresh(t, p))
	refreshKind(t, err, oauth.InvalidInput)
	if calls.Load() != 0 {
		t.Fatal("preflight sent credentials")
	}
}

func TestOAuth2RefreshCancellationAfterAttemptIsUnknown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	release, finished := make(chan struct{}), make(chan struct{})
	defer close(release)
	var calls atomic.Int32
	p, adapter := refreshFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		cancel()
		select {
		case <-r.Context().Done():
		case <-release:
		}
		close(finished)
	})
	_, err := adapter.Refresh(ctx, storedRefresh(t, p))
	refreshKind(t, err, oauth.Unknown)
	if !errors.Is(err, context.Canceled) || calls.Load() != 1 {
		t.Fatal("attempt cancellation retried or lost unknown outcome")
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("cancelled request retained server handler lifetime")
	}
}

func TestOAuth2RefreshCustodyExcludesOverlapAndDestroyDoesNotInterruptAdmittedUse(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{}, 1)
	defer close(release)
	var calls atomic.Int32
	p, adapter := refreshFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		close(entered)
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		if r.ParseForm() != nil || r.PostForm.Get("refresh_token") != "fixture-original-refresh" {
			t.Error("destroy damaged admitted private token bytes")
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"a","token_type":"Bearer","expires_in":60,"scope":"read"}`)
	})
	input := storedRefresh(t, p)
	done := make(chan error, 1)
	go func() {
		result, err := adapter.Refresh(context.Background(), input)
		result.Tokens.Destroy()
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("admitted refresh never reached token endpoint")
	}
	_, err := adapter.Refresh(context.Background(), input)
	refreshKind(t, err, oauth.InvalidInput)
	input.Destroy()
	release <- struct{}{}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	_, err = adapter.Refresh(context.Background(), input)
	refreshKind(t, err, oauth.InvalidInput)
	if calls.Load() != 1 {
		t.Fatal("overlapping or destroyed custody performed another request")
	}
}

func TestOAuth2RefreshRejectsUnselectedPolicyAndInvalidCustody(t *testing.T) {
	provider, err := oauth.NewOAuth2UserInfoProviderWithPolicy(githubOAuth2Config(), oauth.OAuth2GitHubOAuthAppPolicy)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	if _, err := oauth.NewOAuth2RefreshProvider(provider); err == nil {
		t.Fatal("refresh silently selected GitHub policy")
	}
	if _, err := oauth.NewOAuth2RefreshProvider(nil); err == nil {
		t.Fatal("nil provider gained capability")
	}
	p, adapter := refreshFixture(t, func(http.ResponseWriter, *http.Request) { t.Error("invalid custody reached network") })
	for _, value := range [][]byte{nil, []byte("bad\ntoken"), []byte(strings.Repeat("x", 16385))} {
		if _, err := oauth.NewRefreshToken(value, p.Profile(), []string{"read"}); err == nil {
			t.Fatal("invalid token bytes admitted")
		}
	}
	for _, scopes := range [][]string{nil, {"read", "read"}, {"read write"}} {
		if _, err := oauth.NewRefreshToken([]byte("fixture-refresh"), p.Profile(), scopes); err == nil {
			t.Fatal("invalid grant scope admitted")
		}
	}
	_, err = adapter.Refresh(context.Background(), oauth.RefreshToken{})
	refreshKind(t, err, oauth.InvalidInput)
	_, err = adapter.Refresh(nil, storedRefresh(t, p))
	refreshKind(t, err, oauth.InvalidInput)
}

func TestOAuth2RefreshReturnedSubsetDoesNotRedefineRefreshGrant(t *testing.T) {
	p, adapter := refreshFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"a","token_type":"Bearer","expires_in":60,"scope":"read","refresh_token":"fixture-rotated"}`)
	})
	profile, scopes := p.Profile(), []string{"read", "write"}
	secret := []byte("fixture-original-refresh")
	input, err := oauth.NewRefreshToken(secret, profile, scopes)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Destroy()
	clear(secret)
	profile.Scopes[0], scopes[0] = "mutated", "mutated"
	result, err := adapter.Refresh(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Tokens.Destroy()
	if !result.Tokens.ScopeReported() || !reflect.DeepEqual(result.Tokens.RequestedScopes(), []string{"read", "write"}) || !reflect.DeepEqual(result.Tokens.GrantedScopes(), []string{"read"}) || result.Rotation != oauth.RotatedRefreshToken {
		t.Fatal("refresh grant scope or copied custody changed")
	}
}
