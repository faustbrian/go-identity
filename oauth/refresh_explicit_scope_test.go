package oauth_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/oauth"
)

func TestOAuth2RefreshWithExplicitScopeTLSRequestAndOmittedResponse(t *testing.T) {
	for _, test := range []struct {
		name     string
		scopes   []string
		explicit bool
	}{
		{"narrowed explicit", []string{"profile"}, true},
		{"ordered explicit", []string{"email", "profile"}, true},
		{"existing omitted request", []string{"profile"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			retainedScopes := append([]string(nil), test.scopes...)
			provider, adapter := sharedRefreshFixture(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				want := url.Values{
					"grant_type": {"refresh_token"}, "refresh_token": {"shared-original +/=: refresh"},
					"client_id": {"registered-client"}, "client_secret": {"test-only-client-secret"},
				}
				if test.explicit {
					want.Set("scope", strings.Join(retainedScopes, " "))
				}
				if r.TLS == nil || r.Method != http.MethodPost || r.URL.RequestURI() != "/token" ||
					r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" ||
					r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" ||
					r.ParseForm() != nil || !reflect.DeepEqual(r.PostForm, want) {
					t.Error("refresh changed exact TLS endpoint, credential binding or retained-scope selection")
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"access_token": "explicit-scope-access", "refresh_token": "explicit-scope-rotated",
					"token_type": "Bearer", "expires_in": 60,
				})
			})
			input := sharedStoredRefresh(t, provider.Profile(), test.scopes)
			test.scopes[0] = "caller-reassigned"
			refresh := adapter.Refresh
			if test.explicit {
				refresh = adapter.RefreshWithExplicitScope
			}
			result, err := refresh(t.Context(), input)
			if err != nil {
				t.Fatal(err)
			}
			defer result.Tokens.Destroy()
			if calls.Load() != 1 || !reflect.DeepEqual(result.Tokens.RequestedScopes(), retainedScopes) ||
				!reflect.DeepEqual(result.Tokens.GrantedScopes(), retainedScopes) || result.Tokens.ScopeReported() ||
				result.Rotation != oauth.RotatedRefreshToken || !result.Tokens.ReceivedAt().Equal(testNow) ||
				!result.Tokens.ExpiresAt().Equal(testNow.Add(time.Minute)) {
				t.Fatal("omitted response scope changed retained selection, rotation or bounded one-send behavior")
			}
			if err := result.Tokens.Use(t.Context(), func(_ context.Context, value oauth.TokenBytes) error {
				if string(value.AccessToken) != "explicit-scope-access" || string(value.RefreshToken) != "explicit-scope-rotated" || len(value.IDToken) != 0 {
					t.Error("explicit-scope refresh returned wrong custody or invented identity proof")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestOAuth2RefreshWithExplicitScopeDeniesBeforeIO(t *testing.T) {
	var calls atomic.Int32
	provider, adapter := sharedRefreshFixture(t, func(http.ResponseWriter, *http.Request) { calls.Add(1) })
	input := sharedStoredRefresh(t, provider.Profile(), []string{"profile"})
	_, err := adapter.RefreshWithExplicitScope(nil, input)
	refreshKind(t, err, oauth.InvalidInput)
	_, err = adapter.RefreshWithExplicitScope(t.Context(), oauth.RefreshToken{})
	refreshKind(t, err, oauth.InvalidInput)
	var absent *oauth.OAuth2RefreshProvider
	_, err = absent.RefreshWithExplicitScope(t.Context(), input)
	refreshKind(t, err, oauth.InvalidInput)
	profile := provider.Profile()
	profile.ClientID = "different-client"
	_, err = adapter.RefreshWithExplicitScope(t.Context(), sharedStoredRefresh(t, profile, []string{"profile"}))
	refreshKind(t, err, oauth.InvalidInput)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = adapter.RefreshWithExplicitScope(ctx, input)
	refreshKind(t, err, oauth.Unavailable)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("pre-attempt cancellation lost its cause")
	}
	input.Destroy()
	_, err = adapter.RefreshWithExplicitScope(t.Context(), input)
	refreshKind(t, err, oauth.InvalidInput)
	provider.Close()
	_, err = adapter.RefreshWithExplicitScope(t.Context(), sharedStoredRefresh(t, provider.Profile(), []string{"profile"}))
	refreshKind(t, err, oauth.InvalidInput)
	if calls.Load() != 0 {
		t.Fatal("invalid or cancelled explicit-scope request sent credentials")
	}
}

func TestOAuth2RefreshWithExplicitScopeOutcomesNeverRetry(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
		kind   oauth.ErrorKind
	}{
		{"grant rejected", 400, `{"error":"invalid_grant"}`, oauth.RefreshGrantRejected},
		{"scope refused", 400, `{"error":"invalid_scope"}`, oauth.Refused},
		{"scope broadened", 200, `{"access_token":"a","token_type":"Bearer","expires_in":60,"scope":"profile email"}`, oauth.Unknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			provider, adapter := sharedRefreshFixture(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.ParseForm() != nil || r.PostForm.Get("scope") != "profile" {
					t.Error("explicit scope was not sent")
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, test.body)
			})
			result, err := adapter.RefreshWithExplicitScope(t.Context(), sharedStoredRefresh(t, provider.Profile(), []string{"profile"}))
			defer result.Tokens.Destroy()
			refreshKind(t, err, test.kind)
			if calls.Load() != 1 || result.Rotation != "" {
				t.Fatal("failed explicit-scope refresh retried or returned rotation evidence")
			}
		})
	}
}

func TestOAuth2RefreshWithExplicitScopeCancellationAfterAttemptIsUnknown(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	release, finished := make(chan struct{}), make(chan struct{})
	defer close(release)
	var calls atomic.Int32
	provider, adapter := sharedRefreshFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		cancel()
		select {
		case <-r.Context().Done():
		case <-release:
		}
		close(finished)
	})
	result, err := adapter.RefreshWithExplicitScope(ctx, sharedStoredRefresh(t, provider.Profile(), []string{"profile"}))
	defer result.Tokens.Destroy()
	refreshKind(t, err, oauth.Unknown)
	if !errors.Is(err, context.Canceled) || calls.Load() != 1 || result.Rotation != "" {
		t.Fatal("attempt cancellation retried or lost unknown outcome")
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("cancelled explicit-scope request retained server handler lifetime")
	}
}
