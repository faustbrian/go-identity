package oauth_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/oauth"
)

func oauth2SecurityConfig(issuer string) oauth.OAuth2UserInfoConfig {
	return oauth.OAuth2UserInfoConfig{ID: "gitlab", Version: 1, Issuer: issuer, AuthorizationEndpoint: issuer + "/oauth/authorize", TokenEndpoint: issuer + "/oauth/token", UserInfoEndpoint: issuer + "/api/v4/user", ClientID: "registered-client", ClientSecret: []byte("test-only-client-secret"), ClientAuthentication: oauth.ClientSecretPost, RedirectURI: "https://application.example/gitlab/callback", Scopes: []string{"read_user"}, SubjectClaim: "id", SubjectEncoding: oauth.OAuth2PositiveIntegerSubject, Timeout: time.Second}
}

func TestOAuth2TokenAndUserInfoFailureOutcomes(t *testing.T) {
	validToken := `{"access_token":"test-only-access-token","token_type":"Bearer","expires_in":60,"scope":"read_user"}`
	for _, tc := range []struct {
		name, token, user       string
		tokenStatus, userStatus int
		want                    oauth.ErrorKind
		calls                   int64
	}{
		{"unexpected-id-token", `{"access_token":"test-only-access-token","id_token":"not-selected","token_type":"Bearer","expires_in":60}`, `{"id":42}`, 200, 200, oauth.Unknown, 1},
		{"definitive-refusal", `{"error":"invalid_grant"}`, `{"id":42}`, 400, 200, oauth.Refused, 1},
		{"expanded-scope", `{"access_token":"test-only-access-token","token_type":"Bearer","expires_in":60,"scope":"read_user api"}`, `{"id":42}`, 200, 200, oauth.Unknown, 1},
		{"userinfo-withdrawn", validToken, `{}`, 200, 401, oauth.InvalidProof, 2},
		{"userinfo-unknown", validToken, `{}`, 200, 503, oauth.Unknown, 2},
		{"userinfo-oversize", validToken, strings.Repeat("x", 1025), 200, 200, oauth.Unknown, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int64
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/oauth/token" {
					w.WriteHeader(tc.tokenStatus)
					fmt.Fprint(w, tc.token)
					return
				}
				w.WriteHeader(tc.userStatus)
				fmt.Fprint(w, tc.user)
			}))
			defer server.Close()
			c := oauth2SecurityConfig(server.URL)
			c.HTTPClient = server.Client()
			c.MaxResponseBytes = 1024
			p, err := oauth.NewOAuth2UserInfoProvider(c)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			callback := oauth2SecurityCallback(t, p.OAuth2Profile())
			defer callback.Destroy()
			input, _ := callback.Input()
			verifier, err := oauth.NewPKCEVerifier([]byte(strings.Repeat("v", 64)))
			if err != nil {
				t.Fatal(err)
			}
			defer verifier.Destroy()
			out, err := p.Exchange(context.Background(), input, verifier, "")
			defer out.Tokens.Destroy()
			var selected *oauth.Error
			if !errors.As(err, &selected) || selected.Kind() != tc.want || out.Identity.Subject() != "" || calls.Load() != tc.calls {
				t.Fatal("failure changed certainty, disclosed identity or retried")
			}
		})
	}
}

type oauth2ObservationClock struct {
	points []time.Time
	reads  atomic.Int32
}

func (c *oauth2ObservationClock) Now() time.Time {
	i := int(c.reads.Add(1)) - 1
	if i >= len(c.points) {
		i = len(c.points) - 1
	}
	return c.points[i]
}

func TestOAuth2ObservationCannotRenewAfterUserInfoOrTokenExpiry(t *testing.T) {
	now := time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name         string
		tokenSeconds int
		finished     time.Duration
		expires      time.Duration
		deny         bool
	}{
		{"original-read-bound", 60, 2 * time.Second, 21 * time.Second, false},
		{"token-deadline-cap", 5, 2 * time.Second, 5 * time.Second, false},
		{"late-userinfo", 60, 21 * time.Second, 0, true},
		{"expired-token", 2, 2 * time.Second, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/oauth/token" {
					fmt.Fprintf(w, `{"access_token":"test-only-access-token","token_type":"Bearer","expires_in":%d,"scope":"read_user"}`, tc.tokenSeconds)
					return
				}
				fmt.Fprint(w, `{"id":42}`)
			}))
			defer server.Close()
			c := oauth2SecurityConfig(server.URL)
			c.HTTPClient = server.Client()
			c.Clock = &oauth2ObservationClock{points: []time.Time{now, now.Add(time.Second), now.Add(tc.finished)}}
			p, err := oauth.NewOAuth2UserInfoProvider(c)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			callback := oauth2SecurityCallback(t, p.OAuth2Profile())
			defer callback.Destroy()
			input, _ := callback.Input()
			verifier, err := oauth.NewPKCEVerifier([]byte(strings.Repeat("v", 64)))
			if err != nil {
				t.Fatal(err)
			}
			defer verifier.Destroy()
			out, err := p.Exchange(context.Background(), input, verifier, "")
			defer out.Tokens.Destroy()
			if tc.deny {
				if err == nil || out.Identity.Subject() != "" {
					t.Fatal("late response renewed observation authority")
				}
				return
			}
			if err != nil || !out.Identity.EvidenceExpiresAt().Equal(now.Add(tc.expires)) {
				t.Fatal("original evidence/token deadline changed", err)
			}
		})
	}
}

func TestOAuth2CancellationAfterSendStopsWithoutRetry(t *testing.T) {
	entered, finished := make(chan struct{}), make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		close(entered)
		select {
		case <-r.Context().Done():
		case <-release:
		}
		close(finished)
	}))
	defer server.Close()
	defer close(release)
	c := oauth2SecurityConfig(server.URL)
	c.HTTPClient = server.Client()
	p, err := oauth.NewOAuth2UserInfoProvider(c)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	callback := oauth2SecurityCallback(t, p.OAuth2Profile())
	defer callback.Destroy()
	input, _ := callback.Input()
	verifier, err := oauth.NewPKCEVerifier([]byte(strings.Repeat("v", 64)))
	if err != nil {
		t.Fatal(err)
	}
	defer verifier.Destroy()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	completed := make(chan error, 1)
	go func() { out, e := p.Exchange(ctx, input, verifier, ""); out.Tokens.Destroy(); completed <- e }()
	select {
	case <-entered:
	case <-ctx.Done():
		<-completed
		t.Fatal("token endpoint never entered")
	}
	cancel()
	var failure *oauth.Error
	if err := <-completed; !errors.As(err, &failure) || failure.Kind() != oauth.Unknown || calls.Load() != 1 {
		t.Fatal("post-send cancellation lost ambiguity or retried")
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("canceled provider request retained handler lifetime")
	}
}

// Cancellation may occur after the initial Err check but before callback
// custody is borrowed. Deadline is the existing bounded-context boundary;
// this schedules that valid concurrent transition deterministically.
type oauth2CancelAtDeadline struct {
	context.Context
	cancel context.CancelFunc
}

func (c oauth2CancelAtDeadline) Deadline() (time.Time, bool) {
	c.cancel()
	return c.Context.Deadline()
}

func TestOAuth2CancellationBeforeCustodyIsUnavailableNotInvalidInput(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()
	c := oauth2SecurityConfig(server.URL)
	c.HTTPClient = server.Client()
	p, err := oauth.NewOAuth2UserInfoProvider(c)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	callback := oauth2SecurityCallback(t, p.OAuth2Profile())
	defer callback.Destroy()
	input, _ := callback.Input()
	verifier, err := oauth.NewPKCEVerifier([]byte(strings.Repeat("v", 64)))
	if err != nil {
		t.Fatal(err)
	}
	defer verifier.Destroy()
	base, cancel := context.WithCancel(t.Context())
	defer cancel()
	out, err := p.Exchange(oauth2CancelAtDeadline{Context: base, cancel: cancel}, input, verifier, "")
	defer out.Tokens.Destroy()
	var failure *oauth.Error
	if !errors.As(err, &failure) {
		t.Fatal("pre-send cancellation lost typed error")
	}
	if failure.Kind() != oauth.Unavailable {
		t.Fatalf("pre-send cancellation kind %q, want %q", failure.Kind(), oauth.Unavailable)
	}
	if !errors.Is(err, context.Canceled) || calls.Load() != 0 || out.Identity.Subject() != "" {
		t.Fatal("pre-send cancellation lost its cause, sent HTTP or produced identity")
	}
}

func TestOAuth2UserInfoRejectsAmbiguousEvidence(t *testing.T) {
	for _, body := range []string{`{"id":"42"}`, `{"id":42.0}`, `{"id":4.2e1}`, `{"id":0}`, `{"id":-42}`, `{"id":9223372036854775808}`, `{"id":42,"id":84}`, `[]`, `{"id":42} {}`, `{"email":"42@example.invalid"}`} {
		t.Run(body, func(t *testing.T) {
			var calls atomic.Int64
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/oauth/token" {
					fmt.Fprint(w, `{"access_token":"test-only-access-token","token_type":"Bearer","expires_in":60,"scope":"read_user"}`)
					return
				}
				fmt.Fprint(w, body)
			}))
			defer server.Close()
			c := oauth2SecurityConfig(server.URL)
			c.HTTPClient = server.Client()
			p, err := oauth.NewOAuth2UserInfoProvider(c)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			callback := oauth2SecurityCallback(t, p.OAuth2Profile())
			defer callback.Destroy()
			input, _ := callback.Input()
			verifier, err := oauth.NewPKCEVerifier([]byte(strings.Repeat("v", 64)))
			if err != nil {
				t.Fatal(err)
			}
			defer verifier.Destroy()
			out, err := p.Exchange(context.Background(), input, verifier, "")
			defer out.Tokens.Destroy()
			if err == nil || out.Identity.Subject() != "" || calls.Load() != 2 {
				t.Fatal("unverified UserInfo produced identity or retried")
			}
		})
	}
}

func oauth2SecurityCallback(t *testing.T, profile oauth.OAuth2UserInfoProfile) oauth.Callback {
	t.Helper()
	query := url.Values{"code": {"test-only-code"}, "state": {base64.RawURLEncoding.EncodeToString(make([]byte, 32))}}
	callback, err := oauth.ParseOAuth2QueryCallback(context.Background(), query.Encode(), profile.Profile.RedirectURI, profile)
	if err != nil {
		t.Fatal(err)
	}
	return callback
}

func TestOAuth2UserInfoRejectsBeforeNetworkAndRedactsSecrets(t *testing.T) {
	c := oauth2SecurityConfig("https://gitlab.example")
	for name, change := range map[string]func(*oauth.OAuth2UserInfoConfig){
		"foreign-token":      func(c *oauth.OAuth2UserInfoConfig) { c.TokenEndpoint = "https://other.example/token" },
		"foreign-userinfo":   func(c *oauth.OAuth2UserInfoConfig) { c.UserInfoEndpoint = "https://other.example/user" },
		"openid":             func(c *oauth.OAuth2UserInfoConfig) { c.Scopes = []string{"openid"} },
		"basic":              func(c *oauth.OAuth2UserInfoConfig) { c.ClientAuthentication = oauth.ClientSecretBasic },
		"long-proof":         func(c *oauth.OAuth2UserInfoConfig) { c.ProofLifetime = 21 * time.Second },
		"unknown-subject":    func(c *oauth.OAuth2UserInfoConfig) { c.SubjectEncoding = "string" },
		"unbounded-response": func(c *oauth.OAuth2UserInfoConfig) { c.MaxResponseBytes = 1 << 30 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := c
			change(&bad)
			p, err := oauth.NewOAuth2UserInfoProvider(bad)
			if err == nil || p != nil {
				t.Fatal("unsupported profile admitted")
			}
		})
	}
	if raw, err := json.Marshal(c); err == nil || len(raw) != 0 {
		t.Fatal("configuration serialized secret")
	}
	if strings.Contains(fmt.Sprintf("%#v", c), string(c.ClientSecret)) {
		t.Fatal("format disclosed secret")
	}
	p, err := oauth.NewOAuth2UserInfoProvider(c)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	profile := p.OAuth2Profile()
	state := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for _, query := range []string{"code=a&state=" + state + "&iss=" + url.QueryEscape(c.Issuer), "code=a&code=b&state=" + state, "error=access_denied&state=" + state + "&code=a", "code=a&state=" + state + "&access_token=x"} {
		if parsed, err := oauth.ParseOAuth2QueryCallback(context.Background(), query, c.RedirectURI, profile); err == nil {
			parsed.Destroy()
			t.Fatal("ambiguous callback admitted")
		}
	}
	denial, err := oauth.ParseOAuth2QueryCallback(context.Background(), "error=access_denied&state="+state, c.RedirectURI, profile)
	if err != nil || !denial.Denied() {
		t.Fatal("coherent original denial rejected", err)
	}
	denial.Destroy()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if parsed, err := oauth.ParseOAuth2QueryCallback(ctx, "code=a&state="+state, c.RedirectURI, profile); err == nil {
		parsed.Destroy()
		t.Fatal("cancellation ignored")
	}
	p.Close()
	if _, err := p.Authorization(context.Background(), oauth.AuthorizationParameters{State: state, PKCEChallenge: state}); err == nil {
		t.Fatal("closed provider remained usable")
	}
}

func FuzzOAuth2DistinctCallback(f *testing.F) {
	c := oauth2SecurityConfig("https://gitlab.example")
	p, err := oauth.NewOAuth2UserInfoProvider(c)
	if err != nil {
		f.Fatal(err)
	}
	defer p.Close()
	profile := p.OAuth2Profile()
	f.Add("code=bounded&state=" + base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	f.Add("error=access_denied&state=bad&iss=https%3A%2F%2Fother.example")
	f.Fuzz(func(t *testing.T, query string) {
		parsed, _ := oauth.ParseOAuth2QueryCallback(context.Background(), query, c.RedirectURI, profile)
		parsed.Destroy()
	})
}
