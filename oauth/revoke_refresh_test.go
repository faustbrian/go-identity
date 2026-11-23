package oauth_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/oauth"
)

func revocationFixture(t *testing.T, handler http.HandlerFunc) (*oauth.OAuth2UserInfoProvider, *oauth.OAuth2RefreshRevocationProvider) {
	t.Helper()
	p, _ := refreshFixture(t, handler)
	adapter, err := oauth.NewOAuth2RefreshRevocationProvider(p, p.Profile().Issuer+"/designated-revoke")
	if err != nil {
		t.Fatal(err)
	}
	return p, adapter
}

func TestOAuth2RefreshRevocationAcknowledgesOneExactPOSTAndIgnoresBody(t *testing.T) {
	for _, body := range []string{"", "not-json", `{"error":"invalid_client","refresh_token":"not-a-result"}`, strings.Repeat("x", 70<<10)} {
		t.Run(fmt.Sprint("body-bytes=", len(body)), func(t *testing.T) {
			var calls atomic.Int32
			p, adapter := revocationFixture(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != http.MethodPost || r.URL.RequestURI() != "/designated-revoke" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || r.ParseForm() != nil || len(r.PostForm) != 4 || r.PostForm.Get("token") != "fixture-original-refresh" || r.PostForm.Get("token_type_hint") != "refresh_token" || r.PostForm.Get("client_id") != "registered-client" || r.PostForm.Get("client_secret") != "fixture-client-secret" {
					t.Error("revocation escaped configured endpoint, refresh hint or credential channel")
				}
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprint(w, body)
			})
			if err := adapter.Revoke(context.Background(), storedRefresh(t, p)); err != nil || calls.Load() != 1 {
				t.Fatalf("HTTP 200 acknowledgement was lost or repeated: %v", err)
			}
		})
	}
}

func TestOAuth2RefreshRevocationAcknowledgementDoesNotWaitForBody(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	p, adapter := revocationFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	if err := adapter.Revoke(context.Background(), storedRefresh(t, p)); err != nil {
		t.Fatal(err)
	}
}

func TestOAuth2RefreshRevocationRefusalAndUnknownNeverRetry(t *testing.T) {
	cases := []struct {
		name, body string
		status     int
		kind       oauth.ErrorKind
	}{
		{"invalid request", `{"error":"invalid_request"}`, 400, oauth.Refused},
		{"invalid client", `{"error":"invalid_client"}`, 401, oauth.Refused},
		{"unsupported token type", `{"error":"unsupported_token_type"}`, 400, oauth.Refused},
		{"invalid grant is not a revocation acknowledgement", `{"error":"invalid_grant"}`, 400, oauth.Refused},
		{"empty optional text", `{"error":"invalid_request","error_description":"","error_uri":""}`, 400, oauth.Refused},
		{"valid optional text", `{"error":"invalid_client","error_description":"Client refused","error_uri":"https://provider.example/help"}`, 400, oauth.Refused},
		{"wrong refusal status", `{"error":"invalid_request"}`, 401, oauth.Unknown},
		{"unknown refusal", `{"error":"new_extension"}`, 400, oauth.Unknown},
		{"conflicting token", `{"error":"invalid_request","refresh_token":"fixture-response-secret"}`, 400, oauth.Unknown},
		{"conflicting access token", `{"error":"invalid_request","access_token":"fixture-response-secret"}`, 400, oauth.Unknown},
		{"duplicate refusal", `{"error":"invalid_request","error":"invalid_client"}`, 400, oauth.Unknown},
		{"malformed JSON", `{"error":`, 400, oauth.Unknown},
		{"malformed description", `{"error":"invalid_client","error_description":"bad\ntext"}`, 400, oauth.Unknown},
		{"malformed URI", `{"error":"invalid_client","error_uri":"not a URI"}`, 400, oauth.Unknown},
		{"oversized refusal", `{"error":"invalid_client","extension":"` + strings.Repeat("x", 70<<10) + `"}`, 400, oauth.Unknown},
		{"no content is not acknowledged", "", 204, oauth.Unknown},
		{"unavailable never acknowledges", `{"error":"invalid_client"}`, 503, oauth.Unknown},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			p, adapter := revocationFixture(t, func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(test.status)
				fmt.Fprint(w, test.body)
			})
			err := adapter.Revoke(context.Background(), storedRefresh(t, p))
			refreshKind(t, err, test.kind)
			if calls.Load() != 1 || strings.Contains(fmt.Sprint(err), "fixture-response-secret") || strings.Contains(fmt.Sprint(err), "Client refused") {
				t.Fatal("revocation retried or disclosed provider response")
			}
		})
	}
}

func TestOAuth2RefreshRevocationRejectsUntrustedEndpointWithoutIO(t *testing.T) {
	var calls atomic.Int32
	p, _ := revocationFixture(t, func(w http.ResponseWriter, _ *http.Request) { calls.Add(1) })
	issuer := p.Profile().Issuer
	for _, endpoint := range []string{"", "http://provider.example/revoke", "https://foreign.example/revoke", issuer + "/revoke?token=never", issuer + "/revoke?", issuer + "/revoke#fragment", strings.Replace(issuer, "https://", "https://user:password@", 1) + "/revoke"} {
		adapter, err := oauth.NewOAuth2RefreshRevocationProvider(p, endpoint)
		refreshKind(t, err, oauth.InvalidInput)
		if adapter != nil {
			t.Fatal("untrusted revocation endpoint gained capability")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("constructor performed discovery or network I/O")
	}
}

func TestOAuth2RefreshRevocationDoesNotInferVendorCapability(t *testing.T) {
	p, err := oauth.NewOAuth2UserInfoProviderWithPolicy(githubOAuth2Config(), oauth.OAuth2GitHubOAuthAppPolicy)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	adapter, err := oauth.NewOAuth2RefreshRevocationProvider(p, "https://github.com/revoke")
	refreshKind(t, err, oauth.InvalidInput)
	if adapter != nil {
		t.Fatal("vendor token policy silently gained revocation capability")
	}
}

func TestOAuth2RefreshRevocationExactStoredProfilePreflightAndLifecycle(t *testing.T) {
	var calls atomic.Int32
	p, adapter := revocationFixture(t, func(w http.ResponseWriter, _ *http.Request) { calls.Add(1) })
	for _, mutate := range []func(*oauth.ProviderProfile){
		func(p *oauth.ProviderProfile) { p.ID = "foreign" },
		func(p *oauth.ProviderProfile) { p.Version++ },
		func(p *oauth.ProviderProfile) { p.ClientID = "foreign-client" },
		func(p *oauth.ProviderProfile) { p.RedirectURI = "https://other.example/callback" },
		func(p *oauth.ProviderProfile) { p.TokenEndpoint += "/foreign" },
		func(p *oauth.ProviderProfile) { p.Scopes = []string{"read"} },
		func(p *oauth.ProviderProfile) {
			p.Issuer = "https://foreign.example"
			p.AuthorizationEndpoint = p.Issuer + "/authorize"
			p.TokenEndpoint = p.Issuer + "/token"
		},
	} {
		profile := p.Profile()
		mutate(&profile)
		input, err := oauth.NewRefreshToken([]byte("fixture-original-refresh"), profile, []string{"read"})
		if err != nil {
			t.Fatal(err)
		}
		refreshKind(t, adapter.Revoke(context.Background(), input), oauth.InvalidInput)
		input.Destroy()
	}
	input := storedRefresh(t, p)
	refreshKind(t, adapter.Revoke(nil, input), oauth.InvalidInput)
	refreshKind(t, adapter.Revoke(context.Background(), oauth.RefreshToken{}), oauth.InvalidInput)
	var absent *oauth.OAuth2RefreshRevocationProvider
	refreshKind(t, absent.Revoke(context.Background(), input), oauth.InvalidInput)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := adapter.Revoke(ctx, input)
	refreshKind(t, err, oauth.Unavailable)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("preflight lost cancellation")
	}
	if strings.Contains(fmt.Sprintf("%+v %#v", adapter, adapter), "fixture-client-secret") {
		t.Fatal("provider credential leaked in diagnostics")
	}
	if _, err := json.Marshal(adapter); err == nil {
		t.Fatal("selected transport permitted implicit serialization")
	}
	alias := input
	input.Destroy()
	refreshKind(t, adapter.Revoke(context.Background(), alias), oauth.InvalidInput)
	p.Close()
	refreshKind(t, adapter.Revoke(context.Background(), storedRefresh(t, p)), oauth.InvalidInput)
	if _, err := oauth.NewOAuth2RefreshRevocationProvider(p, p.Profile().Issuer+"/revoke"); err == nil {
		t.Fatal("closed provider gained revocation capability")
	}
	if _, err := oauth.NewOAuth2RefreshRevocationProvider(nil, "https://provider.example/revoke"); err == nil {
		t.Fatal("nil provider gained revocation capability")
	}
	if calls.Load() != 0 {
		t.Fatal("preflight released original token")
	}
}

func TestOAuth2RefreshRevocationDoesNotFollowRedirects(t *testing.T) {
	for _, status := range []int{http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var calls, leaked atomic.Int32
			foreign := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { leaked.Add(1) }))
			defer foreign.Close()
			p, adapter := revocationFixture(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Location", foreign.URL+"/collect")
				w.WriteHeader(status)
			})
			refreshKind(t, adapter.Revoke(context.Background(), storedRefresh(t, p)), oauth.Unknown)
			if calls.Load() != 1 || leaked.Load() != 0 {
				t.Fatal("redirect replayed original revocation credentials")
			}
		})
	}
}

func TestOAuth2RefreshRevocationCancellationAfterSendIsUnknown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	release := make(chan struct{})
	defer close(release)
	var calls atomic.Int32
	p, adapter := revocationFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		cancel()
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	err := adapter.Revoke(ctx, storedRefresh(t, p))
	refreshKind(t, err, oauth.Unknown)
	if !errors.Is(err, context.Canceled) || calls.Load() != 1 {
		t.Fatal("attempt cancellation lost unknown outcome or retried")
	}
}

func TestOAuth2RefreshRevocationConnectionLossAfterSendIsUnknown(t *testing.T) {
	var calls atomic.Int32
	p, adapter := revocationFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		connection, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_ = connection.Close()
	})
	refreshKind(t, adapter.Revoke(context.Background(), storedRefresh(t, p)), oauth.Unknown)
	if calls.Load() != 1 {
		t.Fatal("ambiguous connection loss retried revocation")
	}
}

func TestOAuth2RefreshRevocationSharesOriginalCustodyExclusion(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	var calls atomic.Int32
	p, adapter := revocationFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		close(entered)
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		if r.ParseForm() != nil || r.PostForm.Get("token") != "fixture-original-refresh" {
			t.Error("destroy damaged admitted private token copy")
		}
	})
	input := storedRefresh(t, p)
	done := make(chan error, 1)
	go func() { done <- adapter.Revoke(context.Background(), input) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("revocation did not reach configured endpoint")
	}
	refreshKind(t, adapter.Revoke(context.Background(), input), oauth.InvalidInput)
	input.Destroy()
	release <- struct{}{}
	if err := <-done; err != nil || calls.Load() != 1 {
		t.Fatalf("admitted revocation was interrupted or duplicated: %v", err)
	}
	refreshKind(t, adapter.Revoke(context.Background(), input), oauth.InvalidInput)
}

func TestOAuth2RefreshRevocationSharedIssuerProfileRemainsExact(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/revoke" || r.ParseForm() != nil || r.PostForm.Get("token") != "shared-original-refresh" {
			t.Error("shared issuer custody was not used at its configured revocation endpoint")
		}
	}))
	defer server.Close()
	p, err := oauth.NewSharedOAuth2UserInfoProvider(oauth.OAuth2UserInfoConfig{
		ID: "enterprise", Version: 2, Issuer: server.URL, AuthorizationEndpoint: server.URL + "/authorize",
		TokenEndpoint: server.URL + "/token", UserInfoEndpoint: server.URL + "/identity", RedirectURI: "https://app.example/shared-callback",
		ClientID: "enterprise-client", ClientSecret: []byte("shared-client-secret"), ClientAuthentication: oauth.ClientSecretPost,
		Scopes: []string{"read"}, SubjectClaim: "sub", SubjectEncoding: oauth.OAuth2StringSubject,
		HTTPClient: server.Client(), Timeout: time.Second,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	adapter, err := oauth.NewSharedOAuth2RefreshRevocationProvider(p, server.URL+"/revoke")
	if err != nil {
		t.Fatal(err)
	}
	input, err := oauth.NewRefreshToken([]byte("shared-original-refresh"), p.Profile(), []string{"read"})
	if err != nil {
		t.Fatal(err)
	}
	defer input.Destroy()
	if err := adapter.Revoke(context.Background(), input); err != nil || calls.Load() != 1 {
		t.Fatalf("shared issuer profile could not revoke its original refresh token: %v", err)
	}
	p.Close()
	if _, err := oauth.NewSharedOAuth2RefreshRevocationProvider(p, server.URL+"/revoke"); err == nil {
		t.Fatal("closed shared provider gained capability")
	}
	if _, err := oauth.NewSharedOAuth2RefreshRevocationProvider(nil, server.URL+"/revoke"); err == nil {
		t.Fatal("nil shared provider gained capability")
	}
}
