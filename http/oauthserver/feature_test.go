package oauthserverhttp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	oauth "github.com/faustbrian/go-oauth-server"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
	password "github.com/faustbrian/go-password/v2"
)

type wireClock struct{ now time.Time }

func (c wireClock) Now() time.Time { return c.now }

// This adapter isolates transport/core behavior, not durable issuance. The
// complete PostgreSQL/HTTPS consumer must independently prove storage effects.
type wireStore struct {
	oauth.Store
	calls int
	mode  string
	clock wireClock
}

func (s *wireStore) Token(ctx context.Context, c oauth.TokenCommand) (oauth.TokenResult, error) {
	s.calls++
	if _, ok := ctx.Deadline(); !ok || c.Request.Network != "198.51.100.7" || c.Client.Workload == nil {
		return oauth.TokenResult{}, oauth.ErrInvalidRequest
	}
	if s.mode == "panic" {
		panic("storage boundary failed")
	}
	if s.mode == "unknown" {
		return oauth.TokenResult{Outcome: identity.CommitOutcomeUnknown}, nil
	}
	if s.mode == "replayed" {
		return oauth.TokenResult{Outcome: identity.CommitOutcomeCommitted, Replayed: true}, nil
	}
	token, err := oauth.NewToken()
	return oauth.TokenResult{Outcome: identity.CommitOutcomeCommitted, AccessToken: token, ExpiresAt: s.clock.Now().Add(30 * time.Second), Resource: c.Client.Resource, Scopes: c.Request.Scopes}, err
}

func (s *wireStore) Revoke(context.Context, oauth.RevocationCommand) (oauth.RevokeResult, error) {
	s.calls++
	if s.mode == "unknown" {
		return oauth.RevokeResult{Outcome: identity.CommitOutcomeUnknown}, nil
	}
	return oauth.RevokeResult{Outcome: identity.CommitOutcomeCommitted}, nil
}

func (s *wireStore) Introspect(context.Context, oauth.IntrospectionCommand) (oauth.IntrospectResult, error) {
	s.calls++
	// Deliberately dirty inactive data tests that the existing core projection
	// remains the disclosure owner, rather than a transport JSON copy.
	return oauth.IntrospectResult{Active: false, Subject: "must-not-disclose"}, nil
}

func featureFixture(t *testing.T, changes ...func(*oauth.Config)) (FeatureConfig, *wireStore, string) {
	t.Helper()
	_, backend := rateFixture(t)
	now := time.Unix(1800000000, 0)
	clock := wireClock{now}
	issuer, _ := oauth.NewIssuer("https://issuer.example")
	owner, _ := oauth.NewPlatformOwner("platform")
	scopes, _ := oauth.NewScopeCatalog([]string{"identity:read"})
	workload, _ := oauth.NewWorkload("tenant", "worker", 30*time.Second)
	secretToken, err := oauth.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := secretToken.Reveal()
	secret, err := password.NewSecret([]byte(wire))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := oauth.NewClientSecretVerifier("machine", 1, secret)
	secret.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	store := &wireStore{clock: clock}
	native := oauth.Config{Issuer: issuer, Environment: "test", Resource: "https://resource.example", Scopes: scopes,
		Clients: []oauth.Client{{ID: "machine", Owner: owner, Version: 1, AuthenticationMethod: "client_secret_basic", Scopes: scopes.Scopes(), Resource: "https://resource.example", Workload: workload}}, ClientSecrets: []oauth.ClientSecretVerifier{verifier}, OwningClientIntrospection: true,
		Discovery: oauth.DiscoveryConfig{Enabled: true, TokenEndpoint: issuer.String() + "/oauth2/token", RevocationEndpoint: issuer.String() + "/oauth2/revoke", IntrospectionEndpoint: issuer.String() + "/oauth2/introspect"},
		Clock:     clock, MaximumDuration: time.Second, CodeTTL: time.Minute, ContinuationTTL: time.Minute, AccessTTL: time.Minute, RefreshTTL: time.Hour}
	for _, change := range changes {
		change(&native)
	}
	service, err := oauth.NewService(native, oauth.Dependencies{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	return FeatureConfig{Service: service, Token: true, Introspect: true, Revoke: true, Network: identityhttp.NetworkConfig{MaximumForwardedHops: 8, PublicHosts: []string{"issuer.example"}, Limits: identityhttp.Limits{MaximumHeaderBytes: 8192, MaximumURLBytes: 4096, MaximumBodyBytes: 16384, MaximumDecodedBytes: 16384, MaximumFields: 16, MaximumDepth: 2}},
		Rate: RateConfig{Shared: backend, Namespace: "oauth-wire-test", Now: clock.Now, MaximumDuration: time.Second}, Now: clock.Now, MaximumDuration: 2 * time.Second}, store, "Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape("machine")+":"+url.QueryEscape(wire)))
}

func operationHandler(t *testing.T, config FeatureConfig, action string) http.Handler {
	t.Helper()
	f, err := NewFeature(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range f.Operations() {
		if op.Record.OperationID == "identity.oauth-server."+action {
			return op.Handler
		}
	}
	t.Fatal("selected operation absent", action)
	return nil
}

func wireRequest(action, form, auth string) *http.Request {
	r := httptest.NewRequest("POST", "/oauth2/"+action, strings.NewReader(form))
	r.Host, r.TLS = "issuer.example", &tls.ConnectionState{}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	r.RemoteAddr = "198.51.100.7:1234"
	return r
}

func TestWorkloadHTTPTokenAndInactiveIntrospection(t *testing.T) {
	c, store, basic := featureFixture(t)
	w := httptest.NewRecorder()
	operationHandler(t, c, "token").ServeHTTP(w, wireRequest("token", "grant_type=client_credentials&scope=identity%3Aread", basic))
	var token map[string]any
	if json.Unmarshal(w.Body.Bytes(), &token) != nil || w.Code != 200 || len(token) != 4 || token["token_type"] != "Bearer" || token["expires_in"] != float64(30) || token["scope"] != "identity:read" || len(token["access_token"].(string)) != 43 || store.calls != 1 {
		t.Fatal("workload token response unavailable", w.Code)
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Pragma") != "no-cache" {
		t.Fatal("credential response is cacheable")
	}
	w = httptest.NewRecorder()
	operationHandler(t, c, "introspect").ServeHTTP(w, wireRequest("introspect", "token="+token["access_token"].(string), basic))
	if w.Code != 200 || strings.TrimSpace(w.Body.String()) != `{"active":false}` || store.calls != 2 {
		t.Fatal("inactive metadata disclosure changed", w.Code)
	}
	w = httptest.NewRecorder()
	operationHandler(t, c, "revoke").ServeHTTP(w, wireRequest("revoke", "token="+token["access_token"].(string), basic))
	if w.Code != 200 || w.Body.Len() != 0 || store.calls != 3 {
		t.Fatal("RFC7009 empty successful response changed", w.Code)
	}
}

func TestWorkloadHTTPDeniesBeforeNativeEffects(t *testing.T) {
	for _, change := range []struct {
		name string
		edit func(*http.Request)
	}{
		{"wrong_method", func(r *http.Request) { r.Method = "GET" }},
		{"unknown_host", func(r *http.Request) { r.Host = "foreign.example" }},
		{"query_credential", func(r *http.Request) { r.URL.RawQuery = "client_secret=not-accepted" }},
		{"header_duplicate", func(r *http.Request) { r.Header.Add("Authorization", r.Header.Get("Authorization")) }},
		{"cookie_only", func(r *http.Request) { r.Header.Del("Authorization"); r.Header.Set("Cookie", "session=not-authority") }},
		{"wrong_secret", func(r *http.Request) {
			r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("machine:"+strings.Repeat("w", 43))))
		}},
		{"unsupported_grant", func(r *http.Request) { r.Body = http.NoBody; r.ContentLength = 0 }},
		{"idempotency_header", func(r *http.Request) { r.Header.Set("Idempotency-Key", "unsupported") }},
		{"http_downgrade", func(r *http.Request) { r.TLS = nil; r.URL.Scheme = "http" }},
		{"encoded_path", func(r *http.Request) { r.URL.RawPath = "/oauth2/%74oken" }},
	} {
		t.Run(change.name, func(t *testing.T) {
			c, store, basic := featureFixture(t)
			r := wireRequest("token", "grant_type=client_credentials", basic)
			change.edit(r)
			w := httptest.NewRecorder()
			operationHandler(t, c, "token").ServeHTTP(w, r)
			if w.Code < 400 || store.calls != 0 || strings.Contains(w.Body.String(), basic) {
				t.Fatal("invalid request reached durable effect or disclosed credential", w.Code)
			}
		})
	}
}

func TestWorkloadHTTPUnknownAndReplayNeverDeliverCredentials(t *testing.T) {
	for _, mode := range []string{"unknown", "replayed"} {
		c, store, basic := featureFixture(t)
		store.mode = mode
		w := httptest.NewRecorder()
		operationHandler(t, c, "token").ServeHTTP(w, wireRequest("token", "grant_type=client_credentials", basic))
		if w.Code != 503 || strings.Contains(w.Body.String(), "access_token") || strings.Contains(w.Body.String(), "command") || store.calls != 1 {
			t.Fatal("nonfresh outcome became token response", mode, w.Code)
		}
	}
	c, store, basic := featureFixture(t)
	store.mode = "unknown"
	w := httptest.NewRecorder()
	operationHandler(t, c, "revoke").ServeHTTP(w, wireRequest("revoke", "token="+strings.Repeat("A", 43), basic))
	if w.Code != 503 || w.Body.Len() == 0 || strings.Contains(w.Body.String(), "command") || store.calls != 1 {
		t.Fatal("unknown revocation became empty successful response", w.Code)
	}
}

func TestWorkloadHTTPMissingSelectedDependenciesFailConstruction(t *testing.T) {
	for _, change := range []func(*FeatureConfig){
		func(c *FeatureConfig) { c.Service = nil },
		func(c *FeatureConfig) { c.Token, c.Introspect, c.Revoke = false, false, false },
		func(c *FeatureConfig) { c.Now = nil },
		func(c *FeatureConfig) { c.Rate.Shared = nil },
		func(c *FeatureConfig) { c.Network.PublicHosts = []string{"not-the-issuer.example"} },
	} {
		c, _, _ := featureFixture(t)
		change(&c)
		if f, err := NewFeature(context.Background(), c); err == nil || f.ID() != "" {
			t.Fatal("unusable selected contribution was constructed")
		}
	}
	c, _, _ := featureFixture(t, func(c *oauth.Config) {
		c.OwningClientIntrospection = false
		c.Discovery.IntrospectionEndpoint = ""
	})
	if _, err := NewFeature(context.Background(), c); err == nil {
		t.Fatal("unselected native introspection was exposed")
	}
}

func TestWorkloadHTTPSelectedRouterAndWireSchemaAgree(t *testing.T) {
	c, _, basic := featureFixture(t)
	c.Introspect, c.Revoke = false, false
	f, err := NewFeature(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{f}})
	if err != nil {
		t.Fatal(err)
	}
	h, doc, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: c.Network, HandlerTimeout: c.MaximumDuration, Document: identityhttp.DocumentConfig{Title: "Workload OAuth", Version: "1"}}, ops, nil)
	if err != nil {
		t.Fatal("selected router/OpenAPI construction", err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, wireRequest("token", "grant_type=client_credentials", basic))
	if w.Code != 200 {
		t.Fatal("selected router token response", w.Code)
	}
	parsed, err := openapi.ParseJSON(t.Context(), bytes.NewReader(doc.JSON()), parse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	node := parsed.Raw()
	for _, name := range []string{"paths", "/oauth2/token", "post", "responses", "200", "content", "application/json", "schema"} {
		var ok bool
		node, ok = node.Lookup(name)
		if !ok {
			t.Fatal("actual response has no selected schema")
		}
	}
	body, err := parse.JSON(t.Context(), bytes.NewReader(w.Body.Bytes()), parse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	report, err := validate.SchemaInstance(t.Context(), parsed, node, body, validate.InstanceOptions{Direction: validate.DirectionResponse})
	if err != nil || !report.Valid() {
		t.Fatal("actual token response violates selected schema", err)
	}
	for _, path := range []string{"/oauth2/introspect", "/oauth2/revoke", "/oauth2/authorize", "/.well-known/oauth-authorization-server"} {
		r := wireRequest("token", "grant_type=client_credentials", basic)
		r.URL.Path, r.RequestURI = path, path
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 404 || bytes.Contains(doc.JSON(), []byte(`"`+path+`"`)) {
			t.Fatal("disabled route/metadata was exposed", path, w.Code)
		}
	}
}

func TestWorkloadHTTPIncorrectSecretsDoNotConsumeAuthenticatedClientBudget(t *testing.T) {
	c, store, basic := featureFixture(t)
	h := operationHandler(t, c, "token")
	wrong := "Basic " + base64.StdEncoding.EncodeToString([]byte("machine:"+strings.Repeat("w", 43)))
	for range 59 {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, wireRequest("token", "grant_type=client_credentials", wrong))
		if w.Code != 401 || w.Header().Get("WWW-Authenticate") == "" {
			t.Fatal("wrong credential did not retain uniform client denial", w.Code)
		}
	}
	for range 60 {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, wireRequest("token", "grant_type=client_credentials", basic))
		if w.Code != 200 {
			t.Fatal("incorrect secrets consumed a verified client's budget", w.Code)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, wireRequest("token", "grant_type=client_credentials", basic))
	if w.Code != 429 || w.Header().Get("Retry-After") == "" || store.calls != 60 {
		t.Fatal("authenticated client budget did not bound native effects", w.Code)
	}
}
