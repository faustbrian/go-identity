package oauthhttp_test

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	oauthhttp "github.com/faustbrian/go-identity/http/oauth"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/session"
	ratelimit "github.com/faustbrian/go-rate-limit/v2"
	"github.com/faustbrian/go-rate-limit/v2/memory"
)

// This unit adapter tests HTTP dispatch only, not native state/session authority.
type callbackProbe struct {
	sources, callbacks int
	last               oauth.Callback
}

type startProbe struct{}

func (startProbe) LinkStart(context.Context, oauth.LinkStartRequest) (oauth.LinkStartResult, error) {
	return oauth.LinkStartResult{}, identityhttp.ErrUnavailable
}

type sessionProbe struct{}

func (sessionProbe) Get(context.Context, session.GetRequest) (session.GetResult, error) {
	return session.GetResult{}, identityhttp.ErrUnavailable
}

func (p *callbackProbe) CallbackRateSource(_ context.Context, r oauth.CallbackRequest) (oauth.CallbackRateContext, error) {
	p.sources++
	p.last = r.Callback
	return oauth.CallbackRateContext{}, identityhttp.ErrUnavailable
}
func (p *callbackProbe) Callback(context.Context, oauth.CallbackRequest) (oauth.CallbackResult, error) {
	p.callbacks++
	return oauth.CallbackResult{}, identityhttp.ErrUnavailable
}

type localStrict struct{ *memory.Store }

func (s localStrict) Name() string { return "test-process-only" }
func (s localStrict) AdmitStrict(ctx context.Context, r ratelimit.Request) (ratelimit.Decision, error) {
	p := r.Policy
	r.Policy, _ = ratelimit.NewPolicy(ratelimit.PolicySpec{ID: p.ID(), Revision: p.Revision(), Algorithm: p.Algorithm(), Capacity: p.Capacity(), Period: p.Period(), Consistency: ratelimit.ConsistencyProcessLocal})
	return s.Store.AdmitStrict(ctx, r)
}
func TestCallbackRejectsIssuerMixupBeforeNativeLookupOrExchange(t *testing.T) {
	store, err := memory.New(memory.Options{MaxKeys: 256, Shards: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	rate, err := identityhttp.NewAuthRateLimiter(identityhttp.AuthRateConfig{Shared: localStrict{store}, Namespace: "social-test", IdentifierKey: [32]byte{1}, Now: time.Now, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer rate.Close()
	cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_session", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	profile := oauth.ProviderProfile{ID: "configured", Version: 1, Issuer: "https://issuer.example", ClientID: "client", AuthorizationEndpoint: "https://issuer.example/authorize", TokenEndpoint: "https://issuer.example/token", RedirectURI: "https://app.example/v1/oauth/callback", ClientAuthentication: oauth.PublicClient, Scopes: []string{"openid"}, Algorithms: []string{"ES256"}, ResponseMode: "query", PKCEMethod: "S256", NonceRequired: true, StateBytes: 32, NonceBytes: 32, Timeout: time.Second, ClockSkew: time.Minute, MaxResponseBytes: 65536, MaxTokenBytes: 16384, MaxCodeBytes: 4096}
	probe := &callbackProbe{}
	config := oauthhttp.Config{Network: identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 16384, MaximumURLBytes: 8192, MaximumBodyBytes: 16384, MaximumDecodedBytes: 16384, MaximumFields: 32, MaximumDepth: 8}, MaximumForwardedHops: 8, TenantHosts: []identityhttp.TenantHost{{Host: "app.example", TenantID: "tenant"}}}, Callback: probe, Rate: rate, Cookie: cookie, Origin: "https://app.example", Provider: profile, MaximumDuration: time.Second}
	handler, err := oauthhttp.NewCallbackHandler(config)
	if err != nil {
		t.Fatal(err)
	}
	query := (url.Values{"code": {"synthetic-code"}, "state": {base64.RawURLEncoding.EncodeToString(make([]byte, 32))}, "iss": {"https://foreign.example"}}).Encode()
	request := httptest.NewRequest("GET", "https://app.example/v1/oauth/callback?"+query, nil)
	request.RequestURI = request.URL.RequestURI()
	request.RemoteAddr = "192.0.2.1:1234"
	request.TLS = &tls.ConnectionState{}
	request.Header.Set("Cookie", "__Host-identity_session="+strings.Repeat("A", 43))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code < 400 || probe.sources != 0 || probe.callbacks != 0 || strings.Contains(response.Body.String(), "synthetic-code") {
		t.Fatal("issuer mixup reached native custody or leaked input", response.Code)
	}
	config.Start, config.Sessions, config.Now, config.PolicyRevision = startProbe{}, sessionProbe{}, time.Now, 9
	config.CallbackAllowlist = []string{"https://app.example/complete"}
	feature, err := oauthhttp.NewFeature(oauthhttp.FeatureConfig{LinkStart: &config, Callback: &config})
	if err != nil {
		t.Fatal("select actual handlers", err)
	}
	if _, _, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Selected social linking", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}}); err != nil {
		t.Fatal("selected linking cannot construct its public document", err)
	}
	hooks := 0
	bound, err := identityhttp.WithOperationMiddleware(handler, []identityhttp.MiddlewareDescriptor{{Owner: "identity/reference", Middleware: identityhttp.Middleware{Name: "before-native-lookup", Phase: identityhttp.MiddlewareBeforeAuth, Order: 1, Handler: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hooks++; next.ServeHTTP(w, r) })
	}}}})
	if err != nil {
		t.Fatal("actual callback phases cannot bind selected middleware", err)
	}
	valid := request.Clone(t.Context())
	queryValues := valid.URL.Query()
	queryValues.Set("iss", profile.Issuer)
	valid.URL.RawQuery = queryValues.Encode()
	valid.RequestURI = valid.URL.RequestURI()
	response = httptest.NewRecorder()
	bound.ServeHTTP(response, valid)
	if response.Code != http.StatusServiceUnavailable || hooks != 1 || probe.sources != 1 || probe.callbacks != 0 {
		t.Fatal("middleware replaced or bypassed original native lookup", response.Code, hooks, probe.sources, probe.callbacks)
	}
	input, ok := probe.last.Input()
	if !ok {
		t.Fatal("native lookup never received original callback custody")
	}
	if err := input.Use(t.Context(), func(context.Context, []byte, []byte) error { return nil }); err == nil {
		t.Fatal("failed native lookup retained callback secrets after handler return")
	}
	response = httptest.NewRecorder()
	bound.ServeHTTP(response, nil)
	if response.Code != http.StatusBadRequest || probe.sources != 1 {
		t.Fatal("nil request reached native lookup", response.Code)
	}
	config.Provider.Version = 0
	if _, err := oauthhttp.NewCallbackHandler(config); err == nil {
		t.Fatal("invalid provider profile enabled a callback handler")
	}
}
