package magiclinkhttp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	identityhttp "github.com/faustbrian/go-identity/http"
	magiclinkhttp "github.com/faustbrian/go-identity/http/magiclink"
	"github.com/faustbrian/go-identity/magiclink"
	"github.com/faustbrian/go-identity/session"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
	ratelimit "github.com/faustbrian/go-rate-limit/v2"
	"github.com/faustbrian/go-rate-limit/v2/memory"
)

// Only native workflow IO and shared-backend consistency are deliberate seams.
// The real decoder, origin, tenant and primitive token buckets execute here;
// these tests do not certify PostgreSQL or distributed rate persistence.
type shared struct {
	*memory.Store
	calls int
	fail  bool
}

func (*shared) Name() string { return "magic-transport-test" }
func (s *shared) AdmitStrict(ctx context.Context, r ratelimit.Request) (ratelimit.Decision, error) {
	s.calls++
	if s.fail {
		return ratelimit.Decision{}, ratelimit.ErrUnavailable
	}
	p := r.Policy
	r.Policy, _ = ratelimit.NewPolicy(ratelimit.PolicySpec{ID: p.ID(), Revision: p.Revision(), Algorithm: p.Algorithm(), Capacity: p.Capacity(), Period: p.Period(), Consistency: ratelimit.ConsistencyProcessLocal})
	return s.Store.AdmitStrict(ctx, r)
}

type work struct {
	rate         *shared
	reads, calls int
	last         magiclink.RequestRequest
	outcome      identity.CommitOutcome
	failure      error
	panicCall    bool
}

func (s *work) RequestRateSource(ctx context.Context, raw email.AddressInput) (string, error) {
	s.reads++
	if s.rate.calls != 1 || raw != "Person@EXAMPLE.test" {
		panic("unadmitted normalization")
	}
	return "person@example.test", nil
}
func (s *work) Request(ctx context.Context, r magiclink.RequestRequest) (magiclink.RequestResult, error) {
	s.calls++
	s.last = r
	if s.rate.calls != 2 || r.Validate() != nil {
		panic("unadmitted native request")
	}
	if s.panicCall {
		panic("private diagnostic")
	}
	return magiclink.RequestResult{CommandID: r.CommandID, Outcome: s.outcome, Accepted: s.outcome == identity.CommitOutcomeCommitted}, s.failure
}
func fixture(t *testing.T) (magiclinkhttp.RequestConfig, *work) {
	t.Helper()
	store, err := memory.New(memory.Options{MaxKeys: 64, Shards: 4})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	b := &shared{Store: store}
	now := func() time.Time { return time.Unix(1800000000, 0) }
	rate, err := identityhttp.NewAuthRateLimiter(identityhttp.AuthRateConfig{Shared: b, Namespace: "magic-test", IdentifierKey: [32]byte{1}, Now: now, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rate.Close() })
	w := &work{rate: b, outcome: identity.CommitOutcomeCommitted}
	return magiclinkhttp.RequestConfig{Network: identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 1024, MaximumBodyBytes: 4096, MaximumDecodedBytes: 4096, MaximumFields: 32, MaximumDepth: 4}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: "tenant.example", TenantID: "tenant-a"}}}, Service: w, Rate: rate, Origin: "https://tenant.example", CallbackURL: "https://tenant.example/login", ActorID: "ingress", PolicyRevision: 1, Device: deviceConfiguration(), Now: now, MaximumDuration: time.Second}, w
}

func deviceConfiguration() session.BrowserDeviceConfig {
	key, _ := session.NewBrowserDeviceKey(1, bytes.Repeat([]byte{42}, 32))
	cookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_device", SameSite: http.SameSiteLaxMode})
	return session.BrowserDeviceConfig{Namespace: "magic-http-device", Keys: []session.BrowserDeviceKey{key}, ActiveVersion: 1, Lifetime: time.Hour, Cookie: cookie}
}

func TestMagicLinkRequiresAuthenticatedBrowserDevice(t *testing.T) {
	for _, consume := range []bool{false, true} {
		for _, mode := range []string{"missing", "duplicate", "malformed", "expired", "foreign-tenant", "foreign-origin"} {
			t.Run(fmt.Sprintf("consume=%t/%s", consume, mode), func(t *testing.T) {
				c, work := fixture(t)
				r := request(body)
				var h http.Handler
				var err error
				var consuming *consumeWork
				if consume {
					cc, cw, raw := consumeFixture(t)
					consuming = cw
					r = consumeRequest(raw)
					h, err = magiclinkhttp.NewConsumeHandler(cc)
				} else {
					h, err = magiclinkhttp.NewRequestHandler(c)
				}
				if err != nil {
					t.Fatal(err)
				}
				cookies := r.Cookies()
				r.Header.Del("Cookie")
				for _, cookie := range cookies {
					if cookie.Name == "__Host-identity_device" {
						switch mode {
						case "missing":
							continue
						case "malformed":
							cookie.Value = "malformed"
						case "expired", "foreign-tenant", "foreign-origin":
							codec, _ := session.NewBrowserDeviceCodec(deviceConfiguration())
							now, tenant, origin := time.Unix(1800000000, 0), identity.TenantID("tenant-a"), "https://tenant.example"
							if mode == "expired" {
								now = now.Add(-time.Hour)
							}
							if mode == "foreign-tenant" {
								tenant = "foreign"
							}
							if mode == "foreign-origin" {
								origin = "https://foreign.example"
							}
							device, issueErr := codec.Issue(context.Background(), now, tenant, origin)
							if issueErr != nil {
								t.Fatal(issueErr)
							}
							response := &http.Response{Header: http.Header{"Set-Cookie": []string{device.CookieHeader()}}}
							cookie.Value = response.Cookies()[0].Value
						}
						if mode == "duplicate" {
							r.AddCookie(cookie)
						}
					}
					r.AddCookie(cookie)
				}
				out := httptest.NewRecorder()
				h.ServeHTTP(out, r)
				if out.Code != 400 || len(out.Result().Cookies()) != 0 || out.Header().Get("X-CSRF-Token") != "" || work.calls != 0 || consume && (consuming.calls != 0 || consuming.reads != 0) {
					t.Fatal("untrusted browser correlation entered native workflow", out.Code)
				}
			})
		}
	}
}

const body = `{"commandID":"AQEBAQEBAQEBAQEBAQEBAQ","email":"Person@EXAMPLE.test","intent":"signin-only","callbackURL":"https://tenant.example/login","preAuthID":"AgICAgICAgICAgICAgICAg"}`

func request(raw string) *http.Request {
	r := httptest.NewRequest("POST", "https://tenant.example/v1/magic-link/request", strings.NewReader(raw))
	r.RequestURI = r.URL.RequestURI()
	r.RemoteAddr = "198.51.100.1:1234"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://tenant.example")
	r.Header.Set("Idempotency-Key", "Original-Custody_001")
	r.Header.Set("Cookie", "__Host-identity_flow=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB")
	codec, _ := session.NewBrowserDeviceCodec(deviceConfiguration())
	device, _ := codec.Issue(context.Background(), time.Unix(1800000000, 0), "tenant-a", "https://tenant.example")
	response := &http.Response{Header: http.Header{"Set-Cookie": []string{device.CookieHeader()}}}
	r.AddCookie(response.Cookies()[0])
	return r
}
func TestRequestTransportAdmissionAndAcknowledgement(t *testing.T) {
	for _, mode := range []string{"success", "unknown-field", "duplicate-json", "missing-key", "authorization", "proxy-authorization", "origin", "callback", "missing-cookie", "duplicate-cookie", "query", "encoded-path", "method", "rate-outage"} {
		t.Run(mode, func(t *testing.T) {
			c, w := fixture(t)
			raw := body
			want := 200
			switch mode {
			case "unknown-field":
				raw = strings.TrimSuffix(raw, "}") + `,"userID":"foreign"}`
				want = 400
			case "duplicate-json":
				raw = strings.TrimSuffix(raw, "}") + `,"email":"foreign"}`
				want = 400
			case "callback":
				raw = strings.Replace(raw, string(c.CallbackURL), "https://foreign.test", 1)
				want = 400
			}
			r := request(raw)
			switch mode {
			case "missing-key":
				r.Header.Del("Idempotency-Key")
				want = 400
			case "authorization":
				r.Header.Set("Authorization", "Bearer private")
				want = 400
			case "proxy-authorization":
				r.Header.Set("Proxy-Authorization", "Bearer private")
				want = 400
			case "origin":
				r.Header.Set("Origin", "https://foreign.test")
				want = 403
			case "missing-cookie":
				r.Header.Del("Cookie")
				want = 400
			case "duplicate-cookie":
				r.Header.Add("Cookie", r.Header.Get("Cookie"))
				want = 400
			case "query":
				r.URL.RawQuery = "token=private"
				want = 400
			case "encoded-path":
				r.URL.RawPath = "/v1/magic-link/%72equest"
				want = 404
			case "method":
				r.Method = "GET"
				want = 405
			case "rate-outage":
				w.rate.fail = true
				want = 503
			}
			h, err := magiclinkhttp.NewRequestHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			out := httptest.NewRecorder()
			h.ServeHTTP(out, r)
			if out.Code != want {
				t.Fatal("HTTP outcome", out.Code, out.Body.String())
			}
			if out.Header().Get("Cache-Control") != "no-store" || len(out.Result().Cookies()) != 0 || out.Header().Get("Location") != "" || strings.Contains(out.Body.String(), "Person@") || strings.Contains(out.Body.String(), "private") {
				t.Fatal("response custody leaked")
			}
			if want != 200 {
				if w.calls != 0 {
					t.Fatal("denial entered workflow")
				}
				return
			}
			var ack magiclinkhttp.RequestResponse
			if json.Unmarshal(out.Body.Bytes(), &ack) != nil || !ack.Accepted || ack.CommitOutcome != "committed" || ack.CommandID != w.last.CommandID || w.calls != 1 || w.reads != 1 || w.last.TenantID != "tenant-a" || w.last.Origin != string(c.Origin) {
				t.Fatal("acknowledgement or trusted scope lost")
			}
		})
	}
}
func TestRequestTransportPreservesAmbiguity(t *testing.T) {
	for _, mode := range []string{"unknown", "conflict", "in-progress", "not-committed", "committed-error", "panic"} {
		t.Run(mode, func(t *testing.T) {
			c, w := fixture(t)
			want := 503
			switch mode {
			case "unknown":
				w.outcome = identity.CommitOutcomeUnknown
			case "conflict":
				w.outcome = identity.CommitOutcomeConflict
				want = 409
			case "in-progress":
				w.outcome = identity.CommitOutcomeInProgress
				want = 409
			case "not-committed":
				w.outcome = identity.CommitOutcomeNotCommitted
				want = 403
			case "committed-error":
				w.failure = errors.New("private diagnostic")
			case "panic":
				w.panicCall = true
			}
			h, err := magiclinkhttp.NewRequestHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			out := httptest.NewRecorder()
			h.ServeHTTP(out, request(body))
			var ack magiclinkhttp.RequestResponse
			if out.Code != want || json.Unmarshal(out.Body.Bytes(), &ack) != nil || ack.Accepted || ack.CommandID != "AQEBAQEBAQEBAQEBAQEBAQ" || ack.CommitOutcome == "none" || strings.Contains(out.Body.String(), "private") {
				t.Fatal("attempt ambiguity lost", out.Code, out.Body.String())
			}
			if mode == "committed-error" && ack.CommitOutcome != "committed" {
				t.Fatal("known commit rewritten as rollback")
			}
		})
	}
}

func TestRequestFeatureSelectsOnlyDocumentedRoute(t *testing.T) {
	c, w := fixture(t)
	feature, err := magiclinkhttp.NewFeature(magiclinkhttp.FeatureConfig{Request: &c})
	if err != nil {
		t.Fatal(err)
	}
	h, doc, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Magic link", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil || len(doc.Operations()) != 1 {
		t.Fatal("selected composition", err)
	}
	out := httptest.NewRecorder()
	h.ServeHTTP(out, request(body))
	if out.Code != 200 || w.calls != 1 {
		t.Fatal("selected route did not reach native request", out.Code, out.Body.String())
	}
	if !strings.Contains(string(doc.JSON()), `"preAuthID"`) || strings.Contains(string(doc.JSON()), "/v1/magic-link/consume") {
		t.Fatal("metadata advertises unselected or incomplete operation")
	}
	parsed, err := openapi.ParseJSON(context.Background(), bytes.NewReader(doc.JSON()), parse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	schema := parsed.Raw()
	for _, key := range []string{"paths", "/v1/magic-link/request", "post", "responses", "200", "content", "application/json", "schema"} {
		var ok bool
		schema, ok = schema.Lookup(key)
		if !ok {
			t.Fatal("selected wire schema missing")
		}
	}
	instance, err := parse.JSON(context.Background(), bytes.NewReader(out.Body.Bytes()), parse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	report, err := validate.SchemaInstance(context.Background(), parsed, schema, instance, validate.InstanceOptions{Direction: validate.DirectionResponse})
	if err != nil || !report.Valid() {
		t.Fatal("response contradicts selected schema", err)
	}
	r := request(body)
	r.URL.Path = "/v1/magic-link/consume"
	r.RequestURI = r.URL.Path
	out = httptest.NewRecorder()
	h.ServeHTTP(out, r)
	if out.Code != 404 || w.calls != 1 {
		t.Fatal("unselected route exposed")
	}
	if _, err := magiclinkhttp.NewFeature(magiclinkhttp.FeatureConfig{}); err == nil {
		t.Fatal("empty feature selected")
	}
}

func TestRequestMiddlewareCannotPublishCredentials(t *testing.T) {
	c, _ := fixture(t)
	h, err := magiclinkhttp.NewRequestHandlerWithMiddleware(c, []identityhttp.MiddlewareDescriptor{{Owner: "identity/magiclink", Middleware: identityhttp.Middleware{Name: "hostile-output", Phase: identityhttp.MiddlewareBeforeHandler, Order: 1, Handler: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header()["set-cookie"] = []string{"private"}
			w.Header().Set("Location", "https://foreign.test")
			w.Header().Set("Trailer", "Authorization")
			w.Header()[http.TrailerPrefix+"Authorization"] = []string{"private"}
			next.ServeHTTP(w, r)
			w.Header().Set("Set-Cookie", "private")
			w.Header().Set("Cache-Control", "public")
		})
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	out := httptest.NewRecorder()
	h.ServeHTTP(out, request(body))
	if out.Code != 200 || len(out.Result().Cookies()) != 0 || out.Header().Get("Set-Cookie") != "" || out.Header().Get("Location") != "" || out.Header().Get("Trailer") != "" || out.Header().Get("Cache-Control") != "no-store" || len(out.Result().Trailer) != 0 {
		t.Fatal("middleware escaped response custody")
	}
}

func FuzzRequestBoundedTransport(f *testing.F) {
	f.Add(body)
	f.Add(`{"email":"duplicate","email":"duplicate"}`)
	f.Add(`{"email":"\u0000"}`)
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 8192 {
			return
		}
		c, w := fixture(t)
		h, err := magiclinkhttp.NewRequestHandler(c)
		if err != nil {
			t.Fatal(err)
		}
		out := httptest.NewRecorder()
		h.ServeHTTP(out, request(raw))
		if out.Body.Len() > 4096 || w.calls > 1 || len(out.Result().Cookies()) != 0 || out.Header().Get("Location") != "" || out.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("unbounded or credential-bearing response")
		}
	})
}
