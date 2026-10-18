package passwordhttp_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	"github.com/faustbrian/go-identity/session"
	"github.com/faustbrian/go-identity/username"
)

type availableWork struct {
	calls int
	last  username.AvailabilityRequest
	out   username.AvailabilityResult
	err   error
}

func TestUsernameAvailabilityFeatureIsIndependentlySelected(t *testing.T) {
	f := newChange(t, session.CredentialBearer)
	owner := &availableWork{out: username.AvailabilityResult{Available: true}}
	c := passwordhttp.UsernameAvailabilityConfig{Network: f.config.Network, Service: owner, MaximumDuration: time.Second}
	feature, err := passwordhttp.NewUsernameFeature(passwordhttp.UsernameFeatureConfig{Available: &c})
	if err != nil {
		t.Fatal(err)
	}
	selected, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "https://tenant.example/v1/username/available?username=valid", nil)
	r.RequestURI, r.RemoteAddr = r.URL.RequestURI(), "198.51.100.7:1234"
	w := httptest.NewRecorder()
	selected.ServeHTTP(w, r)
	if w.Code != 200 || owner.calls != 1 {
		t.Fatal("selected availability does not execute", w.Code)
	}
	ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil || len(ops) != 1 || ops[0].Record.OperationID != "identity.username.available" || ops[0].Wire == nil || !strings.Contains(string(ops[0].Wire.Definition), `"in":"query"`) {
		t.Fatal("availability selection has incorrect wire contract", err)
	}
	r.URL.Path, r.URL.RawQuery = "/v1/username/signin", ""
	r.RequestURI = r.URL.RequestURI()
	w = httptest.NewRecorder()
	selected.ServeHTTP(w, r)
	if w.Code != 404 || owner.calls != 1 {
		t.Fatal("availability enabled unrelated username operation")
	}
}

func (w *availableWork) Available(ctx context.Context, r username.AvailabilityRequest) (username.AvailabilityResult, error) {
	if _, ok := ctx.Deadline(); !ok {
		panic("unbounded availability")
	}
	w.calls++
	w.last = r
	return w.out, w.err
}

func TestUsernameAvailabilityRetainsTrustedScopeAndNeverCachesPromise(t *testing.T) {
	f := newChange(t, session.CredentialBearer)
	owner := &availableWork{out: username.AvailabilityResult{Available: true}}
	h, err := passwordhttp.NewUsernameAvailabilityHandler(passwordhttp.UsernameAvailabilityConfig{Network: f.config.Network, Service: owner, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	request := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "https://tenant.example/v1/username/available?username=Stra%C3%9Fe", nil)
		r.RequestURI = r.URL.RequestURI()
		r.RemoteAddr = "198.51.100.7:1234"
		return r
	}
	for range 2 {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, request())
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"available":true`) || !strings.Contains(w.Header().Get("Cache-Control"), "no-store") || w.Header().Get("Set-Cookie") != "" || strings.Contains(w.Body.String(), "Straße") {
			t.Fatal("availability leaked identity or cached a reservation promise", w.Code)
		}
	}
	if owner.calls != 2 || owner.last.TenantID != "tenant-a" || owner.last.Network != "198.51.100.7" || owner.last.Username != "Straße" {
		t.Fatal("availability bypassed per-attempt owner or trusted scope")
	}
	owner.err = errors.New("synthetic-private-provider-diagnostic")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request())
	if w.Code != 503 || strings.Contains(w.Body.String(), `"available":true`) || strings.Contains(w.Body.String(), "synthetic-private") {
		t.Fatal("unknown native availability became an available name")
	}
}

func TestUsernameAvailabilityRejectsScopeAndCredentialAlternatives(t *testing.T) {
	for name, mutate := range map[string]func(*http.Request){
		"duplicate":    func(r *http.Request) { r.URL.RawQuery = "username=one&username=two" },
		"tenant":       func(r *http.Request) { r.URL.RawQuery += "&tenantID=foreign" },
		"missing":      func(r *http.Request) { r.URL.RawQuery = "" },
		"empty":        func(r *http.Request) { r.URL.RawQuery = "username=" },
		"oversize":     func(r *http.Request) { r.URL.RawQuery = "username=" + strings.Repeat("a", 129) },
		"bearer":       func(r *http.Request) { r.Header.Set("Authorization", "Bearer synthetic") },
		"proxy-bearer": func(r *http.Request) { r.Header.Set("Proxy-Authorization", "Bearer synthetic") },
		"key":          func(r *http.Request) { r.Header.Set("Idempotency-Key", "not-availability-custody") },
		"body":         func(r *http.Request) { r.Body = http.NoBody; r.ContentLength = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			f := newChange(t, session.CredentialBearer)
			owner := &availableWork{}
			h, err := passwordhttp.NewUsernameAvailabilityHandler(passwordhttp.UsernameAvailabilityConfig{Network: f.config.Network, Service: owner, MaximumDuration: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodGet, "https://tenant.example/v1/username/available?username=valid", nil)
			r.RemoteAddr = "198.51.100.7:1234"
			mutate(r)
			r.RequestURI = r.URL.RequestURI()
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 400 || owner.calls != 0 {
				t.Fatal("invalid availability invoked owner", w.Code)
			}
		})
	}
}
