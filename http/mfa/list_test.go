package mfahttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/mfa"
	rate "github.com/faustbrian/go-rate-limit/v2"
)

type listOwner struct {
	calls  int
	result mfa.ListResult
	err    error
	after  func()
}

type listRate struct{ strictRate }

func (*listRate) AdmitStrict(_ context.Context, r rate.Request) (rate.Decision, error) {
	return rate.Decision{Allowed: true, Limit: r.Policy.Limit(), Remaining: r.Policy.Limit() - r.Cost, Reset: r.Now.Add(r.Policy.Period()), Reason: rate.ReasonAllowed}, nil
}

func (o *listOwner) List(ctx context.Context, r mfa.ListRequest) (mfa.ListResult, error) {
	o.calls++
	if _, ok := ctx.Deadline(); !ok || r.Validate() != nil || r.TenantID != "tenant-a" {
		panic("unbounded or foreign listing")
	}
	if o.after != nil {
		o.after()
	}
	return o.result, o.err
}

func TestMFAListHTTPRequiresNativeOwners(t *testing.T) {
	if h, err := NewListHandler(ListConfig{}); err == nil || h != nil {
		t.Fatal("unconfigured listing acquired metadata authority")
	}
}

func TestMFAListHTTPConservesCredentialAndSafeDisplay(t *testing.T) {
	for _, mode := range []string{"fresh", "empty", "missing-cookie", "authorization", "query", "body", "key", "method", "owner-denied", "expired", "corrupt-result"} {
		t.Run(mode, func(t *testing.T) {
			c, _, reader, clock, r := uriFixture(t)
			rate, err := identityhttp.NewSafeRateLimiter(identityhttp.SafeRateConfig{Shared: &listRate{}, Namespace: "mfa-list-test", Now: clock.Now, Degraded: func(context.Context, identityhttp.SafeRateEvent) error { return nil }, MaximumDuration: time.Second, EmergencyMaximumKeys: 128})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := rate.Close(); err != nil {
					t.Error(err)
				}
			})
			o := &listOwner{result: mfa.ListResult{Factors: []mfa.FactorProjection{{ID: "AAAAAAAAAAAAAAAAAAAAAQ", Method: "totp", State: mfa.FactorActive, CreatedAt: clock.now.Add(-time.Minute), Version: 1}}, TrustedDevices: []mfa.TrustedDeviceProjection{}, RecoveryCodeCount: 10}}
			r.Method = http.MethodGet
			r.URL.Path = "/v1/mfa/list"
			r.RequestURI = r.URL.RequestURI()
			r.Body = http.NoBody
			r.ContentLength = 0
			r.Header.Del("X-CSRF-Token")
			r.Header.Del("Origin")
			want := 200
			switch mode {
			case "empty":
				o.result = mfa.ListResult{Factors: []mfa.FactorProjection{}, TrustedDevices: []mfa.TrustedDeviceProjection{}}
			case "missing-cookie":
				r.Header.Del("Cookie")
				want = 403
			case "authorization":
				r.Header.Set("Authorization", "Bearer synthetic")
				want = 400
			case "query":
				r.URL.RawQuery = "userID=other"
				want = 400
			case "body":
				r.Body = ioBody("{}")
				r.ContentLength = 2
				want = 400
			case "key":
				r.Header.Set("Idempotency-Key", "synthetic-key")
				want = 400
			case "method":
				r.Method = http.MethodPost
				want = 405
			case "owner-denied":
				o.err = identity.ForbiddenError{}
				want = 403
			case "expired":
				o.after = func() { clock.now = clock.now.Add(20 * time.Second) }
				want = 503
			case "corrupt-result":
				o.result.Factors[0].Version = 0
				want = 503
			}
			config := ListConfig{Network: c.Network, Sessions: c.Sessions, Service: o, Rate: rate, Cookie: c.Cookie, Now: clock.Now, MaximumDuration: time.Second}
			h, err := NewListHandler(config)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			w.Header().Set("Set-Cookie", "injected")
			h.ServeHTTP(w, r)
			if w.Code != want || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" {
				t.Fatal("listing lost denial/no-store/no-credential contract", w.Code, "ownerCalls", o.calls, "sessionReads", reader.calls, "safeError", w.Body.String())
			}
			if want != 200 && strings.Contains(w.Body.String(), "AAAAAAAAAAAAAAAAAAAAAQ") {
				t.Fatal("failed listing disclosed metadata")
			}
			if want == 200 && (o.calls != 1 || !strings.Contains(w.Body.String(), `"recoveryCodeCount":`)) {
				t.Fatal("safe display result unavailable")
			}
			if mode == "fresh" {
				feature, err := NewFeature(FeatureConfig{List: &config})
				if err != nil {
					t.Fatal("independent listing feature unavailable", err)
				}
				ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
				if err != nil || len(ops) != 1 || ops[0].Record.OperationID != "identity.mfa.list" || ops[0].Wire == nil {
					t.Fatal("listing selected unrelated routes or omitted wire schema", err)
				}
			}
		})
	}
}
