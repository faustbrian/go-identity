package identityhttp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func probeHook(phase identityhttp.MiddlewarePhase, f func(http.ResponseWriter, *http.Request, http.Handler)) identityhttp.MiddlewareDescriptor {
	return identityhttp.MiddlewareDescriptor{Owner: "probe-observer", Middleware: identityhttp.Middleware{Name: "observe", Phase: phase, Order: 1, Handler: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f(w, r, next) })
	}}}
}

func TestProbeBindingCancellationDuringFinalObservationDenies(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var observations, checks int
	_, ready := probes(t, func() identityhttp.ServerState {
		observations++
		if observations == 3 {
			cancel()
		}
		return identityhttp.ServerRunning
	}, func(context.Context) (identityhttp.ReadinessSnapshot, error) {
		checks++
		return identityhttp.ReadinessSnapshot{Ready: true}, nil
	}, time.Second)
	h, err := identityhttp.WithOperationMiddleware(ready, []identityhttp.MiddlewareDescriptor{probeHook(identityhttp.MiddlewareBeforeHandler, func(w http.ResponseWriter, r *http.Request, next http.Handler) { next.ServeHTTP(w, r) })})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/readyz", nil).WithContext(ctx))
	if observations != 3 || checks != 1 || w.Code != 503 || w.Body.String() != "{\"ready\":false}\n" {
		t.Fatalf("final cancellation admitted readiness: status%d observations%d checks%d", w.Code, observations, checks)
	}
}

func TestProbeBindingProtectsOwnedResponseAndCredentials(t *testing.T) {
	for _, path := range []string{"/healthz", "/readyz"} {
		for _, behavior := range []string{"normal", "short-circuit", "panic", "write-panic", "drain", "cancel"} {
			t.Run(path+"/"+behavior, func(t *testing.T) {
				var checks atomic.Int32
				state := identityhttp.ServerRunning
				live, ready := probes(t, func() identityhttp.ServerState { return state }, func(context.Context) (identityhttp.ReadinessSnapshot, error) {
					checks.Add(1)
					return identityhttp.ReadinessSnapshot{Ready: true}, nil
				}, time.Second)
				original := live
				if path == "/readyz" {
					original = ready
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				hook := probeHook(identityhttp.MiddlewareBeforeHandler, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
					for name := range r.Header {
						if strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "Cookie") || strings.EqualFold(name, "Proxy-Authorization") || strings.EqualFold(name, "Cookie2") {
							t.Error("public hook received credentials")
						}
					}
					r.URL.Path, r.Host = "/other", "attacker.example"
					w.Header().Set("Set-Cookie", "invented=1")
					w.Header().Set("Cache-Control", "public")
					if behavior == "short-circuit" {
						w.Write([]byte(`{"ready":true}`))
						return
					}
					if behavior == "panic" {
						panic("private diagnostic")
					}
					if behavior == "write-panic" {
						w.Write([]byte("private diagnostic"))
						panic("private diagnostic")
					}
					if behavior == "cancel" {
						cancel()
					}
					next.ServeHTTP(w, r)
					if behavior == "drain" {
						state = identityhttp.ServerDraining
					}
					w.Write([]byte("private diagnostic"))
				})
				h, err := identityhttp.WithOperationMiddleware(original, []identityhttp.MiddlewareDescriptor{hook})
				if err != nil {
					t.Fatal(err)
				}
				r := httptest.NewRequest("GET", path, nil).WithContext(ctx)
				r.Header["authorization"] = []string{"Bearer test-input"}
				r.Header["cookie"] = []string{"session=test-input"}
				r.Header.Set("Proxy-Authorization", "Basic test-input")
				r.Header.Set("Cookie2", "test-input")
				w := httptest.NewRecorder()
				func() {
					defer func() {
						if recover() != nil {
							t.Error("probe aborted before any real response commitment")
						}
					}()
					h.ServeHTTP(w, r)
				}()
				want := 200
				if behavior == "short-circuit" || behavior == "panic" || behavior == "write-panic" || behavior == "cancel" || (behavior == "drain" && path == "/readyz") {
					want = 503
				}
				body := "{\"status\":\"alive\"}\n"
				if path == "/readyz" {
					body = "{\"ready\":true}\n"
				}
				if want == 503 {
					body = "{\"error\":\"unavailable\"}\n"
					if path == "/readyz" {
						body = "{\"ready\":false}\n"
					}
				}
				if w.Code != want || w.Body.String() != body || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Set-Cookie") != "" {
					t.Fatalf("unsafe probe response status%d", w.Code)
				}
				wantChecks := int32(0)
				if path == "/readyz" && (behavior == "normal" || behavior == "drain") {
					wantChecks = 1
				}
				if checks.Load() != wantChecks || r.URL.Path != path || len(r.Header["authorization"]) != 1 {
					t.Fatal("owner was bypassed/repeated or caller request mutated")
				}
			})
		}
	}
}

func TestProbeBindingPreservesIndependentSnapshotsAndInputRejection(t *testing.T) {
	var calls, hooks atomic.Int32
	live, ready := probes(t, func() identityhttp.ServerState { return identityhttp.ServerRunning }, func(context.Context) (identityhttp.ReadinessSnapshot, error) {
		return identityhttp.ReadinessSnapshot{Ready: calls.Add(1) == 1}, nil
	}, time.Second)
	hook := probeHook(identityhttp.MiddlewareAfterAuth, func(w http.ResponseWriter, r *http.Request, next http.Handler) { hooks.Add(1); next.ServeHTTP(w, r) })
	bound, err := identityhttp.WithOperationMiddleware(ready, []identityhttp.MiddlewareDescriptor{hook})
	if err != nil {
		t.Fatal(err)
	}
	assertProbe(t, bound, "GET", "/readyz", 200, "{\"ready\":true}\n")
	assertProbe(t, bound, "GET", "/readyz", 503, "{\"ready\":false}\n")
	for _, tc := range []struct {
		method, path string
		status       int
		body         string
	}{
		{"GET", "/readyz?", 400, "{\"error\":\"invalid_request\"}\n"},
		{"GET", "/readyz/", 404, "{\"error\":\"not_found\"}\n"},
		{"HEAD", "/readyz", 405, ""},
	} {
		assertProbe(t, bound, tc.method, tc.path, tc.status, tc.body)
	}
	if calls.Load() != 2 || hooks.Load() != 2 {
		t.Fatal("malformed request reached hooks or readiness")
	}
	if h, err := identityhttp.WithOperationMiddleware(bound, []identityhttp.MiddlewareDescriptor{hook}); err == nil || h != nil {
		t.Fatal("duplicate binding accepted")
	}
	var other atomic.Int32
	second, err := identityhttp.WithOperationMiddleware(ready, []identityhttp.MiddlewareDescriptor{probeHook(identityhttp.MiddlewareAfterAuth, func(w http.ResponseWriter, r *http.Request, next http.Handler) { other.Add(1); next.ServeHTTP(w, r) })})
	if err != nil {
		t.Fatal(err)
	}
	assertProbe(t, second, "GET", "/readyz", 503, "{\"ready\":false}\n")
	assertProbe(t, live, "GET", "/healthz", 200, "{\"status\":\"alive\"}\n")
	if hooks.Load() != 2 || other.Load() != 1 {
		t.Fatal("independent binding changed original owner")
	}
	// Valid legacy nanosecond readiness budgets still construct when bound.
	_, tiny := probes(t, func() identityhttp.ServerState { return identityhttp.ServerRunning }, func(context.Context) (identityhttp.ReadinessSnapshot, error) {
		return identityhttp.ReadinessSnapshot{}, nil
	}, time.Nanosecond)
	if _, err := identityhttp.WithOperationMiddleware(tiny, []identityhttp.MiddlewareDescriptor{hook}); err != nil {
		t.Fatal("narrowed legacy timeout bounds", err)
	}
}

func TestProbeBindingConcurrentRequestsRemainIndependent(t *testing.T) {
	var checks atomic.Int32
	_, ready := probes(t, func() identityhttp.ServerState { return identityhttp.ServerRunning }, func(context.Context) (identityhttp.ReadinessSnapshot, error) {
		checks.Add(1)
		return identityhttp.ReadinessSnapshot{Ready: true}, nil
	}, time.Second)
	h, err := identityhttp.WithOperationMiddleware(ready, []identityhttp.MiddlewareDescriptor{probeHook(identityhttp.MiddlewareBeforeHandler, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		next.ServeHTTP(w, r)
		next.ServeHTTP(w, r)
	})})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() { defer wg.Done(); assertProbe(t, h, "GET", "/readyz", 200, "{\"ready\":true}\n") }()
	}
	wg.Wait()
	if checks.Load() != 16 {
		t.Fatal("requests shared or repeated readiness")
	}
}

func TestProbeBindingComposesRealPublicPhases(t *testing.T) {
	var checks atomic.Int32
	feature, err := identityhttp.NewProbeFeature(identityhttp.ProbeConfig{State: func() identityhttp.ServerState { return identityhttp.ServerRunning }, Timeout: time.Second, Readiness: identityhttp.ReadinessProvider{Check: func(context.Context) (identityhttp.ReadinessSnapshot, error) {
		checks.Add(1)
		return identityhttp.ReadinessSnapshot{Ready: true}, nil
	}}})
	if err != nil {
		t.Fatal(err)
	}
	ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	var trace []identityhttp.MiddlewarePhase
	var hooks []identityhttp.MiddlewareDescriptor
	for _, phase := range []identityhttp.MiddlewarePhase{identityhttp.MiddlewareBeforeAuth, identityhttp.MiddlewareAfterAuth, identityhttp.MiddlewareBeforeHandler, identityhttp.MiddlewareAfterHandler} {
		hooks = append(hooks, identityhttp.MiddlewareDescriptor{Owner: "probe-observer", Middleware: identityhttp.Middleware{Name: "observe", Phase: phase, Order: uint32(phase), Handler: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				trace = append(trace, phase)
				if _, ok := identityhttp.PipelineValue[int](r); ok {
					t.Error("public probe invented authentication")
				}
				next.ServeHTTP(w, r)
				next.ServeHTTP(w, r)
			})
		}}})
	}
	// Names identify wrappers across phases, independently of order.
	for i := range hooks {
		hooks[i].Middleware.Name += string(rune('a' + i))
	}
	h, doc, err := identityhttp.NewRouter(routerPolicy(), ops, hooks)
	if err != nil {
		t.Fatalf("owned probes cannot compose global middleware: %v", err)
	}
	if checks.Load() != 0 || len(doc.Operations()) != 2 {
		t.Fatal("construction performed checks or changed selection")
	}
	for _, path := range []string{"/healthz", "/readyz"} {
		trace = nil
		w := httptest.NewRecorder()
		h.ServeHTTP(w, corsRequest("GET", path, ""))
		if w.Code != 200 || !reflect.DeepEqual(trace, []identityhttp.MiddlewarePhase{1, 2, 3, 4}) {
			t.Fatalf("public phases lost: %v status%d", trace, w.Code)
		}
	}
	if checks.Load() != 1 {
		t.Fatal("reentry repeated readiness or liveness consulted dependencies")
	}
}
