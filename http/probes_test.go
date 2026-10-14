package identityhttp_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
)

// HP-01/02/05: public responses project status, never callback diagnostics.
func TestProbeResults(t *testing.T) {
	var calls atomic.Int32
	for _, tc := range []struct {
		name     string
		snapshot identityhttp.ReadinessSnapshot
		err      error
		status   int
	}{
		{"ready", identityhttp.ReadinessSnapshot{Ready: true}, nil, 200},
		{"dependency", identityhttp.ReadinessSnapshot{Codes: []identityhttp.ReadinessCode{"dependency"}}, nil, 503},
		{"migration", identityhttp.ReadinessSnapshot{Codes: []identityhttp.ReadinessCode{"migration"}}, nil, 503},
		{"key", identityhttp.ReadinessSnapshot{Codes: []identityhttp.ReadinessCode{"key"}}, nil, 503},
		{"worker", identityhttp.ReadinessSnapshot{Codes: []identityhttp.ReadinessCode{"worker"}}, nil, 503},
		{"error", identityhttp.ReadinessSnapshot{Ready: true}, errors.New("private provider diagnostic"), 503},
		{"invalid affirmative", identityhttp.ReadinessSnapshot{Ready: true, Codes: []identityhttp.ReadinessCode{"blocked"}}, nil, 503},
		{"zero snapshot", identityhttp.ReadinessSnapshot{}, nil, 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			live, ready, err := identityhttp.NewProbeHandlers(identityhttp.ProbeConfig{
				State: func() identityhttp.ServerState { return identityhttp.ServerRunning }, Timeout: time.Second,
				Readiness: identityhttp.ReadinessProvider{Check: func(context.Context) (identityhttp.ReadinessSnapshot, error) {
					calls.Add(1)
					return tc.snapshot, tc.err
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			before := calls.Load()
			assertProbe(t, live, http.MethodGet, "/healthz", 200, "{\"status\":\"alive\"}\n")
			if calls.Load() != before {
				t.Fatal("liveness consulted dependencies")
			}
			body := "{\"ready\":false}\n"
			if tc.status == 200 {
				body = "{\"ready\":true}\n"
			}
			assertProbe(t, ready, http.MethodGet, "/readyz", tc.status, body)
			if calls.Load() != before+1 {
				t.Fatal("missing or duplicate readiness check")
			}
		})
	}
}

func assertProbe(t *testing.T, handler http.Handler, method, path string, status int, body string) {
	t.Helper()
	r := httptest.NewRequest(method, path, nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != status || w.Body.String() != body {
		t.Fatalf("%s %s: status=%d body=%q, want %d %q", method, path, w.Code, w.Body.String(), status, body)
	}
	if w.Header().Get("Content-Type") != "application/json" || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" || len(w.Header().Values("Set-Cookie")) != 0 {
		t.Fatalf("unsafe probe headers: %v", w.Header())
	}
}

func probes(t *testing.T, state identityhttp.ServerStateFunc, check identityhttp.ReadinessCheckFunc, timeout time.Duration) (http.Handler, http.Handler) {
	t.Helper()
	live, ready, err := identityhttp.NewProbeHandlers(identityhttp.ProbeConfig{State: state, Readiness: identityhttp.ReadinessProvider{Check: check}, Timeout: timeout})
	if err != nil {
		t.Fatal(err)
	}
	return live, ready
}

// HP-04/05: no implicit HEAD, mux aliases or credentials in request values.
func TestProbeRoutes(t *testing.T) {
	var calls atomic.Int32
	live, ready := probes(t, func() identityhttp.ServerState { return identityhttp.ServerRunning }, func(context.Context) (identityhttp.ReadinessSnapshot, error) {
		calls.Add(1)
		return identityhttp.ReadinessSnapshot{Ready: true}, nil
	}, time.Second)
	for _, pair := range []struct {
		handler http.Handler
		path    string
	}{{live, "/healthz"}, {ready, "/readyz"}} {
		for _, method := range []string{http.MethodHead, http.MethodPost, http.MethodOptions, http.MethodPut, http.MethodDelete} {
			w := httptest.NewRecorder()
			pair.handler.ServeHTTP(w, httptest.NewRequest(method, pair.path, nil))
			want := "{\"error\":\"method_not_allowed\"}\n"
			if method == http.MethodHead {
				want = ""
			}
			if w.Code != 405 || w.Body.String() != want || w.Header().Get("Allow") != "GET" {
				t.Fatalf("method %s: %d %q", method, w.Code, w.Body.String())
			}
		}
		for _, path := range []string{pair.path + "/", "/v1" + pair.path, strings.ToUpper(pair.path), "/" + "%" + "68" + pair.path[2:], "/x/.." + pair.path, "/other", pair.path + "%2f"} {
			assertProbe(t, pair.handler, "GET", path, 404, "{\"error\":\"not_found\"}\n")
		}
		for _, path := range []string{pair.path + "?", pair.path + "?tenant=private"} {
			assertProbe(t, pair.handler, "GET", path, 400, "{\"error\":\"invalid_request\"}\n")
		}
		for _, alter := range []func(*http.Request){
			func(r *http.Request) { r.Header.Add("Idempotency-Key", "opaque") },
			func(r *http.Request) { r.ContentLength = 1 },
			func(r *http.Request) { r.ContentLength = -1; r.TransferEncoding = []string{"chunked"} },
			func(r *http.Request) { r.Trailer = http.Header{"X-Trailer": []string{"opaque"}} },
			func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader("private")) },
		} {
			r := httptest.NewRequest("GET", pair.path, nil)
			alter(r)
			w := httptest.NewRecorder()
			pair.handler.ServeHTTP(w, r)
			if w.Code != 400 || w.Body.String() != "{\"error\":\"invalid_request\"}\n" {
				t.Fatal("accepted nonempty request")
			}
		}
	}
	if calls.Load() != 0 {
		t.Fatal("rejected input invoked readiness")
	}
}

// HP-03/07: lifecycle is checked both before and after composed work.
func TestProbeLifecycle(t *testing.T) {
	var state atomic.Uint32
	var calls atomic.Int32
	live, ready := probes(t, func() identityhttp.ServerState { return identityhttp.ServerState(state.Load()) }, func(context.Context) (identityhttp.ReadinessSnapshot, error) {
		calls.Add(1)
		return identityhttp.ReadinessSnapshot{Ready: true}, nil
	}, time.Second)
	for _, s := range []identityhttp.ServerState{0, identityhttp.ServerNew, identityhttp.ServerStarting, identityhttp.ServerDraining, identityhttp.ServerStopped, 255} {
		state.Store(uint32(s))
		assertProbe(t, ready, "GET", "/readyz", 503, "{\"ready\":false}\n")
		assertProbe(t, live, "GET", "/healthz", 200, "{\"status\":\"alive\"}\n")
	}
	if calls.Load() != 0 {
		t.Fatal("checked prerequisites outside running state")
	}
	state.Store(uint32(identityhttp.ServerRunning))
	assertProbe(t, ready, "GET", "/readyz", 200, "{\"ready\":true}\n")
	_, late := probes(t, func() identityhttp.ServerState { return identityhttp.ServerState(state.Load()) }, func(context.Context) (identityhttp.ReadinessSnapshot, error) {
		state.Store(uint32(identityhttp.ServerDraining))
		return identityhttp.ReadinessSnapshot{Ready: true}, nil
	}, time.Second)
	assertProbe(t, late, "GET", "/readyz", 503, "{\"ready\":false}\n")
}

// HP-06: cooperative work stays synchronous and cannot revive an expired check.
func TestProbeDeadline(t *testing.T) {
	for _, early := range []bool{false, true} {
		parent := context.Background()
		cancel := func() {}
		if early {
			parent, cancel = context.WithTimeout(parent, 20*time.Millisecond)
		}
		var exited atomic.Bool
		start := time.Now()
		_, ready := probes(t, func() identityhttp.ServerState { return identityhttp.ServerRunning }, func(ctx context.Context) (identityhttp.ReadinessSnapshot, error) {
			d, ok := ctx.Deadline()
			if !ok || d.After(start.Add(120*time.Millisecond)) {
				t.Error("missing probe bound")
			}
			if pd, ok := parent.Deadline(); ok && d.After(pd) {
				t.Error("extended parent deadline")
			}
			<-ctx.Done()
			exited.Store(true)
			return identityhttp.ReadinessSnapshot{Ready: true}, nil
		}, 100*time.Millisecond)
		r := httptest.NewRequest("GET", "/readyz", nil).WithContext(parent)
		w := httptest.NewRecorder()
		ready.ServeHTTP(w, r)
		cancel()
		if w.Code != 503 || !exited.Load() || time.Since(start) > time.Second {
			t.Fatal("expired or detached check admitted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, ready := probes(t, func() identityhttp.ServerState { return identityhttp.ServerRunning }, func(context.Context) (identityhttp.ReadinessSnapshot, error) {
		t.Fatal("checked dependencies after cancellation")
		return identityhttp.ReadinessSnapshot{}, nil
	}, time.Second)
	w := httptest.NewRecorder()
	ready.ServeHTTP(w, httptest.NewRequest("GET", "/readyz", nil).WithContext(ctx))
	if w.Code != 503 {
		t.Fatal("cancelled request admitted")
	}
}

func TestProbeCancellationDuringFinalStateObservation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var observations int
	_, ready := probes(t, func() identityhttp.ServerState {
		observations++
		if observations == 2 {
			cancel()
		}
		return identityhttp.ServerRunning
	}, func(context.Context) (identityhttp.ReadinessSnapshot, error) {
		return identityhttp.ReadinessSnapshot{Ready: true}, nil
	}, time.Second)
	w := httptest.NewRecorder()
	ready.ServeHTTP(w, httptest.NewRequest("GET", "/readyz", nil).WithContext(ctx))
	if w.Code != 503 {
		t.Fatal("readiness succeeded after final observation cancelled the request")
	}
}

// HP-08: configuration is explicit; construction never checks live services.
func TestProbeConstruction(t *testing.T) {
	c := identityhttp.ProbeConfig{State: func() identityhttp.ServerState { t.Fatal("construction called state"); return 0 },
		Readiness: identityhttp.ReadinessProvider{Check: func(context.Context) (identityhttp.ReadinessSnapshot, error) {
			t.Fatal("construction called readiness")
			return identityhttp.ReadinessSnapshot{}, nil
		}}, Timeout: time.Second}
	for _, alter := range []func(*identityhttp.ProbeConfig){
		func(c *identityhttp.ProbeConfig) { c.State = nil }, func(c *identityhttp.ProbeConfig) { c.Readiness.Check = nil },
		func(c *identityhttp.ProbeConfig) { c.Timeout = -1 }, func(c *identityhttp.ProbeConfig) { c.Timeout = 0 }, func(c *identityhttp.ProbeConfig) { c.Timeout = 2*time.Second + 1 },
	} {
		bad := c
		alter(&bad)
		live, ready, err := identityhttp.NewProbeHandlers(bad)
		if !errors.Is(err, identityhttp.ErrInvalidInput) || live != nil || ready != nil {
			t.Fatal("invalid construction succeeded")
		}
	}
	for _, d := range []time.Duration{1, 2 * time.Second} {
		c.Timeout = d
		if _, _, err := identityhttp.NewProbeHandlers(c); err != nil {
			t.Fatal(err)
		}
	}
}

// HP-03/07: actual listener drain does not wait on a readiness-owned lock.
func TestProbeNetworkDrain(t *testing.T) {
	mux := http.NewServeMux()
	s, err := identityhttp.NewHTTPServer(config(), mux)
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	live, ready := probes(t, s.State, func(ctx context.Context) (identityhttp.ReadinessSnapshot, error) {
		if s.State() != identityhttp.ServerRunning {
			t.Error("callback starts outside running state")
		}
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
		}
		return identityhttp.ReadinessSnapshot{Ready: true}, nil
	}, time.Second)
	mux.Handle("/healthz", live)
	mux.Handle("/readyz", ready)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serving := make(chan error, 1)
	go func() { serving <- s.Serve(context.Background(), ln) }()
	defer func() {
		once.Do(func() { close(release) })
		s.Shutdown(context.Background())
		if err := wait(t, serving); err != nil {
			t.Error(err)
		}
	}()
	<-s.Started()
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	defer client.CloseIdleConnections()
	result := make(chan error, 1)
	go func() {
		r, err := client.Get("http://" + s.Address() + "/readyz")
		if err == nil {
			defer r.Body.Close()
			body, e := io.ReadAll(r.Body)
			if e != nil {
				err = e
			} else if r.StatusCode != 503 || string(body) != "{\"ready\":false}\n" {
				err = errors.New("late readiness survived network drain")
			}
		}
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("probe never entered")
	}
	shutdown := make(chan error, 1)
	go func() { shutdown <- s.Shutdown(context.Background()) }()
	deadline := time.Now().Add(time.Second)
	for s.State() != identityhttp.ServerDraining && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if s.State() != identityhttp.ServerDraining {
		t.Fatal("callback blocked lifecycle transition")
	}
	once.Do(func() { close(release) })
	if err := wait(t, result); err != nil {
		t.Fatal(err)
	}
	if err := wait(t, shutdown); err != nil {
		t.Fatal(err)
	}
	assertProbe(t, ready, "GET", "/readyz", 503, "{\"ready\":false}\n")
}
