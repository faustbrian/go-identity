package identityhttp_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
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

type pipelineSubject struct{ User string }

func TestOperationPipelineOwnsActualAuthenticationBoundary(t *testing.T) {
	var trace []string
	config := identityhttp.OperationPipelineConfig[pipelineSubject]{
		MaximumDuration: time.Second,
		Decode: func(r *http.Request) (pipelineSubject, error) {
			body, err := io.ReadAll(r.Body)
			if err != nil || string(body) != "original" {
				t.Fatal("body custody")
			}
			trace = append(trace, "decode")
			return pipelineSubject{}, nil
		},
		Authenticate: func(r *http.Request, state pipelineSubject) (pipelineSubject, error) {
			if r.Header.Get("Authorization") != "original" || r.Host != "tenant.example" {
				t.Fatal("middleware changed authority input")
			}
			trace = append(trace, "authenticate")
			return pipelineSubject{User: "owner-produced"}, nil
		},
		Admit: func(_ *http.Request, state pipelineSubject) error {
			if state.User != "owner-produced" {
				t.Fatal("lost typed owner state")
			}
			trace = append(trace, "admit")
			return nil
		},
		Handle: func(w http.ResponseWriter, _ *http.Request, state pipelineSubject) {
			trace = append(trace, "handle")
			w.Header().Set("X-Owner", state.User)
			w.WriteHeader(204)
		},
		Reject: func(w http.ResponseWriter, _ *http.Request, err error) {
			t.Error("unexpected rejection", err)
			w.WriteHeader(503)
		},
	}
	for i, phase := range []identityhttp.MiddlewarePhase{identityhttp.MiddlewareBeforeAuth, identityhttp.MiddlewareAfterAuth, identityhttp.MiddlewareBeforeHandler, identityhttp.MiddlewareAfterHandler} {
		name := []string{"before-auth", "after-auth", "before-handler", "after-handler"}[i]
		config.Middleware = append(config.Middleware, identityhttp.MiddlewareDescriptor{Owner: "extension", Middleware: identityhttp.Middleware{Name: name, Phase: phase, Order: 1, Handler: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				trace = append(trace, name)
				value, ok := identityhttp.PipelineValue[pipelineSubject](r)
				if (phase == identityhttp.MiddlewareBeforeAuth && ok) || (phase != identityhttp.MiddlewareBeforeAuth && (!ok || value.User != "owner-produced")) {
					t.Error("false authentication phase")
				}
				r.Header.Set("Authorization", "forged")
				r.Host = "attacker.example"
				if data, _ := io.ReadAll(r.Body); len(data) != 0 {
					t.Error("middleware acquired body")
				}
				if phase == identityhttp.MiddlewareAfterHandler {
					w.Header().Set("X-Owner", "forged")
					if _, err := w.Write([]byte("forged")); err == nil {
						t.Error("after-handler writes accepted")
					}
				}
				next.ServeHTTP(w, r)
				next.ServeHTTP(w, r) // Re-entry must not repeat authentication or mutation.
			})
		}}})
	}
	h, err := identityhttp.NewOperationPipeline(config)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "https://tenant.example/operation", strings.NewReader("original"))
	r.Header.Set("Authorization", "original")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	want := []string{"decode", "before-auth", "authenticate", "after-auth", "admit", "before-handler", "handle", "after-handler"}
	if !reflect.DeepEqual(trace, want) || w.Code != 204 || w.Header().Get("X-Owner") != "owner-produced" || w.Body.Len() != 0 {
		t.Fatalf("incorrect pipeline: %v %d", trace, w.Code)
	}
	if r.Host != "tenant.example" || r.Header.Get("Authorization") != "original" {
		t.Fatal("borrowed request mutated")
	}
	if _, ok := identityhttp.PipelineValue[pipelineSubject](r); ok {
		t.Fatal("state escaped request")
	}
}

func TestOperationPipelineDenialStopsLaterStages(t *testing.T) {
	for _, stop := range []string{"decode", "authenticate", "admit", "cancel", "short-circuit", "panic"} {
		t.Run(stop, func(t *testing.T) {
			denied := errors.New("private diagnostic")
			var trace []string
			stage := func(name string) error {
				trace = append(trace, name)
				if stop == name {
					return denied
				}
				if stop == "panic" && name == "authenticate" {
					panic(denied)
				}
				return nil
			}
			config := identityhttp.OperationPipelineConfig[int]{MaximumDuration: time.Second,
				Decode:       func(*http.Request) (int, error) { return 0, stage("decode") },
				Authenticate: func(_ *http.Request, value int) (int, error) { return value, stage("authenticate") },
				Admit:        func(*http.Request, int) error { return stage("admit") },
				Handle: func(w http.ResponseWriter, _ *http.Request, _ int) {
					trace = append(trace, "handle")
					w.WriteHeader(204)
				},
				Reject: func(w http.ResponseWriter, _ *http.Request, _ error) { w.WriteHeader(503) },
			}
			if stop == "short-circuit" {
				config.Middleware = []identityhttp.MiddlewareDescriptor{{Owner: "extension", Middleware: identityhttp.Middleware{Name: "deny", Phase: identityhttp.MiddlewareAfterAuth, Order: 1, Handler: func(http.Handler) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(403) })
				}}}}
			}
			h, err := identityhttp.NewOperationPipeline(config)
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest("POST", "https://tenant.example/operation", nil)
			if stop == "cancel" {
				ctx, cancel := context.WithCancel(r.Context())
				cancel()
				r = r.WithContext(ctx)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code == 204 || strings.Contains(strings.Join(trace, ","), "handle") || strings.Contains(w.Body.String(), "private") {
				t.Fatalf("denial continued: %v %d", trace, w.Code)
			}
		})
	}
}

func simplePipeline() identityhttp.OperationPipelineConfig[int] {
	return identityhttp.OperationPipelineConfig[int]{MaximumDuration: time.Second,
		Decode:       func(*http.Request) (int, error) { return 7, nil },
		Authenticate: func(_ *http.Request, value int) (int, error) { return value, nil },
		Admit:        func(*http.Request, int) error { return nil },
		Handle:       func(w http.ResponseWriter, _ *http.Request, _ int) { w.WriteHeader(204) },
		Reject:       func(w http.ResponseWriter, _ *http.Request, _ error) { w.WriteHeader(503) },
	}
}

func TestOperationPipelineConstructorRejectsBeforeCallingWrappers(t *testing.T) {
	var constructions int
	wrapper := identityhttp.MiddlewareDescriptor{Owner: "extension", Middleware: identityhttp.Middleware{Name: "trace", Phase: identityhttp.MiddlewareAfterAuth, Order: 1, Handler: func(next http.Handler) http.Handler { constructions++; return next }}}
	for _, change := range []func(*identityhttp.OperationPipelineConfig[int]){
		func(c *identityhttp.OperationPipelineConfig[int]) { c.MaximumDuration = 0 },
		func(c *identityhttp.OperationPipelineConfig[int]) { c.Decode = nil },
		func(c *identityhttp.OperationPipelineConfig[int]) { c.Authenticate = nil },
		func(c *identityhttp.OperationPipelineConfig[int]) { c.Admit = nil },
		func(c *identityhttp.OperationPipelineConfig[int]) { c.Handle = nil },
		func(c *identityhttp.OperationPipelineConfig[int]) { c.Reject = nil },
		func(c *identityhttp.OperationPipelineConfig[int]) {
			c.Middleware = append(c.Middleware, c.Middleware[0])
		},
		func(c *identityhttp.OperationPipelineConfig[int]) { c.Middleware[0].Owner = "invalid owner" },
		func(c *identityhttp.OperationPipelineConfig[int]) { c.Middleware[0].Middleware.Phase = 0 },
		func(c *identityhttp.OperationPipelineConfig[int]) { c.Middleware[0].Middleware.Order = 0 },
		func(c *identityhttp.OperationPipelineConfig[int]) { c.Middleware[0].Middleware.Handler = nil },
	} {
		c := simplePipeline()
		c.Middleware = []identityhttp.MiddlewareDescriptor{wrapper}
		change(&c)
		if h, err := identityhttp.NewOperationPipeline(c); err == nil || h != nil {
			t.Fatal("unsafe partial construction")
		}
	}
	if constructions != 0 {
		t.Fatal("wrapper called before complete validation")
	}
	for _, factory := range []identityhttp.MiddlewareFunc{func(http.Handler) http.Handler { return nil }, func(http.Handler) http.Handler { return http.HandlerFunc(nil) }, func(http.Handler) http.Handler { panic("private") }} {
		c := simplePipeline()
		wrapper.Middleware.Handler = factory
		c.Middleware = []identityhttp.MiddlewareDescriptor{wrapper}
		if h, err := identityhttp.NewOperationPipeline(c); err == nil || h != nil {
			t.Fatal("invalid wrapper published")
		}
	}
}

func TestOperationPipelineOrderingSnapshotAndContextLifetime(t *testing.T) {
	var trace []string
	var retained *http.Request
	c := simplePipeline()
	for _, order := range []uint32{3, 1, 2} {
		name := string(rune('0' + order))
		c.Middleware = append(c.Middleware, identityhttp.MiddlewareDescriptor{Owner: "extension", Middleware: identityhttp.Middleware{Name: name, Phase: identityhttp.MiddlewareAfterAuth, Order: order, Handler: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				trace = append(trace, name+"+")
				retained = r
				next.ServeHTTP(w, r)
				trace = append(trace, name+"-")
			})
		}}})
	}
	h, err := identityhttp.NewOperationPipeline(c)
	if err != nil {
		t.Fatal(err)
	}
	c.Middleware[0].Middleware.Handler = func(http.Handler) http.Handler { panic("mutated constructor") }
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if !reflect.DeepEqual(trace, []string{"1+", "2+", "3+", "3-", "2-", "1-"}) || w.Code != 204 {
		t.Fatal("phase ordering/snapshot", trace)
	}
	if _, ok := identityhttp.PipelineValue[int](retained); ok {
		t.Fatal("retained middleware context still exposes state")
	}
	if _, ok := identityhttp.PipelineValue[string](retained); ok {
		t.Fatal("wrong typed context accepted")
	}
}

func TestOperationPipelineDeadlineAndConcurrentIsolation(t *testing.T) {
	c := simplePipeline()
	var calls atomic.Int32
	c.Authenticate = func(r *http.Request, value int) (int, error) {
		if deadline, ok := r.Context().Deadline(); !ok || time.Until(deadline) > time.Second {
			t.Error("unbounded stage")
		}
		calls.Add(1)
		return value, nil
	}
	h, err := identityhttp.NewOperationPipeline(c)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
			if w.Code != 204 {
				t.Error("concurrent state lost")
			}
		})
	}
	wg.Wait()
	if calls.Load() != 32 {
		t.Fatal("duplicate or missing authentication")
	}
	c = simplePipeline()
	c.MaximumDuration = time.Millisecond
	c.Authenticate = func(r *http.Request, value int) (int, error) { <-r.Context().Done(); return value, r.Context().Err() }
	c.Reject = func(w http.ResponseWriter, _ *http.Request, err error) {
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Error("deadline identity lost")
		}
		w.WriteHeader(503)
	}
	h, err = identityhttp.NewOperationPipeline(c)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 503 {
		t.Fatal("deadline admitted")
	}
}

func TestOperationPipelineMiddlewareCannotChangeTLSInputs(t *testing.T) {
	c := simplePipeline()
	c.Authenticate = func(r *http.Request, value int) (int, error) {
		if r.TLS == nil || r.TLS.ServerName != "original.example" {
			t.Error("middleware changed TLS authority")
		}
		return value, nil
	}
	c.Middleware = []identityhttp.MiddlewareDescriptor{{Owner: "extension", Middleware: identityhttp.Middleware{Name: "tls", Phase: identityhttp.MiddlewareBeforeAuth, Order: 1, Handler: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS != nil {
				r.TLS.ServerName = "forged.example"
			}
			next.ServeHTTP(w, r)
			if _, ok := identityhttp.PipelineValue[int](r); ok {
				t.Error("before-auth wrapper gained post-auth state on unwind")
			}
		})
	}}}}
	h, err := identityhttp.NewOperationPipeline(c)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "https://tenant.example/", nil)
	r.TLS = &tls.ConnectionState{ServerName: "original.example"}
	h.ServeHTTP(httptest.NewRecorder(), r)
	if r.TLS.ServerName != "original.example" {
		t.Fatal("original TLS mutated")
	}
}

func TestOperationPipelineCommittedPanicAbortsNetworkResponse(t *testing.T) {
	c := simplePipeline()
	var observed atomic.Bool
	c.Handle = func(w http.ResponseWriter, _ *http.Request, _ int) {
		io.WriteString(w, "partial")
		w.(http.Flusher).Flush()
		panic("private diagnostic")
	}
	c.Reject = func(w http.ResponseWriter, _ *http.Request, _ error) {
		t.Error("committed response overwritten")
		w.WriteHeader(503)
	}
	c.Middleware = []identityhttp.MiddlewareDescriptor{{Owner: "extension", Middleware: identityhttp.Middleware{Name: "observe", Phase: identityhttp.MiddlewareAfterHandler, Order: 1, Handler: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { observed.Store(true); next.ServeHTTP(w, r) })
	}}}}
	h, err := identityhttp.NewOperationPipeline(c)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(h)
	defer server.Close()
	client := server.Client()
	client.Timeout = time.Second
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err == nil || string(body) != "partial" || observed.Load() {
		t.Fatalf("incomplete response looked successful: %q %v", body, err)
	}
}

func TestOperationPipelineCancellationDuringHandleStopsObservation(t *testing.T) {
	c := simplePipeline()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var observations, rejections int
	c.Handle = func(w http.ResponseWriter, _ *http.Request, _ int) { w.WriteHeader(204); cancel() }
	c.Reject = func(http.ResponseWriter, *http.Request, error) { rejections++ }
	c.Middleware = []identityhttp.MiddlewareDescriptor{{Owner: "extension", Middleware: identityhttp.Middleware{Name: "observe", Phase: identityhttp.MiddlewareAfterHandler, Order: 1, Handler: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { observations++; next.ServeHTTP(w, r) })
	}}}}
	h, err := identityhttp.NewOperationPipeline(c)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil).WithContext(ctx))
	if observations != 0 || rejections != 0 || w.Code != 204 {
		t.Fatalf("canceled operation invoked response/observation work: %d %d", observations, rejections)
	}
}
