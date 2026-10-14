package identityhttp_test

import (
	"bytes"
	"context"
	"encoding/json"
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

func routerPolicy() identityhttp.TransportPolicy {
	return identityhttp.TransportPolicy{Network: networkConfig(), HandlerTimeout: time.Second,
		Document: identityhttp.DocumentConfig{Title: "Identity", Version: "1"}}
}

func TestRouterProtectsStreamingAndPanicResponses(t *testing.T) {
	for _, mode := range []string{"status", "flush", "read-from", "return", "panic", "encoded-panic", "committed-panic", "late-body-limit"} {
		t.Run(mode, func(t *testing.T) {
			op := routerOperation(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Cache-Control", "public")
				w.Header().Del("X-Content-Type-Options")
				w.Header().Set("Referrer-Policy", "unsafe-url")
				switch mode {
				case "status":
					w.WriteHeader(200)
				case "flush":
					w.(http.Flusher).Flush()
				case "read-from":
					read := false
					_, _ = w.(io.ReaderFrom).ReadFrom(corsReaderFunc(func(p []byte) (int, error) {
						if read {
							return 0, io.EOF
						}
						read = true
						w.Header().Set("Referrer-Policy", "unsafe-url")
						w.Header().Del("X-Content-Type-Options")
						return copy(p, "body"), nil
					}))
				case "panic":
					panic("private diagnostics")
				case "encoded-panic":
					w.Header().Set("Content-Encoding", "gzip")
					panic("private diagnostics")
				case "committed-panic":
					w.Write([]byte("partial"))
					panic("private diagnostics")
				case "late-body-limit":
					w.Write([]byte("partial"))
					_, _ = io.ReadAll(r.Body)
				}
			}))
			h, _, err := identityhttp.NewRouter(routerPolicy(), []identityhttp.OperationDescriptor{op}, nil)
			if err != nil {
				t.Fatal(err)
			}
			w := &corsReadFromRecorder{httptest.NewRecorder()}
			abort := mode == "committed-panic" || mode == "late-body-limit"
			func() {
				defer func() {
					if p := recover(); p != nil && (!abort || p != http.ErrAbortHandler) {
						t.Error("raw panic escaped")
					} else if abort && p == nil {
						t.Error("partial response completed")
					}
				}()
				r := corsRequest("GET", op.Route.Path, "")
				if mode == "late-body-limit" {
					r.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", int(routerPolicy().Network.Limits.MaximumBodyBytes)+1)))
					r.ContentLength = -1
				}
				h.ServeHTTP(w, r)
			}()
			res := w.Result()
			defer res.Body.Close()
			if res.Header.Get("X-Content-Type-Options") != "nosniff" || res.Header.Get("Referrer-Policy") != "no-referrer" || res.Header.Get("Cache-Control") != "no-store" {
				t.Fatal("streaming header bypass", res.Header)
			}
			if (mode == "panic" || mode == "encoded-panic") && (res.StatusCode != 503 || strings.Contains(w.Body.String(), "private") || res.Header.Get("Content-Encoding") != "") {
				t.Fatal("panic disclosure")
			}
		})
	}
}

func TestRouterMiddlewareExecutesOnlyRealPhases(t *testing.T) {
	var trace []string
	pipeline, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[int]{MaximumDuration: time.Second,
		Decode:       func(*http.Request) (int, error) { trace = append(trace, "decode"); return 0, nil },
		Authenticate: func(*http.Request, int) (int, error) { trace = append(trace, "auth"); return 42, nil },
		Admit: func(r *http.Request, _ int) error {
			if r.Host != "login.example" {
				t.Error("middleware rewrote owner host")
			}
			trace = append(trace, "admit")
			return nil
		},
		Handle: func(w http.ResponseWriter, _ *http.Request, _ int) {
			trace = append(trace, "handle")
			w.WriteHeader(200)
		},
		Reject: func(w http.ResponseWriter, _ *http.Request, _ error) { w.WriteHeader(503) },
	})
	if err != nil {
		t.Fatal(err)
	}
	var hooks []identityhttp.MiddlewareDescriptor
	for i, phase := range []identityhttp.MiddlewarePhase{identityhttp.MiddlewareBeforeAuth, identityhttp.MiddlewareAfterAuth, identityhttp.MiddlewareBeforeHandler, identityhttp.MiddlewareAfterHandler} {
		name := []string{"before-auth", "after-auth", "before-handler", "after-handler"}[i]
		hooks = append(hooks, identityhttp.MiddlewareDescriptor{Owner: "router", Middleware: identityhttp.Middleware{Name: name, Phase: phase, Order: 1, Handler: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				value, present := identityhttp.PipelineValue[int](r)
				if phase == identityhttp.MiddlewareBeforeAuth && present || phase != identityhttp.MiddlewareBeforeAuth && (!present || value != 42) {
					t.Error("fictitious auth boundary")
				}
				trace = append(trace, name)
				r.Host = "attacker.example"
				next.ServeHTTP(w, r)
			})
		}}})
	}
	op := routerOperation(t, pipeline)
	h, _, err := identityhttp.NewRouter(routerPolicy(), []identityhttp.OperationDescriptor{op}, hooks)
	if err != nil {
		t.Fatal(err)
	}
	hooks[0].Middleware.Handler = nil
	w := httptest.NewRecorder()
	h.ServeHTTP(w, corsRequest("GET", op.Route.Path, ""))
	want := []string{"decode", "before-auth", "auth", "after-auth", "admit", "before-handler", "handle", "after-handler"}
	if w.Code != 200 || !reflect.DeepEqual(trace, want) {
		t.Fatal("phase order", trace, w.Code)
	}
	for _, invalid := range [][]identityhttp.MiddlewareDescriptor{{{}}, {hooks[1], hooks[1]}} {
		if h, d, err := identityhttp.NewRouter(routerPolicy(), []identityhttp.OperationDescriptor{op}, invalid); err == nil || h != nil || len(d.JSON()) != 0 {
			t.Fatal("invalid hooks admitted")
		}
	}
	op.Handler = http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	if h, d, err := identityhttp.NewRouter(routerPolicy(), []identityhttp.OperationDescriptor{op}, hooks[1:]); err == nil || h != nil || len(d.JSON()) != 0 {
		t.Fatal("opaque handler received fictitious hooks")
	}
}

func routerOperation(t *testing.T, handle http.Handler) identityhttp.OperationDescriptor {
	t.Helper()
	op := extensionDescriptor(t, "router", "read")
	op.Handler = handle
	op.Wire = &identityhttp.WireOperation{Definition: []byte(`{"operationId":"` + op.Record.OperationID + `","security":[],"responses":{"200":{"description":"ok"}}}`)}
	return op
}

// Router QA: one frozen selection drives exact routing and concrete wire export.
func TestRouterSelectionAndTransportCustody(t *testing.T) {
	var calls atomic.Int32
	op := routerOperation(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if _, ok := r.Context().Deadline(); !ok {
			t.Error("unbounded request")
		}
		w.Header()["cache-control"] = []string{"public"}
		w.Header().Del("X-Content-Type-Options")
		w.Header().Set("Referrer-Policy", "unsafe-url")
		w.Write([]byte("owned"))
	}))
	policy := routerPolicy()
	ops := []identityhttp.OperationDescriptor{op}
	h, doc, err := identityhttp.NewRouter(policy, ops, nil)
	if err != nil {
		t.Fatal(err)
	}
	before := doc.JSON()
	policy.Network.PublicHosts[0] = "attacker.example"
	ops[0].Route.Path = "/replacement"
	ops[0].Wire.Definition[0] = '!'
	var parsed map[string]any
	if json.Unmarshal(doc.JSON(), &parsed) != nil || len(parsed["paths"].(map[string]any)) != 1 || parsed["paths"].(map[string]any)[op.Route.Path] == nil {
		t.Fatal("handler/document mismatch")
	}
	for _, path := range []string{op.Route.Path + "/", "/Extensions/router/read", "/extensions//router/read", "/extensions/router/../read", "/v1" + op.Route.Path, "/healthz", "/openapi.json"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, corsRequest("GET", path, ""))
		if w.Code != 404 {
			t.Fatalf("alias admitted %q: %d", path, w.Code)
		}
	}
	for _, method := range []string{"HEAD", "OPTIONS", "POST"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, corsRequest(method, op.Route.Path, ""))
		if w.Code != 405 || w.Header().Get("Allow") != "GET" || method == "HEAD" && w.Body.Len() != 0 {
			t.Fatal("implicit method or incorrect Allow")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("routing denial entered owner")
	}
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, corsRequest("GET", op.Route.Path, ""))
			if w.Code != 200 || w.Body.String() != "owned" || w.Result().Header.Get("Cache-Control") != "no-store" || w.Result().Header.Get("X-Content-Type-Options") != "nosniff" || w.Result().Header.Get("Referrer-Policy") != "no-referrer" {
				t.Error("lost transport custody", w.Code)
			}
			copy := doc.Operations()
			copy[0].Wire.Definition[0] = '!'
			if !bytes.Equal(before, doc.JSON()) {
				t.Error("mutable document")
			}
		})
	}
	wg.Wait()
	if calls.Load() != 12 {
		t.Fatal("wrong dispatch")
	}
}

func TestRouterRejectsBeforeOwnerAndDoesNotReadBody(t *testing.T) {
	calls := 0
	op := routerOperation(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	h, _, err := identityhttp.NewRouter(routerPolicy(), []identityhttp.OperationDescriptor{op}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*http.Request){
		"unknown host":            func(r *http.Request) { r.Host = "unknown.example" },
		"cleartext":               func(r *http.Request) { r.TLS = nil },
		"duplicate authorization": func(r *http.Request) { r.Header["Authorization"] = []string{"Bearer one", "Bearer two"} },
		"framing":                 func(r *http.Request) { r.ContentLength = 1; r.TransferEncoding = []string{"chunked"} },
		"large body":              func(r *http.Request) { r.ContentLength = int64(routerPolicy().Network.Limits.MaximumBodyBytes) + 1 },
		"large headers": func(r *http.Request) {
			r.Header.Set("X-Fill", strings.Repeat("a", int(routerPolicy().Network.Limits.MaximumHeaderBytes)))
		},
		"large URL": func(r *http.Request) {
			r.URL.RawQuery = strings.Repeat("a", int(routerPolicy().Network.Limits.MaximumURLBytes)+1)
		},
		"trusted malformed chain": func(r *http.Request) { r.RemoteAddr = "10.0.0.2:443"; r.Header.Set("Forwarded", "for=unknown") },
		"trusted missing chain": func(r *http.Request) { r.RemoteAddr = "10.0.0.2:443" },
		"trusted exhausted chain": func(r *http.Request) {
			r.RemoteAddr = "10.0.0.2:443"
			r.Header.Set("Forwarded", "for=10.0.0.3;host=login.example;proto=https")
		},
		"canceled": func(r *http.Request) {
			ctx, cancel := context.WithCancel(r.Context())
			cancel()
			*r = *r.WithContext(ctx)
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := corsRequest("GET", op.Route.Path, "")
			body := &countedBody{Reader: strings.NewReader("opaque")}
			r.Body = body
			mutate(r)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code < 400 || calls != 0 || body.reads != 0 || body.closes != 0 || w.Result().Header.Get("Cache-Control") != "no-store" {
				t.Fatal("unsafe request entered owner or consumed body")
			}
			if name == "unknown host" && w.Code != 421 {
				t.Fatal("unknown host must be misdirected", w.Code)
			}
			if strings.HasPrefix(name, "trusted ") && (w.Code != http.StatusServiceUnavailable || w.Body.String() != "{\"error\":\"unavailable\"}\n") {
				t.Fatal("proxy admission must retain unavailable classification", w.Code, w.Body.String())
			}
		})
	}
}

func TestRouterReadinessStaysWithCompositionOwner(t *testing.T) {
	state := identityhttp.ServerNew
	checks := 0
	f, err := identityhttp.NewProbeFeature(identityhttp.ProbeConfig{State: func() identityhttp.ServerState { return state }, Timeout: time.Second,
		Readiness: identityhttp.ReadinessProvider{Check: func(context.Context) (identityhttp.ReadinessSnapshot, error) {
			checks++
			return identityhttp.ReadinessSnapshot{Ready: true}, nil
		}}})
	if err != nil {
		t.Fatal(err)
	}
	ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{f}})
	if err != nil {
		t.Fatal(err)
	}
	h, doc, err := identityhttp.NewRouter(routerPolicy(), ops, nil)
	if err != nil {
		t.Fatal(err)
	}
	if checks != 0 || len(doc.Operations()) != 2 {
		t.Fatal("constructor performed readiness")
	}
	for _, tc := range []struct {
		state identityhttp.ServerState
		want  int
	}{{identityhttp.ServerNew, 503}, {identityhttp.ServerRunning, 200}, {identityhttp.ServerDraining, 503}} {
		state = tc.state
		w := httptest.NewRecorder()
		h.ServeHTTP(w, corsRequest("GET", "/readyz", ""))
		if w.Code != tc.want {
			t.Fatal("readiness detached from lifecycle")
		}
	}
	if checks != 1 {
		t.Fatal("unexpected readiness work")
	}
}

func TestRouterCORSBoundToSelectedRoutes(t *testing.T) {
	calls := 0
	op := routerOperation(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(200) }))
	p := routerPolicy()
	p.CORS = []identityhttp.CORSRoutePolicy{{Method: "GET", Path: op.Route.Path, Credentials: identityhttp.CORSBearerCredentials, Origins: []identityhttp.Origin{"https://client.example"}, AllowedHeaders: []string{"Authorization"}}}
	h, _, err := identityhttp.NewRouter(p, []identityhttp.OperationDescriptor{op}, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.CORS[0].Origins[0] = "https://attacker.example"
	r := corsRequest("OPTIONS", op.Route.Path, "https://client.example")
	r.Header.Set("Access-Control-Request-Method", "GET")
	r.Header.Set("Access-Control-Request-Headers", "Authorization")
	body := &countedBody{Reader: strings.NewReader("unread")}
	r.Body = body
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 204 || calls != 0 || body.reads != 0 || body.closes != 0 || w.Result().Header.Get("Access-Control-Allow-Origin") != "https://client.example" || w.Result().Header.Get("Access-Control-Allow-Credentials") != "" {
		t.Fatal("preflight crossed owner boundary")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, corsRequest("GET", op.Route.Path, "https://client.example"))
	if w.Code != 200 || calls != 1 {
		t.Fatal("allowed CORS request denied")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, corsRequest("GET", op.Route.Path, "https://attacker.example"))
	if w.Code != 403 || calls != 1 {
		t.Fatal("mutated/unknown origin admitted")
	}
	p.CORS[0].Path = "/disabled"
	if h, d, err := identityhttp.NewRouter(p, []identityhttp.OperationDescriptor{op}, nil); err == nil || h != nil || len(d.JSON()) != 0 {
		t.Fatal("CORS advertised disabled route")
	}
}

func TestRouterConstructorAtomicAndEmptySelection(t *testing.T) {
	op := routerOperation(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("constructor invoked request") }))
	for _, mutate := range []func(*identityhttp.TransportPolicy, *[]identityhttp.OperationDescriptor){
		func(p *identityhttp.TransportPolicy, _ *[]identityhttp.OperationDescriptor) {
			*p = identityhttp.TransportPolicy{}
		},
		func(p *identityhttp.TransportPolicy, _ *[]identityhttp.OperationDescriptor) { p.HandlerTimeout = 0 },
		func(p *identityhttp.TransportPolicy, _ *[]identityhttp.OperationDescriptor) { p.Document.Title = "" },
		func(_ *identityhttp.TransportPolicy, ops *[]identityhttp.OperationDescriptor) {
			*ops = append(*ops, (*ops)[0])
		},
		func(_ *identityhttp.TransportPolicy, ops *[]identityhttp.OperationDescriptor) {
			(*ops)[0].Handler = nil
		},
		func(_ *identityhttp.TransportPolicy, ops *[]identityhttp.OperationDescriptor) { (*ops)[0].Wire = nil },
		func(_ *identityhttp.TransportPolicy, ops *[]identityhttp.OperationDescriptor) {
			(*ops)[0].Record.RatePolicy = "rate.invented"
		},
	} {
		p := routerPolicy()
		ops := []identityhttp.OperationDescriptor{op}
		mutate(&p, &ops)
		if h, d, err := identityhttp.NewRouter(p, ops, nil); err == nil || h != nil || len(d.JSON()) != 0 {
			t.Fatal("invalid configuration returned partial result")
		}
	}
	h, d, err := identityhttp.NewRouter(routerPolicy(), nil, nil)
	if err != nil || len(d.Operations()) != 0 {
		t.Fatal("empty selection failed", err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, corsRequest("GET", "/healthz", ""))
	if w.Code != 404 || bytes.Contains(d.JSON(), []byte("healthz")) {
		t.Fatal("implicit probe")
	}
}

func TestRouterBodyAndDeadlineCustody(t *testing.T) {
	p := routerPolicy()
	p.HandlerTimeout = 25 * time.Millisecond
	var bodyRead []byte
	var bodyErr error
	op := routerOperation(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyRead, bodyErr = io.ReadAll(r.Body)
		w.WriteHeader(200)
	}))
	h, _, err := identityhttp.NewRouter(p, []identityhttp.OperationDescriptor{op}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := corsRequest("GET", op.Route.Path, "")
	body := &countedBody{Reader: strings.NewReader(strings.Repeat("x", int(p.Network.Limits.MaximumBodyBytes)+1))}
	r.Body = body
	r.ContentLength = -1
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 400 || bodyErr == nil || len(bodyRead) != int(p.Network.Limits.MaximumBodyBytes) || body.closes != 0 || r.Body != body {
		t.Fatal("unbounded or replaced caller body")
	}
	op.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	h, _, err = identityhttp.NewRouter(p, []identityhttp.OperationDescriptor{op}, nil)
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, corsRequest("GET", op.Route.Path, ""))
	if w.Code != 503 {
		t.Fatal("deadline silently returned success", w.Code)
	}
}
