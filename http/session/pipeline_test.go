package sessionhttp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/session"
)

func TestGetPipelineUsesOwnerIdentityAndOriginalInput(t *testing.T) {
	for _, transport := range []session.CredentialKind{session.CredentialCookie, session.CredentialBearer} {
		f := newFixture(t, transport)
		var phases []identityhttp.MiddlewarePhase
		var retained *http.Request
		var middleware []identityhttp.MiddlewareDescriptor
		for _, phase := range []identityhttp.MiddlewarePhase{identityhttp.MiddlewareBeforeAuth, identityhttp.MiddlewareAfterAuth, identityhttp.MiddlewareBeforeHandler, identityhttp.MiddlewareAfterHandler} {
			middleware = append(middleware, identityhttp.MiddlewareDescriptor{Owner: "identity/session", Middleware: identityhttp.Middleware{Name: "inspect", Phase: phase, Order: 1, Handler: func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					phases = append(phases, phase)
					state, ok := identityhttp.PipelineValue[sessionhttp.GetState](r)
					if phase == identityhttp.MiddlewareBeforeAuth {
						if ok || f.calls.Load() != 0 {
							t.Error("before-auth disclosed or acquired identity")
						}
					} else {
						principal, authenticated := state.Principal()
						if !ok || !authenticated || principal.TenantID != "tenant-a" || principal.UserID != "user-a" || f.calls.Load() != 1 {
							t.Error("middleware did not receive actual owner identity exactly once")
						}
						retained = r
						for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
							if diagnostic := fmt.Sprintf(verb, state); diagnostic != "sessionhttp.GetState(redacted)" {
								t.Error("state lacks explicit diagnostic redaction")
							}
						}
						if _, err := json.Marshal(state); err == nil {
							t.Error("state permitted implicit serialization")
						}
					}
					// Detached middleware metadata cannot substitute tenant or credential.
					r.Host = "attacker.example"
					r.Header.Set("Authorization", "Bearer replaced")
					r.Header.Set("Cookie", "__Host-identity_session=replaced")
					next.ServeHTTP(w, r)
				})
			}}})
		}
		// Names are owner-unique even across phases.
		for i := range middleware {
			middleware[i].Middleware.Name = string(rune('a' + i))
		}
		h, err := sessionhttp.NewGetHandlerWithMiddleware(f.config, middleware)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, request(f, true))
		if w.Code != 200 || f.calls.Load() != 1 || !reflect.DeepEqual(phases, []identityhttp.MiddlewarePhase{1, 2, 3, 4}) {
			t.Fatalf("status=%d owner reads=%d phases=%v", w.Code, f.calls.Load(), phases)
		}
		if _, ok := identityhttp.PipelineValue[sessionhttp.GetState](retained); ok {
			t.Fatal("identity remained attached after request")
		}
	}
}

func TestGetPipelineRechecksOriginalValidityAfterMiddleware(t *testing.T) {
	f := newFixture(t, session.CredentialCookie)
	now := f.config.Now()
	f.config.Now = func() time.Time { return now }
	h, err := sessionhttp.NewGetHandlerWithMiddleware(f.config, []identityhttp.MiddlewareDescriptor{{Owner: "identity/session", Middleware: identityhttp.Middleware{Name: "delay", Phase: identityhttp.MiddlewareBeforeHandler, Order: 1, Handler: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { now = now.Add(20 * time.Second); next.ServeHTTP(w, r) })
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(f, true))
	if w.Code != 503 || f.calls.Load() != 1 {
		t.Fatalf("expired original owner evidence was renewed or returned: status=%d reads=%d", w.Code, f.calls.Load())
	}
}

func TestGetPipelineDebitsOnceDespiteRepeatedNext(t *testing.T) {
	f := newFixture(t, session.CredentialBearer)
	h, err := sessionhttp.NewGetHandlerWithMiddleware(f.config, []identityhttp.MiddlewareDescriptor{{Owner: "identity/session", Middleware: identityhttp.Middleware{Name: "repeat", Phase: identityhttp.MiddlewareAfterAuth, Order: 1, Handler: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { next.ServeHTTP(w, r); next.ServeHTTP(w, r) })
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	// The real shared IP budget allows 100 reads, not 50 or 200. The independent
	// subject budget is 300. This observes admission behavior, not mock calls.
	for i := 0; i < 101; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, request(f, true))
		want := 200
		if i == 100 {
			want = 429
		}
		if w.Code != want || f.calls.Load() != int32(i+1) {
			t.Fatalf("read=%d status=%d owner reads=%d", i, w.Code, f.calls.Load())
		}
		if i == 100 && w.Header().Get("Retry-After") == "" {
			t.Fatal("rate denial lost retry metadata")
		}
	}
}

func TestGetPipelineShortCircuitAndDecodeDenialHaveNoLaterEffects(t *testing.T) {
	f := newFixture(t, session.CredentialCookie)
	var entered int
	h, err := sessionhttp.NewGetHandlerWithMiddleware(f.config, []identityhttp.MiddlewareDescriptor{{Owner: "identity/session", Middleware: identityhttp.Middleware{Name: "deny", Phase: identityhttp.MiddlewareBeforeAuth, Order: 1, Handler: func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			entered++
			w.Header()["cache-control"] = []string{"public, max-age=3600"}
			w.Header().Del("X-Content-Type-Options")
			w.Header()["content-type"] = []string{"text/html"}
			w.Header()["set-cookie"] = []string{"unexpected=value"}
			w.WriteHeader(403)
		})
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	r := request(f, true)
	r.Host = "unknown.example"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 421 || entered != 0 || f.calls.Load() != 0 {
		t.Fatal("decode denial ran hooks or owner")
	}
	for i := 0; i < 101; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, request(f, true))
		committed := w.Result()
		if w.Code != 403 || committed.Header.Get("Cache-Control") != "no-store" || committed.Header.Get("X-Content-Type-Options") != "nosniff" || committed.Header.Get("Content-Type") != "application/json" || len(committed.Header.Values("Set-Cookie")) != 0 || len(committed.Cookies()) != 0 {
			t.Fatal("short-circuit bypassed read response security policy")
		}
	}
	if f.calls.Load() != 0 {
		t.Fatal("short circuit authenticated")
	}
	// A subsequent unwrapped read still has its original shared rate budget.
	if w := serve(t, f, request(f, false)); w.Code != 200 {
		t.Fatal("short circuit debited rate")
	}
}

func TestGetPipelineUnauthenticatedStateAndConcurrentRequests(t *testing.T) {
	for _, present := range []bool{false, true} {
		f := newFixture(t, session.CredentialBearer)
		f.observation.Active = false
		h, err := sessionhttp.NewGetHandlerWithMiddleware(f.config, []identityhttp.MiddlewareDescriptor{{Owner: "identity/session", Middleware: identityhttp.Middleware{Name: "inspect", Phase: identityhttp.MiddlewareAfterAuth, Order: 1, Handler: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				state, ok := identityhttp.PipelineValue[sessionhttp.GetState](r)
				principal, authenticated := state.Principal()
				if !ok || authenticated || principal != (sessionhttp.Principal{}) {
					t.Error("unauthenticated request gained identity")
				}
				next.ServeHTTP(w, r)
			})
		}}}})
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Go(func() {
				w := httptest.NewRecorder()
				h.ServeHTTP(w, request(f, present))
				if w.Code != 200 || w.Body.String() != "{\"authenticated\":false,\"needsRefresh\":false}\n" {
					t.Error("concurrent inactive response changed")
				}
			})
		}
		wg.Wait()
		want := int32(0)
		if present {
			want = 16
		}
		if f.calls.Load() != want {
			t.Fatal("inactive authentication repeated or skipped")
		}
	}
}

func TestGetPipelineCancellationAndPanicBeforeHandler(t *testing.T) {
	for _, panics := range []bool{false, true} {
		f := newFixture(t, session.CredentialCookie)
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		h, err := sessionhttp.NewGetHandlerWithMiddleware(f.config, []identityhttp.MiddlewareDescriptor{{Owner: "identity/session", Middleware: identityhttp.Middleware{Name: "fail", Phase: identityhttp.MiddlewareBeforeHandler, Order: 1, Handler: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if panics {
					panic("private diagnostic")
				}
				cancel()
				next.ServeHTTP(w, r)
			})
		}}}})
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, request(f, true).WithContext(ctx))
		if w.Code != 503 || strings.Contains(w.Body.String(), "private") || strings.Contains(w.Body.String(), "user-a") {
			t.Fatal("failed hook returned identity or diagnostics")
		}
	}
}

type readFromRecorder struct{ *httptest.ResponseRecorder }

func (w readFromRecorder) ReadFrom(r io.Reader) (int64, error) {
	return io.Copy(w.ResponseRecorder, r)
}

func TestGetPipelineProtectsImplicitAndStreamingCommits(t *testing.T) {
	for _, mode := range []string{"write", "flush", "reader-from", "no-output"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, session.CredentialBearer)
			h, err := sessionhttp.NewGetHandlerWithMiddleware(f.config, []identityhttp.MiddlewareDescriptor{{Owner: "identity/session", Middleware: identityhttp.Middleware{Name: "stream", Phase: identityhttp.MiddlewareBeforeAuth, Order: 1, Handler: func(http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Cache-Control", "public")
					w.Header().Set("Set-Cookie", "unexpected=value")
					w.Header().Del("X-Content-Type-Options")
					switch mode {
					case "write":
						w.Write([]byte("{}"))
					case "flush":
						w.(http.Flusher).Flush()
					case "reader-from":
						if _, err := w.(io.ReaderFrom).ReadFrom(strings.NewReader("{}")); err != nil {
							t.Error(err)
						}
					}
				})
			}}}})
			if err != nil {
				t.Fatal(err)
			}
			w := readFromRecorder{httptest.NewRecorder()}
			h.ServeHTTP(w, request(f, true))
			committed := w.Result()
			if committed.Header.Get("Cache-Control") != "no-store" || committed.Header.Get("X-Content-Type-Options") != "nosniff" || committed.Header.Get("Content-Type") != "application/json" || len(committed.Cookies()) != 0 || f.calls.Load() != 0 {
				t.Fatal("implicit/streaming response bypassed read policy")
			}
		})
	}
}
