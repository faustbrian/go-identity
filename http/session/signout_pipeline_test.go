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

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/session"
)

func logoutMiddleware(phase identityhttp.MiddlewarePhase, run func(http.ResponseWriter, *http.Request, http.Handler)) identityhttp.MiddlewareDescriptor {
	return identityhttp.MiddlewareDescriptor{Owner: "identity/session", Middleware: identityhttp.Middleware{Name: "logout", Phase: phase, Order: 1, Handler: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { run(w, r, next) })
	}}}
}

func TestSignOutPipelineUsesRealPhasesAndOriginalCommandOutcome(t *testing.T) {
	for _, mode := range []session.CredentialKind{session.CredentialCookie, session.CredentialBearer} {
		f := newLogout(t, mode)
		var phases []identityhttp.MiddlewarePhase
		var hooks []identityhttp.MiddlewareDescriptor
		for _, phase := range []identityhttp.MiddlewarePhase{1, 2, 3, 4} {
			hook := logoutMiddleware(phase, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
				phases = append(phases, phase)
				state, ok := identityhttp.PipelineValue[sessionhttp.SignOutState](r)
				if phase == identityhttp.MiddlewareBeforeAuth {
					if ok || f.calls.Load() != 0 {
						t.Error("before-auth acquired or disclosed identity")
					}
				} else {
					principal, authenticated := state.Principal()
					if !ok || !authenticated || principal.UserID != "user-a" || principal.TenantID != "tenant-a" {
						t.Error("missing original owner identity")
					}
					out, attempted := state.Attempt()
					for _, verb := range []string{"%v", "%+v", "%#v", "%q"} {
						if fmt.Sprintf(verb, state) != "sessionhttp.SignOutState(redacted)" {
							t.Error("state lacks diagnostic redaction")
						}
					}
					if _, err := json.Marshal(state); err == nil {
						t.Error("state allowed implicit JSON export")
					}
					if _, err := state.MarshalText(); err == nil {
						t.Error("state allowed implicit text export")
					}
					if phase == identityhttp.MiddlewareAfterHandler {
						if !attempted || !out.SignedOut || out.CommitOutcome != "committed" || out.CommandID != f.recovery.CommandID || out.Recovery == nil || out.Recovery.OperationID != "identity.session.revoke-one" {
							t.Error("after-handler did not observe original attempted result")
						}
						out.Recovery.CommandID = "detached"
						copy, _ := state.Attempt()
						if copy.Recovery.CommandID != f.recovery.CommandID {
							t.Error("observer mutated original recovery")
						}
					} else if attempted || f.calls.Load() != 1 || f.executions != 0 {
						t.Error("auth/admission ran protected command")
					}
				}
				// Original bounded input has already been acquired; hooks cannot
				// replace either the selected credential or transactional CSRF token.
				r.Host = "attacker.example"
				r.Header.Set("Cookie", "wrong=value")
				r.Header.Set("Authorization", "Bearer replaced")
				r.Header.Set("Origin", "https://attacker.example")
				r.Header.Set("X-CSRF-Token", "replaced")
				next.ServeHTTP(w, r)
				next.ServeHTTP(w, r)
			})
			hook.Middleware.Name = string(rune('a' + phase))
			hooks = append(hooks, hook)
		}
		h, err := sessionhttp.NewSignOutHandlerWithMiddleware(f.config, hooks)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, logoutRequest(f, true))
		if w.Code != 200 || f.executions != 1 || f.calls.Load() != 2 || f.observation.Active || !reflect.DeepEqual(phases, []identityhttp.MiddlewarePhase{1, 2, 3, 4}) {
			t.Fatalf("status=%d reads=%d executions=%d phases=%v", w.Code, f.calls.Load(), f.executions, phases)
		}
	}
}

func TestSignOutPipelinePreservesUnknownOutcomeAndTransport(t *testing.T) {
	f := newLogout(t, session.CredentialCookie)
	f.outcome = identity.CommitOutcomeUnknown
	var observed sessionhttp.SignOutResponse
	h, err := sessionhttp.NewSignOutHandlerWithMiddleware(f.config, []identityhttp.MiddlewareDescriptor{logoutMiddleware(identityhttp.MiddlewareAfterHandler, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		state, ok := identityhttp.PipelineValue[sessionhttp.SignOutState](r)
		var attempted bool
		observed, attempted = state.Attempt()
		if !ok || !attempted {
			t.Error("unknown command was not observed as attempt")
		}
		next.ServeHTTP(w, r)
	})})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, logoutRequest(f, true))
	var out sessionhttp.SignOutResponse
	if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.CommandID != f.recovery.CommandID || out.Recovery == nil || observed.CommitOutcome != "unknown" || observed.CommandID != out.CommandID || out.SignedOut || len(w.Result().Cookies()) != 0 || f.executions != 1 || !f.observation.Active {
		t.Fatal("unknown outcome was lost, retried or cleared transport")
	}
}

func TestSessionFeatureWithMiddlewareUsesBothRealOwners(t *testing.T) {
	f := newLogout(t, session.CredentialBearer)
	var reads, signouts int
	feature, err := sessionhttp.NewFeatureWithMiddleware(f.config, []identityhttp.MiddlewareDescriptor{logoutMiddleware(identityhttp.MiddlewareAfterAuth, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if _, ok := identityhttp.PipelineValue[sessionhttp.GetState](r); ok {
			reads++
		} else if _, ok := identityhttp.PipelineValue[sessionhttp.SignOutState](r); ok {
			signouts++
		} else {
			t.Error("selected handler has no owner state")
		}
		next.ServeHTTP(w, r)
	})})
	if err != nil {
		t.Fatal(err)
	}
	h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(f.fixture, true))
	if w.Code != 200 {
		t.Fatal("selected read failed")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, logoutRequest(f, true))
	if w.Code != 200 || reads != 1 || signouts != 1 || f.executions != 1 {
		t.Fatal("selected hooks bypassed real operations")
	}
}

func TestSignOutPipelineDenialsNeverGrantCookieClearing(t *testing.T) {
	for _, deny := range []string{"origin", "csrf", "short-circuit", "cancel", "expiry", "panic"} {
		t.Run(deny, func(t *testing.T) {
			f := newLogout(t, session.CredentialCookie)
			now := f.config.Now()
			f.config.Now = func() time.Time { return now }
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			var entered int
			deletion, _ := f.config.Cookie.DeletionAttributes()
			h, err := sessionhttp.NewSignOutHandlerWithMiddleware(f.config, []identityhttp.MiddlewareDescriptor{logoutMiddleware(identityhttp.MiddlewareBeforeHandler, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
				entered++
				w.Header()["set-cookie"] = []string{deletion.String()}
				w.Header()["cache-control"] = []string{"public"}
				switch deny {
				case "short-circuit":
					w.WriteHeader(403)
					return
				case "cancel":
					cancel()
				case "expiry":
					now = now.Add(20 * time.Second)
				case "panic":
					panic("private diagnostic")
				}
				next.ServeHTTP(w, r)
			})})
			if err != nil {
				t.Fatal(err)
			}
			r := logoutRequest(f, true).WithContext(ctx)
			if deny == "origin" {
				r.Header.Set("Origin", "https://attacker.example")
			}
			if deny == "csrf" {
				r.Header.Del("X-CSRF-Token")
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			want := 503
			if deny == "origin" || deny == "csrf" || deny == "short-circuit" {
				want = 403
			}
			if w.Code != want || f.executions != 0 || !f.observation.Active || len(w.Result().Cookies()) != 0 || w.Result().Header.Get("Cache-Control") != "no-store" || w.Result().Header.Get("X-Content-Type-Options") != "nosniff" || strings.Contains(w.Body.String(), "private") {
				t.Fatalf("denial changed transport or authority: status=%d commands=%d", w.Code, f.executions)
			}
			if deny == "origin" && (entered != 0 || f.calls.Load() != 0) {
				t.Fatal("origin denial reached hooks/owner")
			}
			if deny == "expiry" && f.calls.Load() != 1 {
				t.Fatal("expired preliminary evidence was renewed by domain read")
			}
		})
	}
}

func TestSignOutPipelineSingleAdmissionAndAbsentConcurrency(t *testing.T) {
	f := newLogout(t, session.CredentialBearer)
	h, err := sessionhttp.NewSignOutHandlerWithMiddleware(f.config, []identityhttp.MiddlewareDescriptor{logoutMiddleware(identityhttp.MiddlewareAfterAuth, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		state, ok := identityhttp.PipelineValue[sessionhttp.SignOutState](r)
		if _, authenticated := state.Principal(); !ok || authenticated {
			t.Error("absent bearer gained identity")
		}
		next.ServeHTTP(w, r)
		next.ServeHTTP(w, r)
	})})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			r := logoutRequest(f, false)
			r.Header.Set("Cookie", "__Host-identity_session="+f.wire)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			var out sessionhttp.SignOutResponse
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.SignedOut || !out.ClearBearer || out.CommitOutcome != "none" || len(w.Result().Cookies()) != 0 {
				t.Error("absent concurrent bearer logout changed profile")
			}
		})
	}
	wg.Wait()
	for i := 16; i < 101; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, logoutRequest(f, false))
		want := 200
		if i == 100 {
			want = 429
		}
		if w.Code != want {
			t.Fatalf("rate admission repeated or skipped: request=%d status=%d", i, w.Code)
		}
	}
	if f.executions != 0 || f.calls.Load() != 0 || !f.observation.Active {
		t.Fatal("absent profile borrowed ambient session authority")
	}
}

type countingLogoutBody struct {
	io.Reader
	bytes int
}

func (b *countingLogoutBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	b.bytes += n
	return n, err
}
func (*countingLogoutBody) Close() error { return nil }

func TestSignOutPipelineConsumesOriginalBodyBeforeHooksOnce(t *testing.T) {
	f := newLogout(t, session.CredentialCookie)
	body := &countingLogoutBody{Reader: strings.NewReader("csrf_token=" + f.csrf)}
	h, err := sessionhttp.NewSignOutHandlerWithMiddleware(f.config, []identityhttp.MiddlewareDescriptor{logoutMiddleware(identityhttp.MiddlewareBeforeAuth, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if body.bytes != len("csrf_token="+f.csrf) {
			t.Error("body not decoded before before-auth hook")
		}
		if raw, err := io.ReadAll(r.Body); err != nil || len(raw) != 0 {
			t.Error("hook received readable original body")
		}
		r.Body = io.NopCloser(strings.NewReader("csrf_token=replaced"))
		next.ServeHTTP(w, r)
	})})
	if err != nil {
		t.Fatal(err)
	}
	r := logoutRequest(f, true)
	r.Header.Del("X-CSRF-Token")
	r.Body = body
	r.ContentLength = int64(len("csrf_token=" + f.csrf))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || f.executions != 1 || body.bytes != int(r.ContentLength) {
		t.Fatal("original body custody lost or acquired twice")
	}
}

func TestSessionFeatureWithMiddlewareValidatesOwnersBeforeFactories(t *testing.T) {
	f := newLogout(t, session.CredentialCookie)
	f.config.CookieSignOut = nil
	var factories int
	hook := logoutMiddleware(identityhttp.MiddlewareAfterAuth, func(http.ResponseWriter, *http.Request, http.Handler) {})
	hook.Middleware.Handler = func(next http.Handler) http.Handler { factories++; return next }
	if feature, err := sessionhttp.NewFeatureWithMiddleware(f.config, []identityhttp.MiddlewareDescriptor{hook}); err == nil || feature.ID() != "" || factories != 0 || f.calls.Load() != 0 {
		t.Fatal("invalid selected dependency exposed feature or invoked factories")
	}
	var state sessionhttp.SignOutState
	if principal, ok := state.Principal(); ok || principal != (sessionhttp.Principal{}) {
		t.Fatal("zero state has identity")
	}
	if out, attempted := state.Attempt(); attempted || out.CommitOutcome != "none" {
		t.Fatal("zero state has attempted command")
	}
}
