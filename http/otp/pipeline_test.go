package otphttp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	otphttp "github.com/faustbrian/go-identity/http/otp"
	"github.com/faustbrian/go-identity/otp"
)

func hook(phase identityhttp.MiddlewarePhase, run func(http.ResponseWriter, *http.Request, http.Handler)) identityhttp.MiddlewareDescriptor {
	return identityhttp.MiddlewareDescriptor{Owner: "identity/otp", Middleware: identityhttp.Middleware{Name: fmt.Sprintf("phase%d", phase), Phase: phase, Order: 1, Handler: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { run(w, r, next) })
	}}}
}

func TestSigninPipelineUsesOriginalOwnerPhasesOnce(t *testing.T) {
	c, s, body := fixture(t)
	s.result = func(_ context.Context, r otp.SigninRequest) (otp.SigninResult, error) { return issuance(t, c, r), nil }
	var phases []identityhttp.MiddlewarePhase
	var hooks []identityhttp.MiddlewareDescriptor
	var retained *http.Request
	for _, phase := range []identityhttp.MiddlewarePhase{1, 2, 3, 4} {
		hooks = append(hooks, hook(phase, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			phases = append(phases, phase)
			state, ok := identityhttp.PipelineValue[otphttp.SigninState](r)
			if phase == identityhttp.MiddlewareBeforeAuth {
				if ok || s.sources != 0 || s.attempts != 0 {
					t.Error("before auth acquired owner custody")
				}
			} else {
				retained = r
				if !ok || fmt.Sprintf("%#v", state) != "otphttp.SigninState(redacted)" {
					t.Error("missing/redaction-unsafe state")
				}
				if _, err := json.Marshal(state); err == nil {
					t.Error("implicit state export")
				}
				out, attempted := state.Attempt()
				if phase == identityhttp.MiddlewareAfterHandler {
					if !attempted || !out.SignedIn || out.Recovery == nil || out.CommitOutcome != "committed" {
						t.Error("lost attempted native outcome")
					}
					out.Recovery.Attempt.CommandID = "detached"
					copy, _ := state.Attempt()
					if copy.Recovery.Attempt.CommandID == "detached" {
						t.Error("observer mutated original recovery")
					}
				} else if attempted || s.sources != 1 || s.attempts != 0 {
					t.Error("phase consumed OTP early")
				}
			}
			r.Host = "attacker.example"
			r.Header.Set("Origin", "https://attacker.example")
			r.Header.Set("Cookie", "replaced=value")
			w.Header()["set-cookie"] = []string{"attacker=value"}
			w.Header()["x-csrf-token"] = []string{"forged"}
			w.Header()["cache-control"] = []string{"public"}
			w.Header().Set("Trailer", "X-CSRF-Token")
			next.ServeHTTP(w, r)
			next.ServeHTTP(w, r)
			w.Header()[http.TrailerPrefix+"Set-Cookie"] = []string{"attacker=value"}
			w.Header()[http.TrailerPrefix+"X-CSRF-Token"] = []string{"forged"}
		}))
	}
	h, err := otphttp.NewSigninHandlerWithMiddleware(c, hooks)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(body))
	if w.Code != 200 || s.sources != 1 || s.attempts != 1 || !reflect.DeepEqual(phases, []identityhttp.MiddlewarePhase{1, 2, 3, 4}) {
		t.Fatalf("wrong owner dispatch status=%d phases=%v", w.Code, phases)
	}
	if len(w.Result().Cookies()) != 1 || w.Result().Cookies()[0].Name != "__Host-identity_session" || w.Result().Header.Get("X-CSRF-Token") == "forged" || w.Result().Header.Get("Cache-Control") != "no-store" {
		t.Fatal("hook forged response custody")
	}
	if w.Result().Trailer.Get("Set-Cookie") != "" || w.Result().Trailer.Get("X-CSRF-Token") != "" {
		t.Fatal("hook unwind forged credential trailers")
	}
	if _, ok := identityhttp.PipelineValue[otphttp.SigninState](retained); ok {
		t.Fatal("state survives request")
	}
}

func TestSigninPipelineShortCircuitCannotForgeCredentials(t *testing.T) {
	for _, phase := range []identityhttp.MiddlewarePhase{1, 2, 3} {
		t.Run(fmt.Sprint(phase), func(t *testing.T) {
			c, s, body := fixture(t)
			h, err := otphttp.NewSigninHandlerWithMiddleware(c, []identityhttp.MiddlewareDescriptor{hook(phase, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
				w.Header()["set-cookie"] = []string{"attacker=value"}
				w.Header()["x-csrf-token"] = []string{"forged"}
				w.Header()["content-type"] = []string{"text/plain"}
				w.Header()["cache-control"] = []string{"public"}
				w.Header().Set("Trailer", "X-CSRF-Token")
				w.Header()[http.TrailerPrefix+"Set-Cookie"] = []string{"attacker=value"}
				w.Header()[http.TrailerPrefix+"X-CSRF-Token"] = []string{"forged"}
				w.WriteHeader(403)
				w.Write([]byte(`{"error":"hook_denied"}`))
			})})
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, request(body))
			wantSources := 1
			if phase == 1 {
				wantSources = 0
			}
			if w.Code != 403 || s.sources != wantSources || s.attempts != 0 || len(w.Result().Cookies()) != 0 || w.Result().Header.Get("X-CSRF-Token") != "" || w.Result().Header.Get("Content-Type") != "application/json" || w.Result().Header.Get("Cache-Control") != "no-store" {
				t.Fatal("short circuit bypassed guard")
			}
			if w.Result().Trailer.Get("Set-Cookie") != "" || w.Result().Trailer.Get("X-CSRF-Token") != "" {
				t.Fatal("short circuit forged credential trailers")
			}
		})
	}
}

func TestSigninRouterRebindingRetainsCustodyAndCancellation(t *testing.T) {
	for _, cancelRequest := range []bool{false, true} {
		c, s, body := fixture(t)
		s.result = func(_ context.Context, r otp.SigninRequest) (otp.SigninResult, error) { return issuance(t, c, r), nil }
		h, err := otphttp.NewSigninHandler(c)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		h, err = identityhttp.WithOperationMiddleware(h, []identityhttp.MiddlewareDescriptor{hook(identityhttp.MiddlewareBeforeHandler, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			w.Header().Set("Set-Cookie", "attacker=value")
			w.Header().Set("X-CSRF-Token", "forged")
			if cancelRequest {
				cancel()
			}
			next.ServeHTTP(w, r)
		})})
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, request(body).WithContext(ctx))
		want := 200
		wantAttempts := 1
		wantCookies := 1
		if cancelRequest {
			want = 503
			wantAttempts = 0
			wantCookies = 0
		}
		if w.Code != want || s.attempts != wantAttempts || len(w.Result().Cookies()) != wantCookies || w.Result().Header.Get("X-CSRF-Token") == "forged" {
			t.Fatal("rebinding lost response custody or bypassed cancellation")
		}
	}
}

func TestSigninPipelineAfterHandlerObservesUnknownWithoutRetry(t *testing.T) {
	c, s, body := fixture(t)
	var observed otphttp.SigninResponse
	s.result = func(_ context.Context, r otp.SigninRequest) (otp.SigninResult, error) {
		out := issuance(t, c, r)
		out.Issuance.CommitOutcome = identity.CommitOutcomeUnknown
		return out, nil
	}
	h, err := otphttp.NewSigninHandlerWithMiddleware(c, []identityhttp.MiddlewareDescriptor{hook(4, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		state, ok := identityhttp.PipelineValue[otphttp.SigninState](r)
		var attempted bool
		observed, attempted = state.Attempt()
		if !ok || !attempted {
			t.Error("unknown result not observed")
		}
		next.ServeHTTP(w, r)
	})})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(body))
	if w.Code != 503 || s.attempts != 1 || observed.CommitOutcome != "unknown" || observed.Recovery == nil || observed.SignedIn || len(w.Result().Cookies()) != 0 {
		t.Fatal("unknown result lost or retried")
	}
}
