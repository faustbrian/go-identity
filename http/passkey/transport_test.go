package passkeyhttp

import (
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
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
)

func transportHook(phase identityhttp.MiddlewarePhase, fn func(http.ResponseWriter, *http.Request, http.Handler)) identityhttp.MiddlewareDescriptor {
	return identityhttp.MiddlewareDescriptor{Owner: "extension", Middleware: identityhttp.Middleware{Name: "custody", Phase: phase, Order: 1, Handler: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fn(w, r, next) })
	}}}
}

func TestNativeUnknownRecoverySurvivesCancellationAndFinalExpiry(t *testing.T) {
	for _, mode := range []string{"cancellation", "freshness", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			c, owner, flow, device := signinFixture(t)
			now := c.Now()
			c.Now = func() time.Time { return now }
			owner.commandID = "AAAAAAAAAAAAAAAAAAAAAg"
			owner.err = identity.UnknownCommitError{CommandID: owner.commandID}
			if mode == "deadline" {
				c.MaximumDuration = 10 * time.Millisecond
				owner.waitForDeadline = true
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			h, err := NewSigninOptionsHandlerWithMiddleware(c, []identityhttp.MiddlewareDescriptor{transportHook(identityhttp.MiddlewareBeforeHandler, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
				next.ServeHTTP(w, r)
				if mode == "cancellation" {
					cancel()
				} else if mode == "freshness" {
					now = now.Add(2 * time.Second)
				}
			})})
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			r := signinRequest("signin-options", `{"mode":"identified","flowID":"AAAAAAAAAAAAAAAAAAAAAQ","identifier":"person@example.invalid"}`, flow, device).WithContext(ctx)
			h.ServeHTTP(w, r)
			var result struct {
				CommandID identity.CommandID `json:"commandID"`
				Outcome   string             `json:"commitOutcome"`
				Options   json.RawMessage    `json:"options"`
			}
			if json.Unmarshal(w.Body.Bytes(), &result) != nil || w.Code != 503 || owner.options != 1 || result.CommandID != owner.commandID || result.Outcome != "unknown" || len(result.Options) != 0 || w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" {
				t.Fatal("final guard erased observed native recovery or disclosed credentials", w.Code)
			}
		})
	}
}

type custodyCapture struct {
	http.ResponseWriter
	captured []byte
}

func (w *custodyCapture) Write(data []byte) (int, error) {
	w.captured = append(w.captured, data...)
	return w.ResponseWriter.Write(data)
}

// This isolates response custody with synthetic bytes only. It constructs no
// positive native result, protocol proof, session authority or domain workflow.
func TestOwnedRenderNeverPassesPayloadThroughMiddlewareWriter(t *testing.T) {
	for _, operation := range []string{"register-options", "register-verify", "signin-options", "signin-verify", "list"} {
		for _, mode := range []string{"fresh", "expired", "tampered"} {
			t.Run(operation+"/"+mode, func(t *testing.T) {
				valid := true
				var captured []byte
				h := &protectedPipeline{maximum: time.Second, pipeline: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					ctx, cancel := context.WithTimeout(r.Context(), time.Second)
					defer cancel()
					r = r.WithContext(ctx)
					wrapper := &custodyCapture{ResponseWriter: w}
					d := requestDelivery(r)
					d.cookie, d.csrf = "synthetic-cookie", "synthetic-csrf"
					d.render(wrapper, r, map[string]string{"ownedPayload": "synthetic-owned-" + operation}, func() bool { return valid })
					captured = append(captured, wrapper.captured...)
					if mode == "expired" {
						valid = false
					}
					if mode == "tampered" {
						_, _ = w.Write([]byte(`{"injected":true}`))
					}
				})}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, httptest.NewRequest("POST", "/", nil))
				if len(captured) != 0 {
					t.Fatal("owned bytes reached a middleware writer before final validation")
				}
				if mode == "fresh" {
					if w.Code != 200 || !strings.Contains(w.Body.String(), "synthetic-owned-"+operation) {
						t.Fatal("fresh owned payload was lost")
					}
				} else if w.Code != 503 || strings.Contains(w.Body.String(), "synthetic-owned-") || w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" {
					t.Fatal("invalid final delivery disclosed owned payload or credentials", w.Code)
				}
			})
		}
	}
}

func TestObservedCommitMetadataSurvivesRejectedDelivery(t *testing.T) {
	for _, genuine := range []bool{false, true} {
		t.Run(fmt.Sprint(genuine), func(t *testing.T) {
			h := &protectedPipeline{maximum: time.Second, pipeline: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx, cancel := context.WithTimeout(r.Context(), time.Second)
				defer cancel()
				r = r.WithContext(ctx)
				d := requestDelivery(r)
				if genuine {
					// Simulates only the private validated observation slot. No
					// native result, authentication or cryptographic proof is made.
					d.observed = &failure{status: 503, code: "unavailable", commandID: "AAAAAAAAAAAAAAAAAAAAAg", outcome: "committed"}
					d.render(w, r, map[string]any{"signedIn": true, "ownedPayload": "synthetic-owned"}, func() bool { return false })
				} else {
					// A lookalike middleware body is never an owner observation.
					writeJSON(w, 503, map[string]any{"commandID": "AAAAAAAAAAAAAAAAAAAAAg", "commitOutcome": "committed"})
					d.valid = func() bool { return false }
				}
			})}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest("POST", "/", nil))
			var out map[string]json.RawMessage
			if json.Unmarshal(w.Body.Bytes(), &out) != nil || w.Code != 503 || out["signedIn"] != nil || out["ownedPayload"] != nil {
				t.Fatal("failed delivery disclosed successful/owned response")
			}
			if genuine && (string(out["commandID"]) != `"AAAAAAAAAAAAAAAAAAAAAg"` || string(out["commitOutcome"]) != `"committed"`) || !genuine && (out["commandID"] != nil || out["commitOutcome"] != nil) {
				t.Fatal("final guard lost native commit or accepted fabricated metadata")
			}
			if genuine {
				c, _, _, _ := signinFixture(t)
				feature, err := NewFeature(FeatureConfig{Signin: &c})
				if err != nil {
					t.Fatal(err)
				}
				_, document, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
				if err != nil {
					t.Fatal(err)
				}
				parsed, err := openapi.ParseJSON(t.Context(), strings.NewReader(string(document.JSON())), parse.DefaultLimits())
				if err != nil {
					t.Fatal(err)
				}
				node := parsed.Raw()
				for _, key := range []string{"paths", "/v1/passkey/signin-verify", "post", "responses", "503", "content", "application/json", "schema"} {
					var ok bool
					node, ok = node.Lookup(key)
					if !ok {
						t.Fatal("missing recovery wire")
					}
				}
				instance, err := parse.JSON(t.Context(), strings.NewReader(w.Body.String()), parse.DefaultLimits())
				if err != nil {
					t.Fatal(err)
				}
				report, err := validate.SchemaInstance(t.Context(), parsed, node, instance, validate.InstanceOptions{Direction: validate.DirectionResponse})
				if err != nil || !report.Valid() {
					t.Fatal("durability-only fallback not represented by selected wire", err)
				}
			}
		})
	}
}

func TestSigninHooksCannotReplaceFrozenInputsOrExportPrivateCustody(t *testing.T) {
	c, owner, flow, device := signinFixture(t)
	observed := 0
	h, err := NewSigninOptionsHandlerWithMiddleware(c, []identityhttp.MiddlewareDescriptor{transportHook(identityhttp.MiddlewareAfterAuth, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		s, ok := identityhttp.PipelineValue[SigninState](r)
		if !ok {
			t.Fatal("real owner custody absent")
		}
		for _, value := range []any{s, struct{ private SigninState }{s}, c, struct{ private SigninConfig }{c}} {
			wire := fmt.Sprintf("%+v %#v", value, value)
			if strings.Contains(wire, flow.Value) || strings.Contains(wire, device.Value) || strings.Contains(wire, "person@example.invalid") {
				t.Fatal("private custody formatting leaked")
			}
		}
		if _, err := s.MarshalJSON(); !errors.Is(err, session.ErrSecretSerialization) {
			t.Fatal("state JSON did not deny exact sentinel")
		}
		if _, err := s.MarshalText(); !errors.Is(err, session.ErrSecretSerialization) {
			t.Fatal("state text did not deny exact sentinel")
		}
		if _, err := json.Marshal(s); !errors.Is(err, session.ErrSecretSerialization) {
			t.Fatal("implicit state JSON did not deny exact sentinel")
		}
		observed++
		r.Host = "foreign.example"
		r.Header.Set("Authorization", "Bearer alternate")
		r.Header.Set("Idempotency-Key", "alternate")
		w.Header()["sEt-CoOkIe"] = []string{"unowned=value; Secure"}
		w.Header()["x-csrf-token"] = []string{"unowned"}
		w.Header().Set("Cache-Control", "public")
		next.ServeHTTP(w, r)
		next.ServeHTTP(w, r)
	})})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, signinRequest("signin-options", `{"mode":"identified","flowID":"AAAAAAAAAAAAAAAAAAAAAQ","identifier":"person@example.invalid"}`, flow, device))
	if w.Code != 403 || observed != 1 || owner.options != 1 || owner.last.Identifier != "person@example.invalid" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("hook replaced frozen request or repeated native owner", w.Code)
	}
	for name := range w.Header() {
		if strings.EqualFold(name, "Set-Cookie") || strings.EqualFold(name, "X-CSRF-Token") {
			t.Fatal("hook acquired credential delivery")
		}
	}
}

func TestSigninHookCannotRenewOriginalDeviceAndPipelineValidity(t *testing.T) {
	c, owner, flow, device := signinFixture(t)
	now := c.Now()
	c.Now = func() time.Time { return now }
	h, err := NewSigninOptionsHandlerWithMiddleware(c, []identityhttp.MiddlewareDescriptor{transportHook(identityhttp.MiddlewareAfterAuth, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		now = now.Add(2 * time.Second)
		next.ServeHTTP(w, r)
	})})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, signinRequest("signin-options", `{"mode":"identified","flowID":"AAAAAAAAAAAAAAAAAAAAAQ","identifier":"person@example.invalid"}`, flow, device))
	if w.Code != 503 || owner.options != 0 || w.Header().Get("Set-Cookie") != "" {
		t.Fatal("hook renewed original delivery validity", w.Code)
	}
}
