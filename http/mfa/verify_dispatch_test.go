package mfahttp

import (
	identityhttp "github.com/faustbrian/go-identity/http"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestVerifyDispatchSelectsExplicitVariantWithoutReadingBody(t *testing.T) {
	for _, mode := range []string{"login", "enrollment", "empty", "unknown", "duplicate", "case-duplicate", "missing-enrollment", "missing-login"} {
		t.Run(mode, func(t *testing.T) {
			loginCalls, enrollmentCalls := 0, 0
			login := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				loginCalls++
				body, _ := io.ReadAll(r.Body)
				if string(body) != "unchanged-secret-body" {
					t.Fatal("dispatch reread body")
				}
				w.WriteHeader(202)
			})
			enrollment := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				enrollmentCalls++
				body, _ := io.ReadAll(r.Body)
				if string(body) != "unchanged-secret-body" {
					t.Fatal("dispatch reread body")
				}
				w.WriteHeader(201)
			})
			h := &verifyDispatch{login: login, enrollment: enrollment}
			r := httptest.NewRequest(http.MethodPost, "https://tenant.example/v1/mfa/totp-verify", strings.NewReader("unchanged-secret-body"))
			switch mode {
			case "enrollment":
				r.Header.Set("X-MFA-Variant", "enrollment")
			case "empty":
				r.Header["X-MFA-Variant"] = []string{""}
			case "unknown":
				r.Header.Set("X-MFA-Variant", "other")
			case "duplicate":
				r.Header["X-MFA-Variant"] = []string{"enrollment", "enrollment"}
			case "case-duplicate":
				r.Header["X-MFA-Variant"] = []string{"enrollment"}
				r.Header["x-mfa-variant"] = []string{"enrollment"}
			case "missing-enrollment":
				h.enrollment = nil
				r.Header.Set("X-MFA-Variant", "enrollment")
			case "missing-login":
				h.login = nil
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if mode == "login" {
				if loginCalls != 1 || enrollmentCalls != 0 || w.Code != 202 {
					t.Fatal("legacy absent-header login changed")
				}
			} else if mode == "enrollment" {
				if enrollmentCalls != 1 || loginCalls != 0 || w.Code != 201 {
					t.Fatal("explicit enrollment not selected")
				}
			} else if loginCalls != 0 || enrollmentCalls != 0 || w.Code != 400 {
				t.Fatal("invalid variant fell back to authentication", mode, w.Code)
			}
		})
	}
}

func TestVerifyDispatchPasswordSelectionNeverFallsBack(t *testing.T) {
	for _, variant := range []string{"password", "enrollment", "unknown"} {
		t.Run(variant, func(t *testing.T) {
			var calls int
			h := &verifyDispatch{password: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(202) })}
			r := httptest.NewRequest(http.MethodPost, "https://tenant.example/v1/mfa/totp-verify", strings.NewReader("secret-body"))
			r.Header.Set("X-MFA-Variant", variant)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if variant == "password" {
				if calls != 1 || w.Code != 202 {
					t.Fatal("password variant missing")
				}
			} else if calls != 0 || w.Code != 400 {
				t.Fatal("unselected variant fell back")
			}
		})
	}
}

func TestVerifyDispatchBindsMiddlewareToBothRealPipelines(t *testing.T) {
	var hooks, handled int
	makePipeline := func() http.Handler {
		p, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[bool]{MaximumDuration: time.Second, Decode: func(*http.Request) (bool, error) { return true, nil }, Authenticate: func(_ *http.Request, s bool) (bool, error) { return s, nil }, Admit: func(*http.Request, bool) error { return nil }, Handle: func(w http.ResponseWriter, _ *http.Request, _ bool) { handled++; w.WriteHeader(204) }, Reject: func(http.ResponseWriter, *http.Request, error) { t.Fatal("pipeline denied") }})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	h, err := (&verifyDispatch{login: makePipeline(), password: makePipeline(), enrollment: makePipeline()}).WithOperationMiddleware([]identityhttp.MiddlewareDescriptor{{Owner: "identity/mfa", Middleware: identityhttp.Middleware{Name: "verify-hook", Phase: identityhttp.MiddlewareBeforeAuth, Order: 1, Handler: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hooks++; next.ServeHTTP(w, r) })
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range []string{"", "enrollment", "password"} {
		r := httptest.NewRequest(http.MethodPost, "https://tenant.example/v1/mfa/totp-verify", nil)
		if variant != "" {
			r.Header.Set("X-MFA-Variant", variant)
		}
		h.ServeHTTP(httptest.NewRecorder(), r)
	}
	if hooks != 3 || handled != 3 {
		t.Fatal("variant wrapper lost actual pipeline hooks")
	}
}

func TestVerifyFeatureRejectsUnselectedEnrollmentWithoutLoginFallback(t *testing.T) {
	c, owner, body, device := handlerFixture(t)
	f, err := NewFeature(FeatureConfig{TOTPVerify: &c})
	if err != nil {
		t.Fatal(err)
	}
	ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{f}})
	if err != nil || len(ops) != 1 {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "https://tenant.example/v1/mfa/totp-verify", strings.NewReader(body))
	r.RequestURI = r.URL.RequestURI()
	r.RemoteAddr = "127.0.0.1:4242"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", string(c.Origin))
	r.Header.Set("X-MFA-Variant", "enrollment")
	r.AddCookie(&http.Cookie{Name: "__Host-identity_flow", Value: strings.Repeat("A", 43)})
	r.AddCookie(device)
	w := httptest.NewRecorder()
	ops[0].Handler.ServeHTTP(w, r)
	if w.Code != 400 || owner.calls != 0 || owner.reads != 0 || owner.rate.calls != 0 {
		t.Fatal("unselected enrollment executed existing login")
	}
}
