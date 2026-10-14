package passwordhttp_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
)

// This double observes transport conservation only. The real native adapter
// remains responsible for cryptographic synchronizer and primary fences.
type cookieVerificationWork struct {
	*verificationWork
	csrf        session.CSRFToken
	afterVerify func()
}

func (w *cookieVerificationWork) Verify(ctx context.Context, r password.CookieVerificationRequest) (password.VerificationResult, error) {
	w.csrf = r.CSRFToken
	result, err := w.verificationWork.Verify(ctx, r.Request)
	if w.afterVerify != nil {
		w.afterVerify()
	}
	return result, err
}

func TestCookieVerificationRejectsIncompleteOrAmbiguousComposition(t *testing.T) {
	for _, scenario := range []string{"sessions", "service", "typed-nil", "rate", "policy", "clock", "duration-short", "duration-long", "cookie", "device", "origins", "collision"} {
		t.Run(scenario, func(t *testing.T) {
			f, c, _, _, _ := newCookieVerification(t)
			switch scenario {
			case "sessions":
				c.Sessions = nil
			case "service":
				c.Verification = nil
			case "typed-nil":
				c.Verification = (*cookieVerificationWork)(nil)
			case "rate":
				c.Rate = nil
			case "policy":
				c.PolicyRevision = 0
			case "clock":
				c.Now = nil
			case "duration-short":
				c.MaximumDuration = time.Millisecond - time.Nanosecond
			case "duration-long":
				c.MaximumDuration = 30*time.Second + time.Nanosecond
			case "cookie":
				c.Cookie = session.CookiePolicy{}
			case "device":
				c.Device = session.BrowserDeviceConfig{}
			case "origins":
				c.TrustedOrigins = nil
			case "collision":
				c.Cookie = c.Device.Cookie
			}
			if _, err := passwordhttp.NewCookieVerificationFeature(c); err == nil {
				t.Fatal("incomplete native composition selected")
			}
			if f.reader.calls != 0 || f.rate.calls != 0 {
				t.Fatal("construction performed IO")
			}
		})
	}
	f, c, _, _, _ := newCookieVerification(t)
	_, bearer, _ := newVerification(t)
	if _, err := passwordhttp.NewFeature(passwordhttp.FeatureConfig{CookieVerification: &c, BearerVerification: &bearer}); err == nil {
		t.Fatal("ambiguous verification selected")
	}
	if _, err := passwordhttp.NewFeature(passwordhttp.FeatureConfig{Change: &f.config, CookieVerification: &c}); err == nil {
		// This fixture has no cookie-change owner. A selected sibling must fail
		// atomically rather than yielding a partial verification contribution.
		t.Fatal("invalid selected sibling yielded partial feature")
	}
	for _, duration := range []time.Duration{time.Millisecond, 30 * time.Second} {
		c.MaximumDuration = duration
		if _, err := passwordhttp.NewCookieVerificationHandler(c); err != nil {
			t.Fatal("valid duration boundary rejected")
		}
	}
}

func TestCookieVerificationDoesNotDeliverProofAfterExpiredOrFailedWork(t *testing.T) {
	for _, scenario := range []string{"primary-expiry-hook", "device-expiry-hook", "primary-expiry-native", "committed-error"} {
		t.Run(scenario, func(t *testing.T) {
			f, c, work, device, _ := newCookieVerification(t)
			var middleware []identityhttp.MiddlewareDescriptor
			switch scenario {
			case "primary-expiry-hook", "device-expiry-hook":
				advance := 20 * time.Second
				if scenario == "device-expiry-hook" {
					codec, _ := session.NewBrowserDeviceCodec(c.Device)
					original, err := codec.Issue(context.Background(), f.clock.Now().Add(-time.Hour+5*time.Second), "tenant-a", "https://tenant.example")
					if err != nil {
						t.Fatal(err)
					}
					device, _ = http.ParseSetCookie(original.CookieHeader())
					advance = 5 * time.Second
				}
				middleware = []identityhttp.MiddlewareDescriptor{{Owner: "identity/password", Middleware: identityhttp.Middleware{Name: "expire-original", Phase: identityhttp.MiddlewareBeforeHandler, Order: 1, Handler: func(next http.Handler) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						f.clock.now = f.clock.now.Add(advance)
						next.ServeHTTP(w, r)
					})
				}}}}
			case "primary-expiry-native":
				work.afterVerify = func() { f.clock.now = f.clock.now.Add(20 * time.Second) }
			case "committed-error":
				work.err = errors.New("synthetic failed delivery")
			}
			h, err := passwordhttp.NewCookieVerificationHandlerWithMiddleware(c, middleware)
			if err != nil {
				t.Fatal(err)
			}
			r := verificationRequest(f)
			r.AddCookie(device)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			var out passwordhttp.VerificationResponse
			if json.Unmarshal(w.Body.Bytes(), &out) != nil || w.Code != 503 || out.Verified || out.Proof != nil || w.Header().Get("Set-Cookie") != "" {
				t.Fatal("stale or failed work disclosed proof")
			}
			attempted := scenario == "primary-expiry-native" || scenario == "committed-error"
			if attempted {
				if work.calls != 1 || out.CommandID != work.result.CommandID || out.CommitOutcome != "committed" {
					t.Fatal("original failed-delivery observation lost")
				}
				if work.last.Password.Len() != 0 {
					t.Fatal("handler-owned password retained")
				}
			} else if work.calls != 0 {
				t.Fatal("expired custody reached native work")
			}
		})
	}
}

func newCookieVerification(t *testing.T) (*changeFixture, passwordhttp.CookieVerificationConfig, *cookieVerificationWork, *http.Cookie, string) {
	t.Helper()
	f, bearer, work := newVerification(t)
	f.config.Transport = session.CredentialCookie
	device, cookie, id := verificationDevice(t, f)
	w := &cookieVerificationWork{verificationWork: work}
	c := passwordhttp.CookieVerificationConfig{Network: bearer.Network, Sessions: bearer.Sessions, Verification: w, Rate: bearer.Rate, PolicyRevision: bearer.PolicyRevision, Now: bearer.Now, MaximumDuration: bearer.MaximumDuration, Cookie: f.config.Cookie, TrustedOrigins: []identityhttp.Origin{"https://tenant.example"}, Device: device}
	return f, c, w, cookie, id
}

func TestCookieVerificationConservesOriginalCustodyAndSecurityConjunction(t *testing.T) {
	f, c, work, device, id := newCookieVerification(t)
	feature, err := passwordhttp.NewCookieVerificationFeature(c)
	if err != nil {
		t.Fatal(err)
	}
	h, doc, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Cookie verification", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	r := verificationRequest(f)
	r.AddCookie(device)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	csrfWire, csrfErr := work.csrf.Reveal()
	if w.Code != 200 || work.calls != 1 || work.last.Device != id || csrfErr != nil || csrfWire != strings.Repeat("A", 43) || f.reader.calls != 1 || f.rate.calls != 1 {
		t.Fatalf("original cookie custody not conserved: status=%d calls=%d", w.Code, work.calls)
	}
	if w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("verification emitted or cached credentials")
	}
	var out passwordhttp.VerificationResponse
	if json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Verified || out.Proof == nil || out.Proof.ProofID != string(work.result.CommandID) {
		t.Fatal("original proof projection absent")
	}
	var document struct {
		Paths map[string]map[string]struct {
			Security []map[string][]string `json:"security"`
		} `json:"paths"`
	}
	if json.Unmarshal(doc.JSON(), &document) != nil {
		t.Fatal("invalid selected OpenAPI")
	}
	security := document.Paths["/v1/password/verify"]["post"].Security
	if len(doc.Operations()) != 1 || len(security) != 1 || len(security[0]) != 3 {
		t.Fatal("cookie custody advertised as alternatives")
	}
	for _, name := range []string{"PasswordVerificationSessionCookie", "PasswordVerificationCSRF", "PasswordVerificationBrowserDevice"} {
		if _, ok := security[0][name]; !ok {
			t.Fatal("required cookie input absent from wire")
		}
	}
}

func TestCookieVerificationRejectsAlternateCredentialChannelsBeforeNativeWork(t *testing.T) {
	for _, scenario := range []string{"bearer", "missing-origin", "referer-only", "foreign-origin", "missing-csrf", "duplicate-csrf", "missing-device", "duplicate-session", "retry-key", "query", "body-csrf"} {
		t.Run(scenario, func(t *testing.T) {
			f, c, work, device, _ := newCookieVerification(t)
			h, err := passwordhttp.NewCookieVerificationHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			r := verificationRequest(f)
			if scenario != "missing-device" {
				r.AddCookie(device)
			}
			switch scenario {
			case "bearer":
				r.Header.Set("Authorization", "Bearer "+f.wire)
			case "missing-origin":
				r.Header.Del("Origin")
			case "referer-only":
				r.Header.Del("Origin")
				r.Header.Set("Referer", "https://tenant.example/form")
			case "foreign-origin":
				r.Header.Set("Origin", "https://foreign.example")
			case "missing-csrf":
				r.Header.Del("X-CSRF-Token")
			case "duplicate-csrf":
				r.Header.Add("X-CSRF-Token", strings.Repeat("A", 43))
			case "duplicate-session":
				r.AddCookie(&http.Cookie{Name: "__Host-identity_session", Value: f.wire})
			case "retry-key":
				r.Header.Set("Idempotency-Key", "client-key")
			case "query":
				r.URL.RawQuery = "csrf_token=" + strings.Repeat("A", 43)
			case "body-csrf":
				r.Body = httpBody(`{"password":"synthetic","purpose":"identity.password.verify","action":"identity.password.change","audience":"identity-service","csrf_token":"alternate"}`)
				r.ContentLength = -1
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code == 200 || work.calls != 0 || f.rate.calls != 0 || w.Header().Get("Set-Cookie") != "" || strings.Contains(w.Body.String(), "proofID") {
				t.Fatal("alternate custody reached native authority or disclosed proof")
			}
		})
	}
}
