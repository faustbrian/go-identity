package sessionhttp_test

import (
	"bytes"
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
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/session"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
)

type adminSessionRevokePort struct {
	input             sessionhttp.AdminSessionRevokeInput
	result            sessionhttp.AdminSessionRevokeOutput
	calls, admissions int
	actor             identity.UserID
	err               error
	ignoreAdmission   bool
	admissionContext  func(context.Context) context.Context
}

func (p *adminSessionRevokePort) AdminSessionRevokeWithAdmission(ctx context.Context, in sessionhttp.AdminSessionRevokeInput, admit func(context.Context, identity.UserID) error) (sessionhttp.AdminSessionRevokeOutput, error) {
	p.calls++
	p.input = in
	bounded := ctx
	if p.admissionContext != nil {
		bounded = p.admissionContext(ctx)
	}
	for range p.admissions {
		if err := admit(bounded, p.actor); err != nil && !p.ignoreAdmission {
			return sessionhttp.AdminSessionRevokeOutput{}, err
		}
	}
	return p.result, p.err
}

func adminSessionRevokeFixture(t testing.TB) (*adminSessionRevokePort, *adminSessionListRate, sessionhttp.AdminSessionRevokeConfig) {
	t.Helper()
	_, _, status := adminStatusFixture(t)
	p := &adminSessionRevokePort{admissions: 1, actor: "actual-admin", result: sessionhttp.AdminSessionRevokeOutput{Revoked: true, Version: 2}}
	rate := &adminSessionListRate{configured: true}
	return p, rate, sessionhttp.AdminSessionRevokeConfig{Network: status.Network, TrustedOrigins: status.TrustedOrigins, OriginalCookieName: status.OriginalCookieName, Native: p, Rate: rate, MaximumDuration: time.Second}
}

func adminSessionRevokeHandler(t testing.TB, c sessionhttp.AdminSessionRevokeConfig) (http.Handler, identityhttp.OpenAPIDocument) {
	t.Helper()
	f, err := sessionhttp.NewAdminSessionRevokeFeature(c)
	if err != nil {
		t.Fatal(err)
	}
	h, document, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{f}})
	if err != nil {
		t.Fatal(err)
	}
	return h, document
}

func adminSessionRevokeRequest(body string) *http.Request {
	r := adminStatusRequest(true, body)
	r.URL.Path = "/v1/admin/session-revoke"
	r.RequestURI = r.URL.RequestURI()
	r.Header.Del("Idempotency-Key")
	return r
}

func adminSessionRevokeServe(t testing.TB, h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" || len(w.Header().Values("Set-Cookie")) != 0 {
		t.Fatal("revocation changed cookie custody or omitted privacy headers")
	}
	for _, secret := range []string{adminStatusToken(2), adminStatusToken(3), "private backend diagnostic", "target-user", "target-session"} {
		if strings.Contains(w.Body.String()+w.Header().Get("Location"), secret) {
			t.Fatal("revocation disclosed private custody or target")
		}
	}
	return w
}

func TestAdminSessionRevokeCanonicalRepeatAdmission(t *testing.T) {
	p, rate, c := adminSessionRevokeFixture(t)
	h, doc := adminSessionRevokeHandler(t, c)
	w := adminSessionRevokeServe(t, h, adminSessionRevokeRequest(`{"userID":"target-user","sessionID":"target-session"}`))
	var confirmed map[string]json.RawMessage
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &confirmed) != nil || len(confirmed) != 2 || string(confirmed["revoked"]) != "true" || string(confirmed["version"]) != "2" || p.calls != 1 || rate.calls != 1 {
		t.Fatalf("revocation status=%d body=%s", w.Code, w.Body.String())
	}
	csrf, _ := p.input.CSRF.Reveal()
	if p.input.TenantID != "tenant-a" || p.input.TargetSubjectID != "target-user" || p.input.SessionID != "target-session" || p.input.Bearer.Token() != adminStatusToken(3) || csrf != adminStatusToken(2) {
		t.Fatal("native input did not preserve exact mapped intent and original custody")
	}
	if rate.operation != "identity.admin.session-revoke" || rate.actor != "actual-admin" || !rate.facts.Valid() || rate.facts.TenantID() != "tenant-a" || rate.facts.ClientIP().String() != "198.51.100.7" {
		t.Fatal("shared quota did not receive authenticated actor and exact operation")
	}
	p.result = sessionhttp.AdminSessionRevokeOutput{}
	w = adminSessionRevokeServe(t, h, adminSessionRevokeRequest(`{"userID":"target-user","sessionID":"target-session"}`))
	var noop map[string]json.RawMessage
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &noop) != nil || len(noop) != 1 || string(noop["revoked"]) != "false" || p.calls != 2 || rate.calls != 2 {
		t.Fatal("repeated no-op fabricated a version or skipped fresh native admission")
	}
	ops := doc.Operations()
	if len(ops) != 1 || ops[0].Record.OperationID != "identity.admin.session-revoke" || len(ops[0].Record.Owners) != 1 || ops[0].Record.Owners[0] != "identity/session" || ops[0].Record.RatePolicy != "rate.admin" || ops[0].Record.Idempotency != "repeat" || ops[0].Record.CSRFOrigin.Mode != identityhttp.CSRFSessionState || ops[0].Record.CSRFOrigin.TokenMaximumAge != 0 {
		t.Fatal("selected operation is not original-session stored-CSRF repeat administration")
	}
}

func TestAdminSessionRevokeRejectsUntrustedEnvelopeBeforeOwners(t *testing.T) {
	for name, change := range map[string]func(*http.Request){
		"missing-origin":      func(r *http.Request) { r.Header.Del("Origin"); r.Header.Set("Referer", "https://tenant.example/") },
		"foreign-origin":      func(r *http.Request) { r.Header.Set("Origin", "https://other.example") },
		"duplicate-origin":    func(r *http.Request) { r.Header.Add("Origin", "https://tenant.example") },
		"missing-csrf":        func(r *http.Request) { r.Header.Del("X-CSRF-Token") },
		"duplicate-csrf":      func(r *http.Request) { r.Header.Add("X-CSRF-Token", adminStatusToken(2)) },
		"case-csrf":           func(r *http.Request) { r.Header["x-csrf-token"] = []string{adminStatusToken(2)} },
		"invalid-csrf":        func(r *http.Request) { r.Header.Set("X-CSRF-Token", "invalid") },
		"missing-cookie":      func(r *http.Request) { r.Header.Del("Cookie") },
		"child-cookie":        func(r *http.Request) { r.Header.Set("Cookie", "__Host-identity_impersonation="+adminStatusToken(3)) },
		"duplicate-cookie":    func(r *http.Request) { r.Header.Add("Cookie", r.Header.Get("Cookie")) },
		"authorization":       func(r *http.Request) { r.Header.Set("Authorization", "Bearer unused") },
		"proxy-authorization": func(r *http.Request) { r.Header.Set("Proxy-Authorization", "Bearer unused") },
		"key":                 func(r *http.Request) { r.Header.Set("Idempotency-Key", "unused") },
		"empty-key":           func(r *http.Request) { r.Header["Idempotency-Key"] = []string{""} },
		"query":               func(r *http.Request) { r.URL.RawQuery = "userID=other" },
		"empty-query":         func(r *http.Request) { r.URL.ForceQuery = true },
		"trailer":             func(r *http.Request) { r.Trailer = http.Header{"X-CSRF-Token": []string{adminStatusToken(2)}} },
		"trailer-header":      func(r *http.Request) { r.Header.Set("Trailer", "X-CSRF-Token") },
		"http":                func(r *http.Request) { r.TLS = nil },
		"unmapped":            func(r *http.Request) { r.Host = "other.example" },
		"escaped-path":        func(r *http.Request) { r.URL.RawPath = "/v1/admin/session-%72evoke" },
		"method":              func(r *http.Request) { r.Method = http.MethodGet },
		"form":                func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") },
	} {
		t.Run(name, func(t *testing.T) {
			p, rate, c := adminSessionRevokeFixture(t)
			h, _ := adminSessionRevokeHandler(t, c)
			r := adminSessionRevokeRequest(`{"userID":"target-user","sessionID":"target-session"}`)
			change(r)
			w := adminSessionRevokeServe(t, h, r)
			if w.Code < 400 || p.calls != 0 || rate.calls != 0 {
				t.Fatalf("untrusted envelope reached owner: %d", w.Code)
			}
		})
	}
}

func TestAdminSessionRevokeRejectsNoncanonicalBodyBeforeOwners(t *testing.T) {
	for _, body := range []string{
		``, `null`, `[]`, `{}`, `{"userID":"x"}`, `{"sessionID":"x"}`,
		`{"userID":"x","sessionID":null}`, `{"userID":null,"sessionID":"x"}`,
		`{"userID":1,"sessionID":"x"}`, `{"userID":"x","sessionID":1}`,
		`{"userID":"","sessionID":"x"}`, `{"userID":"x","sessionID":""}`,
		`{"userID":"x y","sessionID":"x"}`, `{"userID":"x","sessionID":"x y"}`,
		`{"userID":"ä","sessionID":"x"}`, `{"userID":"x","sessionID":"ä"}`,
		`{"userID":"x","sessionID":"x","actorID":"admin"}`,
		`{"userID":"x","sessionID":"x","tenantID":"other"}`,
		`{"userID":"x","sessionID":"x","csrf_token":"unused"}`,
		`{"userID":"x","sessionID":"x","bearer":"unused"}`,
		`{"userID":"x","sessionID":"x","UserID":"x"}`,
		`{"UserID":"x","sessionID":"x"}`, `{"userID":"x","SessionID":"x"}`,
		`{"userID":"x","userID":"x","sessionID":"x"}`,
		`{"userID":"x","sessionID":"x","sessionID":"x"}`,
		`{"userID":"x","sessionID":"x"}{}`,
		`{"userID":"` + strings.Repeat("x", 129) + `","sessionID":"x"}`,
		`{"userID":"x","sessionID":"` + strings.Repeat("x", 129) + `"}`,
		`{"userID":"x","sessionID":"` + strings.Repeat("x", 2050) + `"}`,
	} {
		t.Run(body, func(t *testing.T) {
			p, rate, c := adminSessionRevokeFixture(t)
			h, _ := adminSessionRevokeHandler(t, c)
			w := adminSessionRevokeServe(t, h, adminSessionRevokeRequest(body))
			if w.Code != 400 || p.calls != 0 || rate.calls != 0 {
				t.Fatalf("invalid body reached owner: %d", w.Code)
			}
		})
	}
}

func TestAdminSessionRevokeAdmissionFailureDisclosesNoOutcome(t *testing.T) {
	for _, tc := range []struct {
		name       string
		admissions int
		actor      identity.UserID
		retry      time.Duration
		err        error
		status     int
		hint       string
	}{
		{"absent", 0, "admin", 0, nil, 503, ""}, {"twice", 2, "admin", 0, nil, 503, ""}, {"no-actor", 1, "", 0, nil, 503, ""},
		{"limited", 1, "admin", time.Second, identityhttp.ErrRateLimited, 429, "1"}, {"maximum", 1, "admin", time.Minute, identityhttp.ErrRateLimited, 429, "60"},
		{"fractional", 1, "admin", time.Millisecond, identityhttp.ErrRateLimited, 503, ""}, {"excess", 1, "admin", 61 * time.Second, identityhttp.ErrRateLimited, 503, ""}, {"missing-hint", 1, "admin", 0, identityhttp.ErrRateLimited, 503, ""},
		{"unexpected-hint", 1, "admin", time.Second, nil, 503, ""}, {"unavailable", 1, "admin", 0, errors.New("private backend diagnostic"), 503, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, rate, c := adminSessionRevokeFixture(t)
			p.admissions, p.actor, p.ignoreAdmission = tc.admissions, tc.actor, true
			rate.retry, rate.err = tc.retry, tc.err
			h, _ := adminSessionRevokeHandler(t, c)
			w := adminSessionRevokeServe(t, h, adminSessionRevokeRequest(`{"userID":"target-user","sessionID":"target-session"}`))
			if w.Code != tc.status || w.Header().Get("Retry-After") != tc.hint || rate.calls > 1 || strings.Contains(w.Body.String(), "revoked") || strings.Contains(w.Body.String(), "version") {
				t.Fatalf("unsafe admission failure: %d %s", w.Code, w.Body.String())
			}
		})
	}
	for name, bounded := range map[string]func(context.Context) context.Context{
		"nil":       func(context.Context) context.Context { return nil },
		"unbounded": func(context.Context) context.Context { return context.Background() },
		"extended": func(context.Context) context.Context {
			ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
			t.Cleanup(cancel)
			return ctx
		},
		"canceled": func(ctx context.Context) context.Context {
			ctx, cancel := context.WithCancel(ctx)
			cancel()
			return ctx
		},
	} {
		t.Run(name, func(t *testing.T) {
			p, rate, c := adminSessionRevokeFixture(t)
			p.admissionContext = bounded
			p.ignoreAdmission = true
			h, _ := adminSessionRevokeHandler(t, c)
			w := adminSessionRevokeServe(t, h, adminSessionRevokeRequest(`{"userID":"target-user","sessionID":"target-session"}`))
			if w.Code != 503 || rate.calls != 0 || strings.Contains(w.Body.String(), "revoked") {
				t.Fatal("invalid admission context reached quota or succeeded")
			}
		})
	}
}

func TestAdminSessionRevokeNativeErrorsNeverProjectPartialSuccess(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status int
	}{
		{"unauthenticated", session.ErrUnauthenticated, 403}, {"csrf", session.ErrCSRFDenied, 403}, {"forbidden", identity.ForbiddenError{}, 403},
		{"invalid", identity.InvalidInputError{}, 400}, {"unknown", identity.UnknownCommitError{}, 503}, {"backend", errors.New("private backend diagnostic"), 503}, {"deadline", context.DeadlineExceeded, 503},
	} {
		for _, result := range []sessionhttp.AdminSessionRevokeOutput{{}, {Revoked: true, Version: 2}, {Revoked: false, Version: 9}, {Revoked: true}} {
			t.Run(tc.name+fmt.Sprint(result.Revoked, result.Version), func(t *testing.T) {
				p, _, c := adminSessionRevokeFixture(t)
				p.result, p.err = result, tc.err
				h, _ := adminSessionRevokeHandler(t, c)
				w := adminSessionRevokeServe(t, h, adminSessionRevokeRequest(`{"userID":"target-user","sessionID":"target-session"}`))
				if w.Code != tc.status || strings.Contains(w.Body.String(), "revoked") || strings.Contains(w.Body.String(), "version") {
					t.Fatalf("native error became false success: %d %s", w.Code, w.Body.String())
				}
			})
		}
	}
	for _, result := range []sessionhttp.AdminSessionRevokeOutput{{Revoked: true}, {Revoked: false, Version: 1}} {
		t.Run(fmt.Sprint(result.Revoked, result.Version), func(t *testing.T) {
			p, _, c := adminSessionRevokeFixture(t)
			p.result = result
			h, _ := adminSessionRevokeHandler(t, c)
			w := adminSessionRevokeServe(t, h, adminSessionRevokeRequest(`{"userID":"target-user","sessionID":"target-session"}`))
			if w.Code != 503 || strings.Contains(w.Body.String(), "revoked") {
				t.Fatal("malformed native success escaped")
			}
		})
	}
}

func TestAdminSessionRevokeConfigurationAndSecretCustody(t *testing.T) {
	for name, change := range map[string]func(*sessionhttp.AdminSessionRevokeConfig){
		"native": func(c *sessionhttp.AdminSessionRevokeConfig) { c.Native = nil }, "typed-native": func(c *sessionhttp.AdminSessionRevokeConfig) { c.Native = (*adminSessionRevokePort)(nil) },
		"rate": func(c *sessionhttp.AdminSessionRevokeConfig) { c.Rate = nil }, "unconfigured": func(c *sessionhttp.AdminSessionRevokeConfig) { c.Rate = &adminSessionListRate{} },
		"origin": func(c *sessionhttp.AdminSessionRevokeConfig) { c.TrustedOrigins = nil }, "http-origin": func(c *sessionhttp.AdminSessionRevokeConfig) {
			c.TrustedOrigins = []identityhttp.Origin{"http://tenant.example"}
		},
		"cookie": func(c *sessionhttp.AdminSessionRevokeConfig) { c.OriginalCookieName = "session" }, "child": func(c *sessionhttp.AdminSessionRevokeConfig) { c.OriginalCookieName = "__Host-identity_impersonation" },
		"duration": func(c *sessionhttp.AdminSessionRevokeConfig) { c.MaximumDuration = 0 }, "excess-duration": func(c *sessionhttp.AdminSessionRevokeConfig) { c.MaximumDuration = 31 * time.Second },
	} {
		t.Run(name, func(t *testing.T) {
			p, rate, c := adminSessionRevokeFixture(t)
			change(&c)
			if _, err := sessionhttp.NewAdminSessionRevokeFeature(c); err == nil || p.calls != 0 || rate.calls != 0 {
				t.Fatal("invalid config accepted or performed IO")
			}
		})
	}
	p, _, c := adminSessionRevokeFixture(t)
	h, _ := adminSessionRevokeHandler(t, c)
	adminSessionRevokeServe(t, h, adminSessionRevokeRequest(`{"userID":"target-user","sessionID":"target-session"}`))
	if _, err := json.Marshal(p.input); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("input serialized original custody")
	}
	if _, err := p.input.MarshalText(); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("input exported text custody")
	}
	if got := fmt.Sprintf("%+v %#v", p.input, p.input); strings.Contains(got, adminStatusToken(3)) || strings.Contains(got, "target-user") || strings.Contains(got, "target-session") {
		t.Fatal("formatted input disclosed private intent")
	}
}

func TestAdminSessionRevokeWireDiscriminatesNoopFromConfirmedMutation(t *testing.T) {
	_, _, c := adminSessionRevokeFixture(t)
	_, doc := adminSessionRevokeHandler(t, c)
	parsed, err := openapi.ParseJSON(context.Background(), bytes.NewReader(doc.JSON()), parse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	node := parsed.Raw()
	for _, key := range []string{"paths", "/v1/admin/session-revoke", "post", "responses", "200", "content", "application/json", "schema"} {
		var ok bool
		node, ok = node.Lookup(key)
		if !ok {
			t.Fatal("missing explicit revoke success schema")
		}
	}
	for _, tc := range []struct {
		payload string
		valid   bool
	}{
		{`{"revoked":true,"version":2}`, true}, {`{"revoked":true,"version":1}`, true}, {`{"revoked":false}`, true},
		{`{"revoked":true}`, false}, {`{"revoked":true,"version":0}`, false}, {`{"revoked":false,"version":0}`, false}, {`{"revoked":false,"version":2}`, false},
		{`{"revoked":false,"bearer":"unused"}`, false}, {`{"version":2}`, false},
	} {
		instance, err := parse.JSON(context.Background(), strings.NewReader(tc.payload), parse.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		report, err := validate.SchemaInstance(context.Background(), parsed, node, instance, validate.InstanceOptions{Direction: validate.DirectionResponse})
		if err != nil || report.Valid() != tc.valid {
			t.Fatalf("wire discrimination failed for %s: %v", tc.payload, err)
		}
	}
}

func FuzzAdminSessionRevokeBoundedJSON(f *testing.F) {
	for _, seed := range []string{`{"userID":"target-user","sessionID":"target-session"}`, `{}`, `{"userID":"x","sessionID":"x","sessionID":"x"}`, `{"userID":null,"sessionID":[]}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 4096 {
			t.Skip()
		}
		p, rate, c := adminSessionRevokeFixture(t)
		feature, err := sessionhttp.NewAdminSessionRevokeFeature(c)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		feature.Operations()[0].Handler.ServeHTTP(w, adminSessionRevokeRequest(body))
		if p.calls > 1 || rate.calls > 1 || w.Header().Get("Set-Cookie") != "" {
			t.Fatal("bounded parser multiplied work or altered cookie custody")
		}
		if p.calls != 0 {
			if p.input.TenantID != "tenant-a" || p.input.TargetSubjectID == "" || p.input.SessionID == "" || len(p.input.SessionID) > 128 || len(p.input.TargetSubjectID) > 128 {
				t.Fatal("parser admitted invalid target")
			}
		} else if w.Code < 400 {
			t.Fatal("parser reported success without native admission")
		}
	})
}
