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

type adminSessionRevokeAllPort struct {
	input             sessionhttp.AdminSessionRevokeAllInput
	result            sessionhttp.AdminSessionRevokeAllOutput
	calls, admissions int
	actor             identity.UserID
	err               error
	ignoreAdmission   bool
	admissionContext  func(context.Context) context.Context
}

func (p *adminSessionRevokeAllPort) AdminSessionRevokeAllWithAdmission(ctx context.Context, in sessionhttp.AdminSessionRevokeAllInput, admit func(context.Context, identity.UserID) error) (sessionhttp.AdminSessionRevokeAllOutput, error) {
	p.calls++
	p.input = in
	bounded := ctx
	if p.admissionContext != nil {
		bounded = p.admissionContext(ctx)
	}
	for range p.admissions {
		if err := admit(bounded, p.actor); err != nil && !p.ignoreAdmission {
			return sessionhttp.AdminSessionRevokeAllOutput{}, err
		}
	}
	return p.result, p.err
}

func adminSessionRevokeAllFixture(t testing.TB) (*adminSessionRevokeAllPort, *adminSessionListRate, sessionhttp.AdminSessionRevokeAllConfig) {
	t.Helper()
	_, _, single := adminSessionRevokeFixture(t)
	p := &adminSessionRevokeAllPort{admissions: 1, actor: "actual-admin", result: sessionhttp.AdminSessionRevokeAllOutput{RevokedCount: 2, SubjectVersion: 3}}
	rate := &adminSessionListRate{configured: true}
	return p, rate, sessionhttp.AdminSessionRevokeAllConfig{Network: single.Network, TrustedOrigins: single.TrustedOrigins, OriginalCookieName: single.OriginalCookieName, Native: p, Rate: rate, MaximumDuration: time.Second}
}

func adminSessionRevokeAllHandler(t testing.TB, c sessionhttp.AdminSessionRevokeAllConfig) (http.Handler, identityhttp.OpenAPIDocument) {
	t.Helper()
	f, err := sessionhttp.NewAdminSessionRevokeAllFeature(c)
	if err != nil {
		t.Fatal(err)
	}
	h, document, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{f}})
	if err != nil {
		t.Fatal(err)
	}
	return h, document
}

func adminSessionRevokeAllRequest(body string) *http.Request {
	r := adminSessionRevokeRequest(body)
	r.URL.Path = "/v1/admin/session-revoke-all"
	r.RequestURI = r.URL.RequestURI()
	return r
}

func adminSessionRevokeAllServe(t testing.TB, h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" || len(w.Header().Values("Set-Cookie")) != 0 {
		t.Fatal("revoke-all changed cookie custody or omitted privacy headers")
	}
	for _, secret := range []string{adminStatusToken(2), adminStatusToken(3), "private backend diagnostic", "target-user"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("revoke-all response disclosed original custody or private intent")
		}
	}
	return w
}

func TestAdminSessionRevokeAllCanonicalRepeatTransitions(t *testing.T) {
	p, rate, c := adminSessionRevokeAllFixture(t)
	h, doc := adminSessionRevokeAllHandler(t, c)
	for _, result := range []sessionhttp.AdminSessionRevokeAllOutput{{RevokedCount: 2, SubjectVersion: 3}, {RevokedCount: 0, SubjectVersion: 4}, {RevokedCount: 100000, SubjectVersion: ^uint64(0)}} {
		p.result = result
		w := adminSessionRevokeAllServe(t, h, adminSessionRevokeAllRequest(`{"userID":"target-user"}`))
		want := fmt.Sprintf("{\"revokedCount\":%d,\"subjectVersion\":%d}\n", result.RevokedCount, result.SubjectVersion)
		if w.Code != 200 || w.Body.String() != want {
			t.Fatalf("confirmed transition status=%d body=%s want=%s", w.Code, w.Body.String(), want)
		}
	}
	csrf, _ := p.input.CSRF.Reveal()
	if p.calls != 3 || rate.calls != 3 || p.input.TenantID != "tenant-a" || p.input.TargetSubjectID != "target-user" || p.input.Bearer.Token() != adminStatusToken(3) || csrf != adminStatusToken(2) {
		t.Fatal("repeat did not freshly admit exact mapped target and original custody")
	}
	if rate.operation != "identity.admin.session-revoke-all" || rate.actor != "actual-admin" || !rate.facts.Valid() || rate.facts.TenantID() != "tenant-a" || rate.facts.ClientIP().String() != "198.51.100.7" {
		t.Fatal("shared quota did not receive derived native actor and canonical operation")
	}
	ops := doc.Operations()
	if len(ops) != 1 || ops[0].Record.OperationID != "identity.admin.session-revoke-all" || len(ops[0].Record.Owners) != 1 || ops[0].Record.Owners[0] != "identity/session" || ops[0].Record.RatePolicy != "rate.admin" || ops[0].Record.Idempotency != "repeat" || ops[0].Record.CSRFOrigin.Mode != identityhttp.CSRFSessionState || ops[0].Record.CSRFOrigin.TokenMaximumAge != 0 {
		t.Fatal("selected revoke-all is not stored-session-CSRF repeat administration")
	}
}

func TestAdminSessionRevokeAllRejectsUntrustedEnvelopeBeforeOwners(t *testing.T) {
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
		"escaped-path":        func(r *http.Request) { r.URL.RawPath = "/v1/admin/session-%72evoke-all" },
		"method":              func(r *http.Request) { r.Method = http.MethodGet },
		"form":                func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") },
	} {
		t.Run(name, func(t *testing.T) {
			p, rate, c := adminSessionRevokeAllFixture(t)
			h, _ := adminSessionRevokeAllHandler(t, c)
			r := adminSessionRevokeAllRequest(`{"userID":"target-user"}`)
			change(r)
			w := adminSessionRevokeAllServe(t, h, r)
			if w.Code < 400 || p.calls != 0 || rate.calls != 0 {
				t.Fatalf("untrusted envelope reached owners: %d", w.Code)
			}
		})
	}
}

func TestAdminSessionRevokeAllRejectsNoncanonicalBodyBeforeOwners(t *testing.T) {
	for _, body := range []string{
		``, `null`, `[]`, `{}`, `{"userID":null}`, `{"userID":1}`, `{"userID":""}`, `{"userID":"x y"}`, `{"userID":"ä"}`,
		`{"userID":"x","sessionID":"x"}`, `{"userID":"x","actorID":"admin"}`, `{"userID":"x","tenantID":"other"}`,
		`{"userID":"x","csrf_token":"unused"}`, `{"userID":"x","bearer":"unused"}`, `{"userID":"x","UserID":"x"}`, `{"UserID":"x"}`,
		`{"userID":"x","userID":"x"}`, `{"userID":"x"}{}`, `{"userID":"` + strings.Repeat("x", 129) + `"}`, `{"userID":"` + strings.Repeat("x", 2050) + `"}`,
	} {
		t.Run(body, func(t *testing.T) {
			p, rate, c := adminSessionRevokeAllFixture(t)
			h, _ := adminSessionRevokeAllHandler(t, c)
			w := adminSessionRevokeAllServe(t, h, adminSessionRevokeAllRequest(body))
			if w.Code != 400 || p.calls != 0 || rate.calls != 0 {
				t.Fatalf("invalid body reached owners: %d", w.Code)
			}
		})
	}
}

func TestAdminSessionRevokeAllAdmissionFailureDisclosesNoOutcome(t *testing.T) {
	for _, tc := range []struct {
		name       string
		admissions int
		actor      identity.UserID
		retry      time.Duration
		err        error
		status     int
		hint       string
	}{
		{"absent", 0, "admin", 0, nil, 503, ""}, {"twice", 2, "admin", 0, nil, 503, ""}, {"no-actor", 1, "", 0, nil, 503, ""}, {"malformed-actor", 1, "bad actor", 0, nil, 503, ""},
		{"limited", 1, "admin", time.Second, identityhttp.ErrRateLimited, 429, "1"}, {"maximum", 1, "admin", time.Minute, identityhttp.ErrRateLimited, 429, "60"},
		{"fractional", 1, "admin", time.Millisecond, identityhttp.ErrRateLimited, 503, ""}, {"excess", 1, "admin", 61 * time.Second, identityhttp.ErrRateLimited, 503, ""}, {"missing-hint", 1, "admin", 0, identityhttp.ErrRateLimited, 503, ""},
		{"unexpected-hint", 1, "admin", time.Second, nil, 503, ""}, {"unavailable", 1, "admin", 0, errors.New("private backend diagnostic"), 503, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, rate, c := adminSessionRevokeAllFixture(t)
			p.admissions, p.actor, p.ignoreAdmission = tc.admissions, tc.actor, true
			rate.retry, rate.err = tc.retry, tc.err
			h, _ := adminSessionRevokeAllHandler(t, c)
			w := adminSessionRevokeAllServe(t, h, adminSessionRevokeAllRequest(`{"userID":"target-user"}`))
			if w.Code != tc.status || w.Header().Get("Retry-After") != tc.hint || rate.calls > 1 || strings.Contains(w.Body.String(), "revokedCount") || strings.Contains(w.Body.String(), "subjectVersion") {
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
			p, rate, c := adminSessionRevokeAllFixture(t)
			p.admissionContext, p.ignoreAdmission = bounded, true
			h, _ := adminSessionRevokeAllHandler(t, c)
			w := adminSessionRevokeAllServe(t, h, adminSessionRevokeAllRequest(`{"userID":"target-user"}`))
			if w.Code != 503 || rate.calls != 0 || strings.Contains(w.Body.String(), "revokedCount") {
				t.Fatal("invalid context reached quota or confirmed a transition")
			}
		})
	}
}

func TestAdminSessionRevokeAllNativeErrorsNeverProjectConfirmation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status int
	}{
		{"unauthenticated", session.ErrUnauthenticated, 403}, {"csrf", session.ErrCSRFDenied, 403}, {"forbidden", identity.ForbiddenError{}, 403},
		{"invalid", identity.InvalidInputError{}, 400}, {"unknown", identity.UnknownCommitError{}, 503}, {"backend", errors.New("private backend diagnostic"), 503}, {"deadline", context.DeadlineExceeded, 503},
	} {
		for _, result := range []sessionhttp.AdminSessionRevokeAllOutput{{}, {RevokedCount: 2, SubjectVersion: 3}, {RevokedCount: 0, SubjectVersion: 4}} {
			t.Run(tc.name+fmt.Sprint(result), func(t *testing.T) {
				p, _, c := adminSessionRevokeAllFixture(t)
				p.result, p.err = result, tc.err
				h, _ := adminSessionRevokeAllHandler(t, c)
				w := adminSessionRevokeAllServe(t, h, adminSessionRevokeAllRequest(`{"userID":"target-user"}`))
				if w.Code != tc.status || strings.Contains(w.Body.String(), "revokedCount") || strings.Contains(w.Body.String(), "subjectVersion") {
					t.Fatalf("native error became confirmation: %d %s", w.Code, w.Body.String())
				}
			})
		}
	}
	for _, result := range []sessionhttp.AdminSessionRevokeAllOutput{{}, {RevokedCount: 1}, {RevokedCount: 100001, SubjectVersion: 2}} {
		t.Run(fmt.Sprint(result), func(t *testing.T) {
			p, _, c := adminSessionRevokeAllFixture(t)
			p.result = result
			h, _ := adminSessionRevokeAllHandler(t, c)
			w := adminSessionRevokeAllServe(t, h, adminSessionRevokeAllRequest(`{"userID":"target-user"}`))
			if w.Code != 503 || strings.Contains(w.Body.String(), "revokedCount") {
				t.Fatal("malformed native confirmation escaped")
			}
		})
	}
}

func TestAdminSessionRevokeAllConfigurationAndSecretCustody(t *testing.T) {
	for name, change := range map[string]func(*sessionhttp.AdminSessionRevokeAllConfig){
		"native": func(c *sessionhttp.AdminSessionRevokeAllConfig) { c.Native = nil }, "typed-native": func(c *sessionhttp.AdminSessionRevokeAllConfig) { c.Native = (*adminSessionRevokeAllPort)(nil) },
		"rate": func(c *sessionhttp.AdminSessionRevokeAllConfig) { c.Rate = nil }, "unconfigured": func(c *sessionhttp.AdminSessionRevokeAllConfig) { c.Rate = &adminSessionListRate{} },
		"origin": func(c *sessionhttp.AdminSessionRevokeAllConfig) { c.TrustedOrigins = nil }, "http-origin": func(c *sessionhttp.AdminSessionRevokeAllConfig) {
			c.TrustedOrigins = []identityhttp.Origin{"http://tenant.example"}
		},
		"cookie": func(c *sessionhttp.AdminSessionRevokeAllConfig) { c.OriginalCookieName = "session" }, "child": func(c *sessionhttp.AdminSessionRevokeAllConfig) {
			c.OriginalCookieName = "__Host-identity_impersonation"
		},
		"duration": func(c *sessionhttp.AdminSessionRevokeAllConfig) { c.MaximumDuration = 0 }, "excess-duration": func(c *sessionhttp.AdminSessionRevokeAllConfig) { c.MaximumDuration = 31 * time.Second },
	} {
		t.Run(name, func(t *testing.T) {
			p, rate, c := adminSessionRevokeAllFixture(t)
			change(&c)
			if _, err := sessionhttp.NewAdminSessionRevokeAllFeature(c); err == nil || p.calls != 0 || rate.calls != 0 {
				t.Fatal("invalid config accepted or performed IO")
			}
		})
	}
	p, _, c := adminSessionRevokeAllFixture(t)
	h, _ := adminSessionRevokeAllHandler(t, c)
	adminSessionRevokeAllServe(t, h, adminSessionRevokeAllRequest(`{"userID":"target-user"}`))
	if _, err := json.Marshal(p.input); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("input serialized original custody")
	}
	if _, err := p.input.MarshalText(); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("input exported text custody")
	}
	if got := fmt.Sprintf("%+v %#v", p.input, p.input); strings.Contains(got, adminStatusToken(3)) || strings.Contains(got, "target-user") {
		t.Fatal("formatted input disclosed custody or private intent")
	}
}

func TestAdminSessionRevokeAllWireRequiresExactCountAndPositiveGeneration(t *testing.T) {
	_, _, c := adminSessionRevokeAllFixture(t)
	_, doc := adminSessionRevokeAllHandler(t, c)
	parsed, err := openapi.ParseJSON(context.Background(), bytes.NewReader(doc.JSON()), parse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		response bool
		payload  string
		valid    bool
	}{
		{false, `{"userID":"x"}`, true}, {false, `{"userID":"x","sessionID":"y"}`, false}, {false, `{"userID":""}`, false}, {false, `{"UserID":"x"}`, false}, {false, `{"userID":"x","tenantID":"t"}`, false},
		{true, `{"revokedCount":2,"subjectVersion":3}`, true}, {true, `{"revokedCount":0,"subjectVersion":1}`, true}, {true, `{"revokedCount":100000,"subjectVersion":18446744073709551615}`, true},
		{true, `{"revokedCount":100001,"subjectVersion":2}`, false}, {true, `{"revokedCount":-1,"subjectVersion":2}`, false}, {true, `{"revokedCount":1.5,"subjectVersion":2}`, false},
		{true, `{"revokedCount":0,"subjectVersion":0}`, false}, {true, `{"revokedCount":0}`, false}, {true, `{"subjectVersion":2}`, false}, {true, `{"revokedCount":0,"subjectVersion":2,"bearer":"unused"}`, false},
	} {
		node := parsed.Raw()
		path := []string{"paths", "/v1/admin/session-revoke-all", "post"}
		direction := validate.DirectionRequest
		if tc.response {
			path = append(path, "responses", "200", "content", "application/json", "schema")
			direction = validate.DirectionResponse
		} else {
			path = append(path, "requestBody", "content", "application/json", "schema")
		}
		for _, key := range path {
			var ok bool
			node, ok = node.Lookup(key)
			if !ok {
				t.Fatal("missing explicit revoke-all schema")
			}
		}
		instance, err := parse.JSON(context.Background(), strings.NewReader(tc.payload), parse.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		report, err := validate.SchemaInstance(context.Background(), parsed, node, instance, validate.InstanceOptions{Direction: direction})
		if err != nil || report.Valid() != tc.valid {
			t.Fatalf("wire validation failed for %s: %v", tc.payload, err)
		}
	}
}

func FuzzAdminSessionRevokeAllBoundedJSON(f *testing.F) {
	for _, seed := range []string{`{"userID":"target-user"}`, `{}`, `{"userID":"x","userID":"x"}`, `{"userID":null}`, `{"userID":"x","sessionID":"x"}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 4096 {
			t.Skip()
		}
		p, rate, c := adminSessionRevokeAllFixture(t)
		feature, err := sessionhttp.NewAdminSessionRevokeAllFeature(c)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		feature.Operations()[0].Handler.ServeHTTP(w, adminSessionRevokeAllRequest(body))
		if p.calls > 1 || rate.calls > 1 || w.Header().Get("Set-Cookie") != "" {
			t.Fatal("parser multiplied work or altered cookie custody")
		}
		if p.calls == 0 {
			if w.Code < 400 {
				t.Fatal("parser confirmed without native admission")
			}
			return
		}
		var fields map[string]json.RawMessage
		var target string
		if json.Unmarshal([]byte(body), &fields) != nil || len(fields) != 1 || json.Unmarshal(fields["userID"], &target) != nil || p.input.TargetSubjectID != identity.SubjectID(target) || p.input.TenantID != "tenant-a" || len(target) < 1 || len(target) > 128 {
			t.Fatal("parser admitted invalid target shape")
		}
		for _, b := range []byte(target) {
			if b < '!' || b > '~' {
				t.Fatal("parser admitted noncanonical identifier")
			}
		}
		if w.Code != 200 || w.Body.String() != "{\"revokedCount\":2,\"subjectVersion\":3}\n" || rate.calls != 1 {
			t.Fatal("accepted target lost exact native confirmation or admission")
		}
	})
}
