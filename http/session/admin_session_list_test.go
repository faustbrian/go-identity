package sessionhttp_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	authorization "github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/session"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
)

type adminSessionListPort struct {
	input             session.AdminSessionListRequest
	result            session.AdminSessionListResult
	calls, admissions int
	actor             identity.UserID
	err               error
	ignoreAdmission   bool
}

func (p *adminSessionListPort) AdminSessionListWithAdmission(ctx context.Context, in session.AdminSessionListRequest, admit func(context.Context, identity.UserID) error) (session.AdminSessionListResult, error) {
	p.calls++
	p.input = in
	for range p.admissions {
		if err := admit(ctx, p.actor); err != nil && !p.ignoreAdmission {
			return session.AdminSessionListResult{}, err
		}
	}
	return p.result, p.err
}

type adminSessionListRate struct {
	configured bool
	calls      int
	facts      identityhttp.NetworkFacts
	operation  string
	actor      identity.UserID
	retry      time.Duration
	err        error
}

func (r *adminSessionListRate) Configured() bool { return r != nil && r.configured }
func (r *adminSessionListRate) AdmitSessionAdministration(ctx context.Context, facts identityhttp.NetworkFacts, operation string, actor identity.UserID) (time.Duration, error) {
	r.calls++
	r.facts, r.operation, r.actor = facts, operation, actor
	if _, bounded := ctx.Deadline(); !bounded {
		return 0, errors.New("private unbounded diagnostic")
	}
	return r.retry, r.err
}

func adminSessionListFixture(t *testing.T) (*adminSessionListPort, *adminSessionListRate, sessionhttp.AdminSessionListConfig) {
	t.Helper()
	_, _, status := adminStatusFixture(t)
	now := time.Date(2026, 11, 28, 10, 0, 0, 123000, time.UTC)
	p := &adminSessionListPort{admissions: 1, actor: "actual-admin", result: session.AdminSessionListResult{Sessions: []session.Device{{SessionID: "target-a", Label: "<browser>", LastSeenAt: now, ExpiresAt: now.Add(time.Hour), Inactive: true}}}}
	rate := &adminSessionListRate{configured: true}
	return p, rate, sessionhttp.AdminSessionListConfig{Network: status.Network, OriginalCookieName: status.OriginalCookieName, Native: p, Rate: rate, MaximumDuration: time.Second}
}

func adminSessionListHandler(t testing.TB, c sessionhttp.AdminSessionListConfig) (http.Handler, identityhttp.OpenAPIDocument) {
	t.Helper()
	f, err := sessionhttp.NewAdminSessionListFeature(c)
	if err != nil {
		t.Fatal(err)
	}
	h, doc, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{f}})
	if err != nil {
		t.Fatal(err)
	}
	return h, doc
}

func adminSessionListRequest(query string) *http.Request {
	r := adminStatusRequest(true, "")
	r.Method, r.Body, r.ContentLength = http.MethodGet, nil, 0
	r.URL.Path, r.URL.RawQuery = "/v1/admin/session-list", query
	r.RequestURI = r.URL.RequestURI()
	r.Header.Del("Content-Type")
	r.Header.Del("Origin")
	r.Header.Del("X-CSRF-Token")
	r.Header.Del("Idempotency-Key")
	return r
}

func adminSessionListServe(t testing.TB, h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("Set-Cookie") != "" {
		t.Fatal("read altered cookie custody or privacy headers")
	}
	for _, secret := range []string{adminStatusToken(3), "private backend diagnostic", "credential", "authority", "proof"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("private native material escaped")
		}
	}
	return w
}

func TestAdminSessionListCanonicalAdmissionAndSafeWire(t *testing.T) {
	p, rate, c := adminSessionListFixture(t)
	h, doc := adminSessionListHandler(t, c)
	w := adminSessionListServe(t, h, adminSessionListRequest("targetSubjectID=target-user&limit=1"))
	if w.Code != 200 || p.calls != 1 || rate.calls != 1 {
		t.Fatalf("authorized read status=%d", w.Code)
	}
	if p.input.TenantID != "tenant-a" || p.input.ActorID != "" || p.input.TargetSubjectID != "target-user" || p.input.Limit != 1 || p.input.Credential.Kind() != session.CredentialCookie {
		t.Fatal("native input changed or introduced actor authority")
	}
	if rate.operation != "identity.admin.session-list" || rate.actor != "actual-admin" || !rate.facts.Valid() || rate.facts.TenantID() != "tenant-a" || rate.facts.ClientIP().String() != "198.51.100.7" {
		t.Fatal("quota lost canonical operation or authenticated actor")
	}
	var out struct {
		Sessions []struct {
			SessionID, Label      string
			LastSeenAt, ExpiresAt time.Time
			Current, Inactive     bool
		}
		NextCursor string
	}
	if json.Unmarshal(w.Body.Bytes(), &out) != nil || len(out.Sessions) != 1 || out.Sessions[0].SessionID != "target-a" || out.Sessions[0].Label != "<browser>" || !out.Sessions[0].Inactive || out.Sessions[0].Current || !out.Sessions[0].LastSeenAt.Equal(p.result.Sessions[0].LastSeenAt) {
		t.Fatal("explicit Device projection missing")
	}
	ops := doc.Operations()
	if len(ops) != 1 || ops[0].Record.OperationID != "identity.admin.session-list" || len(ops[0].Record.Owners) != 1 || ops[0].Record.Owners[0] != "identity/session" || ops[0].Record.RatePolicy != "rate.admin" || ops[0].Record.CSRFOrigin.Mode != identityhttp.CSRFNone || ops[0].Record.Idempotency != "read" {
		t.Fatal("canonical selected operation mismatch")
	}
	parsed, err := openapi.ParseJSON(context.Background(), bytes.NewReader(doc.JSON()), parse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	node := parsed.Raw()
	for _, key := range []string{"paths", "/v1/admin/session-list", "get", "responses", "200", "content", "application/json", "schema"} {
		var ok bool
		node, ok = node.Lookup(key)
		if !ok {
			t.Fatal("missing explicit success schema")
		}
	}
	for _, tc := range []struct {
		payload []byte
		valid   bool
	}{
		{w.Body.Bytes(), true},
		{[]byte(`{"sessions":[],"nextCursor":""}`), true},
		{[]byte(`{"sessions":[],"nextCursor":"","bearer":"secret"}`), false},
		{[]byte(`{"sessions":null,"nextCursor":""}`), false},
		{[]byte(`{"sessions":[]}`), false},
		{[]byte(`{"sessions":[{"sessionID":"x","label":"","lastSeenAt":"2026-11-28T10:00:00Z","expiresAt":"2026-11-28T11:00:00Z","current":false,"inactive":false,"proof":{}}],"nextCursor":""}`), false},
	} {
		instance, err := parse.JSON(context.Background(), bytes.NewReader(tc.payload), parse.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		report, err := validate.SchemaInstance(context.Background(), parsed, node, instance, validate.InstanceOptions{Direction: validate.DirectionResponse})
		if err != nil || report.Valid() != tc.valid {
			t.Fatal("wire did not enforce exact safe page shape", err)
		}
	}
}

type adminSessionListUnreadBody struct{ reads int }

func (b *adminSessionListUnreadBody) Read([]byte) (int, error) { b.reads++; return 0, io.EOF }
func (*adminSessionListUnreadBody) Close() error               { return nil }

func TestAdminSessionListRejectsUntrustedEnvelopeBeforeOwners(t *testing.T) {
	for name, change := range map[string]func(*http.Request){
		"body":                func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader("x")); r.ContentLength = 1 },
		"http1-reader":        func(r *http.Request) { r.Body = &adminSessionListUnreadBody{} },
		"unknown-length":      func(r *http.Request) { r.ContentLength = -1 },
		"transfer":            func(r *http.Request) { r.TransferEncoding = []string{"chunked"} },
		"trailer":             func(r *http.Request) { r.Trailer = http.Header{"X-Actor": []string{"other"}} },
		"authorization":       func(r *http.Request) { r.Header.Set("Authorization", "Bearer unused") },
		"proxy-authorization": func(r *http.Request) { r.Header.Set("Proxy-Authorization", "Bearer unused") },
		"key":                 func(r *http.Request) { r.Header.Set("Idempotency-Key", "unused") },
		"empty-key":           func(r *http.Request) { r.Header["Idempotency-Key"] = []string{""} },
		"csrf":                func(r *http.Request) { r.Header.Set("X-CSRF-Token", adminStatusToken(2)) },
		"cookie-duplicate":    func(r *http.Request) { r.Header.Add("Cookie", r.Header.Get("Cookie")) },
		"cookie-absent":       func(r *http.Request) { r.Header.Del("Cookie") },
		"http":                func(r *http.Request) { r.TLS = nil },
		"unmapped":            func(r *http.Request) { r.Host = "other.example" },
		"method":              func(r *http.Request) { r.Method = http.MethodPost },
		"escaped-path":        func(r *http.Request) { r.URL.RawPath = "/v1/admin/session-%6cist" },
	} {
		t.Run(name, func(t *testing.T) {
			p, rate, c := adminSessionListFixture(t)
			h, _ := adminSessionListHandler(t, c)
			r := adminSessionListRequest("targetSubjectID=target-user&limit=1")
			change(r)
			if w := adminSessionListServe(t, h, r); w.Code < 400 || p.calls != 0 || rate.calls != 0 {
				t.Fatalf("untrusted envelope reached owner: %d", w.Code)
			}
		})
	}
	for _, query := range []string{"", "targetSubjectID=x", "limit=1", "targetSubjectID=x&limit=0", "targetSubjectID=x&limit=101", "targetSubjectID=x&limit=01", "targetSubjectID=x&limit=%2B1", "targetSubjectID=x&limit=1.0", "targetSubjectID=x&limit=1&limit=2", "targetSubjectID=x&limit=1&actorID=admin", "targetSubjectID=x&limit=1&includeInactive=false", "targetSubjectID=x&limit=1&cursor=", "targetSubjectID=x&limit=1&cursor=bad", "targetSubjectID=a+b&limit=1", "targetSubjectID=%C3%A4&limit=1", "targetSubjectID=" + strings.Repeat("x", 129) + "&limit=1"} {
		t.Run(query, func(t *testing.T) {
			p, rate, c := adminSessionListFixture(t)
			h, _ := adminSessionListHandler(t, c)
			if w := adminSessionListServe(t, h, adminSessionListRequest(query)); w.Code != 400 || p.calls != 0 || rate.calls != 0 {
				t.Fatalf("invalid query reached native: %d", w.Code)
			}
		})
	}
}

func TestAdminSessionListHTTP2EmptyStreamAndCanonicalCursor(t *testing.T) {
	p, _, c := adminSessionListFixture(t)
	p.result.Sessions[0].SessionID = "target-b"
	h, _ := adminSessionListHandler(t, c)
	body := &adminSessionListUnreadBody{}
	data := append(append([]byte{1}, make([]byte, 32)...), []byte("target-a")...)
	cursor := base64.RawURLEncoding.EncodeToString(data)
	r := adminSessionListRequest("targetSubjectID=target-user&limit=100&cursor=" + url.QueryEscape(cursor))
	r.ProtoMajor, r.Body = 2, body
	if w := adminSessionListServe(t, h, r); w.Code != 200 || body.reads != 0 || p.input.Cursor != cursor || p.input.Limit != 100 || !strings.Contains(w.Body.String(), `"sessionID":"target-b"`) {
		t.Fatalf("valid HTTP/2 empty stream or cursor denied: %d", w.Code)
	}
}

func TestAdminSessionListAdmissionFailuresNeverDisclosePages(t *testing.T) {
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
		{"hint-without-error", 1, "admin", time.Second, nil, 503, ""}, {"unavailable", 1, "admin", 0, errors.New("private backend diagnostic"), 503, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, rate, c := adminSessionListFixture(t)
			p.admissions, p.actor, p.ignoreAdmission = tc.admissions, tc.actor, true
			rate.retry, rate.err = tc.retry, tc.err
			h, _ := adminSessionListHandler(t, c)
			w := adminSessionListServe(t, h, adminSessionListRequest("targetSubjectID=target-user&limit=1"))
			if w.Code != tc.status || w.Header().Get("Retry-After") != tc.hint || rate.calls > 1 || strings.Contains(w.Body.String(), "sessions") {
				t.Fatalf("unsafe admission failure: %d", w.Code)
			}
		})
	}
}

func TestAdminSessionListRejectsMalformedOrPartialNativeProjection(t *testing.T) {
	for name, change := range map[string]func(*session.AdminSessionListResult){
		"nil-page":      func(r *session.AdminSessionListResult) { r.Sessions = nil },
		"excess-page":   func(r *session.AdminSessionListResult) { r.Sessions = append(r.Sessions, r.Sessions[0]) },
		"bad-id":        func(r *session.AdminSessionListResult) { r.Sessions[0].SessionID = "bad id" },
		"long-id":       func(r *session.AdminSessionListResult) { r.Sessions[0].SessionID = strings.Repeat("x", 129) },
		"label-control": func(r *session.AdminSessionListResult) { r.Sessions[0].Label = "browser\n" },
		"label-long":    func(r *session.AdminSessionListResult) { r.Sessions[0].Label = strings.Repeat("x", 129) },
		"label-utf8":    func(r *session.AdminSessionListResult) { r.Sessions[0].Label = string([]byte{255}) },
		"time-zero":     func(r *session.AdminSessionListResult) { r.Sessions[0].LastSeenAt = time.Time{} },
		"time-year": func(r *session.AdminSessionListResult) {
			r.Sessions[0].ExpiresAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
		},
		"time-order":       func(r *session.AdminSessionListResult) { r.Sessions[0].ExpiresAt = r.Sessions[0].LastSeenAt },
		"inactive-current": func(r *session.AdminSessionListResult) { r.Sessions[0].Current = true },
		"bad-cursor":       func(r *session.AdminSessionListResult) { r.NextCursor = "bad" },
		"wrong-marker": func(r *session.AdminSessionListResult) {
			r.NextCursor = base64.RawURLEncoding.EncodeToString(append(append([]byte{1}, make([]byte, 32)...), []byte("other-id")...))
		},
	} {
		t.Run(name, func(t *testing.T) {
			p, _, c := adminSessionListFixture(t)
			change(&p.result)
			h, _ := adminSessionListHandler(t, c)
			if w := adminSessionListServe(t, h, adminSessionListRequest("targetSubjectID=target-user&limit=1")); w.Code != 503 || strings.Contains(w.Body.String(), "sessions") {
				t.Fatalf("malformed native projection disclosed page: %d", w.Code)
			}
		})
	}
	for _, tc := range []struct {
		err    error
		status int
	}{{session.ErrInvalidInput, 400}, {identity.ForbiddenError{}, 403}, {session.ErrUnauthenticated, 403}, {session.ErrUnavailable, 503}, {errors.New("private backend diagnostic"), 503}} {
		p, _, c := adminSessionListFixture(t)
		p.err = tc.err
		h, _ := adminSessionListHandler(t, c)
		if w := adminSessionListServe(t, h, adminSessionListRequest("targetSubjectID=target-user&limit=1")); w.Code != tc.status || strings.Contains(w.Body.String(), "sessions") {
			t.Fatal("native error leaked partial page")
		}
	}
}

func TestAdminSessionListConfigurationAndCancellation(t *testing.T) {
	for name, change := range map[string]func(*sessionhttp.AdminSessionListConfig){
		"no-owner": func(c *sessionhttp.AdminSessionListConfig) { c.Native = nil }, "nil-owner": func(c *sessionhttp.AdminSessionListConfig) { c.Native = (*adminSessionListPort)(nil) },
		"no-rate": func(c *sessionhttp.AdminSessionListConfig) { c.Rate = nil }, "unconfigured": func(c *sessionhttp.AdminSessionListConfig) { c.Rate = &adminSessionListRate{} },
		"cookie": func(c *sessionhttp.AdminSessionListConfig) { c.OriginalCookieName = "ordinary" }, "child-cookie": func(c *sessionhttp.AdminSessionListConfig) { c.OriginalCookieName = "__Host-identity_impersonation" },
		"zero-duration": func(c *sessionhttp.AdminSessionListConfig) { c.MaximumDuration = 0 }, "long-duration": func(c *sessionhttp.AdminSessionListConfig) { c.MaximumDuration = 31 * time.Second },
	} {
		t.Run(name, func(t *testing.T) {
			p, rate, c := adminSessionListFixture(t)
			change(&c)
			if _, err := sessionhttp.NewAdminSessionListFeature(c); err == nil || p.calls != 0 || rate.calls != 0 {
				t.Fatal("invalid construction succeeded or performed IO")
			}
		})
	}
	p, rate, c := adminSessionListFixture(t)
	h, _ := adminSessionListHandler(t, c)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if w := adminSessionListServe(t, h, adminSessionListRequest("targetSubjectID=target-user&limit=1").WithContext(ctx)); w.Code != 503 || p.calls != 0 || rate.calls != 0 {
		t.Fatal("cancelled request reached native owner")
	}
}

type adminSessionListPolicy func(context.Context, authorization.DecisionContext) (authorization.Decision, error)

func (f adminSessionListPolicy) Decide(ctx context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
	return f(ctx, dc)
}

type adminSessionListPages func(context.Context, session.SessionPageQuery) (session.SessionPage, error)

func (f adminSessionListPages) ReadSessionPage(ctx context.Context, q session.SessionPageQuery) (session.SessionPage, error) {
	return f(ctx, q)
}

func TestAdminSessionListRealCoreAuthorizesExactTargetBeforeSharedQuota(t *testing.T) {
	f := newFixture(t, session.CredentialCookie)
	rate := &adminSessionListRate{configured: true}
	allowed, policies, scans := true, 0, 0
	policy := adminSessionListPolicy(func(_ context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
		policies++
		r := dc.Request
		if dc.PolicyRevision != 1 || r.Action != "identity.admin.session-list" || r.Tenant != "tenant-a" || r.Subject.ID != "user-a" || r.Subject.Kind != authorization.SubjectUser || r.Resource.Type != "identity.user" || r.Resource.ID != "target-user" || rate.calls != scans {
			t.Fatal("policy did not bind current actual actor and exact target before quota")
		}
		outcome := authorization.Allow
		if !allowed {
			outcome = authorization.Deny
		}
		return authorization.Decision{Outcome: outcome, Revision: 1}, nil
	})
	spec, _ := f.observation.Session.Bindings()
	spec.SessionID, spec.UserID, spec.Authentication.Proof.Subject = "target-a", "target-user", "target-user"
	record, err := session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	pages := adminSessionListPages(func(_ context.Context, q session.SessionPageQuery) (session.SessionPage, error) {
		scans++
		if rate.calls != scans || q.TenantID != "tenant-a" || q.UserID != "target-user" || q.Audience != "identity-service" || q.Limit != 1 || q.AfterSessionID != "" {
			t.Fatal("page scan lacked exact admitted scope")
		}
		return session.SessionPage{Entries: []session.SessionListEntry{{Session: record, Label: "browser", Revoked: true}}}, nil
	})
	native, err := session.NewAdminListService(f.config.Sessions, pages, session.ListConfig{Authorization: policy, PolicyRevision: 1, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	c := sessionhttp.AdminSessionListConfig{Network: f.config.Network, OriginalCookieName: "__Host-identity_session", Native: native, Rate: rate, MaximumDuration: time.Second}
	h, _ := adminSessionListHandler(t, c)
	r := adminSessionListRequest("targetSubjectID=target-user&limit=1")
	r.Header.Set("Cookie", "__Host-identity_session="+f.wire)
	if w := adminSessionListServe(t, h, r); w.Code != 200 || policies != 1 || scans != 1 || rate.actor != "user-a" {
		t.Fatalf("real authorized read status=%d", w.Code)
	}
	allowed = false
	if w := adminSessionListServe(t, h, r); w.Code != 403 || policies != 2 || scans != 1 || rate.calls != 1 {
		t.Fatalf("policy denial consumed quota or disclosed target: %d", w.Code)
	}
}

func FuzzAdminSessionListBoundedQuery(f *testing.F) {
	for _, seed := range []string{"targetSubjectID=x&limit=1", "targetSubjectID=x&limit=100", "targetSubjectID=x&limit=01", "targetSubjectID=x&limit=1&cursor=bad", "actorID=x&limit=1", "%zz"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, query string) {
		if len(query) > 2048 {
			return
		}
		p, _, c := adminSessionListFixture(t)
		feature, err := sessionhttp.NewAdminSessionListFeature(c)
		if err != nil {
			t.Fatal(err)
		}
		w := adminSessionListServe(t, feature.Operations()[0].Handler, adminSessionListRequest(query))
		if p.calls == 0 {
			if w.Code < 400 {
				t.Fatal("invalid query succeeded without owner")
			}
			return
		}
		q, err := url.ParseQuery(query)
		limit, parseErr := strconv.Atoi(q.Get("limit"))
		if err != nil || parseErr != nil || limit < 1 || limit > 100 || strconv.Itoa(limit) != q.Get("limit") || p.input.ActorID != "" || p.input.TargetSubjectID == "" || p.input.Limit != uint16(limit) || len(q) < 2 || len(q) > 3 {
			t.Fatal("malformed or unbounded query reached native")
		}
	})
}
