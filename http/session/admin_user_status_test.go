package sessionhttp_test

import (
	"context"
	"crypto/tls"
	"encoding/base64"
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
)

const adminStatusCommand = "AAAAAAAAAAAAAAAAAAAAAQ"
const adminStatusKey = "CaseSensitive_retry.~+-"

func adminStatusToken(b byte) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat(string([]byte{b}), 32)))
}

type adminStatusPort struct {
	t                 testing.TB
	input             sessionhttp.AdminUserStatusInput
	calls, admissions int
	actor             identity.UserID
	ignoreAdmission   bool
	err               error
	change            func(*identity.UserStatusResult)
}

func (p *adminStatusPort) BanUserWithAdmission(ctx context.Context, input sessionhttp.AdminUserStatusInput, admit func(context.Context, identity.UserID) error) (identity.UserStatusResult, error) {
	return p.run(ctx, input, admit, "identity.admin.user-ban", identity.StatusBanned)
}

func (p *adminStatusPort) UnbanUserWithAdmission(ctx context.Context, input sessionhttp.AdminUserStatusInput, admit func(context.Context, identity.UserID) error) (identity.UserStatusResult, error) {
	return p.run(ctx, input, admit, "identity.admin.user-unban", identity.StatusActive)
}

func (p *adminStatusPort) run(ctx context.Context, input sessionhttp.AdminUserStatusInput, admit func(context.Context, identity.UserID) error, operation string, status identity.Status) (identity.UserStatusResult, error) {
	p.t.Helper()
	p.calls++
	p.input = input
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > time.Second {
		p.t.Error("native status call lost bounded deadline")
	}
	for range p.admissions {
		if err := admit(ctx, p.actor); err != nil && !p.ignoreAdmission {
			return identity.UserStatusResult{}, err
		}
	}
	consumers := (identity.UserStatusCommand{Binding: identity.CommandBinding{OperationID: operation}}).RequiredConsumers()
	owners := make([]identity.RevocationOwnerReceipt, len(consumers))
	for i, consumer := range consumers {
		owners[i] = identity.RevocationOwnerReceipt{Owner: consumer, Status: identity.RevocationPending}
	}
	result := identity.UserStatusResult{
		CommandID: adminStatusCommand, CommitOutcome: identity.CommitOutcomeCommitted,
		User:       identity.User{ID: input.UserID, TenantID: input.TenantID, Status: status, Version: 3},
		Revocation: identity.RevocationOutcome{CascadeID: adminStatusCommand, Generation: 1, AuthorityVersion: 2, Status: identity.RevocationPending, Owners: owners},
	}
	if p.change != nil {
		p.change(&result)
	}
	return result, p.err
}

type adminStatusRate struct {
	calls      int
	configured bool
	operation  string
	actor      identity.UserID
	facts      identityhttp.NetworkFacts
	retry      time.Duration
	err        error
}

func (r *adminStatusRate) Configured() bool { return r != nil && r.configured }
func (r *adminStatusRate) AdmitUserStatus(ctx context.Context, facts identityhttp.NetworkFacts, operation string, actor identity.UserID) (time.Duration, error) {
	r.calls++
	r.facts, r.operation, r.actor = facts, operation, actor
	return r.retry, r.err
}

func adminStatusFixture(t testing.TB) (*adminStatusPort, *adminStatusRate, sessionhttp.AdminUserStatusConfig) {
	t.Helper()
	p := &adminStatusPort{t: t, admissions: 1, actor: "actual-admin"}
	rate := &adminStatusRate{configured: true}
	c := sessionhttp.AdminUserStatusConfig{
		Network:        identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 1024, MaximumBodyBytes: 2048, MaximumDecodedBytes: 2048, MaximumFields: 32, MaximumDepth: 4}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: "tenant.example", TenantID: "tenant-a"}}},
		TrustedOrigins: []identityhttp.Origin{"https://tenant.example"}, OriginalCookieName: "__Host-identity_session", Native: p, Rate: rate, MaximumDuration: time.Second, Ban: true, Unban: true,
	}
	return p, rate, c
}

func adminStatusHandler(t testing.TB, c sessionhttp.AdminUserStatusConfig) (http.Handler, identityhttp.OpenAPIDocument) {
	t.Helper()
	f, err := sessionhttp.NewAdminUserStatusFeature(c)
	if err != nil {
		t.Fatal(err)
	}
	h, document, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{f}})
	if err != nil {
		t.Fatal("construct documented administrator status feature", err)
	}
	return h, document
}

func adminStatusRequest(ban bool, body string) *http.Request {
	path := "/v1/admin/user-ban"
	if !ban {
		path = "/v1/admin/user-unban"
	}
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	r.Host, r.RemoteAddr, r.TLS = "tenant.example", "198.51.100.7:1234", &tls.ConnectionState{}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://tenant.example")
	r.Header.Set("X-CSRF-Token", adminStatusToken(2))
	r.Header.Set("Idempotency-Key", adminStatusKey)
	r.AddCookie(&http.Cookie{Name: "__Host-identity_session", Value: adminStatusToken(3)})
	return r
}

func serveAdminStatus(t testing.TB, h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" || len(w.Header().Values("Set-Cookie")) != 0 {
		t.Error("status response lacks private protections or altered cookies")
	}
	for _, secret := range []string{adminStatusToken(2), adminStatusToken(3), adminStatusKey, "private backend diagnostic", "policy-reason"} {
		if strings.Contains(w.Body.String()+w.Header().Get("Location"), secret) {
			t.Error("status response disclosed private input")
		}
	}
	return w
}

func TestAdminUserStatusCanonicalSelectionAndSafeNativeProjection(t *testing.T) {
	for _, ban := range []bool{true, false} {
		t.Run(fmt.Sprint(ban), func(t *testing.T) {
			p, rate, c := adminStatusFixture(t)
			c.Ban, c.Unban = ban, !ban
			h, document := adminStatusHandler(t, c)
			body, operation, status := `{"userID":"target-user","expectedVersion":2}`, "identity.admin.user-unban", "active"
			if ban {
				body, operation, status = `{"userID":"target-user","reason":"policy-reason","expiresAt":"2026-12-01T00:00:00.123456Z"}`, "identity.admin.user-ban", "banned"
			}
			w := serveAdminStatus(t, h, adminStatusRequest(ban, body))
			if w.Code != 200 || p.calls != 1 || rate.calls != 1 {
				t.Fatalf("status=%d native=%d quota=%d body=%s", w.Code, p.calls, rate.calls, w.Body.String())
			}
			csrf, _ := p.input.CSRF.Reveal()
			wantKey, _ := identity.NewIdempotencyKey([]byte(adminStatusKey))
			keyDigest, keyErr := p.input.Key.Digest([32]byte{1})
			wantDigest, _ := wantKey.Digest([32]byte{1})
			if p.input.TenantID != "tenant-a" || p.input.UserID != "target-user" || p.input.Bearer.Token() != adminStatusToken(3) || csrf != adminStatusToken(2) || keyErr != nil || keyDigest != wantDigest {
				t.Fatal("native input changed original custody or mapped scope")
			}
			if ban && (p.input.ExpectedVersion != 0 || p.input.Reason != "policy-reason" || p.input.ExpiresAt.Nanosecond() != 123456000) || !ban && (p.input.ExpectedVersion != 2 || p.input.Reason != "" || !p.input.ExpiresAt.IsZero()) {
				t.Fatal("native input changed canonical body")
			}
			if rate.operation != operation || rate.actor != p.actor || !rate.facts.Valid() || rate.facts.TenantID() != "tenant-a" || rate.facts.ClientIP().String() != "198.51.100.7" {
				t.Fatal("quota did not receive exact operation and authenticated actor")
			}
			var out map[string]json.RawMessage
			if json.Unmarshal(w.Body.Bytes(), &out) != nil || len(out) != 4 || out["user"] == nil || out["revocation"] == nil || string(out["commitOutcome"]) != `"committed"` || string(out["commandID"]) != `"`+adminStatusCommand+`"` {
				t.Fatal("unsafe or incomplete native result projection")
			}
			var user struct {
				ID       string `json:"id"`
				TenantID string `json:"tenantID"`
				Status   string `json:"status"`
				Version  uint64 `json:"version"`
			}
			if json.Unmarshal(out["user"], &user) != nil || user.ID != "target-user" || user.TenantID != "tenant-a" || user.Status != status || user.Version != 3 {
				t.Fatal("safe User projection changed")
			}
			ops := document.Operations()
			if len(ops) != 1 || ops[0].Record.OperationID != operation || ops[0].Record.Owners[0] != "identity" || ops[0].Record.RatePolicy != "rate.admin" || ops[0].Record.CSRFOrigin.Mode != identityhttp.CSRFSessionState || ops[0].Record.CSRFOrigin.TokenMaximumAge != 0 || ops[0].Record.Idempotency != "keyed" {
				t.Fatal("canonical metadata disagrees with selected route")
			}
			other := adminStatusRequest(!ban, body)
			if serveAdminStatus(t, h, other).Code != 404 || p.calls != 1 {
				t.Fatal("unselected administrator route became active")
			}
		})
	}
}

func TestAdminUserStatusRejectsMalformedBodyAndAlternateCustody(t *testing.T) {
	for name, change := range map[string]func(*http.Request){
		"missing-origin":   func(r *http.Request) { r.Header.Del("Origin"); r.Header.Set("Referer", "https://tenant.example/") },
		"foreign-origin":   func(r *http.Request) { r.Header.Set("Origin", "https://other.example") },
		"duplicate-origin": func(r *http.Request) { r.Header.Add("Origin", "https://tenant.example") },
		"missing-csrf":     func(r *http.Request) { r.Header.Del("X-CSRF-Token") },
		"duplicate-csrf":   func(r *http.Request) { r.Header.Add("X-CSRF-Token", adminStatusToken(2)) },
		"missing-cookie":   func(r *http.Request) { r.Header.Del("Cookie") },
		"duplicate-cookie": func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: "__Host-identity_session", Value: adminStatusToken(3)})
		},
		"authorization": func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+adminStatusToken(3)) },
		"missing-key":   func(r *http.Request) { r.Header.Del("Idempotency-Key") },
		"duplicate-key": func(r *http.Request) { r.Header.Add("Idempotency-Key", adminStatusKey) },
		"query":         func(r *http.Request) { r.URL.RawQuery = "actorID=other" },
		"empty-query":   func(r *http.Request) { r.URL.ForceQuery = true },
		"trailer":       func(r *http.Request) { r.Trailer = http.Header{"X-CSRF-Token": []string{adminStatusToken(2)}} },
		"http":          func(r *http.Request) { r.TLS = nil },
		"unmapped":      func(r *http.Request) { r.Host = "other.example" },
		"escaped-path":  func(r *http.Request) { r.URL.RawPath = "/v1/admin/user-%62an" },
		"get":           func(r *http.Request) { r.Method = http.MethodGet },
	} {
		t.Run(name, func(t *testing.T) {
			p, rate, c := adminStatusFixture(t)
			h, _ := adminStatusHandler(t, c)
			r := adminStatusRequest(true, `{"userID":"target-user","reason":"policy-reason"}`)
			change(r)
			if w := serveAdminStatus(t, h, r); w.Code < 400 || p.calls != 0 || rate.calls != 0 {
				t.Fatalf("malformed request reached native: %d", w.Code)
			}
		})
	}
	for _, body := range []string{`null`, `{}`, `{"userID":null,"reason":"policy-reason"}`, `{"userID":"target-user","reason":null}`, `{"userID":"target-user","reason":""}`, `{"userID":"target-user","reason":"not a code"}`, `{"userID":"target-user","reason":"policy-reason","expectedVersion":2}`, `{"userID":"target-user","reason":"policy-reason","csrf_token":"x"}`, `{"userID":"target-user","userID":"target-user","reason":"policy-reason"}`, `{"userID":"target-user","reason":"policy-reason","expiresAt":null}`, `{"userID":"target-user","reason":"policy-reason","expiresAt":"2026-12-01T00:00:00+01:00"}`, `{"userID":"target-user","reason":"policy-reason","expiresAt":"2026-12-01T00:00:00.000000001Z"}`, `{"userID":"target-user","reason":"policy-reason","expiresAt":"0001-01-01T00:00:00Z"}`} {
		t.Run(body, func(t *testing.T) {
			p, rate, c := adminStatusFixture(t)
			h, _ := adminStatusHandler(t, c)
			if w := serveAdminStatus(t, h, adminStatusRequest(true, body)); w.Code != 400 || p.calls != 0 || rate.calls != 0 {
				t.Fatalf("invalid ban body status=%d", w.Code)
			}
		})
	}
	for _, body := range []string{`{"userID":"target-user"}`, `{"userID":"target-user","expectedVersion":null}`, `{"userID":"target-user","expectedVersion":0}`, `{"userID":"target-user","expectedVersion":2,"reason":"policy-reason"}`, `{"userID":"target-user","expectedVersion":2.0}`} {
		t.Run(body, func(t *testing.T) {
			p, rate, c := adminStatusFixture(t)
			h, _ := adminStatusHandler(t, c)
			if w := serveAdminStatus(t, h, adminStatusRequest(false, body)); w.Code != 400 || p.calls != 0 || rate.calls != 0 {
				t.Fatalf("invalid unban body status=%d", w.Code)
			}
		})
	}
}

func TestAdminUserStatusFailsClosedOnAdmissionAndQuota(t *testing.T) {
	for _, tc := range []struct {
		name       string
		admissions int
		actor      identity.UserID
		retry      time.Duration
		err        error
		status     int
		header     string
	}{
		{"bypassed", 0, "actual-admin", 0, nil, 503, ""}, {"duplicate", 2, "actual-admin", 0, nil, 503, ""}, {"missing-actor", 1, "", 0, nil, 503, ""},
		{"minimum-limit", 1, "actual-admin", time.Second, identityhttp.ErrRateLimited, 429, "1"}, {"maximum-limit", 1, "actual-admin", time.Minute, identityhttp.ErrRateLimited, 429, "60"},
		{"fractional-limit", 1, "actual-admin", 1500 * time.Millisecond, identityhttp.ErrRateLimited, 503, ""}, {"excess-limit", 1, "actual-admin", 61 * time.Second, identityhttp.ErrRateLimited, 503, ""},
		{"missing-limit", 1, "actual-admin", 0, identityhttp.ErrRateLimited, 503, ""}, {"unavailable", 1, "actual-admin", 0, errors.New("private backend diagnostic"), 503, ""}, {"hint-without-error", 1, "actual-admin", time.Second, nil, 503, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, rate, c := adminStatusFixture(t)
			p.admissions, p.actor, p.ignoreAdmission = tc.admissions, tc.actor, true
			rate.retry, rate.err = tc.retry, tc.err
			h, _ := adminStatusHandler(t, c)
			w := serveAdminStatus(t, h, adminStatusRequest(true, `{"userID":"target-user","reason":"policy-reason"}`))
			if w.Code != tc.status || w.Header().Get("Retry-After") != tc.header || rate.calls > 1 || strings.Contains(w.Body.String(), `"user"`) {
				t.Fatal("native bypass or invalid quota produced unsafe response", w.Code)
			}
		})
	}
}

func TestAdminUserStatusRejectsWrongNativeResultAndPreservesErrorOutcomes(t *testing.T) {
	for name, change := range map[string]func(*identity.UserStatusResult){
		"wrong-user": func(r *identity.UserStatusResult) { r.User.ID = "other-user" }, "wrong-tenant": func(r *identity.UserStatusResult) { r.User.TenantID = "other-tenant" },
		"wrong-status": func(r *identity.UserStatusResult) { r.User.Status = identity.StatusActive }, "zero-version": func(r *identity.UserStatusResult) { r.User.Version = 0 },
		"missing-command": func(r *identity.UserStatusResult) { r.CommandID = "" }, "missing-cascade": func(r *identity.UserStatusResult) { r.Revocation.CascadeID = "" },
		"closed-cascade": func(r *identity.UserStatusResult) { r.Revocation.Status = identity.RevocationCompleted }, "generation": func(r *identity.UserStatusResult) { r.Revocation.Generation = 2 },
		"authority": func(r *identity.UserStatusResult) { r.Revocation.AuthorityVersion = 1 }, "missing-owner": func(r *identity.UserStatusResult) { r.Revocation.Owners = r.Revocation.Owners[1:] },
		"closed-owner": func(r *identity.UserStatusResult) { r.Revocation.Owners[0].Status = identity.RevocationCompleted }, "unknown-limit": func(r *identity.UserStatusResult) {
			r.Revocation.ExternalLimitations = []identity.PolicyReason{"private backend diagnostic"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			p, _, c := adminStatusFixture(t)
			p.change = change
			h, _ := adminStatusHandler(t, c)
			if w := serveAdminStatus(t, h, adminStatusRequest(true, `{"userID":"target-user","reason":"policy-reason"}`)); w.Code != 503 || strings.Contains(w.Body.String(), `"user"`) {
				t.Fatal("invalid native result disclosed metadata", w.Code)
			}
		})
	}
	for _, tc := range []struct {
		name    string
		outcome identity.CommitOutcome
		err     error
		status  int
	}{
		{"unknown", identity.CommitOutcomeUnknown, nil, 503}, {"conflict", identity.CommitOutcomeConflict, nil, 409}, {"progress", identity.CommitOutcomeInProgress, nil, 409}, {"not-committed", identity.CommitOutcomeNotCommitted, nil, 409},
		{"error-with-commit", identity.CommitOutcomeCommitted, errors.New("private backend diagnostic"), 503}, {"denied", identity.CommitOutcomeInvalid, identity.ForbiddenError{}, 403}, {"csrf-denied", identity.CommitOutcomeInvalid, session.ErrCSRFDenied, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _, c := adminStatusFixture(t)
			p.err = tc.err
			p.change = func(r *identity.UserStatusResult) {
				r.CommitOutcome = tc.outcome
				r.User = identity.User{}
				r.Revocation = identity.RevocationOutcome{}
			}
			h, _ := adminStatusHandler(t, c)
			w := serveAdminStatus(t, h, adminStatusRequest(true, `{"userID":"target-user","reason":"policy-reason"}`))
			if w.Code != tc.status || strings.Contains(w.Body.String(), `"user"`) {
				t.Fatal("native error became success or disclosed metadata", w.Code)
			}
			if tc.outcome != identity.CommitOutcomeInvalid && !strings.Contains(w.Body.String(), `"commandID":"`+adminStatusCommand+`"`) {
				t.Fatal("error lost original command correlation")
			}
		})
	}
}

func TestAdminUserStatusConfigurationCancellationAndCredentialSerialization(t *testing.T) {
	for name, change := range map[string]func(*sessionhttp.AdminUserStatusConfig){
		"disabled": func(c *sessionhttp.AdminUserStatusConfig) { c.Ban, c.Unban = false, false }, "missing-native": func(c *sessionhttp.AdminUserStatusConfig) { c.Native = nil }, "typed-nil-native": func(c *sessionhttp.AdminUserStatusConfig) { c.Native = (*adminStatusPort)(nil) },
		"missing-rate": func(c *sessionhttp.AdminUserStatusConfig) { c.Rate = nil }, "closed-rate": func(c *sessionhttp.AdminUserStatusConfig) { c.Rate = &adminStatusRate{} }, "missing-origin": func(c *sessionhttp.AdminUserStatusConfig) { c.TrustedOrigins = nil },
		"ordinary-cookie": func(c *sessionhttp.AdminUserStatusConfig) { c.OriginalCookieName = "session" }, "child-cookie": func(c *sessionhttp.AdminUserStatusConfig) { c.OriginalCookieName = "__Host-identity_impersonation" }, "duration": func(c *sessionhttp.AdminUserStatusConfig) { c.MaximumDuration = 31 * time.Second },
	} {
		t.Run(name, func(t *testing.T) {
			p, rate, c := adminStatusFixture(t)
			change(&c)
			if _, err := sessionhttp.NewAdminUserStatusFeature(c); err == nil || p.calls != 0 || rate.calls != 0 {
				t.Fatal("invalid construction performed IO or succeeded")
			}
		})
	}
	p, rate, c := adminStatusFixture(t)
	h, _ := adminStatusHandler(t, c)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w := serveAdminStatus(t, h, adminStatusRequest(true, `{"userID":"target-user","reason":"policy-reason"}`).WithContext(ctx))
	if w.Code != 503 || p.calls != 0 || rate.calls != 0 {
		t.Fatal("cancelled input reached native")
	}
	key, _ := identity.NewIdempotencyKey([]byte(adminStatusKey))
	input := sessionhttp.AdminUserStatusInput{Reason: "private backend diagnostic", Key: key}
	if b, err := json.Marshal(input); err == nil || len(b) != 0 {
		t.Fatal("credential DTO permits JSON export")
	}
	if b, err := input.MarshalText(); err == nil || len(b) != 0 {
		t.Fatal("credential DTO permits text export")
	}
	if strings.Contains(fmt.Sprintf("%+v %#v", input, &input), "private backend diagnostic") || strings.Contains(fmt.Sprint(input), adminStatusKey) {
		t.Fatal("credential DTO permits implicit formatting")
	}
}

func TestAdminUserStatusRejectsLossyExpiryPrecision(t *testing.T) {
	p, rate, c := adminStatusFixture(t)
	h, _ := adminStatusHandler(t, c)
	body := `{"userID":"target-user","reason":"policy-reason","expiresAt":"2026-12-01T00:00:00.1234560001Z"}`
	w := serveAdminStatus(t, h, adminStatusRequest(true, body))
	if w.Code != http.StatusBadRequest || p.calls != 0 || rate.calls != 0 {
		t.Fatalf("lossy expiry precision reached native: status=%d native=%d quota=%d", w.Code, p.calls, rate.calls)
	}
}

func TestAdminUserStatusRejectsUnbanVersionOutsideExactSuccessor(t *testing.T) {
	p, rate, c := adminStatusFixture(t)
	p.change = func(result *identity.UserStatusResult) { result.User.Version = 4 }
	h, _ := adminStatusHandler(t, c)
	w := serveAdminStatus(t, h, adminStatusRequest(false, `{"userID":"target-user","expectedVersion":2}`))
	if w.Code != http.StatusServiceUnavailable || p.calls != 1 || rate.calls != 1 || strings.Contains(w.Body.String(), `"user"`) {
		t.Fatalf("non-successor unban result escaped validation: status=%d", w.Code)
	}
}

func TestAdminUserStatusRejectsUnbanVersionOverflow(t *testing.T) {
	p, rate, c := adminStatusFixture(t)
	h, _ := adminStatusHandler(t, c)
	w := serveAdminStatus(t, h, adminStatusRequest(false, `{"userID":"target-user","expectedVersion":18446744073709551615}`))
	if w.Code != http.StatusBadRequest || p.calls != 0 || rate.calls != 0 {
		t.Fatalf("non-incrementable unban version reached native: status=%d native=%d quota=%d", w.Code, p.calls, rate.calls)
	}
}

func TestAdminUserStatusWithholdsCorrelationWithoutAdmissionOrValidCommittedProjection(t *testing.T) {
	for _, tc := range []struct {
		name        string
		admissions  int
		err         error
		foreignUser bool
		status      int
	}{
		{"no-admission-error", 0, identity.ForbiddenError{}, false, http.StatusForbidden},
		{"foreign-committed-user", 1, nil, true, http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _, c := adminStatusFixture(t)
			p.admissions, p.err = tc.admissions, tc.err
			if tc.foreignUser {
				p.change = func(result *identity.UserStatusResult) { result.User.ID = "foreign-user" }
			}
			h, _ := adminStatusHandler(t, c)
			w := serveAdminStatus(t, h, adminStatusRequest(true, `{"userID":"target-user","reason":"policy-reason"}`))
			var out map[string]json.RawMessage
			if w.Code != tc.status || json.Unmarshal(w.Body.Bytes(), &out) != nil || out["commandID"] != nil || string(out["commitOutcome"]) != `"none"` || out["user"] != nil || out["revocation"] != nil {
				t.Fatalf("unadmitted or malformed native output disclosed correlation: status=%d", w.Code)
			}
		})
	}
}

func TestAdminUserStatusValidatesCommittedErrorProjectionBeforeCorrelation(t *testing.T) {
	for _, tc := range []struct {
		name        string
		change      func(*identity.UserStatusResult)
		status      int
		correlation bool
	}{
		{"legitimate-withheld", func(result *identity.UserStatusResult) {
			result.User = identity.User{}
			result.Revocation = identity.RevocationOutcome{}
		}, http.StatusForbidden, true},
		{"foreign-user", func(result *identity.UserStatusResult) {
			result.User.ID = "foreign-user"
		}, http.StatusServiceUnavailable, false},
		{"partial-user", func(result *identity.UserStatusResult) {
			result.Revocation = identity.RevocationOutcome{}
		}, http.StatusServiceUnavailable, false},
		{"partial-revocation", func(result *identity.UserStatusResult) {
			result.User = identity.User{}
		}, http.StatusServiceUnavailable, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, rate, c := adminStatusFixture(t)
			p.err, p.change = identity.ForbiddenError{}, tc.change
			h, _ := adminStatusHandler(t, c)
			w := serveAdminStatus(t, h, adminStatusRequest(true, `{"userID":"target-user","reason":"policy-reason"}`))
			var out map[string]json.RawMessage
			if w.Code != tc.status || p.calls != 1 || rate.calls != 1 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out["user"] != nil || out["revocation"] != nil {
				t.Fatalf("committed error result escaped custody validation: status=%d", w.Code)
			}
			if tc.correlation {
				if string(out["commandID"]) != `"`+adminStatusCommand+`"` || string(out["commitOutcome"]) != `"committed"` {
					t.Fatal("legitimate withheld result lost original correlation")
				}
			} else if out["commandID"] != nil || string(out["commitOutcome"]) != `"none"` {
				t.Fatal("malformed committed error projection disclosed correlation")
			}
		})
	}
}

func TestAdminUserStatusRejectsCrossTenantApprovedOrigin(t *testing.T) {
	p, rate, c := adminStatusFixture(t)
	c.Network.TenantHosts = append(c.Network.TenantHosts, identityhttp.TenantHost{Host: "other.example", TenantID: "tenant-b"})
	c.TrustedOrigins = append(c.TrustedOrigins, identityhttp.Origin("https://other.example"))
	h, _ := adminStatusHandler(t, c)
	r := adminStatusRequest(true, `{"userID":"target-user","reason":"policy-reason"}`)
	r.Header.Set("Origin", "https://other.example")
	w := serveAdminStatus(t, h, r)
	if w.Code != http.StatusForbidden || p.calls != 0 || rate.calls != 0 {
		t.Fatalf("another approved tenant origin reached native: status=%d native=%d quota=%d", w.Code, p.calls, rate.calls)
	}
}

func TestAdminUserStatusRejectsProjectedNoncommittedError(t *testing.T) {
	p, rate, c := adminStatusFixture(t)
	p.err = identity.ForbiddenError{}
	p.change = func(result *identity.UserStatusResult) { result.CommitOutcome = identity.CommitOutcomeUnknown }
	h, _ := adminStatusHandler(t, c)
	w := serveAdminStatus(t, h, adminStatusRequest(true, `{"userID":"target-user","reason":"policy-reason"}`))
	var out map[string]json.RawMessage
	if w.Code != http.StatusServiceUnavailable || p.calls != 1 || rate.calls != 1 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out["commandID"] != nil || string(out["commitOutcome"]) != `"none"` || out["user"] != nil || out["revocation"] != nil {
		t.Fatalf("projected noncommitted error disclosed correlation: status=%d", w.Code)
	}
}
