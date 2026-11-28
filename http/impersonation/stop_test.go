package impersonationhttp_test

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	impersonationhttp "github.com/faustbrian/go-identity/http/impersonation"
	impersonationpg "github.com/faustbrian/go-identity/impersonation/postgres"
	"github.com/faustbrian/go-identity/session"
)

type stopPort struct {
	t              testing.TB
	input          impersonationpg.StopInput
	csrf           string
	parent         string
	prepared       int
	executed       int
	outcome        identity.CommitOutcome
	prepareError   error
	executionError error
	changeReceipt  func(*identity.CommandResult)
}

func (p *stopPort) PrepareStop(ctx context.Context, input impersonationpg.StopInput) (impersonationpg.PreparedStop, error) {
	p.t.Helper()
	if _, bounded := ctx.Deadline(); !bounded {
		p.t.Error("native stop preparation lacks a deadline")
	}
	p.prepared++
	p.input = input
	p.csrf, _ = input.Authentication.CSRF.Reveal()
	if p.csrf != stopToken(2) {
		return impersonationpg.PreparedStop{}, session.ErrCSRFDenied
	}
	return impersonationpg.PreparedStop{}, p.prepareError
}

func (p *stopPort) ExecuteStop(ctx context.Context, _ impersonationpg.PreparedStop, parent authentication.BearerCredential) (impersonationpg.StopResult, error) {
	p.t.Helper()
	if _, bounded := ctx.Deadline(); !bounded {
		p.t.Error("native stop execution lacks a deadline")
	}
	p.executed++
	p.parent = parent.Token()
	op := identity.FeatureOperation{Owner: "identity/impersonation", OperationID: "identity.impersonation.stop", SchemaID: "impersonation-stop", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	r := identity.CommandResult{
		Binding: identity.CommandBinding{
			CommandID: p.input.CommandID, TenantID: "tenant-a", UserID: "target-user",
			ActorID: "request-admin", ActorKind: authorization.SubjectUser,
			OperationID: op.OperationID, PolicyID: "impersonation-policy", PolicyVersion: 1,
			SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion,
			CorrelationID: string(p.input.CommandID), RecordID: "AAAAAAAAAAAAAAAAAAAAAQ",
		},
		Outcome: p.outcome,
		Feature: &identity.FeatureReceipt{Operation: op},
	}
	if p.outcome == identity.CommitOutcomeCommitted {
		r.AuditEventID = "audit-stop"
		r.Feature.BeforeVersion, r.Feature.AfterVersion = 3, 4
	}
	if p.outcome == identity.CommitOutcomeInProgress {
		r.RetryAfter = time.Second
	}
	if err := r.Validate(); err != nil {
		p.t.Fatal("invalid baseline native stop receipt", err)
	}
	if p.changeReceipt != nil {
		p.changeReceipt(&r)
	}
	return impersonationpg.StopResult{Receipt: r}, p.executionError
}

func stopToken(value byte) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat(string([]byte{value}), 32)))
}

func stopConfig(p *stopPort) impersonationhttp.StopConfig {
	return impersonationhttp.StopConfig{
		Network: identityhttp.NetworkConfig{
			Limits:               identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 1024, MaximumBodyBytes: 1024, MaximumDecodedBytes: 1024, MaximumFields: 32, MaximumDepth: 4},
			MaximumForwardedHops: 1,
			TenantHosts:          []identityhttp.TenantHost{{Host: "tenant.example", TenantID: "tenant-a"}},
		},
		TrustedOrigins:     []identityhttp.Origin{"https://tenant.example"},
		OriginalCookieName: "__Host-identity_session", Native: p, MaximumDuration: time.Second,
	}
}

func stopHandler(t testing.TB, p *stopPort) http.Handler {
	t.Helper()
	feature, err := impersonationhttp.NewStopFeature(stopConfig(p))
	if err != nil {
		t.Fatal(err)
	}
	h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func stopRequest(body string, original bool) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/v1/impersonation/stop", strings.NewReader(body))
	r.Host = "tenant.example"
	r.RemoteAddr = "198.51.100.7:1234"
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://tenant.example")
	r.Header.Set("X-CSRF-Token", stopToken(2))
	r.AddCookie(&http.Cookie{Name: impersonationhttp.ChildCookieName, Value: "imp1." + stopToken(1)})
	r.AddCookie(&http.Cookie{Name: impersonationhttp.ChildCSRFCookieName, Value: stopToken(2)})
	if original {
		r.AddCookie(&http.Cookie{Name: "__Host-identity_session", Value: stopToken(3)})
	}
	return r
}

func serveStop(t testing.TB, h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("stop response can be cached")
	}
	for _, secret := range []string{"imp1." + stopToken(1), stopToken(2), stopToken(3), "private backend diagnostic"} {
		if strings.Contains(w.Body.String(), secret) || strings.Contains(w.Header().Get("Location"), secret) {
			t.Error("stop response disclosed a credential or backend detail")
		}
	}
	return w
}

func TestStopCommitsChildAndDeletesOnlyChildCookies(t *testing.T) {
	for _, original := range []bool{false, true} {
		p := &stopPort{t: t, outcome: identity.CommitOutcomeCommitted}
		w := serveStop(t, stopHandler(t, p), stopRequest(`{}`, original))
		if w.Code != http.StatusOK || p.prepared != 1 || p.executed != 1 {
			t.Fatalf("stop status=%d preparations=%d executions=%d", w.Code, p.prepared, p.executed)
		}
		if _, err := identity.ParseCommandID(string(p.input.CommandID)); err != nil {
			t.Error("HTTP did not generate a canonical command identity")
		}
		if p.input.Authentication.Tenant != "tenant-a" || p.input.Authentication.Bearer != "imp1."+stopToken(1) || p.csrf != stopToken(2) || p.input.Network != "198.51.100.7" {
			t.Error("stop lost original child, CSRF or trusted network input")
		}
		wantParent := ""
		if original {
			wantParent = stopToken(3)
		}
		if p.parent != wantParent {
			t.Error("stop substituted an absent or original ordinary parent")
		}
		cookies := w.Result().Cookies()
		if len(cookies) != 2 {
			t.Fatalf("committed stop deleted %d cookies, want exactly two child cookies", len(cookies))
		}
		seen := make(map[string]bool)
		for _, cookie := range cookies {
			if (cookie.Name != impersonationhttp.ChildCookieName && cookie.Name != impersonationhttp.ChildCSRFCookieName) || seen[cookie.Name] || cookie.Value != "" || cookie.MaxAge != -1 || cookie.Path != "/" || cookie.Domain != "" || !cookie.Secure || cookie.Expires.IsZero() || !cookie.Expires.Before(time.Now()) {
				t.Error("committed stop did not delete only exact secure host child cookies")
			}
			seen[cookie.Name] = true
		}
	}
}

func TestStopSelectionMatchesOpenAPIAndLeavesSiblingsAbsent(t *testing.T) {
	p := &stopPort{t: t, outcome: identity.CommitOutcomeCommitted}
	config := stopConfig(p)
	config.Native = (*stopPort)(nil)
	if _, err := impersonationhttp.NewStopFeature(config); err == nil {
		t.Fatal("selected an absent native owner")
	}
	feature, err := impersonationhttp.NewStopFeature(stopConfig(p))
	if err != nil {
		t.Fatal(err)
	}
	handler, document, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil || document.Version() != "3.1.1" {
		t.Fatal("failed to build selected OpenAPI", err)
	}
	ops := document.Operations()
	if len(ops) != 1 || ops[0].Record.OperationID != "identity.impersonation.stop" || ops[0].Record.Idempotency != "repeat" {
		t.Fatal("document advertised a different operation set")
	}
	for _, path := range []string{"/v1/impersonation/start", "/v1/impersonation/revoke", "/v1/impersonation/stop/"} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "https://tenant.example"+path, nil))
		if w.Code != http.StatusNotFound || p.prepared != 0 {
			t.Fatal("unselected route reached native stop", path)
		}
	}
}

func FuzzStopClosedBody(f *testing.F) {
	for _, seed := range []string{`{}`, `{"actorID":"other"}`, `{"csrf_token":"other"}`, `{"Idempotency-Key":"body"}`, `{}{}`, `null`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 1025 {
			return
		}
		p := &stopPort{t: t, outcome: identity.CommitOutcomeCommitted}
		w := serveStop(t, stopHandler(t, p), stopRequest(body, true))
		if w.Code != http.StatusOK {
			if p.prepared != 0 || len(w.Result().Cookies()) != 0 {
				t.Fatal("rejected body reached native stop or changed cookies")
			}
			return
		}
		var decoded map[string]any
		if json.Unmarshal([]byte(body), &decoded) != nil || decoded == nil || len(decoded) != 0 || p.prepared != 1 {
			t.Fatal("non-empty object reached native stop")
		}
	})
}

func TestStopRejectsMalformedBodyAndAlternateChannelsBeforeNativeWork(t *testing.T) {
	for _, body := range []string{"", `null`, `[]`, `{"tenantID":"other"}`, `{"commandID":"forged"}`, `{"grantID":"other"}`, `{"csrf":"alternate"}`, `{} {}`, `{"x":1,"x":2}`} {
		t.Run("body-"+body, func(t *testing.T) {
			p := &stopPort{t: t, outcome: identity.CommitOutcomeCommitted}
			w := serveStop(t, stopHandler(t, p), stopRequest(body, true))
			if w.Code != 400 || p.prepared != 0 || p.executed != 0 || len(w.Result().Cookies()) != 0 {
				t.Fatalf("malformed body reached native stop or changed cookies: status=%d", w.Code)
			}
		})
	}
	for name, change := range map[string]func(*http.Request){
		"authorization":   func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+stopToken(3)) },
		"query":           func(r *http.Request) { r.URL.RawQuery = "grantID=other" },
		"empty-query":     func(r *http.Request) { r.URL.ForceQuery = true },
		"idempotency-key": func(r *http.Request) { r.Header.Set("Idempotency-Key", "forged") },
		"trailer":         func(r *http.Request) { r.Trailer = http.Header{"X-CSRF-Token": []string{stopToken(2)}} },
		"duplicate-child": func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: impersonationhttp.ChildCookieName, Value: "imp1." + stopToken(4)})
		},
		"duplicate-parent": func(r *http.Request) { r.AddCookie(&http.Cookie{Name: "__Host-identity_session", Value: stopToken(4)}) },
	} {
		t.Run(name, func(t *testing.T) {
			p := &stopPort{t: t, outcome: identity.CommitOutcomeCommitted}
			r := stopRequest(`{}`, true)
			change(r)
			w := serveStop(t, stopHandler(t, p), r)
			if w.Code != 400 || p.prepared != 0 || p.executed != 0 || len(w.Result().Cookies()) != 0 {
				t.Fatalf("alternate input channel reached native stop or changed cookies: status=%d", w.Code)
			}
		})
	}
}

func TestStopRequiresExactOriginHostAndCSRF(t *testing.T) {
	for name, change := range map[string]func(*http.Request){
		"missing-origin": func(r *http.Request) { r.Header.Del("Origin") },
		"wrong-origin":   func(r *http.Request) { r.Header.Set("Origin", "https://other.example") },
		"missing-csrf":   func(r *http.Request) { r.Header.Del("X-CSRF-Token") },
		"wrong-csrf":     func(r *http.Request) { r.Header.Set("X-CSRF-Token", stopToken(4)) },
		"malformed-csrf": func(r *http.Request) { r.Header.Set("X-CSRF-Token", "not-a-token") },
		"wrong-host":     func(r *http.Request) { r.Host = "other.example" },
	} {
		t.Run(name, func(t *testing.T) {
			p := &stopPort{t: t, outcome: identity.CommitOutcomeCommitted}
			r := stopRequest(`{}`, true)
			change(r)
			w := serveStop(t, stopHandler(t, p), r)
			want := 403
			if name == "wrong-host" {
				want = 421
			}
			if w.Code != want || p.executed != 0 || len(w.Result().Cookies()) != 0 {
				t.Fatalf("denied stop changed child transport: status=%d want=%d", w.Code, want)
			}
		})
	}
}

func TestStopPreservesChildCookiesWithoutExactSuccessfulCommit(t *testing.T) {
	for _, outcome := range []identity.CommitOutcome{identity.CommitOutcomeUnknown, identity.CommitOutcomeNotCommitted, identity.CommitOutcomeConflict, identity.CommitOutcomeInProgress, identity.CommitOutcomeCommitted} {
		p := &stopPort{t: t, outcome: outcome}
		if outcome == identity.CommitOutcomeCommitted {
			p.executionError = errors.New("private backend diagnostic")
		}
		w := serveStop(t, stopHandler(t, p), stopRequest(`{}`, true))
		if w.Code == 200 || p.executed != 1 || len(w.Result().Cookies()) != 0 {
			t.Fatalf("non-successful stop cleared transport: outcome=%d status=%d", outcome, w.Code)
		}
		if outcome == identity.CommitOutcomeUnknown && w.Code != 503 {
			t.Error("unknown durable stop is not unavailable")
		}
	}
	for name, err := range map[string]error{"denied": identity.ForbiddenError{}, "unavailable": errors.New("private backend diagnostic")} {
		t.Run(name, func(t *testing.T) {
			p := &stopPort{t: t, prepareError: err}
			w := serveStop(t, stopHandler(t, p), stopRequest(`{}`, true))
			want := 503
			if name == "denied" {
				want = 403
			}
			if w.Code != want || p.executed != 0 || len(w.Result().Cookies()) != 0 {
				t.Fatalf("native denial cleared transport: status=%d want=%d", w.Code, want)
			}
		})
	}
}

func TestStopCancellationPreservesCookiesDespiteKnownCommit(t *testing.T) {
	request := stopRequest(`{}`, true)
	ctx, cancel := context.WithCancel(request.Context())
	defer cancel()
	p := &stopPort{t: t, outcome: identity.CommitOutcomeCommitted, changeReceipt: func(*identity.CommandResult) {
		cancel()
	}}
	w := serveStop(t, stopHandler(t, p), request.WithContext(ctx))
	if w.Code != http.StatusServiceUnavailable || p.executed != 1 || len(w.Result().Cookies()) != 0 {
		t.Fatal("canceled request cleared original child transport despite no usable response")
	}
	var body struct {
		Stopped   bool               `json:"stopped"`
		Outcome   string             `json:"commitOutcome"`
		CommandID identity.CommandID `json:"commandID"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.Stopped ||
		body.Outcome != "committed" || body.CommandID != p.input.CommandID {
		t.Fatal("cancellation lost the original committed observation or promoted it to success", err)
	}
}

func TestStopRejectsMalformedOrMismatchedNativeReceipts(t *testing.T) {
	for name, change := range map[string]func(*identity.CommandResult){
		"missing-feature":     func(r *identity.CommandResult) { r.Feature = nil },
		"missing-audit":       func(r *identity.CommandResult) { r.AuditEventID = "" },
		"foreign-command":     func(r *identity.CommandResult) { r.Binding.CommandID = "AAAAAAAAAAAAAAAAAAAAAQ" },
		"foreign-tenant":      func(r *identity.CommandResult) { r.Binding.TenantID = "tenant-other" },
		"missing-grant":       func(r *identity.CommandResult) { r.Binding.RecordID = "" },
		"self-target":         func(r *identity.CommandResult) { r.Binding.UserID = identity.UserID(r.Binding.ActorID) },
		"wrong-operation":     func(r *identity.CommandResult) { r.Binding.OperationID = "identity.impersonation.revoke" },
		"wrong-schema":        func(r *identity.CommandResult) { r.Binding.SchemaID = "impersonation-revoke" },
		"foreign-correlation": func(r *identity.CommandResult) { r.Binding.CorrelationID = "other-command" },
		"wrong-lifecycle":     func(r *identity.CommandResult) { r.Feature.BeforeVersion, r.Feature.AfterVersion = 2, 3 },
	} {
		t.Run(name, func(t *testing.T) {
			p := &stopPort{t: t, outcome: identity.CommitOutcomeCommitted, changeReceipt: change}
			w := serveStop(t, stopHandler(t, p), stopRequest(`{}`, true))
			if w.Code != 503 || p.executed != 1 || len(w.Result().Cookies()) != 0 {
				t.Fatalf("invalid native stop became a cookie-clearing success: status=%d", w.Code)
			}
		})
	}
}
