package impersonationhttp_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	impersonationhttp "github.com/faustbrian/go-identity/http/impersonation"
	"github.com/faustbrian/go-identity/impersonation"
	impersonationpg "github.com/faustbrian/go-identity/impersonation/postgres"
	"github.com/faustbrian/go-identity/session"
)

type quorumPort struct {
	t                  testing.TB
	input              impersonationpg.QuorumInput
	result             impersonationpg.QuorumResult
	calls              int
	admissionCalls     int
	actor              identity.UserID
	err                error
	ignoreAdmissionErr bool
}

func (p *quorumPort) QuorumWithAdmission(ctx context.Context, input impersonationpg.QuorumInput, admit func(context.Context, identity.UserID) error) (impersonationpg.QuorumResult, error) {
	p.t.Helper()
	deadline, bounded := ctx.Deadline()
	if !bounded || time.Until(deadline) > time.Second {
		p.t.Error("native quorum lacks the selected bounded deadline")
	}
	p.calls++
	p.input = input
	if admit == nil {
		p.t.Fatal("transport omitted native admission")
	}
	for range p.admissionCalls {
		if err := admit(ctx, p.actor); err != nil && !p.ignoreAdmissionErr {
			return impersonationpg.QuorumResult{}, err
		}
	}
	return p.result, p.err
}

type quorumRate struct {
	configured bool
	calls      int
	facts      identityhttp.NetworkFacts
	actor      identity.UserID
	retry      time.Duration
	err        error
}

func (r *quorumRate) Configured() bool { return r != nil && r.configured }

func (r *quorumRate) AdmitImpersonationQuorum(ctx context.Context, facts identityhttp.NetworkFacts, actor identity.UserID) (time.Duration, error) {
	r.calls++
	r.facts, r.actor = facts, actor
	if _, bounded := ctx.Deadline(); !bounded {
		return 0, errors.New("private unbounded quota diagnostic")
	}
	return r.retry, r.err
}

func quorumFixture(t testing.TB) (*quorumPort, *quorumRate) {
	t.Helper()
	return &quorumPort{
		t: t, admissionCalls: 1, actor: "read-admin",
		result: impersonationpg.QuorumResult{
			GrantID: startGrantID, RequiredApprovals: 1, Status: impersonation.StatusApproved,
			Approvals: []impersonationpg.QuorumApproval{{ApproverID: "independent-admin", DecidedAt: time.Date(2026, 11, 28, 10, 0, 0, 123000, time.UTC)}},
		},
	}, &quorumRate{configured: true}
}

func quorumConfig(p *quorumPort, rate *quorumRate) impersonationhttp.QuorumConfig {
	start := startConfig(nil)
	return impersonationhttp.QuorumConfig{
		Network: start.Network, OriginalCookieName: start.OriginalCookieName,
		Native: p, Rate: rate, MaximumDuration: start.MaximumDuration,
	}
}

func quorumHandler(t testing.TB, p *quorumPort, rate *quorumRate) (http.Handler, identityhttp.OpenAPIDocument) {
	t.Helper()
	feature, err := impersonationhttp.NewQuorumFeature(quorumConfig(p, rate))
	if err != nil {
		t.Fatal(err)
	}
	handler, document, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal("construct documented quorum handler", err)
	}
	return handler, document
}

func quorumRequest() *http.Request {
	r := startRequest("")
	r.Method = http.MethodGet
	r.URL.Path = "/v1/impersonation/quorum"
	r.URL.RawQuery = "grantID=" + startGrantID
	r.RequestURI = r.URL.RequestURI()
	r.Body = http.NoBody
	r.ContentLength = 0
	r.Header.Del("Content-Type")
	r.Header.Del("Origin")
	r.Header.Del("X-CSRF-Token")
	r.Header.Del("Idempotency-Key")
	return r
}

func serveQuorum(t testing.TB, handler http.Handler, request *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, request)
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("quorum response omitted private-response protections")
	}
	if len(w.Header().Values("Set-Cookie")) != 0 {
		t.Error("quorum read issued or cleared browser credentials")
	}
	public := w.Body.String() + w.Header().Get("Location")
	for _, secret := range []string{startToken(2), startToken(3), "imp1." + startToken(4), startToken(5), "private backend diagnostic", "private unbounded quota diagnostic"} {
		if strings.Contains(public, secret) {
			t.Error("quorum disclosed credentials or backend details")
		}
	}
	return w
}

func assertQuorumFailure(t testing.TB, response *httptest.ResponseRecorder, status int) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("quorum status=%d, want %d", response.Code, status)
	}
	var body map[string]json.RawMessage
	if json.Unmarshal(response.Body.Bytes(), &body) != nil || len(body) != 1 || body["error"] == nil {
		t.Fatal("quorum failure disclosed grant metadata or an alternate result shape")
	}
}

func TestQuorumReadsBodylessHTTP2(t *testing.T) {
	p, rate := quorumFixture(t)
	handler, _ := quorumHandler(t, p, rate)
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/v1/impersonation/quorum?grantID="+startGrantID, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "tenant.example"
	request.AddCookie(&http.Cookie{Name: "__Host-identity_session", Value: startToken(3)})
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal("HTTP/2 quorum request failed")
	}
	defer response.Body.Close()
	if response.ProtoMajor != 2 || response.StatusCode != http.StatusOK {
		t.Fatalf("bodyless HTTPS quorum read: HTTP/%d status=%d", response.ProtoMajor, response.StatusCode)
	}

	request, err = http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/v1/impersonation/quorum?grantID="+startGrantID, strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "tenant.example"
	request.AddCookie(&http.Cookie{Name: "__Host-identity_session", Value: startToken(3)})
	withBody, err := server.Client().Do(request)
	if err != nil {
		t.Fatal("HTTP/2 quorum request with body failed at transport")
	}
	defer withBody.Body.Close()
	if withBody.ProtoMajor != 2 || withBody.StatusCode != http.StatusBadRequest {
		t.Fatalf("HTTPS quorum body rejection: HTTP/%d status=%d", withBody.ProtoMajor, withBody.StatusCode)
	}
}

func TestQuorumDocumentedReadPreservesNativeMetadataAndOriginalCookie(t *testing.T) {
	for _, state := range []struct {
		status    impersonation.Status
		approvals bool
	}{
		{impersonation.StatusPendingApproval, false}, {impersonation.StatusApproved, true},
		{impersonation.StatusActive, true}, {impersonation.StatusStopped, true},
		{impersonation.StatusDenied, false}, {impersonation.StatusRevoked, false},
		{impersonation.StatusRevoked, true}, {impersonation.StatusExpired, false}, {impersonation.StatusExpired, true},
	} {
		t.Run(string(state.status)+"/approvals="+strconv.FormatBool(state.approvals), func(t *testing.T) {
			p, rate := quorumFixture(t)
			p.result.Status = state.status
			if !state.approvals {
				p.result.Approvals = []impersonationpg.QuorumApproval{}
			}
			handler, document := quorumHandler(t, p, rate)
			request := quorumRequest()
			request.AddCookie(&http.Cookie{Name: impersonationhttp.ChildCookieName, Value: "imp1." + startToken(4)})
			request.AddCookie(&http.Cookie{Name: impersonationhttp.ChildCSRFCookieName, Value: startToken(5)})
			response := serveQuorum(t, handler, request)
			if response.Code != http.StatusOK || p.calls != 1 || rate.calls != 1 {
				t.Fatalf("quorum did not read once through required admission: status=%d native=%d quota=%d", response.Code, p.calls, rate.calls)
			}
			if p.input.Tenant != "tenant-a" || p.input.Bearer.Token() != startToken(3) || string(p.input.GrantID) != startGrantID {
				t.Fatal("quorum substituted original cookie, mapped tenant or exact grant")
			}
			if !rate.facts.Valid() || rate.facts.TenantID() != "tenant-a" || rate.facts.ClientIP().String() != "198.51.100.7" || rate.facts.Scheme() != "https" || rate.actor != p.actor {
				t.Fatal("quorum quota received untrusted network facts or another actor")
			}
			var decoded impersonationpg.QuorumResult
			var fields map[string]json.RawMessage
			if json.Unmarshal(response.Body.Bytes(), &decoded) != nil || !reflect.DeepEqual(decoded, p.result) || json.Unmarshal(response.Body.Bytes(), &fields) != nil || len(fields) != 4 {
				t.Fatal("quorum response changed or extended native safe metadata")
			}
			operations := document.Operations()
			if len(operations) != 1 || operations[0].Record.OperationID != "identity.impersonation.quorum" || operations[0].Route.Method != http.MethodGet || operations[0].Route.Path != "/v1/impersonation/quorum" || operations[0].Record.CSRFOrigin.Mode != identityhttp.CSRFNone || operations[0].Record.RatePolicy != "rate.admin" || operations[0].Record.Idempotency != "read" {
				t.Fatal("document and executable quorum read disagree")
			}
			if response.Header().Get("Retry-After") != "" {
				t.Error("successful quorum advertised a quota retry")
			}
		})
	}
}

func TestQuorumRejectsMalformedOrAlternateChannelsBeforeNativeWork(t *testing.T) {
	for name, change := range map[string]func(*http.Request){
		"missing-grant":       func(r *http.Request) { r.URL.RawQuery = "" },
		"empty-query":         func(r *http.Request) { r.URL.RawQuery = ""; r.URL.ForceQuery = true },
		"empty-grant":         func(r *http.Request) { r.URL.RawQuery = "grantID=" },
		"invalid-grant":       func(r *http.Request) { r.URL.RawQuery = "grantID=not-native-id" },
		"zero-grant":          func(r *http.Request) { r.URL.RawQuery = "grantID=AAAAAAAAAAAAAAAAAAAAAA" },
		"noncanonical-grant":  func(r *http.Request) { r.URL.RawQuery = "grantID=AAAAAAAAAAAAAAAAAAAAAR" },
		"grant-case":          func(r *http.Request) { r.URL.RawQuery = "grantId=" + startGrantID },
		"duplicate-grant":     func(r *http.Request) { r.URL.RawQuery += "&grantID=" + startGrantID },
		"extra-query":         func(r *http.Request) { r.URL.RawQuery += "&actorID=other" },
		"query-credential":    func(r *http.Request) { r.URL.RawQuery += "&bearer=" + startToken(3) },
		"query-csrf":          func(r *http.Request) { r.URL.RawQuery += "&csrf_token=" + startToken(2) },
		"malformed-escape":    func(r *http.Request) { r.URL.RawQuery += "%" },
		"trailing-separator":  func(r *http.Request) { r.URL.RawQuery += "&" },
		"authorization":       func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+startToken(3)) },
		"empty-authorization": func(r *http.Request) { r.Header.Set("Authorization", "") },
		"retry-key":           func(r *http.Request) { r.Header.Set("Idempotency-Key", startKey) },
		"empty-retry-key":     func(r *http.Request) { r.Header.Set("Idempotency-Key", "") },
		"duplicate-cookie": func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: "__Host-identity_session", Value: startToken(3)})
		},
		"missing-cookie": func(r *http.Request) { r.Header.Del("Cookie") },
		"child-only": func(r *http.Request) {
			r.Header.Del("Cookie")
			r.AddCookie(&http.Cookie{Name: impersonationhttp.ChildCookieName, Value: "imp1." + startToken(4)})
		},
		"json-body": func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(`{}`))
			r.ContentLength = 2
			r.Header.Set("Content-Type", "application/json")
		},
		"unknown-length-body": func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(`{}`))
			r.ContentLength = -1
		},
		"trailer": func(r *http.Request) { r.Trailer = http.Header{"GrantID": []string{startGrantID}} },
	} {
		t.Run(name, func(t *testing.T) {
			p, rate := quorumFixture(t)
			handler, _ := quorumHandler(t, p, rate)
			request := quorumRequest()
			change(request)
			response := serveQuorum(t, handler, request)
			if response.Code < 400 || p.calls != 0 || rate.calls != 0 {
				t.Fatalf("invalid quorum input reached native read: status=%d native=%d quota=%d", response.Code, p.calls, rate.calls)
			}
		})
	}
}

func TestQuorumRejectsUnmappedOrInsecureFactsAndWrongRoutes(t *testing.T) {
	for name, change := range map[string]func(*http.Request){
		"cleartext":        func(r *http.Request) { r.TLS = nil },
		"unknown-host":     func(r *http.Request) { r.Host = "other.example" },
		"spoofed-https":    func(r *http.Request) { r.TLS = nil; r.Header.Set("X-Forwarded-Proto", "https") },
		"trailing-slash":   func(r *http.Request) { r.URL.Path += "/" },
		"escaped-path":     func(r *http.Request) { r.URL.RawPath = "/v1/impersonation/%71uorum" },
		"wrong-method":     func(r *http.Request) { r.Method = http.MethodPost },
		"unselected-start": func(r *http.Request) { r.Method = http.MethodPost; r.URL.Path = "/v1/impersonation/start" },
	} {
		t.Run(name, func(t *testing.T) {
			p, rate := quorumFixture(t)
			handler, _ := quorumHandler(t, p, rate)
			request := quorumRequest()
			change(request)
			response := serveQuorum(t, handler, request)
			if response.Code < 400 || p.calls != 0 || rate.calls != 0 {
				t.Fatal("wrong route or untrusted network reached native quorum", response.Code)
			}
		})
	}
}

func TestQuorumFailsClosedWhenNativeAdmissionIsBypassedRepeatedOrInvalid(t *testing.T) {
	for _, tc := range []struct {
		name  string
		calls int
		actor identity.UserID
	}{
		{"bypassed", 0, "read-admin"}, {"repeated", 2, "read-admin"}, {"missing-actor", 1, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, rate := quorumFixture(t)
			p.admissionCalls, p.actor, p.ignoreAdmissionErr = tc.calls, tc.actor, true
			handler, _ := quorumHandler(t, p, rate)
			response := serveQuorum(t, handler, quorumRequest())
			assertQuorumFailure(t, response, http.StatusServiceUnavailable)
			if p.calls != 1 || rate.calls > 1 {
				t.Fatal("transport retried native read or repeated quota debit")
			}
		})
	}
}

func TestQuorumMapsNativeDenialAndBackendFailureWithoutMetadata(t *testing.T) {
	for name, tc := range map[string]struct {
		err    error
		status int
	}{
		"unauthenticated": {session.ErrUnauthenticated, http.StatusForbidden},
		"forbidden":       {identity.ForbiddenError{}, http.StatusForbidden},
		"backend":         {errors.New("private backend diagnostic"), http.StatusServiceUnavailable},
		"deadline":        {context.DeadlineExceeded, http.StatusServiceUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			p, rate := quorumFixture(t)
			p.err, p.admissionCalls = tc.err, 0
			handler, _ := quorumHandler(t, p, rate)
			response := serveQuorum(t, handler, quorumRequest())
			assertQuorumFailure(t, response, tc.status)
			if p.calls != 1 || rate.calls != 0 {
				t.Fatal("native denial consumed quota or caused a retry")
			}
		})
	}
}

func TestQuorumCancelledRequestDoesNotReachNativeReadOrQuota(t *testing.T) {
	p, rate := quorumFixture(t)
	handler, _ := quorumHandler(t, p, rate)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	response := serveQuorum(t, handler, quorumRequest().WithContext(ctx))
	assertQuorumFailure(t, response, http.StatusServiceUnavailable)
	if p.calls != 0 || rate.calls != 0 {
		t.Fatal("cancelled quorum request reached native read or quota")
	}
}

func TestQuorumQuotaOnlyPublishesBoundedWholeSecondRetryAfter(t *testing.T) {
	for _, tc := range []struct {
		name   string
		retry  time.Duration
		err    error
		status int
		header string
	}{
		{"minimum", time.Second, identityhttp.ErrRateLimited, 429, "1"},
		{"maximum", time.Minute, identityhttp.ErrRateLimited, 429, "60"},
		{"missing-hint", 0, identityhttp.ErrRateLimited, 503, ""},
		{"fractional-hint", 1500 * time.Millisecond, identityhttp.ErrRateLimited, 503, ""},
		{"negative-hint", -time.Second, identityhttp.ErrRateLimited, 503, ""},
		{"excessive-hint", time.Minute + time.Second, identityhttp.ErrRateLimited, 503, ""},
		{"unknown-quota", 0, errors.New("private backend diagnostic"), 503, ""},
		{"hint-without-denial", time.Second, nil, 503, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, ignoreError := range []bool{false, true} {
				p, rate := quorumFixture(t)
				p.ignoreAdmissionErr = ignoreError
				rate.retry, rate.err = tc.retry, tc.err
				handler, _ := quorumHandler(t, p, rate)
				response := serveQuorum(t, handler, quorumRequest())
				assertQuorumFailure(t, response, tc.status)
				if p.calls != 1 || rate.calls != 1 || response.Header().Get("Retry-After") != tc.header {
					t.Fatal("quota failure was retried, ignored, or published an unsafe retry hint")
				}
			}
		})
	}
}

func TestQuorumRejectsMalformedNativeMetadata(t *testing.T) {
	for name, change := range map[string]func(*impersonationpg.QuorumResult){
		"wrong-grant":               func(r *impersonationpg.QuorumResult) { r.GrantID = "AAAAAAAAAAAAAAAAAAAABA" },
		"missing-grant":             func(r *impersonationpg.QuorumResult) { r.GrantID = "" },
		"missing-policy":            func(r *impersonationpg.QuorumResult) { r.RequiredApprovals = 0 },
		"different-policy":          func(r *impersonationpg.QuorumResult) { r.RequiredApprovals = 2 },
		"missing-approvals":         func(r *impersonationpg.QuorumResult) { r.Approvals = nil },
		"approved-without-decision": func(r *impersonationpg.QuorumResult) { r.Approvals = []impersonationpg.QuorumApproval{} },
		"pending-with-decision":     func(r *impersonationpg.QuorumResult) { r.Status = impersonation.StatusPendingApproval },
		"denied-with-decision":      func(r *impersonationpg.QuorumResult) { r.Status = impersonation.StatusDenied },
		"too-many-decisions":        func(r *impersonationpg.QuorumResult) { r.Approvals = append(r.Approvals, r.Approvals[0]) },
		"missing-approver":          func(r *impersonationpg.QuorumResult) { r.Approvals[0].ApproverID = "" },
		"missing-decision-time":     func(r *impersonationpg.QuorumResult) { r.Approvals[0].DecidedAt = time.Time{} },
		"unknown-status":            func(r *impersonationpg.QuorumResult) { r.Status = "unknown" },
		"nonretained-status":        func(r *impersonationpg.QuorumResult) { r.Status = impersonation.StatusRequested },
	} {
		t.Run(name, func(t *testing.T) {
			p, rate := quorumFixture(t)
			change(&p.result)
			handler, _ := quorumHandler(t, p, rate)
			response := serveQuorum(t, handler, quorumRequest())
			assertQuorumFailure(t, response, http.StatusServiceUnavailable)
			if p.calls != 1 || rate.calls != 1 {
				t.Fatal("malformed receipt caused a native or quota retry")
			}
		})
	}
}

func TestQuorumSelectionRequiresNativeQuotaAndBoundedHTTPSCookieConfiguration(t *testing.T) {
	for name, change := range map[string]func(*impersonationhttp.QuorumConfig){
		"nil-native":         func(c *impersonationhttp.QuorumConfig) { c.Native = nil },
		"typed-nil-native":   func(c *impersonationhttp.QuorumConfig) { c.Native = (*quorumPort)(nil) },
		"nil-rate":           func(c *impersonationhttp.QuorumConfig) { c.Rate = nil },
		"typed-nil-rate":     func(c *impersonationhttp.QuorumConfig) { c.Rate = (*quorumRate)(nil) },
		"unconfigured-rate":  func(c *impersonationhttp.QuorumConfig) { c.Rate = &quorumRate{} },
		"missing-network":    func(c *impersonationhttp.QuorumConfig) { c.Network = identityhttp.NetworkConfig{} },
		"missing-cookie":     func(c *impersonationhttp.QuorumConfig) { c.OriginalCookieName = "" },
		"ordinary-cookie":    func(c *impersonationhttp.QuorumConfig) { c.OriginalCookieName = "identity_session" },
		"child-cookie":       func(c *impersonationhttp.QuorumConfig) { c.OriginalCookieName = impersonationhttp.ChildCookieName },
		"child-csrf-cookie":  func(c *impersonationhttp.QuorumConfig) { c.OriginalCookieName = impersonationhttp.ChildCSRFCookieName },
		"missing-duration":   func(c *impersonationhttp.QuorumConfig) { c.MaximumDuration = 0 },
		"excessive-duration": func(c *impersonationhttp.QuorumConfig) { c.MaximumDuration = 31 * time.Second },
	} {
		t.Run(name, func(t *testing.T) {
			p, rate := quorumFixture(t)
			config := quorumConfig(p, rate)
			change(&config)
			if _, err := impersonationhttp.NewQuorumFeature(config); err == nil {
				t.Fatal("quorum accepted incomplete or unsafe ownership configuration")
			}
		})
	}
}

func FuzzQuorumClosedGrantQuery(f *testing.F) {
	for _, query := range []string{
		"grantID=" + startGrantID, "", "grantID=", "grantID=%", "grantId=" + startGrantID,
		"grantID=" + startGrantID + "&grantID=" + startGrantID,
		"grantID=" + startGrantID + "&actorID=other",
	} {
		f.Add(query)
	}
	f.Fuzz(func(t *testing.T, query string) {
		if len(query) > 1024 {
			return
		}
		p, rate := quorumFixture(t)
		handler, _ := quorumHandler(t, p, rate)
		request := quorumRequest()
		request.URL.RawQuery = query
		response := serveQuorum(t, handler, request)
		if response.Code != http.StatusOK {
			return
		}
		values, err := url.ParseQuery(query)
		grant, parseErr := identity.ParseCommandID(values.Get("grantID"))
		if err != nil || parseErr != nil || len(values) != 1 || len(values["grantID"]) != 1 || string(grant) != startGrantID || p.calls != 1 || rate.calls != 1 {
			t.Fatal("quorum accepted a malformed, ambiguous or extended grant query")
		}
	})
}
