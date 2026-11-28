package impersonationhttp_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
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

const (
	denyReason = "private independent denial decision"
	denyBody   = `{"grantID":"` + startGrantID + `","expectedVersion":1,"reason":"` + denyReason + `"}`
)

// Zero preparation deliberately has no service-owned custody. Successful
// denial, replay and quota are exercised with the native owner in Reference.
type denyPort struct {
	t            testing.TB
	input        impersonationpg.DenyInput
	csrf         string
	prepared     int
	executed     int
	prepareError error
}

func (p *denyPort) PrepareDenial(ctx context.Context, input impersonationpg.DenyInput) (impersonationpg.PreparedCommand, error) {
	p.t.Helper()
	deadline, bounded := ctx.Deadline()
	if !bounded || time.Until(deadline) > time.Second {
		p.t.Error("native denial lacks the selected bounded deadline")
	}
	p.prepared++
	p.input = input
	p.csrf, _ = input.Authentication.CSRF.Reveal()
	if p.csrf != startToken(2) {
		return impersonationpg.PreparedCommand{}, session.ErrCSRFDenied
	}
	return impersonationpg.PreparedCommand{}, p.prepareError
}

func (p *denyPort) Execute(context.Context, impersonationpg.PreparedCommand) (identity.CommandResult, error) {
	p.executed++
	return identity.CommandResult{}, errors.New("private backend diagnostic")
}

type denyRate struct {
	configured bool
	calls      int
}

func (r *denyRate) Configured() bool { return r != nil && r.configured }

func (r *denyRate) AdmitImpersonationDeny(context.Context, identityhttp.NetworkFacts, identity.UserID) (time.Duration, error) {
	r.calls++
	return 0, nil
}

func denyConfig(p *denyPort, rate *denyRate) impersonationhttp.DenyConfig {
	start := startConfig(nil)
	return impersonationhttp.DenyConfig{
		Network: start.Network, TrustedOrigins: start.TrustedOrigins,
		OriginalCookieName: start.OriginalCookieName, Native: p, Rate: rate,
		MaximumDuration: start.MaximumDuration,
	}
}

func denyHandler(t testing.TB, p *denyPort, rate *denyRate) http.Handler {
	t.Helper()
	feature, err := impersonationhttp.NewDenyFeature(denyConfig(p, rate))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func denyRequest(body string) *http.Request {
	r := startRequest(body)
	r.URL.Path = "/v1/impersonation/deny"
	r.RequestURI = r.URL.RequestURI()
	r.Header.Del("Idempotency-Key")
	return r
}

func serveDeny(t testing.TB, h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("denial response can be cached")
	}
	if len(w.Header().Values("Set-Cookie")) != 0 {
		t.Error("denial changed browser credentials")
	}
	public := w.Body.String() + w.Header().Get("Location")
	for _, secret := range []string{denyReason, startToken(2), startToken(3), "imp1." + startToken(4), startToken(5), "private backend diagnostic"} {
		if strings.Contains(public, secret) {
			t.Error("denial disclosed a private reason, credential or backend detail")
		}
	}
	return w
}

func TestDenyPreservesOriginalIntentButRejectsUnownedPreparationBeforeRateAndExecute(t *testing.T) {
	p := &denyPort{t: t}
	rate := &denyRate{configured: true}
	r := denyRequest(denyBody)
	r.AddCookie(&http.Cookie{Name: impersonationhttp.ChildCookieName, Value: "imp1." + startToken(4)})
	r.AddCookie(&http.Cookie{Name: impersonationhttp.ChildCSRFCookieName, Value: startToken(5)})
	w := serveDeny(t, denyHandler(t, p, rate), r)
	if w.Code != http.StatusServiceUnavailable || p.prepared != 1 || p.executed != 0 || rate.calls != 0 {
		t.Fatalf("unowned preparation became usable: status=%d prepared=%d executed=%d rate=%d", w.Code, p.prepared, p.executed, rate.calls)
	}
	if p.input.Authentication.Tenant != "tenant-a" || p.input.Authentication.Bearer.Token() != startToken(3) || p.csrf != startToken(2) ||
		string(p.input.GrantID) != startGrantID || p.input.ExpectedVersion != 1 || p.input.Reason.StorageText() != denyReason || p.input.Network != "198.51.100.7" {
		t.Fatal("denial substituted original actor custody, grant intent, private reason or trusted network")
	}
	if _, err := identity.ParseCommandID(string(p.input.CommandID)); err != nil || string(p.input.CommandID) == startGrantID {
		t.Fatal("denial did not generate its own canonical command distinct from the grant")
	}
}

func TestDenyPreparationFailuresRemainPrivateAndDoNotConsumeRate(t *testing.T) {
	for name, test := range map[string]struct {
		err    error
		status int
	}{
		"unauthenticated": {session.ErrUnauthenticated, http.StatusForbidden},
		"csrf":            {session.ErrCSRFDenied, http.StatusForbidden},
		"forbidden":       {identity.ForbiddenError{}, http.StatusForbidden},
		"conflict":        {impersonation.ErrConflict, http.StatusConflict},
		"unavailable":     {errors.New("private backend diagnostic"), http.StatusServiceUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			p := &denyPort{t: t, prepareError: test.err}
			rate := &denyRate{configured: true}
			w := serveDeny(t, denyHandler(t, p, rate), denyRequest(denyBody))
			if w.Code != test.status || p.prepared != 1 || p.executed != 0 || rate.calls != 0 {
				t.Fatalf("failed preparation reached admission or execution: status=%d want=%d", w.Code, test.status)
			}
		})
	}
}

func TestDenyRejectsMalformedClosedIntentBeforeNativeWork(t *testing.T) {
	for _, body := range []string{
		"", `null`, `[]`, `{}`, `{"grantID":"` + startGrantID + `","expectedVersion":1}`,
		`{"grantID":"not-native-id","expectedVersion":1,"reason":"` + denyReason + `"}`,
		`{"grantID":"AAAAAAAAAAAAAAAAAAAAAA","expectedVersion":1,"reason":"` + denyReason + `"}`,
		strings.Replace(denyBody, `"expectedVersion":1`, `"expectedVersion":0`, 1),
		strings.Replace(denyBody, `"expectedVersion":1`, `"expectedVersion":2`, 1),
		strings.Replace(denyBody, `"expectedVersion":1`, `"expectedVersion":"1"`, 1),
		strings.Replace(denyBody, `"expectedVersion":1`, `"expectedVersion":1.0`, 1),
		strings.Replace(denyBody, `"expectedVersion":1`, `"expectedVersion":1e0`, 1),
		strings.Replace(denyBody, `"expectedVersion":1`, `"expectedVersion":1,"expectedVersion":1`, 1),
		strings.Replace(denyBody, `"grantID"`, `"grantId"`, 1),
		strings.Replace(denyBody, `"reason"`, `"Reason"`, 1),
		strings.Replace(denyBody, denyReason, "", 1),
		strings.Replace(denyBody, denyReason, " \\t", 1),
		strings.Replace(denyBody, denyReason, strings.Repeat("x", 1025), 1),
		strings.TrimSuffix(denyBody, "}") + `,"actorID":"other"}`,
		strings.TrimSuffix(denyBody, "}") + `,"commandID":"forged"}`,
		strings.TrimSuffix(denyBody, "}") + `,"csrf_token":"alternate"}`,
		strings.TrimSuffix(denyBody, "}") + `,"Idempotency-Key":"alternate"}`,
		denyBody + `{}`,
	} {
		t.Run(body, func(t *testing.T) {
			p := &denyPort{t: t}
			rate := &denyRate{configured: true}
			w := serveDeny(t, denyHandler(t, p, rate), denyRequest(body))
			if w.Code != http.StatusBadRequest || p.prepared != 0 || p.executed != 0 || rate.calls != 0 {
				t.Fatalf("malformed denial reached native work: status=%d", w.Code)
			}
		})
	}
}

func TestDenyRejectsAlternateChannelsBeforeNativeWork(t *testing.T) {
	for name, change := range map[string]func(*http.Request){
		"authorization": func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+startToken(3)) },
		"query":         func(r *http.Request) { r.URL.RawQuery = "grantID=" + startGrantID },
		"empty-query":   func(r *http.Request) { r.URL.ForceQuery = true },
		"trailer":       func(r *http.Request) { r.Trailer = http.Header{"X-CSRF-Token": []string{startToken(2)}} },
		"retry-key":     func(r *http.Request) { r.Header.Set("Idempotency-Key", startKey) },
		"empty-key":     func(r *http.Request) { r.Header.Set("Idempotency-Key", "") },
		"duplicate-parent": func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: "__Host-identity_session", Value: startToken(3)})
		},
		"duplicate-csrf": func(r *http.Request) { r.Header.Add("X-CSRF-Token", startToken(2)) },
		"form-body":      func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") },
	} {
		t.Run(name, func(t *testing.T) {
			p := &denyPort{t: t}
			rate := &denyRate{configured: true}
			r := denyRequest(denyBody)
			change(r)
			w := serveDeny(t, denyHandler(t, p, rate), r)
			if w.Code < 400 || p.prepared != 0 || p.executed != 0 || rate.calls != 0 {
				t.Fatalf("alternate input channel reached native denial: status=%d", w.Code)
			}
		})
	}
}

func TestDenyBoundsPrivateReasonWithoutTrimmingIt(t *testing.T) {
	for _, reason := range []string{"  private decision  ", strings.Repeat("x", 1024), strings.Repeat("x", 1025)} {
		p := &denyPort{t: t}
		rate := &denyRate{configured: true}
		config := denyConfig(p, rate)
		config.Network.Limits.MaximumBodyBytes = 4096
		config.Network.Limits.MaximumDecodedBytes = 4096
		feature, err := impersonationhttp.NewDenyFeature(config)
		if err != nil {
			t.Fatal(err)
		}
		handler, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
		if err != nil {
			t.Fatal(err)
		}
		body := strings.Replace(denyBody, denyReason, reason, 1)
		w := serveDeny(t, handler, denyRequest(body))
		if len(reason) <= 1024 {
			if w.Code != http.StatusServiceUnavailable || p.prepared != 1 || p.input.Reason.StorageText() != reason {
				t.Fatal("valid bounded reason was rejected or normalized")
			}
		} else if w.Code != http.StatusBadRequest || p.prepared != 0 {
			t.Fatal("oversized private reason crossed the native boundary")
		}
		if p.executed != 0 || rate.calls != 0 || strings.Contains(w.Body.String(), reason) {
			t.Fatal("private reason escaped or unowned preparation reached protected work")
		}
	}
}

func TestDenyRequiresOriginalOrdinaryCookieAndExactHTTPSOrigin(t *testing.T) {
	for name, change := range map[string]func(*http.Request){
		"missing-parent":     func(r *http.Request) { r.Header.Del("Cookie") },
		"missing-origin":     func(r *http.Request) { r.Header.Del("Origin") },
		"referer-only":       func(r *http.Request) { r.Header.Del("Origin"); r.Header.Set("Referer", "https://tenant.example/page") },
		"foreign-origin":     func(r *http.Request) { r.Header.Set("Origin", "https://other.example") },
		"http-origin":        func(r *http.Request) { r.Header.Set("Origin", "http://tenant.example") },
		"duplicate-origin":   func(r *http.Request) { r.Header.Add("Origin", "https://tenant.example") },
		"missing-csrf":       func(r *http.Request) { r.Header.Del("X-CSRF-Token") },
		"malformed-csrf":     func(r *http.Request) { r.Header.Set("X-CSRF-Token", "not-a-token") },
		"wrong-host":         func(r *http.Request) { r.Host = "other.example" },
		"insecure-transport": func(r *http.Request) { r.TLS = nil },
		"child-is-not-parent": func(r *http.Request) {
			r.Header.Del("Cookie")
			r.AddCookie(&http.Cookie{Name: impersonationhttp.ChildCookieName, Value: "imp1." + startToken(4)})
			r.AddCookie(&http.Cookie{Name: impersonationhttp.ChildCSRFCookieName, Value: startToken(5)})
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := &denyPort{t: t}
			rate := &denyRate{configured: true}
			r := denyRequest(denyBody)
			change(r)
			w := serveDeny(t, denyHandler(t, p, rate), r)
			if w.Code < 400 || p.prepared != 0 || p.executed != 0 || rate.calls != 0 {
				t.Fatalf("untrusted or substituted actor reached native denial: status=%d", w.Code)
			}
		})
	}
	p := &denyPort{t: t}
	rate := &denyRate{configured: true}
	r := denyRequest(denyBody)
	r.Header.Set("X-CSRF-Token", startToken(5))
	r.AddCookie(&http.Cookie{Name: impersonationhttp.ChildCookieName, Value: "imp1." + startToken(4)})
	r.AddCookie(&http.Cookie{Name: impersonationhttp.ChildCSRFCookieName, Value: startToken(5)})
	w := serveDeny(t, denyHandler(t, p, rate), r)
	if w.Code != http.StatusForbidden || p.prepared != 1 || p.executed != 0 || rate.calls != 0 {
		t.Fatal("child synchronizer substituted for original session authorization")
	}
}

func TestDenyRequiresConfiguredNativeAndRateOwners(t *testing.T) {
	p := &denyPort{t: t}
	rate := &denyRate{configured: true}
	for name, change := range map[string]func(*impersonationhttp.DenyConfig){
		"nil-native":    func(c *impersonationhttp.DenyConfig) { c.Native = nil },
		"typed-native":  func(c *impersonationhttp.DenyConfig) { c.Native = (*denyPort)(nil) },
		"nil-rate":      func(c *impersonationhttp.DenyConfig) { c.Rate = nil },
		"typed-rate":    func(c *impersonationhttp.DenyConfig) { c.Rate = (*denyRate)(nil) },
		"disabled-rate": func(c *impersonationhttp.DenyConfig) { c.Rate = &denyRate{} },
		"child-cookie":  func(c *impersonationhttp.DenyConfig) { c.OriginalCookieName = impersonationhttp.ChildCookieName },
		"no-deadline":   func(c *impersonationhttp.DenyConfig) { c.MaximumDuration = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			config := denyConfig(p, rate)
			change(&config)
			if _, err := impersonationhttp.NewDenyFeature(config); err == nil {
				t.Fatal("denial selected an absent owner or unsafe ingress profile")
			}
		})
	}
	if p.prepared != 0 || p.executed != 0 || rate.calls != 0 {
		t.Fatal("construction performed native work or consumed rate")
	}
}

func TestDenySelectionMatchesItsExactPostRouteAndOpenAPI(t *testing.T) {
	p := &denyPort{t: t}
	rate := &denyRate{configured: true}
	feature, err := impersonationhttp.NewDenyFeature(denyConfig(p, rate))
	if err != nil {
		t.Fatal(err)
	}
	handler, doc, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil || doc.Version() != "3.1.1" {
		t.Fatal("selected denial is not OpenAPI composable", err)
	}
	ops := doc.Operations()
	if len(ops) != 1 || ops[0].Record.OperationID != "identity.impersonation.deny" || ops[0].Record.Idempotency != "repeat" {
		t.Fatal("standalone denial advertised a different operation or retry contract")
	}
	var document struct {
		Paths map[string]map[string]struct {
			Responses map[string]struct {
				Content map[string]struct {
					Schema struct {
						Constant string `json:"const"`
					}
				}
			}
		}
	}
	if err := json.Unmarshal(doc.JSON(), &document); err != nil {
		t.Fatal(err)
	}
	forbidden := document.Paths["/v1/impersonation/deny"]["post"].Responses["403"].Content
	if _, ok := forbidden["application/json"]; !ok || forbidden["text/plain"].Schema.Constant != "identity.http.origin_denied\n" {
		t.Fatal("denial does not document both its JSON rejection and the shared CORS guard's rejection")
	}
	for _, path := range []string{"/v1/impersonation/deny/", "/v1/impersonation/start", "/v1/impersonation/stop", "/v1/impersonation/revoke"} {
		r := denyRequest(denyBody)
		r.URL.Path = path
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusNotFound || p.prepared != 0 || rate.calls != 0 || p.executed != 0 || len(w.Header().Values("Set-Cookie")) != 0 {
			t.Fatal("unselected route reached native denial or changed credentials", path)
		}
	}
	r := denyRequest(denyBody)
	r.Method = http.MethodGet
	if w := serveDeny(t, handler, r); w.Code != http.StatusMethodNotAllowed || p.prepared != 0 {
		t.Fatal("non-POST denial reached native work")
	}
}

func TestStartStopDenySelectionDispatchesOnlyItsThreeOwners(t *testing.T) {
	start := &startPort{t: t, outcome: identity.CommitOutcomeCommitted}
	stop := &stopPort{t: t, outcome: identity.CommitOutcomeCommitted}
	deny := &denyPort{t: t}
	rate := &denyRate{configured: true}
	feature, err := impersonationhttp.NewStartStopDenyFeature(startConfig(start), stop, deny, rate)
	if err != nil {
		t.Fatal(err)
	}
	handler, doc, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil || doc.Version() != "3.1.1" {
		t.Fatal("combined Start, Stop and Deny are not OpenAPI composable", err)
	}
	want := map[string]string{"identity.impersonation.start": "keyed", "identity.impersonation.stop": "repeat", "identity.impersonation.deny": "repeat"}
	if len(doc.Operations()) != len(want) {
		t.Fatal("combined selection advertised a different operation set")
	}
	for _, op := range doc.Operations() {
		if want[op.Record.OperationID] != op.Record.Idempotency {
			t.Fatal("combined selection changed its operation or retry contract")
		}
		delete(want, op.Record.OperationID)
	}
	if len(want) != 0 {
		t.Fatal("combined selection omitted an operation")
	}
	if w := serveStart(t, handler, startRequest(startBody)); w.Code != http.StatusOK || start.calls != 1 || stop.prepared != 0 || deny.prepared != 0 {
		t.Fatal("combined Start reached the wrong owner")
	}
	if w := serveStop(t, handler, stopRequest(`{}`, true)); w.Code != http.StatusOK || start.calls != 1 || stop.executed != 1 || deny.prepared != 0 {
		t.Fatal("combined Stop reached the wrong owner")
	}
	if w := serveDeny(t, handler, denyRequest(denyBody)); w.Code != http.StatusServiceUnavailable || start.calls != 1 || stop.executed != 1 || deny.prepared != 1 || deny.executed != 0 || rate.calls != 0 {
		t.Fatal("combined Deny reached the wrong owner or trusted unowned preparation")
	}
}

func FuzzDenyClosedBody(f *testing.F) {
	for _, seed := range []string{denyBody, `{}`, denyBody + `{}`, `{"grantID":"a","expectedVersion":1,"reason":"x"}`, strings.Replace(denyBody, `"reason"`, `"Reason"`, 1)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 1025 {
			return
		}
		p := &denyPort{t: t}
		rate := &denyRate{configured: true}
		w := serveDeny(t, denyHandler(t, p, rate), denyRequest(body))
		if p.executed != 0 || rate.calls != 0 || w.Code < 400 {
			t.Fatal("unowned or invalid denial reached rate, execution or success")
		}
		if p.prepared == 0 {
			return
		}
		var fields map[string]json.RawMessage
		var grant, reason string
		if json.Unmarshal([]byte(body), &fields) != nil || len(fields) != 3 ||
			json.Unmarshal(fields["grantID"], &grant) != nil || json.Unmarshal(fields["reason"], &reason) != nil ||
			strings.TrimSpace(string(fields["expectedVersion"])) != "1" || p.prepared != 1 {
			t.Fatal("malformed closed intent reached native denial")
		}
		if _, err := identity.ParseCommandID(grant); err != nil {
			t.Fatal("noncanonical grant reached native denial")
		}
		if _, err := impersonation.NewReason(reason); err != nil || reason != p.input.Reason.StorageText() || grant != string(p.input.GrantID) {
			t.Fatal("invalid or substituted reason or grant reached native denial")
		}
	})
}
