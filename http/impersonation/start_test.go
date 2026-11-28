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

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	impersonationhttp "github.com/faustbrian/go-identity/http/impersonation"
	impersonationpg "github.com/faustbrian/go-identity/impersonation/postgres"
	"github.com/faustbrian/go-identity/session"
)

const (
	startGrantID   = "AAAAAAAAAAAAAAAAAAAAAQ"
	startCommandID = "AgICAgICAgICAgICAgICAg"
	startBody      = `{"grantID":"` + startGrantID + `","expectedVersion":2}`
	startKey       = "Start_retry.MiXeD_+-.~"
)

// The native boundary can return a historical commit without either one-shot
// secret. Real first-issuance custody is exercised by the Reference consumer.
type startPort struct {
	t             testing.TB
	input         impersonationpg.KeyedStartInput
	csrf          string
	calls         int
	outcome       identity.CommitOutcome
	err           error
	changeReceipt func(*identity.CommandResult)
}

func (p *startPort) Start(ctx context.Context, input impersonationpg.KeyedStartInput) (impersonationpg.StoppableActivationResult, error) {
	p.t.Helper()
	deadline, bounded := ctx.Deadline()
	if !bounded || time.Until(deadline) > time.Second {
		p.t.Error("native start lacks the selected bounded deadline")
	}
	p.calls++
	p.input = input
	p.csrf, _ = input.Authentication.CSRF.Reveal()
	if p.csrf != startToken(2) {
		return impersonationpg.StoppableActivationResult{}, session.ErrCSRFDenied
	}
	op := identity.FeatureOperation{
		Owner: "identity/impersonation", OperationID: "identity.impersonation.start",
		SchemaID: "impersonation-start", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired,
	}
	r := identity.CommandResult{
		Binding: identity.CommandBinding{
			CommandID: startCommandID, TenantID: "tenant-a", UserID: "target-user",
			ActorID: "request-admin", ActorKind: authorization.SubjectUser,
			OperationID: op.OperationID, PolicyID: "impersonation-policy", PolicyVersion: 1,
			SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion,
			CorrelationID: startCommandID, RecordID: startGrantID,
		},
		Outcome: p.outcome,
		Feature: &identity.FeatureReceipt{Operation: op},
	}
	if p.outcome == identity.CommitOutcomeCommitted {
		r.AuditEventID = "audit-start"
		r.Feature.BeforeVersion, r.Feature.AfterVersion = 2, 3
	}
	if p.outcome == identity.CommitOutcomeInProgress {
		r.RetryAfter = time.Second
	}
	if err := r.Validate(); err != nil {
		p.t.Fatal("invalid baseline native start receipt", err)
	}
	if p.changeReceipt != nil {
		p.changeReceipt(&r)
	}
	return impersonationpg.StoppableActivationResult{ActivationResult: impersonationpg.ActivationResult{Receipt: r}}, p.err
}

func startToken(value byte) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat(string([]byte{value}), 32)))
}

func startConfig(p *startPort) impersonationhttp.StartConfig {
	return impersonationhttp.StartConfig{
		Network: identityhttp.NetworkConfig{
			Limits:               identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 1024, MaximumBodyBytes: 1024, MaximumDecodedBytes: 1024, MaximumFields: 32, MaximumDepth: 4},
			MaximumForwardedHops: 1,
			TenantHosts:          []identityhttp.TenantHost{{Host: "tenant.example", TenantID: "tenant-a"}},
		},
		TrustedOrigins:     []identityhttp.Origin{"https://tenant.example"},
		OriginalCookieName: "__Host-identity_session", Native: p, MaximumDuration: time.Second,
	}
}

func startHandler(t testing.TB, p *startPort) http.Handler {
	t.Helper()
	feature, err := impersonationhttp.NewStartFeature(startConfig(p))
	if err != nil {
		t.Fatal(err)
	}
	h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func startRequest(body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/v1/impersonation/start", strings.NewReader(body))
	r.Host = "tenant.example"
	r.RemoteAddr = "198.51.100.7:1234"
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://tenant.example")
	r.Header.Set("Idempotency-Key", startKey)
	r.Header.Set("X-CSRF-Token", startToken(2))
	r.AddCookie(&http.Cookie{Name: "__Host-identity_session", Value: startToken(3)})
	return r
}

func serveStart(t testing.TB, h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("start response can be cached")
	}
	if len(w.Header().Values("Set-Cookie")) != 0 {
		t.Error("receipt-only or rejected start altered browser credentials")
	}
	for _, secret := range []string{startKey, startToken(2), startToken(3), "imp1." + startToken(4), startToken(5), "private backend diagnostic"} {
		if strings.Contains(w.Body.String(), secret) || strings.Contains(w.Header().Get("Location"), secret) {
			t.Error("start response disclosed a credential, retry key or backend detail")
		}
	}
	return w
}

func TestStartMetadataReplayPreservesOriginalInputAndIssuesNoCredential(t *testing.T) {
	for _, rawKey := range []string{"x", startKey, strings.Repeat("x", 256)} {
		t.Run(rawKey, func(t *testing.T) {
			p := &startPort{t: t, outcome: identity.CommitOutcomeCommitted}
			h := startHandler(t, p)
			for range 2 {
				r := startRequest(startBody)
				r.Header.Set("Idempotency-Key", rawKey)
				w := serveStart(t, h, r)
				if w.Code != http.StatusOK {
					t.Fatalf("committed metadata replay status=%d", w.Code)
				}
				var body struct {
					Started          bool   `json:"started"`
					CredentialIssued bool   `json:"credentialIssued"`
					CommandID        string `json:"commandID"`
					GrantID          string `json:"grantID"`
					ActorID          string `json:"actorID"`
					TargetID         string `json:"targetID"`
					Outcome          string `json:"commitOutcome"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || !body.Started || body.CredentialIssued ||
					body.CommandID != startCommandID || body.GrantID != startGrantID || body.ActorID != "request-admin" || body.TargetID != "target-user" || body.Outcome != "committed" {
					t.Fatal("metadata replay lost original safe receipt or claimed renewed credentials", err)
				}
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(w.Body.Bytes(), &fields); err != nil || string(fields["credentialIssued"]) != "false" {
					t.Fatal("metadata replay omitted explicit credentialIssued=false", err)
				}
				if p.input.Authentication.Tenant != "tenant-a" || p.input.Authentication.Bearer.Token() != startToken(3) || p.csrf != startToken(2) ||
					string(p.input.GrantID) != startGrantID || p.input.ExpectedVersion != 2 || p.input.Network != "198.51.100.7" {
					t.Fatal("start substituted original actor custody, trusted network or approved grant input")
				}
				want, err := identity.NewIdempotencyKey([]byte(rawKey))
				if err != nil {
					t.Fatal(err)
				}
				authority := [32]byte{1}
				gotDigest, gotErr := p.input.Key.Digest(authority)
				wantDigest, _ := want.Digest(authority)
				if gotErr != nil || gotDigest != wantDigest {
					t.Fatal("start replaced, trimmed or normalized the caller's opaque retry key")
				}
			}
			if p.calls != 2 {
				t.Fatal("HTTP cached native replay instead of consulting the native owner")
			}
		})
	}
}

func TestStartRejectsMalformedClosedGrantIntentBeforeNative(t *testing.T) {
	for _, body := range []string{
		"", `null`, `[]`, `{}`, `{"grantID":"` + startGrantID + `"}`, `{"expectedVersion":2}`,
		`{"grantID":"not-native-id","expectedVersion":2}`, `{"grantID":"AAAAAAAAAAAAAAAAAAAAAA","expectedVersion":2}`,
		`{"grantID":"` + startGrantID + `","expectedVersion":0}`, `{"grantID":"` + startGrantID + `","expectedVersion":1}`,
		`{"grantID":"` + startGrantID + `","expectedVersion":3}`, `{"grantID":"` + startGrantID + `","expectedVersion":"2"}`,
		`{"grantID":"` + startGrantID + `","expectedVersion":2.0}`, `{"grantID":"` + startGrantID + `","expectedVersion":2,"expectedVersion":2}`,
		`{"grantId":"` + startGrantID + `","expectedVersion":2}`, `{"grantID":"` + startGrantID + `","ExpectedVersion":2}`,
		`{"grantID":"` + startGrantID + `","expectedVersion":2,"actorID":"other"}`,
		`{"grantID":"` + startGrantID + `","expectedVersion":2,"Idempotency-Key":"body-key"}`,
		`{"grantID":"` + startGrantID + `","expectedVersion":2,"csrf_token":"body-token"}`, startBody + `{}`,
	} {
		t.Run(body, func(t *testing.T) {
			p := &startPort{t: t, outcome: identity.CommitOutcomeCommitted}
			w := serveStart(t, startHandler(t, p), startRequest(body))
			if w.Code != http.StatusBadRequest || p.calls != 0 {
				t.Fatalf("malformed grant intent reached native start: status=%d calls=%d", w.Code, p.calls)
			}
		})
	}
}

func TestStartRejectsAlternateChannelsAndAmbiguousCredentialsBeforeNative(t *testing.T) {
	for name, change := range map[string]func(*http.Request){
		"missing-key":   func(r *http.Request) { r.Header.Del("Idempotency-Key") },
		"empty-key":     func(r *http.Request) { r.Header.Set("Idempotency-Key", "") },
		"duplicate-key": func(r *http.Request) { r.Header.Add("Idempotency-Key", startKey) },
		"folded-key":    func(r *http.Request) { r.Header["idempotency-key"] = []string{startKey} },
		"comma-key":     func(r *http.Request) { r.Header.Set("Idempotency-Key", "a,b") },
		"oversized-key": func(r *http.Request) { r.Header.Set("Idempotency-Key", strings.Repeat("x", 257)) },
		"query":         func(r *http.Request) { r.URL.RawQuery = "grantID=" + startGrantID },
		"empty-query":   func(r *http.Request) { r.URL.ForceQuery = true },
		"trailer":       func(r *http.Request) { r.Trailer = http.Header{"Idempotency-Key": []string{startKey}} },
		"authorization": func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+startToken(3)) },
		"cookie-key":    func(r *http.Request) { r.AddCookie(&http.Cookie{Name: "Idempotency-Key", Value: startKey}) },
		"duplicate-parent": func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: "__Host-identity_session", Value: startToken(3)})
		},
		"duplicate-csrf":    func(r *http.Request) { r.Header.Add("X-CSRF-Token", startToken(2)) },
		"unsupported-media": func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") },
	} {
		t.Run(name, func(t *testing.T) {
			p := &startPort{t: t, outcome: identity.CommitOutcomeCommitted}
			r := startRequest(startBody)
			change(r)
			w := serveStart(t, startHandler(t, p), r)
			if w.Code == http.StatusOK || p.calls != 0 {
				t.Fatalf("alternate input channel reached native start: status=%d calls=%d", w.Code, p.calls)
			}
		})
	}
}

func TestStartRequiresOriginalOrdinaryCookieAndExactHTTPSOrigin(t *testing.T) {
	for name, change := range map[string]func(*http.Request){
		"missing-parent":     func(r *http.Request) { r.Header.Del("Cookie") },
		"missing-origin":     func(r *http.Request) { r.Header.Del("Origin") },
		"referer-only":       func(r *http.Request) { r.Header.Del("Origin"); r.Header.Set("Referer", "https://tenant.example/page") },
		"foreign-origin":     func(r *http.Request) { r.Header.Set("Origin", "https://other.example") },
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
			p := &startPort{t: t, outcome: identity.CommitOutcomeCommitted}
			r := startRequest(startBody)
			change(r)
			w := serveStart(t, startHandler(t, p), r)
			if w.Code == http.StatusOK || p.calls != 0 {
				t.Fatalf("untrusted or substituted actor custody reached native start: status=%d calls=%d", w.Code, p.calls)
			}
		})
	}
	for _, withChild := range []bool{false, true} {
		p := &startPort{t: t, outcome: identity.CommitOutcomeCommitted}
		r := startRequest(startBody)
		r.Header.Set("X-CSRF-Token", startToken(5))
		if withChild {
			r.AddCookie(&http.Cookie{Name: impersonationhttp.ChildCookieName, Value: "imp1." + startToken(4)})
			r.AddCookie(&http.Cookie{Name: impersonationhttp.ChildCSRFCookieName, Value: startToken(5)})
		}
		w := serveStart(t, startHandler(t, p), r)
		if w.Code != http.StatusForbidden || p.calls != 1 {
			t.Fatal("child or incorrect synchronizer replaced original native CSRF authorization")
		}
	}
	p := &startPort{t: t, outcome: identity.CommitOutcomeCommitted}
	r := startRequest(startBody)
	r.AddCookie(&http.Cookie{Name: impersonationhttp.ChildCookieName, Value: "imp1." + startToken(4)})
	r.AddCookie(&http.Cookie{Name: impersonationhttp.ChildCSRFCookieName, Value: startToken(5)})
	w := serveStart(t, startHandler(t, p), r)
	if w.Code != http.StatusOK || p.calls != 1 || p.input.Authentication.Bearer.Token() != startToken(3) {
		t.Fatal("child cookies replaced the presented original ordinary actor")
	}
	c := startConfig(p)
	c.TrustedOrigins = append(c.TrustedOrigins, "https://other.example")
	feature, err := impersonationhttp.NewStartFeature(c)
	if err != nil {
		t.Fatal(err)
	}
	h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	r = startRequest(startBody)
	r.Header.Set("Origin", "https://other.example")
	w = serveStart(t, h, r)
	if w.Code != http.StatusForbidden || p.calls != 1 {
		t.Fatal("trusted but cross-origin request reached native start")
	}
}

func TestStartNeverPromotesFailedOrUncertainNativeOutcome(t *testing.T) {
	for _, outcome := range []identity.CommitOutcome{identity.CommitOutcomeUnknown, identity.CommitOutcomeNotCommitted, identity.CommitOutcomeConflict, identity.CommitOutcomeInProgress, identity.CommitOutcomeCommitted} {
		p := &startPort{t: t, outcome: outcome}
		if outcome == identity.CommitOutcomeCommitted {
			p.err = errors.New("private backend diagnostic")
		}
		w := serveStart(t, startHandler(t, p), startRequest(startBody))
		if w.Code == http.StatusOK || p.calls != 1 {
			t.Fatalf("failed or uncertain start became successful: outcome=%d status=%d", outcome, w.Code)
		}
		if outcome == identity.CommitOutcomeUnknown && w.Code != http.StatusServiceUnavailable {
			t.Error("unknown durable start is not unavailable")
		}
		var body map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body["started"] == true || body["credentialIssued"] == true {
			t.Fatal("failure response claimed activation or credential issuance", err)
		}
	}
	for name, nativeError := range map[string]error{
		"forbidden": identity.ForbiddenError{},
		"failed":    errors.New("private backend diagnostic"),
	} {
		t.Run(name, func(t *testing.T) {
			p := &startPort{t: t, outcome: identity.CommitOutcomeCommitted, err: nativeError}
			w := serveStart(t, startHandler(t, p), startRequest(startBody))
			want := http.StatusServiceUnavailable
			if name == "forbidden" {
				want = http.StatusForbidden
			}
			if w.Code != want || p.calls != 1 {
				t.Fatalf("native failure became successful: status=%d want=%d", w.Code, want)
			}
		})
	}
}

func TestStartRejectsMalformedOrMismatchedNativeReceipts(t *testing.T) {
	for name, change := range map[string]func(*identity.CommandResult){
		"missing-feature": func(r *identity.CommandResult) { r.Feature = nil },
		"missing-audit":   func(r *identity.CommandResult) { r.AuditEventID = "" },
		"foreign-tenant":  func(r *identity.CommandResult) { r.Binding.TenantID = "tenant-other" },
		"foreign-grant":   func(r *identity.CommandResult) { r.Binding.RecordID = "AwMDAwMDAwMDAwMDAwMDAw" },
		"grant-is-command": func(r *identity.CommandResult) {
			r.Binding.CommandID = startGrantID
			r.Binding.CorrelationID = startGrantID
		},
		"invalid-command":     func(r *identity.CommandResult) { r.Binding.CommandID = "invalid" },
		"self-target":         func(r *identity.CommandResult) { r.Binding.UserID = identity.UserID(r.Binding.ActorID) },
		"wrong-operation":     func(r *identity.CommandResult) { r.Binding.OperationID = "identity.impersonation.stop" },
		"wrong-schema":        func(r *identity.CommandResult) { r.Binding.SchemaID = "impersonation-stop" },
		"foreign-correlation": func(r *identity.CommandResult) { r.Binding.CorrelationID = "other-command" },
		"wrong-feature":       func(r *identity.CommandResult) { r.Feature.Operation.OperationID = "identity.impersonation.stop" },
		"wrong-lifecycle":     func(r *identity.CommandResult) { r.Feature.BeforeVersion, r.Feature.AfterVersion = 3, 4 },
	} {
		t.Run(name, func(t *testing.T) {
			p := &startPort{t: t, outcome: identity.CommitOutcomeCommitted, changeReceipt: change}
			w := serveStart(t, startHandler(t, p), startRequest(startBody))
			if w.Code != http.StatusServiceUnavailable || p.calls != 1 {
				t.Fatalf("mismatched native receipt became successful: status=%d calls=%d", w.Code, p.calls)
			}
		})
	}
}

func TestStartCancellationDoesNotPromoteKnownCommitToUsableResponse(t *testing.T) {
	r := startRequest(startBody)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	p := &startPort{t: t, outcome: identity.CommitOutcomeCommitted, changeReceipt: func(*identity.CommandResult) { cancel() }}
	w := serveStart(t, startHandler(t, p), r.WithContext(ctx))
	if w.Code != http.StatusServiceUnavailable || p.calls != 1 {
		t.Fatal("canceled start became a usable credential response")
	}
	var body struct {
		Started          bool   `json:"started"`
		CredentialIssued bool   `json:"credentialIssued"`
		CommandID        string `json:"commandID"`
		Outcome          string `json:"commitOutcome"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.Started || body.CredentialIssued || body.CommandID != startCommandID || body.Outcome != "committed" {
		t.Fatal("cancellation lost historical commit metadata or claimed usable activation", err)
	}
}

func TestStartSelectsOnlyExactPostRouteAndRequiresNativeOwner(t *testing.T) {
	p := &startPort{t: t, outcome: identity.CommitOutcomeCommitted}
	c := startConfig(p)
	c.Native = (*startPort)(nil)
	if _, err := impersonationhttp.NewStartFeature(c); err == nil {
		t.Fatal("selected an absent native start owner")
	}
	h := startHandler(t, p)
	for _, path := range []string{"/v1/impersonation/start/", "/v1/impersonation/stop", "/v1/impersonation/revoke"} {
		r := startRequest(startBody)
		r.URL.Path = path
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusNotFound || p.calls != 0 || len(w.Header().Values("Set-Cookie")) != 0 {
			t.Fatal("unselected route reached native start or changed cookies", path)
		}
	}
	r := startRequest(startBody)
	r.Method = http.MethodGet
	w := serveStart(t, h, r)
	if w.Code != http.StatusMethodNotAllowed || p.calls != 0 {
		t.Fatal("non-POST start reached native work")
	}
}

func TestStartStopSelectionPublishesOnlyItsTwoRoutes(t *testing.T) {
	start := &startPort{t: t, outcome: identity.CommitOutcomeCommitted}
	stop := &stopPort{t: t, outcome: identity.CommitOutcomeCommitted}
	if _, err := impersonationhttp.NewStartStopFeature(startConfig(start), (*stopPort)(nil)); err == nil {
		t.Fatal("combined selection allowed an absent Stop owner")
	}
	feature, err := impersonationhttp.NewStartStopFeature(startConfig(start), stop)
	if err != nil {
		t.Fatal(err)
	}
	handler, doc, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil || doc.Version() != "3.1.1" {
		t.Fatal("combined Start and Stop are not OpenAPI composable", err)
	}
	ops := doc.Operations()
	if len(ops) != 2 || ops[0].Record.OperationID != "identity.impersonation.start" || ops[0].Record.Idempotency != "keyed" ||
		ops[1].Record.OperationID != "identity.impersonation.stop" || ops[1].Record.Idempotency != "repeat" {
		t.Fatal("combined feature advertised extra operations or changed retry behavior")
	}
	if w := serveStart(t, handler, startRequest(startBody)); w.Code != http.StatusOK || start.calls != 1 || stop.executed != 0 {
		t.Fatal("combined route dispatched Start to the wrong owner")
	}
	if w := serveStop(t, handler, stopRequest(`{}`, true)); w.Code != http.StatusOK || start.calls != 1 || stop.executed != 1 {
		t.Fatal("combined route dispatched Stop to the wrong owner")
	}
}

func FuzzStartClosedBody(f *testing.F) {
	for _, seed := range []string{startBody, `{}`, startBody + `{}`, `{"grantId":"` + startGrantID + `","expectedVersion":2}`, `{"grantID":"a","expectedVersion":3}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 1025 {
			return
		}
		p := &startPort{t: t, outcome: identity.CommitOutcomeCommitted}
		w := serveStart(t, startHandler(t, p), startRequest(body))
		if p.calls == 0 {
			if w.Code == http.StatusOK {
				t.Fatal("rejected body produced success")
			}
			return
		}
		var fields map[string]json.RawMessage
		var grant string
		var version uint64
		if json.Unmarshal([]byte(body), &fields) != nil || len(fields) != 2 ||
			json.Unmarshal(fields["grantID"], &grant) != nil || json.Unmarshal(fields["expectedVersion"], &version) != nil ||
			grant != string(p.input.GrantID) || version != 2 || p.calls != 1 {
			t.Fatal("invalid body reached the native Start service")
		}
	})
}
