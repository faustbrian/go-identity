package impersonationhttp

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/impersonation"
	impersonationpg "github.com/faustbrian/go-identity/impersonation/postgres"
)

const configurableHTTPGrant = "AAAAAAAAAAAAAAAAAAAAAQ"
const configurableHTTPCommand = "AgICAgICAgICAgICAgICAg"

type configurableHTTPPort struct {
	startBefore, stopBefore uint64
	startInput              impersonationpg.KeyedStartInput
	stopInput               impersonationpg.StopInput
	denyInput               impersonationpg.DenyInput
	quorum                  impersonationpg.QuorumResult
	calls, rateCalls        int
}

func configurableHTTPReceipt(op identity.FeatureOperation, command identity.CommandID, before uint64) identity.CommandResult {
	return identity.CommandResult{
		Binding: identity.CommandBinding{CommandID: command, TenantID: "tenant-a", UserID: "target-user", ActorID: "request-admin",
			ActorKind: authorization.SubjectUser, OperationID: op.OperationID, PolicyID: "policy", PolicyVersion: 1,
			SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, CorrelationID: string(command), RecordID: configurableHTTPGrant},
		Outcome: identity.CommitOutcomeCommitted, AuditEventID: "configured-audit",
		Feature: &identity.FeatureReceipt{Operation: op, BeforeVersion: before, AfterVersion: before + 1},
	}
}

func (p *configurableHTTPPort) Start(_ context.Context, input impersonationpg.KeyedStartInput) (impersonationpg.StoppableActivationResult, error) {
	p.calls++
	p.startInput = input
	return impersonationpg.StoppableActivationResult{ActivationResult: impersonationpg.ActivationResult{
		Receipt: configurableHTTPReceipt(startOperation, configurableHTTPCommand, p.startBefore)}}, nil
}

func (p *configurableHTTPPort) PrepareStop(_ context.Context, input impersonationpg.StopInput) (impersonationpg.PreparedStop, error) {
	p.calls++
	p.stopInput = input
	return impersonationpg.PreparedStop{}, nil
}

func (p *configurableHTTPPort) ExecuteStop(context.Context, impersonationpg.PreparedStop, authentication.BearerCredential) (impersonationpg.StopResult, error) {
	return impersonationpg.StopResult{Receipt: configurableHTTPReceipt(stopOperation, p.stopInput.CommandID, p.stopBefore)}, nil
}

func (p *configurableHTTPPort) PrepareDenial(_ context.Context, input impersonationpg.DenyInput) (impersonationpg.PreparedCommand, error) {
	p.calls++
	p.denyInput = input
	return impersonationpg.PreparedCommand{}, nil
}

func (*configurableHTTPPort) Execute(context.Context, impersonationpg.PreparedCommand) (identity.CommandResult, error) {
	return identity.CommandResult{}, identity.UnavailableError{}
}

func (p *configurableHTTPPort) QuorumWithAdmission(ctx context.Context, _ impersonationpg.QuorumInput, admit func(context.Context, identity.UserID) error) (impersonationpg.QuorumResult, error) {
	p.calls++
	if err := admit(ctx, "read-admin"); err != nil {
		return impersonationpg.QuorumResult{}, err
	}
	return p.quorum, nil
}

func (*configurableHTTPPort) Configured() bool { return true }
func (p *configurableHTTPPort) AdmitImpersonationDeny(context.Context, identityhttp.NetworkFacts, identity.UserID) (time.Duration, error) {
	p.rateCalls++
	return 0, nil
}
func (p *configurableHTTPPort) AdmitImpersonationQuorum(context.Context, identityhttp.NetworkFacts, identity.UserID) (time.Duration, error) {
	p.rateCalls++
	return 0, nil
}

func configurableHTTPConfig(p *configurableHTTPPort) (StartConfig, StopConfig, DenyConfig, QuorumConfig) {
	network := identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 1024,
		MaximumBodyBytes: 2048, MaximumDecodedBytes: 2048, MaximumFields: 32, MaximumDepth: 4},
		MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: "tenant.example", TenantID: "tenant-a"}}}
	origins := []identityhttp.Origin{"https://tenant.example"}
	return StartConfig{Network: network, TrustedOrigins: origins, OriginalCookieName: "__Host-identity_session", Native: p, MaximumDuration: time.Second},
		StopConfig{Network: network, TrustedOrigins: origins, OriginalCookieName: "__Host-identity_session", Native: p, MaximumDuration: time.Second},
		DenyConfig{Network: network, TrustedOrigins: origins, OriginalCookieName: "__Host-identity_session", Native: p, Rate: p, MaximumDuration: time.Second},
		QuorumConfig{Network: network, OriginalCookieName: "__Host-identity_session", Native: p, Rate: p, MaximumDuration: time.Second}
}

func configurableHTTPRequest(path, body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	r.Host, r.RemoteAddr, r.TLS = "tenant.example", "198.51.100.7:1234", &tls.ConnectionState{}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://tenant.example")
	r.Header.Set("X-CSRF-Token", base64.RawURLEncoding.EncodeToString(bytesForConfiguredHTTP(2)))
	r.AddCookie(&http.Cookie{Name: "__Host-identity_session", Value: "ordinary-session"})
	if path == startPath {
		r.Header.Set("Idempotency-Key", "configured-retry")
	}
	if path == stopPath {
		r.AddCookie(&http.Cookie{Name: ChildCookieName, Value: "imp1." + base64.RawURLEncoding.EncodeToString(bytesForConfiguredHTTP(3))})
	}
	if path == quorumPath {
		r.Method, r.Body, r.ContentLength = http.MethodGet, http.NoBody, 0
		r.URL.RawQuery = "grantID=" + configurableHTTPGrant
		r.RequestURI = r.URL.RequestURI()
		r.Header.Del("Content-Type")
		r.Header.Del("Origin")
		r.Header.Del("X-CSRF-Token")
	}
	return r
}

func bytesForConfiguredHTTP(value byte) []byte {
	return []byte(strings.Repeat(string([]byte{value}), 32))
}

func configuredHTTPHandler(t *testing.T, feature identityhttp.Feature, err error) (http.Handler, map[string]any) {
	t.Helper()
	if err != nil {
		t.Fatal("configure selected quorum transport", err)
	}
	h, document, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal("compose selected canonical operation", err)
	}
	var literal map[string]any
	if json.Unmarshal(document.JSON(), &literal) != nil {
		t.Fatal("document is not literal OpenAPI JSON")
	}
	return h, literal
}

func configuredHTTPObject(t *testing.T, value any, names ...string) map[string]any {
	t.Helper()
	for _, name := range names {
		object, ok := value.(map[string]any)
		if !ok {
			t.Fatal("OpenAPI object missing", name)
		}
		value = object[name]
	}
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatal("OpenAPI object missing")
	}
	return object
}

func configuredHTTPServe(t *testing.T, h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("selected quorum route lost private response protections")
	}
	for _, private := range []string{"ordinary-session", "configured-retry", "private denial reason", base64.RawURLEncoding.EncodeToString(bytesForConfiguredHTTP(2))} {
		if strings.Contains(w.Body.String(), private) {
			t.Fatal("selected quorum route disclosed private input")
		}
	}
	return w
}

func TestConfigurableHTTPStartVersionAndReceipt(t *testing.T) {
	for _, required := range []int{2, 32} {
		t.Run(fmt.Sprint(required), func(t *testing.T) {
			p := &configurableHTTPPort{startBefore: uint64(required + 1)}
			c, _, _, _ := configurableHTTPConfig(p)
			feature, err := NewConfigurableStartFeature(c, required)
			h, doc := configuredHTTPHandler(t, feature, err)
			paths := configuredHTTPObject(t, doc, "paths")
			if len(paths) != 1 {
				t.Fatal("configured Start selected sibling routes")
			}
			op := configuredHTTPObject(t, paths, startPath, "post")
			version := configuredHTTPObject(t, op, "requestBody", "content", "application/json", "schema", "properties", "expectedVersion")
			if op["operationId"] != startOperation.OperationID || version["const"] != float64(required+1) {
				t.Fatal("literal Start OpenAPI did not describe the selected exact approved version")
			}
			body := fmt.Sprintf(`{"grantID":%q,"expectedVersion":%d}`, configurableHTTPGrant, required+1)
			w := configuredHTTPServe(t, h, configurableHTTPRequest(startPath, body))
			if w.Code != 200 || p.calls != 1 || p.startInput.ExpectedVersion != uint64(required+1) || len(w.Result().Cookies()) != 0 {
				t.Fatal("configured Start failed exact receipt-only metadata delivery", w.Code)
			}
			if p.startInput.Authentication.Tenant != "tenant-a" || p.startInput.Authentication.Bearer.Token() != "ordinary-session" || p.startInput.Network != "198.51.100.7" {
				t.Fatal("configured Start replaced original custody or resolver-owned network facts")
			}
			p.startBefore--
			if w := configuredHTTPServe(t, h, configurableHTTPRequest(startPath, body)); w.Code != 503 || len(w.Result().Cookies()) != 0 {
				t.Fatal("configured Start accepted another lifecycle's receipt", w.Code)
			}
			before := p.calls
			for _, wrong := range []int{2, required + 2} {
				body := fmt.Sprintf(`{"grantID":%q,"expectedVersion":%d}`, configurableHTTPGrant, wrong)
				if w := configuredHTTPServe(t, h, configurableHTTPRequest(startPath, body)); w.Code != 400 || p.calls != before {
					t.Fatal("configured Start admitted a nonmatching request version", wrong, w.Code)
				}
			}
		})
	}
}

func TestConfigurableHTTPStopReceiptAndCookieEffects(t *testing.T) {
	for _, required := range []int{2, 32} {
		p := &configurableHTTPPort{stopBefore: uint64(required + 2)}
		_, c, _, _ := configurableHTTPConfig(p)
		feature, err := NewConfigurableStopFeature(c, required)
		h, doc := configuredHTTPHandler(t, feature, err)
		op := configuredHTTPObject(t, doc, "paths", stopPath, "post")
		description, _ := op["description"].(string)
		if op["operationId"] != stopOperation.OperationID ||
			!strings.Contains(description, fmt.Sprintf("active version %d to stopped version %d", required+2, required+3)) {
			t.Fatal("configured Stop changed canonical ownership")
		}
		w := configuredHTTPServe(t, h, configurableHTTPRequest(stopPath, `{}`))
		if w.Code != 200 || len(w.Result().Cookies()) != 2 {
			t.Fatal("configured Stop did not accept its exact active transition", w.Code)
		}
		for _, cookie := range w.Result().Cookies() {
			if cookie.Name != ChildCookieName && cookie.Name != ChildCSRFCookieName || cookie.MaxAge != -1 || !cookie.Secure {
				t.Fatal("configured Stop changed a non-child credential")
			}
		}
		p.stopBefore--
		if w := configuredHTTPServe(t, h, configurableHTTPRequest(stopPath, `{}`)); w.Code != 503 || len(w.Result().Cookies()) != 0 {
			t.Fatal("configured Stop accepted a mismatched lifecycle and cleared cookies", w.Code)
		}
		before := p.calls
		r := configurableHTTPRequest(stopPath, `{}`)
		r.Header.Del("Origin")
		if w := configuredHTTPServe(t, h, r); w.Code != 403 || p.calls != before {
			t.Fatal("configured Stop weakened the exact Origin guard", w.Code)
		}
	}
}

func TestConfigurableHTTPDenialPendingRangeAndExactReceipt(t *testing.T) {
	for _, required := range []int{2, 32} {
		p := &configurableHTTPPort{}
		_, _, c, _ := configurableHTTPConfig(p)
		feature, err := NewConfigurableDenyFeature(c, required)
		h, doc := configuredHTTPHandler(t, feature, err)
		version := configuredHTTPObject(t, doc, "paths", denyPath, "post", "requestBody", "content", "application/json", "schema", "properties", "expectedVersion")
		if version["minimum"] != float64(1) || version["maximum"] != float64(required) || version["const"] != nil {
			t.Fatal("configured denial OpenAPI lost its pending-version range")
		}
		for _, expected := range []int{1, required} {
			body := fmt.Sprintf(`{"grantID":%q,"expectedVersion":%d,"reason":"private denial reason"}`, configurableHTTPGrant, expected)
			before := p.calls
			w := configuredHTTPServe(t, h, configurableHTTPRequest(denyPath, body))
			if w.Code != 503 || p.calls != before+1 || p.denyInput.ExpectedVersion != uint64(expected) || p.rateCalls != 0 || len(w.Result().Cookies()) != 0 {
				// The zero PreparedCommand has no private native ownership, so
				// even a well-formed request must stop before quota or Execute.
				t.Fatal("configured denial rejected valid intent or trusted an unowned preparation", w.Code)
			}
		}
		for _, expected := range []int{0, required + 1} {
			body := fmt.Sprintf(`{"grantID":%q,"expectedVersion":%d,"reason":"private denial reason"}`, configurableHTTPGrant, expected)
			before := p.calls
			if w := configuredHTTPServe(t, h, configurableHTTPRequest(denyPath, body)); w.Code != 400 || p.calls != before {
				t.Fatal("configured denial admitted a non-pending request version", w.Code)
			}
		}
		for _, before := range []uint64{uint64(required), 1} {
			result := configurableHTTPReceipt(denyOperation, configurableHTTPCommand, before)
			w := httptest.NewRecorder()
			writeDenialForVersion(t.Context(), w, result.Binding, result, nil, uint64(required))
			want := 503
			if before == uint64(required) {
				want = 200
			}
			if w.Code != want || len(w.Result().Cookies()) != 0 {
				t.Fatal("denial response failed to bind its receipt to the exact supplied pending version", before, w.Code)
			}
		}
	}
}

func TestConfigurableHTTPQuorumSafeMetadata(t *testing.T) {
	for _, test := range []struct {
		status          impersonation.Status
		count, required int
		valid           bool
	}{
		{impersonation.StatusPendingApproval, 1, 2, true}, {impersonation.StatusApproved, 2, 2, true},
		{impersonation.StatusActive, 2, 2, true}, {impersonation.StatusStopped, 2, 2, true},
		{impersonation.StatusDenied, 1, 2, true}, {impersonation.StatusRevoked, 1, 2, true},
		{impersonation.StatusExpired, 2, 2, true}, {impersonation.StatusApproved, 32, 32, true},
		{impersonation.StatusApproved, 1, 1, true}, {impersonation.StatusApproved, 1, 2, false},
		{impersonation.StatusPendingApproval, 2, 2, false}, {impersonation.StatusDenied, 2, 2, false},
		{impersonation.StatusApproved, 33, 33, false}, {impersonation.StatusRequested, 1, 2, false},
	} {
		t.Run(fmt.Sprintf("%s-%d-of-%d", test.status, test.count, test.required), func(t *testing.T) {
			p := &configurableHTTPPort{quorum: impersonationpg.QuorumResult{GrantID: configurableHTTPGrant, RequiredApprovals: test.required, Status: test.status, Approvals: []impersonationpg.QuorumApproval{}}}
			for i := range test.count {
				p.quorum.Approvals = append(p.quorum.Approvals, impersonationpg.QuorumApproval{ApproverID: identity.UserID(fmt.Sprintf("reviewer-%d", i)), DecidedAt: time.Now().UTC()})
			}
			_, _, _, c := configurableHTTPConfig(p)
			feature, err := NewConfigurableQuorumReadFeature(c)
			h, doc := configuredHTTPHandler(t, feature, err)
			fields := configuredHTTPObject(t, doc, "paths", quorumPath, "get", "responses", "200", "content", "application/json", "schema", "properties")
			if configuredHTTPObject(t, fields, "requiredApprovals")["maximum"] != float64(32) || configuredHTTPObject(t, fields, "approvals")["maxItems"] != float64(32) {
				t.Fatal("literal configurable quorum OpenAPI retained the fixed-one bound")
			}
			w := configuredHTTPServe(t, h, configurableHTTPRequest(quorumPath, ""))
			want := 503
			if test.valid {
				want = 200
			}
			if w.Code != want || p.rateCalls != 1 || len(w.Result().Cookies()) != 0 {
				t.Fatal("configured quorum did not validate state/count before disclosing safe metadata", w.Code)
			}
			if !test.valid {
				var fields map[string]json.RawMessage
				if json.Unmarshal(w.Body.Bytes(), &fields) != nil || len(fields) != 1 || fields["error"] == nil {
					t.Fatal("invalid configurable quorum disclosed grant metadata")
				}
			}
			if test.valid && test.count > 1 {
				p.quorum.Approvals[1].ApproverID = p.quorum.Approvals[0].ApproverID
				if w := configuredHTTPServe(t, h, configurableHTTPRequest(quorumPath, "")); w.Code != 503 {
					t.Fatal("configured quorum disclosed duplicate reviewer metadata", w.Code)
				}
			}
		})
	}
}

func TestConfigurableHTTPSelectorsRejectInvalidThresholds(t *testing.T) {
	p := &configurableHTTPPort{}
	start, stop, deny, _ := configurableHTTPConfig(p)
	for _, required := range []int{0, 1, 33} {
		if _, err := NewConfigurableStartFeature(start, required); err == nil {
			t.Fatal("Start accepted an unselected quorum", required)
		}
		if _, err := NewConfigurableStopFeature(stop, required); err == nil {
			t.Fatal("Stop accepted an unselected quorum", required)
		}
		if _, err := NewConfigurableDenyFeature(deny, required); err == nil {
			t.Fatal("Deny accepted an unselected quorum", required)
		}
	}
}
