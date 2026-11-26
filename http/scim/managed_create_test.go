package scimhttp_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	scimhttp "github.com/faustbrian/go-identity/http/scim"
	ratelimit "github.com/faustbrian/go-rate-limit/v2"
	scim "github.com/faustbrian/go-scim"
	scimpostgres "github.com/faustbrian/go-scim/postgres"
)

const managedCreatePath = "/v1/scim/connection-create"
const managedCreateBody = `{"organizationID":"` + managedOrganization + `","providerID":"managed-provider","mappings":[{"source":"userName","target":"scim_user_name","writable":true}]}`
const managedIssuedBearer = "isolated-synthetic-managed-issued-credential"

// The native port is deliberately a transport seam, not a replacement replay
// journal. Native original-key/reveal-once persistence is proved by its owner
// and the separate real PostgreSQL Reference consumer.
type managedCreateOwner struct {
	result   scimpostgres.ConnectionCreateResult
	requests []scimpostgres.ConnectionCreateRequest
	err      error
	after    func()
}

func (s *managedCreateOwner) ConnectionCreate(ctx context.Context, request scimpostgres.ConnectionCreateRequest) (scimpostgres.ConnectionCreateResult, error) {
	if _, ok := ctx.Deadline(); !ok {
		panic("unbounded native create")
	}
	s.requests = append(s.requests, request)
	if s.after != nil {
		s.after()
	}
	return s.result, s.err
}

type managedCreateBackend struct {
	ratelimit.StrictBackend
	requests []ratelimit.AtomicBatchRequest
	mode     string
}

func (*managedCreateBackend) Name() string { return "managed-create-test" }
func (b *managedCreateBackend) AdmitAtomicStrict(_ context.Context, request ratelimit.AtomicBatchRequest) (ratelimit.AtomicBatchDecision, error) {
	b.requests = append(b.requests, request)
	if b.mode == "unavailable" {
		return ratelimit.AtomicBatchDecision{}, ratelimit.ErrUnavailable
	}
	if b.mode == "unknown" {
		return ratelimit.AtomicBatchDecision{}, ratelimit.UnknownOutcome(nil)
	}
	decision := ratelimit.AtomicBatchDecision{CommandID: request.CommandID, Allowed: b.mode != "limited", Decisions: make([]ratelimit.Decision, len(request.Requests))}
	for i, bucket := range request.Requests {
		decision.Decisions[i] = ratelimit.Decision{Allowed: decision.Allowed, Remaining: bucket.Policy.Capacity() - 1, Limit: bucket.Policy.Capacity(), Reset: bucket.Now.Add(bucket.Policy.Period()), Reason: ratelimit.ReasonAllowed}
		if !decision.Allowed {
			decision.Decisions[i].Remaining = 0
			decision.Decisions[i].Reason = ratelimit.ReasonLimited
			decision.Decisions[i].RetryAfter = 1500 * time.Millisecond
		}
	}
	if !decision.Allowed {
		return decision, ratelimit.ErrRejected
	}
	return decision, nil
}

type managedCreateFixture struct {
	base         *managedFixture
	config       scimhttp.ManagedCreateConfig
	owner        *managedCreateOwner
	backend      *managedCreateBackend
	events       []organizationhttp.AdminRateEvent
	auditFailure bool
}

func newManagedCreateFixture(t *testing.T) *managedCreateFixture {
	t.Helper()
	f := &managedCreateFixture{base: newManagedFixture(t), owner: &managedCreateOwner{}, backend: &managedCreateBackend{}}
	record, err := scim.NewConnectionRecord(f.base.owner.record.Scope(), f.base.owner.record.Mappings(), scim.RemoveMembership, 1)
	if err != nil {
		t.Fatal(err)
	}
	f.owner.result = scimpostgres.ConnectionCreateResult{Connection: record, Bearer: authentication.NewBearerCredential(managedIssuedBearer)}
	admin, err := organizationhttp.NewAdminRateLimiter(organizationhttp.AdminRateConfig{Shared: f.backend, Namespace: "managed-create-test", Key: [32]byte{0xa7}, Now: f.base.config.Now, MaximumDuration: time.Second, Denied: func(_ context.Context, event organizationhttp.AdminRateEvent) error {
		f.events = append(f.events, event)
		if f.auditFailure {
			return errors.New("private audit diagnostic")
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close() })
	network := f.base.config.Network
	network.Limits.MaximumBodyBytes, network.Limits.MaximumDecodedBytes, network.Limits.MaximumFields = 65536, 65536, 600
	f.config = scimhttp.ManagedCreateConfig{Network: network, Sessions: f.base.config.Sessions, Creator: f.owner, AdminRate: admin, Limits: scim.DefaultLimits(), Now: f.base.config.Now, MaximumDuration: time.Second}
	return f
}
func (f *managedCreateFixture) router(t *testing.T) (http.Handler, identityhttp.OpenAPIDocument) {
	t.Helper()
	feature, err := scimhttp.NewManagedCreateFeature(f.config)
	if err != nil {
		t.Fatal(err)
	}
	ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	return protocolRouter(t, f.config.Network, ops)
}
func (f *managedCreateFixture) request(body string) *http.Request {
	r := f.base.request(managedCreatePath)
	r.Method = http.MethodPost
	r.Body = io.NopCloser(strings.NewReader(body))
	r.ContentLength = int64(len(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", "original-managed-create")
	return r
}

func TestManagedCreateTLSUsesNativeKeyCustodyAndDoesNotInventRepeatReveal(t *testing.T) {
	f := newManagedCreateFixture(t)
	handler, document := f.router(t)
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	client := server.Client()
	defer client.CloseIdleConnections()
	call := func() []byte {
		t.Helper()
		request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+managedCreatePath, strings.NewReader(managedCreateBody))
		if err != nil {
			t.Fatal(err)
		}
		request.Host = "tenant.example"
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", "original-managed-create")
		request.Header.Set("Authorization", "Bearer "+f.base.token)
		request.AddCookie(&http.Cookie{Name: "session", Value: "ignored-ambient-cookie"})
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		wire, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		closeErr := response.Body.Close()
		if response.StatusCode != 200 || readErr != nil || closeErr != nil || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" || response.Header.Get("Set-Cookie") != "" {
			t.Fatalf("managed create TLS failed or unsafe: status %d", response.StatusCode)
		}
		if strings.Contains(string(wire), f.base.token) {
			t.Fatal("administrator bearer disclosed")
		}
		return wire
	}
	first := call()
	var result struct {
		Connection scimhttp.ManagedConnectionView `json:"connection"`
		Bearer     string                         `json:"bearer"`
	}
	if json.Unmarshal(first, &result) != nil || result.Bearer != managedIssuedBearer || result.Connection.ConnectionID != managedConnection || result.Connection.Version != 1 {
		t.Fatal("new native result lost original safe record or invocation-local bearer")
	}
	f.owner.result.Bearer = authentication.BearerCredential{}
	second := call()
	result.Bearer = ""
	if json.Unmarshal(second, &result) != nil || result.Bearer != "" || strings.Contains(string(second), `"bearer"`) || result.Connection.ConnectionID != managedConnection {
		t.Fatal("metadata-only native retry acquired a new credential or lost its stable record")
	}
	if len(f.owner.requests) != 2 || len(f.backend.requests) != 2 {
		t.Fatal("exact retry must reach its original native custodian and fresh admin admission")
	}
	for _, request := range f.owner.requests {
		expected, _ := identity.NewIdempotencyKey([]byte("original-managed-create"))
		want, _ := expected.Digest([32]byte{8})
		got, err := request.IdempotencyKey.Digest([32]byte{8})
		if err != nil || got != want {
			t.Fatal("transport replaced original request key")
		}
		if request.Authentication.TenantID != managedTenant || request.Authentication.Bearer.Token() != f.base.token || request.OrganizationID != managedOrganization || request.ProviderID != "managed-provider" || len(request.Mappings.Entries()) != 1 {
			t.Fatal("transport replaced native authenticated intent")
		}
	}
	if f.backend.requests[0].CommandID == f.backend.requests[1].CommandID {
		t.Fatal("keyed retry reused a cached rate admission")
	}
	for _, secret := range []string{f.base.token, managedIssuedBearer} {
		if strings.Contains(string(document.JSON()), secret) {
			t.Fatal("OpenAPI disclosed credentials")
		}
	}
}

func TestManagedCreateRejectsMalformedClosedJSONAndRequiredKeyBeforeEffects(t *testing.T) {
	for _, body := range []string{"", `{`, `null`, `{}`, strings.Replace(managedCreateBody, `"writable":true`, `"writable":true,"unknown":1`, 1), strings.Replace(managedCreateBody, `"providerID":"managed-provider"`, `"providerID":"managed-provider","ProviderID":"alias"`, 1), strings.Replace(managedCreateBody, `"writable":true`, `"writable":null`, 1), strings.Replace(managedCreateBody, `,"writable":true`, ``, 1), strings.Replace(managedCreateBody, `"source":"userName"`, `"source":"password"`, 1), strings.Replace(managedCreateBody, managedOrganization, "invalid-id", 1), strings.Replace(managedCreateBody, "managed-provider", "provider/invalid", 1), strings.Replace(managedCreateBody, `"mappings":[`, `"idempotencyKey":"override","mappings":[`, 1)} {
		t.Run(body, func(t *testing.T) {
			f := newManagedCreateFixture(t)
			h, _ := f.router(t)
			w := managedServe(h, f.request(body))
			if w.Code != 400 || len(f.owner.requests) != 0 || len(f.backend.requests) != 0 {
				t.Fatalf("invalid input reached admission/create: %d", w.Code)
			}
		})
	}
	for _, change := range []func(*http.Request){func(r *http.Request) { r.Header.Del("Idempotency-Key") }, func(r *http.Request) { r.Header.Add("Idempotency-Key", "other") }, func(r *http.Request) { r.URL.RawQuery = "extra=1"; r.RequestURI = r.URL.RequestURI() }, func(r *http.Request) { r.Trailer = http.Header{"X-Trailer": []string{"forbidden"}} }} {
		f := newManagedCreateFixture(t)
		h, _ := f.router(t)
		r := f.request(managedCreateBody)
		change(r)
		w := managedServe(h, r)
		if w.Code != 400 || len(f.owner.requests) != 0 || len(f.backend.requests) != 0 {
			t.Fatalf("forbidden request key/channel reached create: %d", w.Code)
		}
	}
}

func TestManagedCreateBoundsDeclaredChunkedAndMappingInputs(t *testing.T) {
	for _, chunked := range []bool{false, true} {
		f := newManagedCreateFixture(t)
		h, _ := f.router(t)
		r := f.request(strings.Repeat(" ", 65536) + managedCreateBody)
		if chunked {
			r.ContentLength = -1
			r.TransferEncoding = []string{"chunked"}
		}
		w := managedServe(h, r)
		if w.Code != 400 || len(f.owner.requests) != 0 || len(f.backend.requests) != 0 {
			t.Fatalf("oversized create reached admission: status %d", w.Code)
		}
	}
	f := newManagedCreateFixture(t)
	h, _ := f.router(t)
	body := `{"organizationID":"` + managedOrganization + `","providerID":"managed-provider","mappings":[` + strings.Repeat(`{"source":"userName","target":"scim_user_name","writable":true},`, 128) + `{"source":"userName","target":"scim_user_name","writable":true}]}`
	if w := managedServe(h, f.request(body)); w.Code != 400 || len(f.owner.requests) != 0 || len(f.backend.requests) != 0 {
		t.Fatalf("mapping count exceeded native bound: status %d", w.Code)
	}
}

func TestManagedCreateRequiresVerifiedBearerAndExactAdministrativeAdmission(t *testing.T) {
	for _, mode := range []string{"cookie-only", "inactive", "unavailable-session", "http", "limited", "unavailable", "unknown", "audit-failed", "native-denied", "native-unknown", "native-conflict"} {
		t.Run(mode, func(t *testing.T) {
			f := newManagedCreateFixture(t)
			r := f.request(managedCreateBody)
			want := 503
			switch mode {
			case "cookie-only":
				r.Header.Del("Authorization")
				r.AddCookie(&http.Cookie{Name: "session", Value: f.base.token})
				want = 401
			case "inactive":
				f.base.inactive = true
				want = 403
			case "unavailable-session":
				f.base.unavailable = true
			case "http":
				r.TLS = nil
				want = 403
			case "limited":
				f.backend.mode = "limited"
				want = 429
			case "unavailable", "unknown":
				f.backend.mode = mode
			case "audit-failed":
				f.backend.mode = "limited"
				f.auditFailure = true
			case "native-denied":
				f.owner.err = identity.ForbiddenError{}
				want = 403
			case "native-unknown":
				f.owner.err = identity.UnknownCommitError{}
			case "native-conflict":
				f.owner.err = identity.ConflictError{}
				want = 409
			}
			h, _ := f.router(t)
			w := managedServe(h, r)
			if w.Code != want || strings.Contains(w.Body.String(), f.base.token) || strings.Contains(w.Body.String(), managedIssuedBearer) || strings.Contains(w.Body.String(), "private") {
				t.Fatalf("create denial failed closed: %s status %d want %d", mode, w.Code, want)
			}
			if !strings.HasPrefix(mode, "native-") && len(f.owner.requests) != 0 {
				t.Fatal("denied request reached native create")
			}
			if mode == "limited" || mode == "unavailable" || mode == "unknown" || mode == "audit-failed" {
				if len(f.events) != 1 || f.events[0].Operation != "identity.scim.connection-create" {
					t.Fatal("admin denial lost exact SCIM audit")
				}
			}
			if mode == "unavailable-session" && len(f.backend.requests) != 0 {
				t.Fatal("unavailable session fell back to caller/anonymous admission")
			}
		})
	}
}

func TestManagedCreateWithholdsCredentialOnMalformedNativeProjection(t *testing.T) {
	for _, mismatch := range []string{"zero", "tenant", "organization", "provider", "mappings", "version", "policy", "echoed-bearer"} {
		t.Run(mismatch, func(t *testing.T) {
			f := newManagedCreateFixture(t)
			record := f.owner.result.Connection
			scope := record.Scope()
			mappings := record.Mappings()
			policy := record.DeprovisionPolicy()
			version := uint64(1)
			switch mismatch {
			case "zero":
				f.owner.result.Connection = scim.ConnectionRecord{}
			case "tenant":
				scope.TenantID = "AAAAAAAAAAAAAAAAAAAABQ"
			case "organization":
				scope.OrganizationID = "AAAAAAAAAAAAAAAAAAAABQ"
			case "provider":
				scope.ProviderID = "other-provider"
			case "mappings":
				path, _ := scim.ParseMappingPath("displayName", nil, scim.DefaultLimits())
				mappings, _ = scim.NewMappingSet([]scim.Mapping{{Source: path, Target: "other", Writable: true}})
			case "version":
				version = 2
			case "policy":
				policy = scim.Suspend
			case "echoed-bearer":
				f.owner.result.Bearer = authentication.NewBearerCredential(f.base.token)
			}
			if mismatch != "zero" {
				f.owner.result.Connection, _ = scim.NewConnectionRecord(scope, mappings, policy, version)
			}
			h, _ := f.router(t)
			w := managedServe(h, f.request(managedCreateBody))
			if w.Code != 503 || strings.Contains(w.Body.String(), managedIssuedBearer) || strings.Contains(w.Body.String(), f.base.token) || strings.Contains(w.Body.String(), managedConnection) {
				t.Fatalf("mismatched native projection disclosed: status %d", w.Code)
			}
		})
	}
}

func TestManagedCreateWithholdsBearerAfterObservedSessionExpiry(t *testing.T) {
	for _, stage := range []string{"after-admission", "after-native"} {
		t.Run(stage, func(t *testing.T) {
			f := newManagedCreateFixture(t)
			now := f.base.config.Now()
			elapsed := time.Duration(0)
			f.config.Now = func() time.Time { return now.Add(elapsed) }
			var middleware []identityhttp.MiddlewareDescriptor
			if stage == "after-native" {
				f.owner.after = func() { elapsed = 21 * time.Second }
			} else {
				middleware = []identityhttp.MiddlewareDescriptor{{Owner: "scim", Middleware: identityhttp.Middleware{Name: "expire-before-create", Phase: identityhttp.MiddlewareBeforeHandler, Order: 1, Handler: func(next http.Handler) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { elapsed = 21 * time.Second; next.ServeHTTP(w, r) })
				}}}}
			}
			feature, err := scimhttp.NewManagedCreateFeatureWithMiddleware(f.config, middleware)
			if err != nil {
				t.Fatal(err)
			}
			operations, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
			if err != nil {
				t.Fatal(err)
			}
			h, _ := protocolRouter(t, f.config.Network, operations)
			w := managedServe(h, f.request(managedCreateBody))
			if w.Code != 503 || strings.Contains(w.Body.String(), managedIssuedBearer) || strings.Contains(w.Body.String(), managedConnection) || len(f.backend.requests) != 1 {
				t.Fatal("expired observation disclosed credential/projection or skipped actual admission")
			}
			wantNative := 0
			if stage == "after-native" {
				wantNative = 1
			}
			if len(f.owner.requests) != wantNative {
				t.Fatal("session expiry was checked at the wrong protected boundary")
			}
		})
	}
}

func TestManagedCreateFeatureSelectsOnlyItsCanonicalBearerOperation(t *testing.T) {
	f := newManagedCreateFixture(t)
	h, document := f.router(t)
	for _, path := range []string{managedGetPath, managedListPath, bulkPath, "/v1/scim/connection-delete"} {
		r := f.base.request(path)
		if w := managedServe(h, r); w.Code != 404 {
			t.Fatalf("create selected an unrelated route: %d", w.Code)
		}
	}
	if len(document.Operations()) != 1 || document.Operations()[0].Record.CSRFOrigin.Mode != identityhttp.CSRFNone || document.Operations()[0].Record.RatePolicy != "rate.admin" || document.Operations()[0].Record.Idempotency != "keyed" {
		t.Fatal("create metadata changed actual bearer/keyed/admin contract")
	}
	if _, err := scimhttp.NewManagedCreateFeature(scimhttp.ManagedCreateConfig{}); err == nil {
		t.Fatal("missing actual dependencies were accepted")
	}
	create, err := scimhttp.NewManagedCreateFeature(f.config)
	if err != nil {
		t.Fatal(err)
	}
	read, err := scimhttp.NewManagedReadFeature(f.base.config)
	if err != nil {
		t.Fatal(err)
	}
	bulk := newProtocolFixture()
	protocol, err := scimhttp.NewBulkFeature(bulk.config)
	if err != nil {
		t.Fatal(err)
	}
	operations := append(create.Operations(), read.Operations()...)
	operations = append(operations, protocol.Operations()...)
	combined, err := identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "scim", Operations: operations})
	if err != nil {
		t.Fatal(err)
	}
	selected, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{combined}})
	if err != nil {
		t.Fatal(err)
	}
	_, combinedDocument := protocolRouter(t, f.config.Network, selected)
	if len(combinedDocument.Operations()) != 5 {
		t.Fatal("explicit canonical composition lost independent operations")
	}
}

func FuzzManagedCreateClosedJSON(f *testing.F) {
	f.Add(managedCreateBody)
	f.Add(`{"organizationID":null}`)
	f.Add(`{"mappings":[{"source":"password"}]}`)
	f.Fuzz(func(t *testing.T, body string) {
		fixture := newManagedCreateFixture(t)
		feature, err := scimhttp.NewManagedCreateFeature(fixture.config)
		if err != nil {
			t.Fatal(err)
		}
		h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
		if err != nil {
			t.Fatal(err)
		}
		w := managedServe(h, fixture.request(body))
		if w.Code != 200 && w.Code != 400 && w.Code != 503 || strings.Contains(w.Body.String(), fixture.base.token) {
			t.Fatalf("JSON escaped the bounded authenticated response: status %d", w.Code)
		}
		if w.Code != 200 && strings.Contains(w.Body.String(), managedIssuedBearer) {
			t.Fatal("failed JSON request disclosed credential")
		}
	})
}
