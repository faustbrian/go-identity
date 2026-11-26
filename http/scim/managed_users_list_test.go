package scimhttp_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	scimhttp "github.com/faustbrian/go-identity/http/scim"
	scim "github.com/faustbrian/go-scim"
	scimpostgres "github.com/faustbrian/go-scim/postgres"
)

const managedUsersPath = "/scim/v2/Users"
const managedUsersListBody = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],"totalResults":1,"Resources":[{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"source-user","userName":"list-person","meta":{"version":"W/\"1\""}}],"startIndex":1,"itemsPerPage":1}`

// Only the native protocol boundary is doubled. Native bearer/current-policy,
// RFC query execution and PostgreSQL snapshot effects remain owner acceptance.
type managedUsersExecutor struct {
	client   scim.ProtocolClient
	request  scim.Request
	tenant   identity.TenantID
	calls    int
	err      error
	mode     string
	response scim.Response
	before   func()
	after    func()
}

func (e *managedUsersExecutor) ExecuteManagedAdmittedRead(ctx context.Context, tenant identity.TenantID, request scim.Request, admit scim.ProtocolAdmission) (scim.Response, error) {
	e.calls++
	e.tenant, e.request = tenant, request
	if _, ok := ctx.Deadline(); !ok {
		panic("unbounded native read")
	}
	if e.err != nil {
		return scim.Response{}, e.err
	}
	if e.before != nil {
		e.before()
	}
	if e.mode != "skip" {
		denial := admit(ctx, e.client)
		if e.mode != "ignore" && denial != nil {
			return scim.Response{}, denial
		}
		if e.mode == "double" {
			_ = admit(ctx, e.client)
		}
	}
	if e.after != nil {
		e.after()
	}
	if e.mode == "late-error" {
		return e.response, errors.New("private native diagnostic")
	}
	return e.response, nil
}

var _ scimhttp.ManagedUsersListExecutor = (*scimpostgres.ManagedConnectionService)(nil)

type managedUsersFixture struct {
	config   scimhttp.ManagedUsersListConfig
	executor *managedUsersExecutor
	base     protocolFixture
}

func newManagedUsersFixture() managedUsersFixture {
	base := newProtocolFixture()
	executor := &managedUsersExecutor{client: base.executor.client, response: scim.Response{Status: 200, ContentType: "application/scim+json", Body: []byte(managedUsersListBody)}}
	return managedUsersFixture{base: base, executor: executor, config: scimhttp.ManagedUsersListConfig{Network: base.config.Network, Executor: executor, Rate: base.config.Rate, Limits: scim.DefaultLimits(), MaximumDuration: time.Second}}
}
func (f managedUsersFixture) router(t *testing.T) (http.Handler, identityhttp.OpenAPIDocument) {
	t.Helper()
	feature, err := scimhttp.NewManagedUsersListFeature(f.config)
	if err != nil {
		t.Fatal(err)
	}
	operations, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	return protocolRouter(t, f.config.Network, operations)
}
func (f managedUsersFixture) request(query string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "https://directory.example"+managedUsersPath+query, nil)
	r.RequestURI = r.URL.RequestURI()
	r.Host = "directory.example"
	r.RemoteAddr = "198.51.100.7:43210"
	r.Header.Set("Authorization", "Bearer "+syntheticBearer)
	return r
}

func TestManagedUsersListTLSForwardsOnlyExactRFCScalarsAndChargesAfterNativeAuthorization(t *testing.T) {
	f := newManagedUsersFixture()
	handler, document := f.router(t)
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	client := server.Client()
	defer client.CloseIdleConnections()
	query := url.Values{"filter": []string{`userName eq "list-person"`}, "sortBy": []string{"userName"}, "sortOrder": []string{"descending"}, "startIndex": []string{"1"}, "count": []string{"10"}, "attributes": []string{"userName,meta"}}
	r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+managedUsersPath+"?"+query.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Host = "directory.example"
	r.Header.Set("Authorization", "Bearer "+syntheticBearer)
	r.AddCookie(&http.Cookie{Name: "session", Value: "ignored-cookie"})
	response, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	closeErr := response.Body.Close()
	if response.StatusCode != 200 || readErr != nil || closeErr != nil || string(body) != managedUsersListBody || response.Header.Get("Content-Type") != "application/scim+json" || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Set-Cookie") != "" {
		t.Fatalf("native RFC response did not survive actual TLS: status %d", response.StatusCode)
	}
	got := f.executor.request
	if got.Operation != scim.UserList || got.Credential.Token() != syntheticBearer || got.ResourceID != "" || got.IdempotencyKey != "" || got.Body != nil || f.executor.tenant != f.executor.client.TenantID || got.Query.Filter != query.Get("filter") || got.Query.SortBy != "userName" || got.Query.SortOrder != "descending" || got.Query.StartIndex != 1 || got.Query.Count == nil || *got.Query.Count != 10 || got.Query.Attributes != "userName,meta" {
		t.Fatal("HTTP altered native RFC scalar semantics or selected unauthorized request scope")
	}
	if f.base.backend.calls != 1 || len(f.base.backend.last.Requests) != 3 {
		t.Fatal("read did not use exactly one shared atomic protocol admission")
	}
	if strings.Contains(string(document.JSON()), syntheticBearer) || strings.Contains(string(body), syntheticBearer) {
		t.Fatal("bearer custody escaped to public output")
	}
}

func TestManagedUsersListPreservesOmittedAndZeroPaginationAndRootOwnedSemantics(t *testing.T) {
	for _, query := range []string{"", "?count=0", "?count=-3&startIndex=-2", "?count=999999&startIndex=0", "?excludedAttributes=displayName", "?filter=userName%20co%20%22%2520%22", "?count=%2B001"} {
		t.Run(query, func(t *testing.T) {
			f := newManagedUsersFixture()
			f.executor.response.Body = []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],"totalResults":0,"Resources":[],"startIndex":1,"itemsPerPage":0}`)
			h, _ := f.router(t)
			w := managedServe(h, f.request(query))
			if w.Code != 200 || f.executor.calls != 1 {
				t.Fatalf("valid RFC input denied: status %d", w.Code)
			}
			if query == "" && f.executor.request.Query.Count != nil {
				t.Fatal("omitted count became a supplied default")
			}
			if query == "?count=0" && (f.executor.request.Query.Count == nil || *f.executor.request.Query.Count != 0) {
				t.Fatal("zero count was discarded")
			}
			if query == "?count=-3&startIndex=-2" && (f.executor.request.Query.Count == nil || *f.executor.request.Query.Count != -3 || f.executor.request.Query.StartIndex != -2) {
				t.Fatal("transport replaced defined native negative pagination semantics")
			}
			if strings.Contains(query, "%2520") && f.executor.request.Query.Filter != `userName co "%20"` {
				t.Fatal("filter decoded more than once")
			}
		})
	}
}

func TestManagedUsersListRejectsAmbiguousUnknownAndOverflowingQueryBeforeNativeWork(t *testing.T) {
	for _, query := range []string{"?tenantID=override", "?filter=x&filter=y", "?filter=x&Filter=x", "?count=", "?count=1.2", "?count=1e2", "?count=9223372036854775808", "?startIndex=-9223372036854775809", "?count=1&&sortBy=id", "?filter=%ZZ", "?filter=%FF", "?sortBy=id;count=1", "?access_token=forbidden", "?Idempotency-Key=forbidden", "?", "?unknown="} {
		t.Run(query, func(t *testing.T) {
			f := newManagedUsersFixture()
			h, _ := f.router(t)
			r := f.request("")
			r.URL.RawQuery = strings.TrimPrefix(query, "?")
			r.URL.ForceQuery = query == "?"
			r.RequestURI = r.URL.RequestURI()
			w := managedServe(h, r)
			if w.Code != 400 || f.executor.calls != 0 || f.base.backend.calls != 0 {
				t.Fatalf("bad query reached native authority: status %d", w.Code)
			}
		})
	}
}

func TestManagedUsersListRejectsBodyKeyCookiesAndUnsupportedTransport(t *testing.T) {
	for _, mode := range []string{"body", "key", "cookie-only", "duplicate-bearer", "encoding", "trailer", "if-match", "oversized-query"} {
		t.Run(mode, func(t *testing.T) {
			f := newManagedUsersFixture()
			h, _ := f.router(t)
			r := f.request("")
			want := 400
			switch mode {
			case "body":
				r.Body = io.NopCloser(strings.NewReader("{}"))
				r.ContentLength = 2
			case "key":
				r.Header.Set("Idempotency-Key", "forbidden")
			case "cookie-only":
				r.Header.Del("Authorization")
				r.AddCookie(&http.Cookie{Name: "session", Value: syntheticBearer})
				want = 401
			case "duplicate-bearer":
				r.Header.Add("Authorization", "Bearer "+syntheticBearer)
			case "encoding":
				r.Header.Set("Content-Encoding", "gzip")
				want = 415
			case "trailer":
				r.Trailer = http.Header{"X-Trailer": []string{"forbidden"}}
			case "if-match":
				r.Header.Set("If-Match", `W/"1"`)
			case "oversized-query":
				r.URL.RawQuery = "filter=" + strings.Repeat("a", 1100)
				r.RequestURI = r.URL.RequestURI()
			}
			w := managedServe(h, r)
			if w.Code != want || f.executor.calls != 0 || f.base.backend.calls != 0 || strings.Contains(w.Body.String(), syntheticBearer) {
				t.Fatalf("unsupported transport reached native: %s status %d want %d", mode, w.Code, want)
			}
		})
	}
}

func TestManagedUsersListRequiresOneSuccessfulNativeAuthorizedAtomicCharge(t *testing.T) {
	for _, mode := range []string{"auth-denied", "policy-denied", "wrong-tenant", "limited", "rate-unavailable", "skip", "double", "ignore", "late-error", "bad-json", "empty", "oversized", "bad-status"} {
		t.Run(mode, func(t *testing.T) {
			f := newManagedUsersFixture()
			want := 503
			switch mode {
			case "auth-denied":
				f.executor.err = scim.NewError(401, "")
				want = 401
			case "policy-denied":
				f.executor.err = scim.NewError(403, "")
				want = 403
			case "wrong-tenant":
				f.executor.client.TenantID = "other-tenant"
				want = 403
			case "limited":
				f.base.backend.limited = true
				want = 429
			case "rate-unavailable":
				f.base.backend.unavailable = true
			case "skip", "double", "late-error":
				f.executor.mode = mode
			case "ignore":
				f.executor.mode = mode
				f.base.backend.limited = true
			case "bad-json":
				f.executor.response.Body = []byte(`{"Resources":[`)
			case "empty":
				f.executor.response.Body = nil
			case "oversized":
				f.executor.response.Body = []byte(strings.Repeat("x", scim.DefaultLimits().ResponseBytes+1))
			case "bad-status":
				f.executor.response.Status = 201
			}
			h, _ := f.router(t)
			w := managedServe(h, f.request(""))
			if w.Code != want || strings.Contains(w.Body.String(), "source-user") || strings.Contains(w.Body.String(), syntheticBearer) || strings.Contains(w.Body.String(), "private") {
				t.Fatalf("admission/response boundary failed closed: %s status %d want %d", mode, w.Code, want)
			}
			if mode == "auth-denied" || mode == "policy-denied" || mode == "wrong-tenant" || mode == "skip" {
				if f.base.backend.calls != 0 {
					t.Fatal("unauthorized or absent native gate charged quota")
				}
			}
			if mode == "double" && f.base.backend.calls != 1 {
				t.Fatal("duplicate callback charged a second attempt")
			}
			if mode == "limited" && w.Header().Get("Retry-After") != "3" {
				t.Fatal("protocol Retry-After rounding changed")
			}
		})
	}
}

func TestManagedUsersListCancellationBeforeAndAfterAdmissionCannotDisclose(t *testing.T) {
	for _, phase := range []string{"before", "after"} {
		t.Run(phase, func(t *testing.T) {
			f := newManagedUsersFixture()
			r := f.request("")
			ctx, cancel := context.WithCancel(r.Context())
			defer cancel()
			r = r.WithContext(ctx)
			wantCharges := 0
			if phase == "before" {
				f.executor.before = cancel
			} else {
				f.executor.after = cancel
				wantCharges = 1
			}
			h, _ := f.router(t)
			w := managedServe(h, r)
			if w.Code != 503 || f.base.backend.calls != wantCharges || strings.Contains(w.Body.String(), "source-user") || strings.Contains(w.Body.String(), syntheticBearer) {
				t.Fatalf("cancelled %s admission disclosed data or changed charge custody: status %d", phase, w.Code)
			}
		})
	}
}

func TestManagedUsersListSelectsOnlyListAndComposesUnderCanonicalSCIMOwner(t *testing.T) {
	f := newManagedUsersFixture()
	h, document := f.router(t)
	for _, path := range []string{managedUsersPath + "/source-user", "/scim/v2/Groups", providerConfigPath, bulkPath} {
		r := f.request("")
		r.URL.Path = path
		r.RequestURI = r.URL.RequestURI()
		if w := managedServe(h, r); w.Code != 404 {
			t.Fatalf("unselected protocol operation exposed: status %d", w.Code)
		}
	}
	if len(document.Operations()) != 1 || document.Operations()[0].Record.OperationID != "identity.scim.user-list" || document.Operations()[0].Record.RatePolicy != "rate.protocol" {
		t.Fatal("List metadata differs from actual route")
	}
	list, err := scimhttp.NewManagedUsersListFeature(f.config)
	if err != nil {
		t.Fatal(err)
	}
	bulk, err := scimhttp.NewBulkFeature(f.base.config)
	if err != nil {
		t.Fatal(err)
	}
	combined, err := identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "scim", Operations: append(list.Operations(), bulk.Operations()...)})
	if err != nil {
		t.Fatal(err)
	}
	operations, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{combined}})
	if err != nil {
		t.Fatal(err)
	}
	_, combinedDoc := protocolRouter(t, f.config.Network, operations)
	if len(combinedDoc.Operations()) != 3 {
		t.Fatal("List did not compose with retained Bulk")
	}
	if _, err := scimhttp.NewManagedUsersListFeature(scimhttp.ManagedUsersListConfig{}); err == nil {
		t.Fatal("missing dependencies accepted")
	}
	var wire map[string]any
	if json.Unmarshal(document.JSON(), &wire) != nil {
		t.Fatal("OpenAPI is not exportable JSON")
	}
}

func FuzzManagedUsersListQuery(f *testing.F) {
	f.Add("count=0")
	f.Add("filter=userName%20eq%20%22person%22&startIndex=-2")
	f.Add("filter=%FF&filter=duplicate")
	f.Fuzz(func(t *testing.T, query string) {
		fixture := newManagedUsersFixture()
		feature, err := scimhttp.NewManagedUsersListFeature(fixture.config)
		if err != nil {
			t.Fatal(err)
		}
		h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
		if err != nil {
			t.Fatal(err)
		}
		r := fixture.request("")
		r.URL.RawQuery = query
		r.RequestURI = r.URL.RequestURI()
		w := managedServe(h, r)
		if w.Code != 200 && w.Code != 400 && w.Code != 401 || strings.Contains(w.Body.String(), syntheticBearer) {
			t.Fatalf("hostile query escaped bounded protocol input: status %d", w.Code)
		}
	})
}
