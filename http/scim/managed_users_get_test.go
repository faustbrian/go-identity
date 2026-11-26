package scimhttp_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	scimhttp "github.com/faustbrian/go-identity/http/scim"
	scim "github.com/faustbrian/go-scim"
	scimpostgres "github.com/faustbrian/go-scim/postgres"
)

const managedUserGetPath = "/scim/v2/Users/source-user"
const managedUserGetETag = `"opaque-version:7"`
const managedUserGetBody = `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"source-user","userName":"get-person","meta":{"resourceType":"User","version":"\"opaque-version:7\"","location":"https://directory.example/scim/v2/Users/source-user"}}`

var _ scimhttp.ManagedUsersGetExecutor = (*scimpostgres.ManagedConnectionService)(nil)

type managedUserGetFixture struct {
	config   scimhttp.ManagedUsersGetConfig
	executor *managedUsersExecutor
	base     protocolFixture
}

func newManagedUserGetFixture() managedUserGetFixture {
	base := newProtocolFixture()
	executor := &managedUsersExecutor{client: base.executor.client, response: scim.Response{Status: 200, ContentType: "application/scim+json", Body: []byte(managedUserGetBody), ETag: managedUserGetETag, Location: "https://directory.example/scim/v2/Users/source-user"}}
	return managedUserGetFixture{base: base, executor: executor, config: scimhttp.ManagedUsersGetConfig{Network: base.config.Network, Executor: executor, Rate: base.config.Rate, Limits: scim.DefaultLimits(), MaximumDuration: time.Second}}
}

func (f managedUserGetFixture) router(t *testing.T) (http.Handler, identityhttp.OpenAPIDocument) {
	t.Helper()
	feature, err := scimhttp.NewManagedUsersGetFeature(f.config)
	if err != nil {
		t.Fatal(err)
	}
	ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	return protocolRouter(t, f.config.Network, ops)
}

func (f managedUserGetFixture) request(query string) *http.Request {
	return protocolRequest(http.MethodGet, managedUserGetPath+query, "")
}

func TestManagedUsersGetTLSRetainsExactNativeResourceETagAndProjection(t *testing.T) {
	f := newManagedUserGetFixture()
	handler, document := f.router(t)
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	client := server.Client()
	defer client.CloseIdleConnections()
	r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+managedUserGetPath+"?attributes=userName,meta", nil)
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
	if response.StatusCode != 200 || readErr != nil || closeErr != nil || string(body) != managedUserGetBody || response.Header.Get("ETag") != managedUserGetETag || response.Header.Get("Content-Type") != "application/scim+json" || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" || response.Header.Get("Set-Cookie") != "" || response.Header.Get("Location") != "" {
		t.Fatalf("native resource/ETag did not survive TLS: status %d headers %v", response.StatusCode, response.Header)
	}
	got := f.executor.request
	if got.Operation != scim.UserGet || got.ResourceID != "source-user" || got.Credential.Token() != syntheticBearer || got.Query.Attributes != "userName,meta" || got.Query.ExcludedAttributes != "" || got.Query.Filter != "" || got.Query.Count != nil || got.IfMatch != "" || got.IdempotencyKey != "" || got.Body != nil || f.executor.tenant != f.executor.client.TenantID || f.executor.calls != 1 || f.base.backend.calls != 1 || len(f.base.backend.last.Requests) != 3 {
		t.Fatal("Get changed native request scope or exact-once protocol admission")
	}
	if len(document.Operations()) != 1 || document.Operations()[0].Record.OperationID != "identity.scim.user-get" || document.Operations()[0].Record.RatePolicy != "rate.protocol" {
		t.Fatal("wire metadata differs from selected Get")
	}
	var wire map[string]any
	if json.Unmarshal(document.JSON(), &wire) != nil || strings.Contains(string(document.JSON()), syntheticBearer) {
		t.Fatal("invalid or sensitive OpenAPI")
	}
}

func TestManagedUsersGetTLSDenialsNeverDiscloseNativeResourceOrVersion(t *testing.T) {
	f := newManagedUserGetFixture()
	h, _ := f.router(t)
	server := httptest.NewTLSServer(h)
	defer server.Close()
	client := server.Client()
	defer client.CloseIdleConnections()
	for _, mode := range []string{"cookie-only", "encoding", "key"} {
		t.Run(mode, func(t *testing.T) {
			r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+managedUserGetPath, nil)
			if err != nil {
				t.Fatal(err)
			}
			r.Host = "directory.example"
			r.Header.Set("Authorization", "Bearer "+syntheticBearer)
			want := 400
			switch mode {
			case "cookie-only":
				r.Header.Del("Authorization")
				r.AddCookie(&http.Cookie{Name: "session", Value: syntheticBearer})
				want = 401
			case "encoding":
				r.Header.Set("Content-Encoding", "gzip")
				want = 415
			case "key":
				r.Header.Set("Idempotency-Key", "forbidden")
			}
			response, err := client.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			body, readErr := io.ReadAll(io.LimitReader(response.Body, 8192))
			closeErr := response.Body.Close()
			var protocol struct {
				Schemas []string `json:"schemas"`
				Status  string   `json:"status"`
			}
			if response.StatusCode != want || readErr != nil || closeErr != nil || json.Unmarshal(body, &protocol) != nil || protocol.Status != strconv.Itoa(want) || len(protocol.Schemas) != 1 || protocol.Schemas[0] != "urn:ietf:params:scim:api:messages:2.0:Error" || response.Header.Get("Content-Type") != "application/scim+json" || response.Header.Get("ETag") != "" || response.Header.Get("Set-Cookie") != "" || strings.Contains(string(body), syntheticBearer) || strings.Contains(string(body), "source-user") || f.executor.calls != 0 || f.base.backend.calls != 0 {
				t.Fatalf("TLS denial %s changed protocol/no-disclosure contract: status %d want %d", mode, response.StatusCode, want)
			}
		})
	}
}

func TestManagedUsersGetRejectsNoncanonicalRoutesAndNeverTrustsForgedPathValue(t *testing.T) {
	for _, path := range []string{"/scim/v2/Users", managedUserGetPath + "/", managedUserGetPath + "/extra", "/scim/v2/Users/.search", "/scim/v2/Users/..", "/scim/v2/users/source-user", "/scim/v2/Groups/source-user", "/scim/v2/Users/%73ource-user", "/scim/v2/Users/a%2Fb", "/scim/v2/Users/{resource_id}"} {
		t.Run(path, func(t *testing.T) {
			f := newManagedUserGetFixture()
			h, _ := f.router(t)
			r := protocolRequest(http.MethodGet, path, "")
			r.SetPathValue("resource_id", "source-user")
			w := managedServe(h, r)
			if w.Code != 404 || f.executor.calls != 0 || f.base.backend.calls != 0 {
				t.Fatalf("noncanonical route reached native: %d", w.Code)
			}
		})
	}
	f := newManagedUserGetFixture()
	h, _ := f.router(t)
	r := f.request("")
	r.SetPathValue("resource_id", "forged")
	if w := managedServe(h, r); w.Code != 200 || f.executor.request.ResourceID != "source-user" {
		t.Fatal("router did not replace forged path value with real route provenance")
	}
	for _, method := range []string{http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions} {
		r := f.request("")
		r.Method = method
		w := managedServe(h, r)
		if w.Code != 405 || w.Header().Get("Allow") != "GET" {
			t.Fatalf("implicit method variant exposed: %s %d", method, w.Code)
		}
	}
	feature, err := scimhttp.NewManagedUsersGetFeature(f.config)
	if err != nil {
		t.Fatal(err)
	}
	r = f.request("")
	if w := managedServe(feature.Operations()[0].Handler, r); w.Code != 404 {
		t.Fatal("direct handler accepted absent router path provenance")
	}
}

func TestManagedUsersGetOnlyForwardsBoundedProjectionScalars(t *testing.T) {
	for _, query := range []string{"", "?attributes=userName%2Cmeta", "?excludedAttributes=displayName", "?attributes=urn%3Aexample%3AUser%3Anote%2520"} {
		t.Run(query, func(t *testing.T) {
			f := newManagedUserGetFixture()
			h, _ := f.router(t)
			if w := managedServe(h, f.request(query)); w.Code != 200 {
				t.Fatalf("valid projection denied: %d", w.Code)
			}
			if strings.Contains(query, "%2520") && f.executor.request.Query.Attributes != "urn:example:User:note%20" {
				t.Fatal("projection decoded twice")
			}
		})
	}
	for _, query := range []string{"?filter=id", "?sortBy=id", "?sortOrder=ascending", "?count=1", "?startIndex=1", "?tenantID=override", "?attributes=x&attributes=y", "?attributes=x&Attributes=y", "?attributes=%ZZ", "?attributes=%FF", "?attributes=x;count=1", "?attributes=x&&excludedAttributes=y", "?Idempotency-Key=forbidden", "?access_token=forbidden", "?", "?attributes=" + strings.Repeat("a", 1100)} {
		t.Run(query, func(t *testing.T) {
			f := newManagedUserGetFixture()
			h, _ := f.router(t)
			r := f.request("")
			r.URL.RawQuery = strings.TrimPrefix(query, "?")
			r.URL.ForceQuery = query == "?"
			r.RequestURI = r.URL.RequestURI()
			if w := managedServe(h, r); w.Code != 400 || f.executor.calls != 0 || f.base.backend.calls != 0 {
				t.Fatalf("bad Get query reached native: %d", w.Code)
			}
		})
	}
}

func TestManagedUsersGetEveryReadUsesCurrentNativeOutputAndFreshQuota(t *testing.T) {
	f := newManagedUserGetFixture()
	h, _ := f.router(t)
	first := managedServe(h, f.request(""))
	f.executor.response.ETag = `"next-opaque-version"`
	f.executor.response.Body = []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"source-user","meta":{"version":"\"next-opaque-version\""}}`)
	second := managedServe(h, f.request("?excludedAttributes=userName"))
	if first.Code != 200 || second.Code != 200 || first.Header().Get("ETag") != managedUserGetETag || second.Header().Get("ETag") != `"next-opaque-version"` || second.Body.String() != string(f.executor.response.Body) || f.executor.request.Query.ExcludedAttributes != "userName" || f.executor.calls != 2 || f.base.backend.calls != 2 {
		t.Fatal("Get cached native authority/output, retried or skipped a fresh quota attempt")
	}
}

func TestManagedUsersGetRejectsUnsupportedTransportBeforeNativeAuthority(t *testing.T) {
	for _, mode := range []string{"body", "key", "cookie-only", "duplicate-bearer", "encoding", "trailer", "if-match", "if-none-match", "duplicate-conditional", "range", "duplicate-range", "cleartext"} {
		t.Run(mode, func(t *testing.T) {
			f := newManagedUserGetFixture()
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
				r.Header.Set("If-Match", managedUserGetETag)
			case "if-none-match":
				r.Header.Set("If-None-Match", managedUserGetETag)
			case "duplicate-conditional":
				r.Header["If-None-Match"] = []string{managedUserGetETag, managedUserGetETag}
			case "range":
				r.Header.Set("Range", "bytes=0-1")
			case "duplicate-range":
				r.Header["Range"] = []string{"bytes=0-1", "bytes=2-3"}
			case "cleartext":
				r.TLS = nil
				r.URL.Scheme = "http"
				want = 403
			}
			w := managedServe(h, r)
			if w.Code != want || f.executor.calls != 0 || f.base.backend.calls != 0 || strings.Contains(w.Body.String(), syntheticBearer) {
				t.Fatalf("unsupported transport %s: status %d want %d", mode, w.Code, want)
			}
		})
	}
}

func TestManagedUsersGetIsDefaultOffAndComposesWithListAndBulk(t *testing.T) {
	f := newManagedUserGetFixture()
	empty, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{})
	if err != nil {
		t.Fatal(err)
	}
	if w := managedServe(empty, f.request("")); w.Code != 404 || f.executor.calls != 0 {
		t.Fatal("unselected Get exposed native authority")
	}
	get, err := scimhttp.NewManagedUsersGetFeature(f.config)
	if err != nil {
		t.Fatal(err)
	}
	list, err := scimhttp.NewManagedUsersListFeature(scimhttp.ManagedUsersListConfig{Network: f.config.Network, Executor: f.executor, Rate: f.config.Rate, Limits: f.config.Limits, MaximumDuration: f.config.MaximumDuration})
	if err != nil {
		t.Fatal(err)
	}
	bulk, err := scimhttp.NewBulkFeature(f.base.config)
	if err != nil {
		t.Fatal(err)
	}
	operations := append(get.Operations(), list.Operations()...)
	operations = append(operations, bulk.Operations()...)
	combined, err := identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "scim", Operations: operations})
	if err != nil {
		t.Fatal(err)
	}
	descriptors, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{combined}})
	if err != nil {
		t.Fatal(err)
	}
	h, doc := protocolRouter(t, f.config.Network, descriptors)
	if w := managedServe(h, f.request("")); w.Code != 200 || len(doc.Operations()) != 4 {
		t.Fatal("canonical SCIM composition did not preserve independent Get")
	}
}

func TestManagedUsersGetRequiresNativeAuthorityOneAdmissionAndCompleteOutput(t *testing.T) {
	for _, mode := range []string{"auth-denied", "policy-denied", "missing", "wrong-tenant", "limited", "rate-unavailable", "skip", "double", "ignore", "late-error", "bad-json", "empty", "oversized", "bad-status", "bad-content-type", "empty-etag", "unsafe-etag", "unquoted-etag", "weak-etag", "large-etag"} {
		t.Run(mode, func(t *testing.T) {
			f := newManagedUserGetFixture()
			want := 503
			switch mode {
			case "auth-denied":
				f.executor.err = scim.NewError(401, "")
				want = 401
			case "policy-denied":
				f.executor.err = scim.NewError(403, "")
				want = 403
			case "missing":
				f.executor.err = scim.NewError(404, "")
				want = 404
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
				f.executor.response.Body = []byte(`{"id":`)
			case "empty":
				f.executor.response.Body = nil
			case "oversized":
				f.executor.response.Body = []byte(strings.Repeat("x", scim.DefaultLimits().ResponseBytes+1))
			case "bad-status":
				f.executor.response.Status = 201
			case "bad-content-type":
				f.executor.response.ContentType = "application/json"
			case "empty-etag":
				f.executor.response.ETag = ""
			case "unsafe-etag":
				f.executor.response.ETag = "\"x\r\nSet-Cookie: bad\""
			case "unquoted-etag":
				f.executor.response.ETag = "unquoted"
			case "weak-etag":
				f.executor.response.ETag = `W/"weak"`
			case "large-etag":
				f.executor.response.ETag = scim.Version(`"` + strings.Repeat("x", 255) + `"`)
			}
			h, _ := f.router(t)
			w := managedServe(h, f.request(""))
			if w.Code != want || strings.Contains(w.Body.String(), "source-user") || strings.Contains(w.Body.String(), "private") || w.Header().Get("ETag") != "" || w.Header().Get("Set-Cookie") != "" {
				t.Fatalf("failed output disclosed resource/version: %s status %d want %d", mode, w.Code, want)
			}
			if (mode == "auth-denied" || mode == "policy-denied" || mode == "missing" || mode == "wrong-tenant" || mode == "skip") && f.base.backend.calls != 0 {
				t.Fatal("absent authority/gate charged protocol quota")
			}
			if mode == "double" && f.base.backend.calls != 1 {
				t.Fatal("duplicate native admission debited twice")
			}
			if mode == "limited" && w.Header().Get("Retry-After") != "3" {
				t.Fatal("rate retry hint changed")
			}
			if mode == "auth-denied" && w.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Fatal("missing bearer challenge")
			}
		})
	}
}

func TestManagedUsersGetCancellationAndOwnerFailureNeverDiscloseETag(t *testing.T) {
	for _, mode := range []string{"before", "after", "panic", "error"} {
		t.Run(mode, func(t *testing.T) {
			f := newManagedUserGetFixture()
			r := f.request("")
			ctx, cancel := context.WithCancel(r.Context())
			defer cancel()
			r = r.WithContext(ctx)
			wantCharges := 0
			switch mode {
			case "before":
				f.executor.before = cancel
			case "after":
				f.executor.after = cancel
				wantCharges = 1
			case "panic":
				f.executor.before = func() { panic("private native panic") }
			case "error":
				f.executor.err = errors.New("private native diagnostic")
			}
			h, _ := f.router(t)
			w := managedServe(h, r)
			if w.Code != 503 || f.base.backend.calls != wantCharges || w.Header().Get("ETag") != "" || strings.Contains(w.Body.String(), "source-user") || strings.Contains(w.Body.String(), "private") {
				t.Fatalf("cancelled/failed native Get disclosed output: %s %d", mode, w.Code)
			}
		})
	}
}

func TestManagedUsersGetRejectsMissingOwnersInvalidLimitsAndUnboundedDeadlines(t *testing.T) {
	for _, mode := range []string{"zero", "nil-owner", "typed-nil-owner", "limits", "deadline", "long-deadline", "network", "rate"} {
		t.Run(mode, func(t *testing.T) {
			f := newManagedUserGetFixture()
			switch mode {
			case "zero":
				f.config = scimhttp.ManagedUsersGetConfig{}
			case "nil-owner":
				f.config.Executor = nil
			case "typed-nil-owner":
				f.config.Executor = (*managedUsersExecutor)(nil)
			case "limits":
				f.config.Limits = scim.Limits{}
			case "deadline":
				f.config.MaximumDuration = 0
			case "long-deadline":
				f.config.MaximumDuration = 31 * time.Second
			case "network":
				f.config.Network = identityhttp.NetworkConfig{}
			case "rate":
				f.config.Rate = scimhttp.ProtocolRateConfig{}
			}
			if _, err := scimhttp.NewManagedUsersGetFeature(f.config); !errors.Is(err, identityhttp.ErrInvalidInput) || f.executor.calls != 0 || f.base.backend.calls != 0 {
				t.Fatal("invalid configuration accepted or owner called during construction")
			}
		})
	}
}

func FuzzManagedUsersGetQuery(f *testing.F) {
	f.Add("attributes=userName,meta")
	f.Add("attributes=%FF&attributes=x")
	f.Add("excludedAttributes=displayName")
	f.Fuzz(func(t *testing.T, query string) {
		fixture := newManagedUserGetFixture()
		feature, err := scimhttp.NewManagedUsersGetFeature(fixture.config)
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
			t.Fatalf("hostile projection escaped boundary: %d", w.Code)
		}
	})
}
