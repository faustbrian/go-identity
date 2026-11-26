package scimhttp_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	scimhttp "github.com/faustbrian/go-identity/http/scim"
	jsonschema "github.com/faustbrian/go-json-schema/v2"
	scim "github.com/faustbrian/go-scim"
	scimpostgres "github.com/faustbrian/go-scim/postgres"
)

const managedGroupsPath = "/scim/v2/Groups"
const managedGroupGetPath = managedGroupsPath + "/source-group"
const managedGroupETag = `"opaque-group:7"`
const managedGroupBody = `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"id":"source-group","displayName":"Directory team","members":[{"value":"source-user","type":"User"}],"meta":{"resourceType":"Group","version":"\"opaque-group:7\"","location":"https://directory.example/scim/v2/Groups/source-group"}}`
const managedGroupsBody = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],"totalResults":1,"Resources":[` + managedGroupBody + `],"startIndex":1,"itemsPerPage":1}`

// Only the native protocol boundary is doubled. The native owner's integration
// tests retain actual bearer, Group snapshot, schema and final-fence proof.
type managedGroupsExecutor struct {
	*managedUsersExecutor
	maximum int
}

func (e *managedGroupsExecutor) ExecuteManagedAdmittedGroupRead(ctx context.Context, tenant identity.TenantID, request scim.Request, maximum int, admit scim.ProtocolAdmission) (scim.Response, error) {
	e.maximum = maximum
	return e.ExecuteManagedAdmittedRead(ctx, tenant, request, admit)
}

var _ scimhttp.ManagedGroupsReadExecutor = (*scimpostgres.ManagedConnectionService)(nil)

type managedGroupsFixture struct {
	config   scimhttp.ManagedGroupsReadConfig
	executor *managedGroupsExecutor
	base     protocolFixture
}

func newManagedGroupsFixture(get bool) managedGroupsFixture {
	base := newProtocolFixture()
	response := scim.Response{Status: 200, ContentType: "application/scim+json", Body: []byte(managedGroupsBody)}
	if get {
		response.Body, response.ETag = []byte(managedGroupBody), managedGroupETag
		response.Location = "https://directory.example" + managedGroupGetPath
	}
	executor := &managedGroupsExecutor{managedUsersExecutor: &managedUsersExecutor{client: base.executor.client, response: response}}
	return managedGroupsFixture{base: base, executor: executor, config: scimhttp.ManagedGroupsReadConfig{Network: base.config.Network, Executor: executor, Rate: base.config.Rate, Limits: scim.DefaultLimits(), MaximumDuration: time.Second, MaximumMembers: scim.DefaultGroupMembers, EnableGet: get, EnableList: !get}}
}

func (f managedGroupsFixture) router(t *testing.T) (http.Handler, identityhttp.OpenAPIDocument) {
	t.Helper()
	feature, err := scimhttp.NewManagedGroupsReadFeature(f.config)
	if err != nil {
		t.Fatal(err)
	}
	ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	return protocolRouter(t, f.config.Network, ops)
}

func (f managedGroupsFixture) request(query string) *http.Request {
	path := managedGroupsPath
	if f.config.EnableGet {
		path = managedGroupGetPath
	}
	return protocolRequest(http.MethodGet, path+query, "")
}

func TestManagedGroupsReadTLSRetainsNativeBytesSelectorsAndExactlyOneAdmission(t *testing.T) {
	for _, get := range []bool{false, true} {
		t.Run(strconv.FormatBool(get), func(t *testing.T) {
			f := newManagedGroupsFixture(get)
			h, doc := f.router(t)
			server := httptest.NewTLSServer(h)
			defer server.Close()
			client := server.Client()
			defer client.CloseIdleConnections()
			path, query, operation := managedGroupsPath, "?filter=displayName%20eq%20%22Directory%20team%22&sortBy=displayName&sortOrder=descending&startIndex=-2&count=0&excludedAttributes=members", scim.GroupList
			if get {
				path, query, operation = managedGroupGetPath, "?attributes=displayName%2Cmembers%2Cmeta", scim.GroupGet
			}
			r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+path+query, nil)
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
			if response.StatusCode != 200 || readErr != nil || closeErr != nil || string(body) != string(f.executor.response.Body) || response.Header.Get("ETag") != string(f.executor.response.ETag) || response.Header.Get("Location") != "" || response.Header.Get("Set-Cookie") != "" || response.Header.Get("Content-Type") != "application/scim+json" || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" {
				t.Fatalf("native Group representation changed over TLS: %d", response.StatusCode)
			}
			got := f.executor.request
			if got.Operation != operation || got.Credential.Token() != syntheticBearer || got.IfMatch != "" || got.IdempotencyKey != "" || got.Body != nil || f.executor.tenant != f.executor.client.TenantID || f.executor.maximum != scim.DefaultGroupMembers || f.executor.calls != 1 || f.base.backend.calls != 1 || len(f.base.backend.last.Requests) != 3 {
				t.Fatal("native Group scope, configured member ceiling or exact-once quota custody changed")
			}
			if get {
				if got.ResourceID != "source-group" || got.Query.Attributes != "displayName,members,meta" || got.Query.Count != nil || got.Query.Filter != "" {
					t.Fatal("Get projection or router resource provenance changed")
				}
			} else if got.ResourceID != "" || got.Query.Filter != `displayName eq "Directory team"` || got.Query.SortBy != "displayName" || got.Query.SortOrder != "descending" || got.Query.StartIndex != -2 || got.Query.Count == nil || *got.Query.Count != 0 || got.Query.ExcludedAttributes != "members" {
				t.Fatal("List RFC selector semantics changed")
			}
			if len(doc.Operations()) != 1 || doc.Operations()[0].Record.RatePolicy != "rate.protocol" || strings.Contains(string(doc.JSON()), syntheticBearer) {
				t.Fatal("selected Group metadata differs from protocol custody")
			}
			validateManagedGroupsReadWireResponse(t, doc, get, "200", response.Header.Get("Content-Type"), body)
		})
	}
}

func TestManagedGroupsReadForwardsOmissionSignedPaginationAndOnceDecodedProjection(t *testing.T) {
	for _, query := range []string{"", "?count=-3&startIndex=0", "?count=%2B001", "?count=999999", "?attributes=urn%3Aexample%3AGroup%3Anote%2520"} {
		f := newManagedGroupsFixture(false)
		h, _ := f.router(t)
		if w := managedServe(h, f.request(query)); w.Code != 200 {
			t.Fatalf("native-owned scalar semantics rejected: %s %d", query, w.Code)
		}
		got := f.executor.request.Query
		if query == "" && got.Count != nil || query == "?count=-3&startIndex=0" && (got.Count == nil || *got.Count != -3 || got.StartIndex != 0) || strings.Contains(query, "%2520") && got.Attributes != "urn:example:Group:note%20" {
			t.Fatal("native scalar omission, negative count or once-decoding changed")
		}
	}
}

func TestManagedGroupsReadDocumentsRouterErrors(t *testing.T) {
	for _, get := range []bool{false, true} {
		f := newManagedGroupsFixture(get)
		handler, doc := f.router(t)
		for _, tc := range []struct {
			name   string
			status int
			change func(*http.Request)
		}{
			{"cleartext", http.StatusForbidden, func(r *http.Request) { r.URL.Scheme, r.TLS = "http", nil }},
			{"misdirected host", http.StatusMisdirectedRequest, func(r *http.Request) { r.Host = "unselected.example" }},
			{"unsupported method", http.StatusMethodNotAllowed, func(r *http.Request) { r.Method = http.MethodDelete }},
		} {
			t.Run(strconv.FormatBool(get)+"/"+tc.name, func(t *testing.T) {
				r := f.request("")
				tc.change(r)
				w := managedServe(handler, r)
				if w.Code != tc.status || w.Header().Get("Content-Type") != "application/json" || f.executor.calls != 0 {
					t.Fatalf("expected outer JSON denial %d before native execution; got %d %q", tc.status, w.Code, w.Header().Get("Content-Type"))
				}
				validateManagedGroupsReadWireResponse(t, doc, get, strconv.Itoa(w.Code), w.Header().Get("Content-Type"), w.Body.Bytes())
			})
		}
	}
}

func TestManagedGroupsReadRejectsMalformedDuplicateAndUnexpectedQueriesBeforeNative(t *testing.T) {
	for _, get := range []bool{false, true} {
		queries := []string{"?tenantID=override", "?attributes=x&attributes=y", "?attributes=x&Attributes=y", "?attributes=%ZZ", "?attributes=%FF", "?attributes=x&&excludedAttributes=y", "?attributes=x;count=1", "?access_token=forbidden", "?", "?attributes=" + strings.Repeat("a", 1100)}
		if get {
			queries = append(queries, "?count=1", "?startIndex=1", "?filter=id", "?sortBy=id", "?sortOrder=ascending")
		} else {
			queries = append(queries, "?count=", "?count=1.2", "?count=9223372036854775808", "?startIndex=-9223372036854775809", "?filter=x&filter=y", "?filter=x&Filter=y")
		}
		for _, query := range queries {
			t.Run(fmt.Sprintf("%t/%s", get, query), func(t *testing.T) {
				f := newManagedGroupsFixture(get)
				h, _ := f.router(t)
				r := f.request("")
				r.URL.RawQuery, r.URL.ForceQuery = strings.TrimPrefix(query, "?"), query == "?"
				r.RequestURI = r.URL.RequestURI()
				if w := managedServe(h, r); w.Code != 400 || f.executor.calls != 0 || f.base.backend.calls != 0 {
					t.Fatalf("malformed selector reached native: %d", w.Code)
				}
			})
		}
	}
}

func TestManagedGroupsReadRejectsUnsupportedTransportAndCookieFallback(t *testing.T) {
	for _, get := range []bool{false, true} {
		for _, mode := range []string{"body", "trailer", "transfer", "encoding", "key", "cookie-only", "duplicate-bearer", "if-match", "if-none-match", "if-modified-since", "if-unmodified-since", "if-range", "range", "cleartext"} {
			t.Run(fmt.Sprintf("%t/%s", get, mode), func(t *testing.T) {
				f := newManagedGroupsFixture(get)
				h, _ := f.router(t)
				r, want := f.request(""), 400
				switch mode {
				case "body":
					r.Body, r.ContentLength = io.NopCloser(strings.NewReader("{}")), 2
				case "trailer":
					r.Trailer = http.Header{"X-Trailer": []string{"forbidden"}}
				case "transfer":
					r.TransferEncoding = []string{"chunked"}
				case "encoding":
					r.Header.Set("Content-Encoding", "gzip")
					want = 415
				case "key":
					r.Header.Set("Idempotency-Key", "forbidden")
				case "cookie-only":
					r.Header.Del("Authorization")
					r.AddCookie(&http.Cookie{Name: "session", Value: syntheticBearer})
					want = 401
				case "duplicate-bearer":
					r.Header.Add("Authorization", "Bearer "+syntheticBearer)
				case "cleartext":
					r.TLS, r.URL.Scheme, want = nil, "http", 403
				default:
					r.Header.Set(mode, "forbidden")
				}
				w := managedServe(h, r)
				if w.Code != want || f.executor.calls != 0 || f.base.backend.calls != 0 || w.Header().Get("ETag") != "" || w.Header().Get("Set-Cookie") != "" || strings.Contains(w.Body.String(), syntheticBearer) {
					t.Fatalf("unsupported transport reached native: %d want %d", w.Code, want)
				}
			})
		}
	}
}

func TestManagedGroupsReadNativeFailureAdmissionAndInvalidOutputNeverDisclose(t *testing.T) {
	for _, get := range []bool{false, true} {
		for _, mode := range []string{"auth-denied", "policy-denied", "missing", "wrong-tenant", "limited", "rate-unavailable", "skip", "double", "ignore", "late-error", "error", "panic", "bad-json", "empty", "oversized", "bad-status", "bad-media", "bad-version", "empty-version", "unsafe-version", "large-version", "location"} {
			t.Run(fmt.Sprintf("%t/%s", get, mode), func(t *testing.T) {
				f, want := newManagedGroupsFixture(get), 503
				switch mode {
				case "auth-denied", "policy-denied", "missing":
					want = map[string]int{"auth-denied": 401, "policy-denied": 403, "missing": 404}[mode]
					f.executor.err = scim.NewError(want, "")
				case "wrong-tenant":
					f.executor.client.TenantID, want = "other-tenant", 403
				case "limited":
					f.base.backend.limited, want = true, 429
				case "rate-unavailable":
					f.base.backend.unavailable = true
				case "skip", "double", "late-error":
					f.executor.mode = mode
				case "ignore":
					f.executor.mode, f.base.backend.limited = mode, true
				case "error":
					f.executor.err = errors.New("private native diagnostic")
				case "panic":
					f.executor.before = func() { panic("private panic") }
				case "bad-json":
					f.executor.response.Body = []byte(`{"id":`)
				case "empty":
					f.executor.response.Body = nil
				case "oversized":
					f.executor.response.Body = []byte(strings.Repeat("x", f.config.Limits.ResponseBytes+1))
				case "bad-status":
					f.executor.response.Status = 201
				case "bad-media":
					f.executor.response.ContentType = "application/json"
				case "bad-version":
					f.executor.response.ETag = `W/"weak"`
				case "empty-version", "unsafe-version", "large-version":
					if !get {
						return
					}
					f.executor.response.ETag = ""
					if mode == "unsafe-version" {
						f.executor.response.ETag = "\"x\r\nSet-Cookie: bad\""
					} else if mode == "large-version" {
						f.executor.response.ETag = scim.Version(`"` + strings.Repeat("x", 255) + `"`)
					}
				case "location":
					if get {
						return // Native Get location stays in the body and is not a transport header.
					}
					f.executor.response.Location = "https://directory.example" + managedGroupGetPath
				}
				h, doc := f.router(t)
				w := managedServe(h, f.request(""))
				if w.Code != want || w.Header().Get("ETag") != "" || w.Header().Get("Location") != "" || strings.Contains(w.Body.String(), "source-group") || strings.Contains(w.Body.String(), "private") || strings.Contains(w.Body.String(), syntheticBearer) {
					t.Fatalf("native failure disclosed Group output: %d want %d", w.Code, want)
				}
				if (mode == "auth-denied" || mode == "policy-denied" || mode == "missing" || mode == "wrong-tenant" || mode == "skip") && f.base.backend.calls != 0 || mode == "double" && f.base.backend.calls != 1 {
					t.Fatal("failed authority or duplicate gate changed quota custody")
				}
				if mode == "limited" && w.Header().Get("Retry-After") != "3" || mode == "auth-denied" && w.Header().Get("WWW-Authenticate") != "Bearer" {
					t.Fatal("protocol retry/challenge metadata changed")
				}
				validateManagedGroupsReadWireResponse(t, doc, get, strconv.Itoa(w.Code), w.Header().Get("Content-Type"), w.Body.Bytes())
			})
		}
	}
}

func TestManagedGroupsReadCancellationAndFreshAttempts(t *testing.T) {
	for _, get := range []bool{false, true} {
		for _, after := range []bool{false, true} {
			f := newManagedGroupsFixture(get)
			r := f.request("")
			ctx, cancel := context.WithCancel(r.Context())
			if after {
				f.executor.after = cancel
			} else {
				f.executor.before = cancel
			}
			h, _ := f.router(t)
			w := managedServe(h, r.WithContext(ctx))
			cancel()
			wantCharges := 0
			if after {
				wantCharges = 1
			}
			if w.Code != 503 || f.base.backend.calls != wantCharges || w.Header().Get("ETag") != "" || strings.Contains(w.Body.String(), "source-group") {
				t.Fatal("cancelled Group read disclosed output or changed charge custody")
			}
		}
		f := newManagedGroupsFixture(get)
		h, _ := f.router(t)
		first := managedServe(h, f.request(""))
		f.executor.err = scim.NewError(403, "")
		second := managedServe(h, f.request(""))
		if first.Code != 200 || second.Code != 403 || f.executor.calls != 2 || f.base.backend.calls != 1 {
			t.Fatal("later request reused authority, cached output or retried the native owner")
		}
	}
}

func TestManagedGroupsReadSelectsEachCanonicalRouteAndRejectsUnprovenPaths(t *testing.T) {
	f := newManagedGroupsFixture(true)
	f.config.EnableList = true
	feature, err := scimhttp.NewManagedGroupsReadFeature(f.config)
	if err != nil || len(feature.Operations()) != 2 {
		t.Fatalf("independent selections did not compose: %v", err)
	}
	h, doc := f.router(t)
	if len(doc.Operations()) != 2 {
		t.Fatal("selected routes differ from metadata")
	}
	for _, path := range []string{managedGroupGetPath + "/", managedGroupGetPath + "/extra", managedGroupsPath + "/.search", managedGroupsPath + "/..", "/scim/v2/groups/source-group", managedGroupsPath + "/%73ource-group", managedGroupsPath + "/a%2Fb", managedGroupsPath + "/{resource_id}"} {
		r := protocolRequest(http.MethodGet, path, "")
		r.SetPathValue("resource_id", "source-group")
		if w := managedServe(h, r); w.Code != 404 || f.executor.calls != 0 {
			t.Fatalf("unproven Group route reached native: %s %d", path, w.Code)
		}
	}
	r := f.request("")
	r.SetPathValue("resource_id", "forged")
	if w := managedServe(h, r); w.Code != 200 || f.executor.request.ResourceID != "source-group" {
		t.Fatal("forged PathValue replaced router provenance")
	}
	for _, get := range []bool{false, true} {
		selected := newManagedGroupsFixture(get)
		h, selectedDoc := selected.router(t)
		operation, disabledPath := "identity.scim.group-list", managedGroupGetPath
		if get {
			operation, disabledPath = "identity.scim.group-get", managedGroupsPath
		}
		if len(selectedDoc.Operations()) != 1 || selectedDoc.Operations()[0].Record.OperationID != operation {
			t.Fatal("independent route selection did not match its canonical operation")
		}
		if w := managedServe(h, protocolRequest(http.MethodGet, disabledPath, "")); w.Code != 404 || selected.executor.calls != 0 {
			t.Fatal("disabled Group read reached native")
		}
		for _, method := range []string{http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions} {
			r := selected.request("")
			r.Method = method
			if w := managedServe(h, r); w.Code != 405 || w.Header().Get("Allow") != "GET" || selected.executor.calls != 0 {
				t.Fatalf("implicit Group method selected: %s %d", method, w.Code)
			}
		}
	}
	getFeature, err := scimhttp.NewManagedGroupsReadFeature(newManagedGroupsFixture(true).config)
	if err != nil {
		t.Fatal(err)
	}
	if w := managedServe(getFeature.Operations()[0].Handler, f.request("")); w.Code != 404 {
		t.Fatal("direct Get accepted missing router provenance")
	}
}

func TestManagedGroupsReadConstructionRejectsInvalidSetupWithoutIOAndRedactsCustody(t *testing.T) {
	for _, mode := range []string{"disabled", "nil-owner", "typed-nil", "limits", "network", "rate", "deadline", "long-deadline", "negative-members", "oversized-members"} {
		f := newManagedGroupsFixture(true)
		switch mode {
		case "disabled":
			f.config.EnableGet = false
		case "nil-owner":
			f.config.Executor = nil
		case "typed-nil":
			f.config.Executor = (*managedGroupsExecutor)(nil)
		case "limits":
			f.config.Limits = scim.Limits{}
		case "network":
			f.config.Network = identityhttp.NetworkConfig{}
		case "rate":
			f.config.Rate = scimhttp.ProtocolRateConfig{}
		case "deadline":
			f.config.MaximumDuration = 0
		case "long-deadline":
			f.config.MaximumDuration = 31 * time.Second
		case "negative-members":
			f.config.MaximumMembers = -1
		case "oversized-members":
			f.config.MaximumMembers = scim.DefaultGroupMembers + 1
		}
		if _, err := scimhttp.NewManagedGroupsReadFeature(f.config); !errors.Is(err, identityhttp.ErrInvalidInput) || f.executor.calls != 0 || f.base.backend.calls != 0 {
			t.Fatalf("invalid configuration accepted or caused IO: %s", mode)
		}
	}
	f := newManagedGroupsFixture(true)
	f.config.MaximumMembers = 0
	f.executor.response.Body = []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"id":"source-group","meta":{"version":"\"opaque-group:7\""}}`)
	h, _ := f.router(t)
	if w := managedServe(h, f.request("")); w.Code != 200 || f.executor.maximum != 0 {
		t.Fatal("explicit zero member ceiling was replaced by a default")
	}
	if _, err := json.Marshal(f.config); !errors.Is(err, identityhttp.ErrInvalidInput) || fmt.Sprintf("%+v", f.config) != "scimhttp.ManagedGroupsReadConfig(redacted)" {
		t.Fatal("runtime custody was implicitly exportable")
	}
}

func FuzzManagedGroupsReadQuery(f *testing.F) {
	f.Add(true, "attributes=displayName,members,meta")
	f.Add(false, "count=0&startIndex=-2")
	f.Add(false, "filter=displayName%20eq%20%22Directory%20team%22")
	f.Add(true, "attributes=%FF&attributes=duplicate")
	f.Fuzz(func(t *testing.T, get bool, query string) {
		fixture := newManagedGroupsFixture(get)
		feature, err := scimhttp.NewManagedGroupsReadFeature(fixture.config)
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
			t.Fatalf("hostile Group selector escaped boundary: %d", w.Code)
		}
	})
}

func validateManagedGroupsReadWireResponse(t *testing.T, document identityhttp.OpenAPIDocument, get bool, status, media string, body []byte) {
	t.Helper()
	var wire struct {
		Paths map[string]struct {
			Get struct {
				Responses map[string]struct {
					Content map[string]struct {
						Schema json.RawMessage `json:"schema"`
					} `json:"content"`
				} `json:"responses"`
			} `json:"get"`
		} `json:"paths"`
	}
	if json.Unmarshal(document.JSON(), &wire) != nil {
		t.Fatal("Group OpenAPI is not JSON")
	}
	path := managedGroupsPath
	if get {
		path += "/{resource_id}"
	}
	definition := wire.Paths[path].Get.Responses[status].Content[media].Schema
	if len(definition) == 0 {
		t.Fatalf("Group OpenAPI omitted actual %s %s envelope", status, media)
	}
	compiler, err := jsonschema.NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(t.Context(), definition)
	if err != nil {
		t.Fatal(err)
	}
	result, err := schema.Validate(t.Context(), body)
	if err != nil || !result.Valid {
		t.Fatalf("Group OpenAPI %s %s rejected actual transport envelope: %v", status, media, err)
	}
}
