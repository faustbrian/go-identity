package scimhttp_test

import (
	"bytes"
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

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	scimhttp "github.com/faustbrian/go-identity/http/scim"
	jsonschema "github.com/faustbrian/go-json-schema/v2"
	scim "github.com/faustbrian/go-scim"
	scimpostgres "github.com/faustbrian/go-scim/postgres"
)

const managedGroupCreateID = "AAAAAAAAAAAAAAAAAAAAAQ"
const managedGroupCreateETag = `"opaque-create-version"`
const managedGroupCreateLocation = "https://directory.example/scim/v2/Groups/" + managedGroupCreateID
const managedGroupCreateInput = `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"create-person"}`
const managedGroupCreateBody = `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"id":"` + managedGroupCreateID + `","displayName":"create-person","meta":{"resourceType":"Group","version":"\"opaque-create-version\"","location":"` + managedGroupCreateLocation + `"}}`

// Only the public native execution port is doubled; this proves raw transport
// forwarding/admission/serialization, not native schema or PostgreSQL effects.
type managedGroupsCreateExecutor struct {
	*managedUsersExecutor
	maximum int
}

func (e *managedGroupsCreateExecutor) ExecuteManagedAdmittedGroupCreate(ctx context.Context, tenant identity.TenantID, request scim.Request, maximum int, admit scim.ProtocolAdmission) (scim.Response, error) {
	e.maximum = maximum
	request.Body = bytes.Clone(request.Body)
	return e.ExecuteManagedAdmittedRead(ctx, tenant, request, admit)
}

var _ scimhttp.ManagedGroupsCreateExecutor = (*scimpostgres.ManagedConnectionService)(nil)

type managedGroupCreateFixture struct {
	config   scimhttp.ManagedGroupsCreateConfig
	executor *managedGroupsCreateExecutor
	base     protocolFixture
}

func newManagedGroupCreateFixture() managedGroupCreateFixture {
	base := newProtocolFixture()
	executor := &managedGroupsCreateExecutor{managedUsersExecutor: &managedUsersExecutor{client: base.executor.client, response: scim.Response{Status: 201, ContentType: "application/scim+json", Body: []byte(managedGroupCreateBody), ETag: managedGroupCreateETag, Location: managedGroupCreateLocation}}}
	return managedGroupCreateFixture{base: base, executor: executor, config: scimhttp.ManagedGroupsCreateConfig{Network: base.config.Network, Executor: executor, Rate: base.config.Rate, Limits: scim.DefaultLimits(), MaximumDuration: time.Second, MaximumMembers: scim.DefaultGroupMembers}}
}

func (f managedGroupCreateFixture) router(t *testing.T) (http.Handler, identityhttp.OpenAPIDocument) {
	t.Helper()
	feature, err := scimhttp.NewManagedGroupsCreateFeature(f.config)
	if err != nil {
		t.Fatal(err)
	}
	operations, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	return protocolRouter(t, f.config.Network, operations)
}

func (f managedGroupCreateFixture) request(body string) *http.Request {
	return protocolRequest(http.MethodPost, managedGroupsPath, body)
}

func TestManagedGroupsCreateTLSRetainsNative201BodyETagLocationWithoutTransportCommand(t *testing.T) {
	f := newManagedGroupCreateFixture()
	h, document := f.router(t)
	server := httptest.NewTLSServer(h)
	defer server.Close()
	client := server.Client()
	defer client.CloseIdleConnections()
	r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+managedGroupsPath, strings.NewReader(managedGroupCreateInput))
	if err != nil {
		t.Fatal(err)
	}
	r.Host = "directory.example"
	r.Header.Set("Authorization", "Bearer "+syntheticBearer)
	r.Header.Set("Content-Type", "application/scim+json")
	r.AddCookie(&http.Cookie{Name: "session", Value: "ignored-cookie"})
	response, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	closeErr := response.Body.Close()
	if response.StatusCode != 201 || readErr != nil || closeErr != nil || string(body) != managedGroupCreateBody || response.Header.Get("ETag") != managedGroupCreateETag || response.Header.Get("Location") != managedGroupCreateLocation || response.Header.Get("Content-Type") != "application/scim+json" || response.Header.Get("Set-Cookie") != "" || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("native Create did not survive actual TLS: status %d", response.StatusCode)
	}
	got := f.executor.request
	if f.executor.maximum != scim.DefaultGroupMembers || got.Operation != scim.GroupCreate || got.Credential.Token() != syntheticBearer || got.ResourceID != "" || got.IdempotencyKey != "" || got.IfMatch != "" || got.Query != (scim.Query{}) || got.ContentType != "application/scim+json" || string(got.Body) != managedGroupCreateInput || f.executor.calls != 1 || f.base.backend.calls != 1 || len(f.base.backend.last.Requests) != 3 || f.executor.tenant != f.executor.client.TenantID {
		t.Fatal("Create changed native request/command custody or exact-once admission")
	}
	if len(document.Operations()) != 1 || document.Operations()[0].Record.OperationID != "identity.scim.group-create" || document.Operations()[0].Record.RatePolicy != "rate.protocol" || strings.Contains(string(document.JSON()), syntheticBearer) {
		t.Fatal("Create wire metadata differs from actual selection")
	}
	validateManagedGroupsCreateWireResponse(t, document, "201", response.Header.Get("Content-Type"), body)
}

func TestManagedGroupsCreateTLSDenialsRemainSCIMErrorsBeforeNativeWork(t *testing.T) {
	f := newManagedGroupCreateFixture()
	h, _ := f.router(t)
	server := httptest.NewTLSServer(h)
	defer server.Close()
	client := server.Client()
	defer client.CloseIdleConnections()
	for _, mode := range []string{"cookie-only", "encoding", "media", "key", "query"} {
		t.Run(mode, func(t *testing.T) {
			path := managedGroupsPath
			if mode == "query" {
				path += "?attributes=displayName"
			}
			r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+path, strings.NewReader(managedGroupCreateInput))
			if err != nil {
				t.Fatal(err)
			}
			r.Host = "directory.example"
			r.Header.Set("Authorization", "Bearer "+syntheticBearer)
			r.Header.Set("Content-Type", "application/scim+json")
			want := 400
			switch mode {
			case "cookie-only":
				r.Header.Del("Authorization")
				r.AddCookie(&http.Cookie{Name: "session", Value: syntheticBearer})
				want = 401
			case "encoding":
				r.Header.Set("Content-Encoding", "gzip")
				want = 415
			case "media":
				r.Header.Set("Content-Type", "application/json")
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
			var denial struct {
				Schemas []string `json:"schemas"`
				Status  string   `json:"status"`
			}
			if response.StatusCode != want || readErr != nil || closeErr != nil || json.Unmarshal(body, &denial) != nil || len(denial.Schemas) != 1 || denial.Schemas[0] != "urn:ietf:params:scim:api:messages:2.0:Error" || denial.Status != strconv.Itoa(want) || response.Header.Get("Content-Type") != "application/scim+json" || response.Header.Get("ETag") != "" || response.Header.Get("Location") != "" || response.Header.Get("Set-Cookie") != "" || f.executor.calls != 0 || f.base.backend.calls != 0 {
				t.Fatalf("Create TLS denial %s: status %d want %d", mode, response.StatusCode, want)
			}
		})
	}
}

func TestManagedGroupsCreateBoundsRawBodyAndRejectsAmbiguousChannels(t *testing.T) {
	for _, mode := range []string{"empty", "oversized", "unknown-length-overflow", "query", "empty-query", "key", "cookie-key", "duplicate-bearer", "if-match", "range", "trailer", "cleartext", "bad-charset", "read-error", "no-progress"} {
		t.Run(mode, func(t *testing.T) {
			f := newManagedGroupCreateFixture()
			h, _ := f.router(t)
			r := f.request(managedGroupCreateInput)
			want := 400
			switch mode {
			case "empty":
				r = f.request("")
			case "oversized":
				r = f.request(strings.Repeat("x", 1025))
				want = 413
			case "unknown-length-overflow":
				r = f.request(strings.Repeat("x", 1025))
				r.ContentLength = -1
				want = 413
			case "query":
				r.URL.RawQuery = "tenantID=override"
				r.RequestURI = r.URL.RequestURI()
			case "empty-query":
				r.URL.ForceQuery = true
				r.RequestURI = r.URL.RequestURI()
			case "key":
				r.Header.Set("Idempotency-Key", "forbidden")
			case "cookie-key":
				r.AddCookie(&http.Cookie{Name: "idempotency_key", Value: "forbidden"})
			case "duplicate-bearer":
				r.Header.Add("Authorization", "Bearer "+syntheticBearer)
			case "if-match":
				r.Header.Set("If-Match", managedGroupCreateETag)
			case "range":
				r.Header.Set("Range", "bytes=0-1")
			case "trailer":
				r.Trailer = http.Header{"X-Trailer": []string{"forbidden"}}
			case "cleartext":
				r.TLS = nil
				r.URL.Scheme = "http"
				want = 403
			case "bad-charset":
				r.Header.Set("Content-Type", "application/scim+json; charset=latin-1")
				want = 415
			case "read-error":
				r.Body = io.NopCloser(managedGroupsCreateBrokenReader{})
			case "no-progress":
				r.Body = io.NopCloser(managedGroupsCreateStalledReader{})
			}
			w := managedServe(h, r)
			if w.Code != want || f.executor.calls != 0 || f.base.backend.calls != 0 || w.Header().Get("Location") != "" || w.Header().Get("ETag") != "" {
				t.Fatalf("invalid Create %s reached native: %d want %d", mode, w.Code, want)
			}
		})
	}
	for _, media := range []string{"application/scim+json", "application/scim+json; charset=utf-8"} {
		t.Run(media, func(t *testing.T) {
			f := newManagedGroupCreateFixture()
			h, _ := f.router(t)
			raw := `{"displayName":"native owns duplicate/schema handling","DisplayName":"unchanged"}`
			r := f.request(raw)
			r.Header.Set("Content-Type", media)
			r.Header.Set("Content-Encoding", "identity")
			w := managedServe(h, r)
			if w.Code != 201 || string(f.executor.request.Body) != raw {
				t.Fatalf("transport parsed or rewrote native-owned SCIM schema: %d", w.Code)
			}
		})
	}
}

type managedGroupsCreateBrokenReader struct{}

func (managedGroupsCreateBrokenReader) Read([]byte) (int, error) {
	return 0, errors.New("private reader diagnostic")
}

type managedGroupsCreateStalledReader struct{}

func (managedGroupsCreateStalledReader) Read([]byte) (int, error) { return 0, nil }

func TestManagedGroupsCreateRequiresCurrentNativeAuthorityOneChargeAndSafeCompleteOutput(t *testing.T) {
	for _, mode := range []string{"auth", "policy", "conflict", "wrong-tenant", "limited", "rate-unavailable", "skip", "double", "ignore", "late-error", "status", "media", "empty", "oversized", "bad-json", "etag", "location-origin", "location-query", "location-fragment", "location-encoded", "location-path", "location-id", "body-id", "body-version", "body-location", "body-schema"} {
		t.Run(mode, func(t *testing.T) {
			f := newManagedGroupCreateFixture()
			want := 503
			switch mode {
			case "auth":
				f.executor.err = scim.NewError(401, "")
				want = 401
			case "policy":
				f.executor.err = scim.NewError(403, "")
				want = 403
			case "conflict":
				f.executor.err = scim.NewError(409, "uniqueness")
				want = 409
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
			case "status":
				f.executor.response.Status = 200
			case "media":
				f.executor.response.ContentType = "application/json"
			case "empty":
				f.executor.response.Body = nil
			case "oversized":
				f.executor.response.Body = []byte(strings.Repeat("x", scim.DefaultLimits().ResponseBytes+1))
			case "bad-json":
				f.executor.response.Body = []byte(`{"id":`)
			case "etag":
				f.executor.response.ETag = "\"unsafe\r\nSet-Cookie: bad\""
			case "location-origin":
				f.executor.response.Location = strings.Replace(managedGroupCreateLocation, "directory.example", "other.example", 1)
			case "location-query":
				f.executor.response.Location = managedGroupCreateLocation + "?x=y"
			case "location-fragment":
				f.executor.response.Location = managedGroupCreateLocation + "#fragment"
			case "location-encoded":
				f.executor.response.Location = strings.Replace(managedGroupCreateLocation, "/Groups/", "/Groups/%41", 1)
			case "location-path":
				f.executor.response.Location = strings.Replace(managedGroupCreateLocation, "/Groups/", "/Users/", 1)
			case "location-id":
				f.executor.response.Location = strings.Replace(managedGroupCreateLocation, managedGroupCreateID, "AAAAAAAAAAAAAAAAAAAAAg", 1)
			case "body-id":
				f.executor.response.Body = []byte(strings.Replace(managedGroupCreateBody, `"id":"`+managedGroupCreateID+`"`, `"id":"not-a-native-id"`, 1))
			case "body-version":
				f.executor.response.Body = []byte(strings.Replace(managedGroupCreateBody, "opaque-create-version", "different-version", 1))
			case "body-location":
				f.executor.response.Body = []byte(strings.Replace(managedGroupCreateBody, "directory.example", "other.example", 1))
			case "body-schema":
				f.executor.response.Body = []byte(strings.Replace(managedGroupCreateBody, ":2.0:Group", ":2.0:User", 1))
			}
			h, _ := f.router(t)
			w := managedServe(h, f.request(managedGroupCreateInput))
			if w.Code != want || w.Header().Get("ETag") != "" || w.Header().Get("Location") != "" || w.Header().Get("Set-Cookie") != "" || strings.Contains(w.Body.String(), managedGroupCreateID) || strings.Contains(w.Body.String(), "private") {
				t.Fatalf("Create native failure %s disclosed data/header: %d want %d", mode, w.Code, want)
			}
			if (mode == "auth" || mode == "policy" || mode == "wrong-tenant" || mode == "skip") && f.base.backend.calls != 0 {
				t.Fatal("Create charged before current native authorization")
			}
			if mode == "double" && f.base.backend.calls != 1 {
				t.Fatal("duplicate callback charged twice")
			}
			if mode == "limited" && w.Header().Get("Retry-After") != "3" {
				t.Fatal("Create changed native quota retry hint")
			}
		})
	}
}

func TestManagedGroupsCreateCancellationAndPanicsCannotDiscloseCommittedOutput(t *testing.T) {
	for _, mode := range []string{"before", "after", "panic", "error"} {
		t.Run(mode, func(t *testing.T) {
			f := newManagedGroupCreateFixture()
			r := f.request(managedGroupCreateInput)
			ctx, cancel := context.WithCancel(r.Context())
			defer cancel()
			r = r.WithContext(ctx)
			charges := 0
			switch mode {
			case "before":
				f.executor.before = cancel
			case "after":
				f.executor.after = cancel
				charges = 1
			case "panic":
				f.executor.before = func() { panic("private native panic") }
			case "error":
				f.executor.err = errors.New("private native failure")
			}
			h, _ := f.router(t)
			w := managedServe(h, r)
			if w.Code != 503 || f.base.backend.calls != charges || w.Header().Get("ETag") != "" || w.Header().Get("Location") != "" || strings.Contains(w.Body.String(), managedGroupCreateID) || strings.Contains(w.Body.String(), "private") {
				t.Fatalf("Create cancellation/failure %s disclosed native output: %d", mode, w.Code)
			}
		})
	}
}

func TestManagedGroupsCreateNeverRetriesOrCachesAndComposesWithNeighborReadsAndBulk(t *testing.T) {
	f := newManagedGroupCreateFixture()
	create, err := scimhttp.NewManagedGroupsCreateFeature(f.config)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{})
	if err != nil {
		t.Fatal(err)
	}
	if w := managedServe(empty, f.request(managedGroupCreateInput)); w.Code != 404 {
		t.Fatal("unselected Create exposed a route")
	}
	h, _ := f.router(t)
	for range 2 {
		if w := managedServe(h, f.request(managedGroupCreateInput)); w.Code != 201 {
			t.Fatal("fresh headerless Create attempt denied")
		}
	}
	if f.executor.calls != 2 || f.base.backend.calls != 2 || f.executor.request.IdempotencyKey != "" {
		t.Fatal("transport retried, cached or synthesized a native request key")
	}
	for _, path := range []string{managedGroupsPath + "/", "/scim/v2/groups", managedGroupGetPath, bulkPath} {
		r := f.request(managedGroupCreateInput)
		r.URL.Path = path
		r.RequestURI = r.URL.RequestURI()
		if w := managedServe(h, r); w.Code != 404 {
			t.Fatalf("Create route alias exposed: %d", w.Code)
		}
	}
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions, http.MethodHead} {
		r := f.request("")
		r.Method = method
		if w := managedServe(h, r); w.Code != 405 || w.Header().Get("Allow") != "POST" {
			t.Fatalf("Create implicit method %s exposed: %d", method, w.Code)
		}
	}
	listFixture := newManagedGroupsFixture(false)
	listFixture.config.Rate = f.config.Rate
	list, err := scimhttp.NewManagedGroupsReadFeature(listFixture.config)
	if err != nil {
		t.Fatal(err)
	}
	getFixture := newManagedGroupsFixture(true)
	getFixture.config.Rate = f.config.Rate
	get, err := scimhttp.NewManagedGroupsReadFeature(getFixture.config)
	if err != nil {
		t.Fatal(err)
	}
	bulk, err := scimhttp.NewBulkFeature(f.base.config)
	if err != nil {
		t.Fatal(err)
	}
	operations := append(create.Operations(), list.Operations()...)
	operations = append(operations, get.Operations()...)
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
	if len(doc.Operations()) != 5 || managedServe(h, listFixture.request("")).Code != 200 || managedServe(h, getFixture.request("")).Code != 200 || managedServe(h, protocolRequest(http.MethodPost, bulkPath, bulkRequestBody)).Code != 200 || managedServe(h, f.request(managedGroupCreateInput)).Code != 201 || f.base.backend.calls != 6 {
		t.Fatal("canonical Create/Get/List/Bulk composition changed neighbor dispatch or shared quota")
	}
}

func TestManagedGroupsCreateRejectsInvalidConfigurationWithoutOwnerIO(t *testing.T) {
	for _, mode := range []string{"zero", "nil-owner", "typed-nil-owner", "limits", "duration", "network", "rate", "members-negative", "members-overflow"} {
		t.Run(mode, func(t *testing.T) {
			f := newManagedGroupCreateFixture()
			switch mode {
			case "zero":
				f.config = scimhttp.ManagedGroupsCreateConfig{}
			case "nil-owner":
				f.config.Executor = nil
			case "typed-nil-owner":
				f.config.Executor = (*managedGroupsCreateExecutor)(nil)
			case "limits":
				f.config.Limits = scim.Limits{}
			case "duration":
				f.config.MaximumDuration = 31 * time.Second
			case "network":
				f.config.Network = identityhttp.NetworkConfig{}
			case "rate":
				f.config.Rate = scimhttp.ProtocolRateConfig{}
			case "members-negative":
				f.config.MaximumMembers = -1
			case "members-overflow":
				f.config.MaximumMembers = scim.DefaultGroupMembers + 1
			}
			if _, err := scimhttp.NewManagedGroupsCreateFeature(f.config); !errors.Is(err, identityhttp.ErrInvalidInput) || f.executor.calls != 0 || f.base.backend.calls != 0 {
				t.Fatal("invalid Create configuration accepted or owner called")
			}
		})
	}
}

func TestManagedGroupsCreateForwardsExplicitMemberCeilingWithoutOwningSchema(t *testing.T) {
	for _, maximum := range []int{0, 2, scim.DefaultGroupMembers} {
		t.Run(strconv.Itoa(maximum), func(t *testing.T) {
			f := newManagedGroupCreateFixture()
			f.config.MaximumMembers = maximum
			h, document := f.router(t)
			// Native schema/member validation, including rejection above the
			// configured ceiling, remains before native admission, not in HTTP.
			raw := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group","urn:example:Group"],"displayName":"Directory team","members":[],"urn:example:Group":{"note":"unchanged"}}`
			w := managedServe(h, f.request(raw))
			if w.Code != 201 || f.executor.maximum != maximum || string(f.executor.request.Body) != raw || f.executor.calls != 1 || f.base.backend.calls != 1 {
				t.Fatal("explicit native member ceiling, extensions or raw input changed")
			}
			var wire struct {
				Paths map[string]struct {
					Post struct {
						RequestBody struct {
							Content map[string]struct {
								Schema json.RawMessage `json:"schema"`
							} `json:"content"`
						} `json:"requestBody"`
					} `json:"post"`
				} `json:"paths"`
			}
			if json.Unmarshal(document.JSON(), &wire) != nil {
				t.Fatal("invalid Group Create wire document")
			}
			definition := wire.Paths[managedGroupsPath].Post.RequestBody.Content["application/scim+json"].Schema
			compiler, err := jsonschema.NewCompiler()
			if err != nil {
				t.Fatal(err)
			}
			schema, err := compiler.Compile(t.Context(), definition)
			if err != nil {
				t.Fatal(err)
			}
			result, err := schema.Validate(t.Context(), []byte(raw))
			if err != nil || !result.Valid {
				t.Fatal("published writable Group schema rejects native declared extensions")
			}
			withMember := strings.Replace(raw, `"members":[]`, `"members":[{"value":"member-a","type":"user"}]`, 1)
			result, err = schema.Validate(t.Context(), []byte(withMember))
			if err != nil || result.Valid != (maximum > 0) {
				t.Fatal("published Group member bound disagrees with explicit zero/nonzero configuration")
			}
		})
	}
}

func TestManagedGroupsCreateWireAcceptsActualTransportErrors(t *testing.T) {
	f := newManagedGroupCreateFixture()
	h, document := f.router(t)
	server := httptest.NewTLSServer(h)
	defer server.Close()
	client := server.Client()
	defer client.CloseIdleConnections()
	for _, mode := range []string{"chunked-overflow", "duplicate-bearer", "foreign-origin"} {
		t.Run(mode, func(t *testing.T) {
			input, status, media := managedGroupCreateInput, 400, "application/json"
			if mode == "chunked-overflow" {
				input, status, media = strings.Repeat("x", 1025), 413, "application/scim+json"
			} else if mode == "foreign-origin" {
				status, media = 403, "text/plain"
			}
			r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+managedGroupsPath, io.NopCloser(strings.NewReader(input)))
			if err != nil {
				t.Fatal(err)
			}
			r.Host = "directory.example"
			r.Header.Set("Content-Type", "application/scim+json")
			r.Header.Set("Authorization", "Bearer "+syntheticBearer)
			if mode == "chunked-overflow" {
				r.ContentLength, r.TransferEncoding = -1, []string{"chunked"}
			} else if mode == "duplicate-bearer" {
				r.Header.Add("Authorization", "Bearer "+syntheticBearer)
			} else {
				r.Header.Set("Origin", "https://other.example")
			}
			response, err := client.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			body, readErr := io.ReadAll(io.LimitReader(response.Body, 8192))
			closeErr := response.Body.Close()
			if mode == "foreign-origin" {
				if response.StatusCode != status || response.Header.Get("Content-Type") != "text/plain; charset=utf-8" ||
					readErr != nil || closeErr != nil || string(body) != "identity.http.origin_denied\n" || f.executor.calls != 0 || f.base.backend.calls != 0 {
					t.Fatal("foreign Origin did not retain the fixed outer denial")
				}
				encoded, err := json.Marshal(string(body))
				if err != nil {
					t.Fatal(err)
				}
				validateManagedGroupsCreateWireResponse(t, document, strconv.Itoa(status), media, encoded)
				return
			}
			var envelope map[string]json.RawMessage
			if response.StatusCode != status || response.Header.Get("Content-Type") != media || readErr != nil || closeErr != nil || json.Unmarshal(body, &envelope) != nil || f.executor.calls != 0 || f.base.backend.calls != 0 {
				t.Fatalf("actual TLS transport denial %s changed: status %d", mode, response.StatusCode)
			}
			if mode == "chunked-overflow" && (len(envelope) != 2 || string(envelope["status"]) != `"413"`) || mode == "duplicate-bearer" && (len(envelope) != 1 || string(envelope["error"]) != `"invalid_request"`) {
				t.Fatal("transport denial changed its fixed safe envelope")
			}
			validateManagedGroupsCreateWireResponse(t, document, strconv.Itoa(status), media, body)
		})
	}
}

func validateManagedGroupsCreateWireResponse(t *testing.T, document identityhttp.OpenAPIDocument, status, media string, body []byte) {
	t.Helper()
	var wire struct {
		Paths map[string]struct {
			Post struct {
				Responses map[string]struct {
					Content map[string]struct {
						Schema json.RawMessage `json:"schema"`
					} `json:"content"`
				} `json:"responses"`
			} `json:"post"`
		} `json:"paths"`
	}
	if json.Unmarshal(document.JSON(), &wire) != nil {
		t.Fatal("published Create wire is not JSON")
	}
	definition := wire.Paths[managedGroupsPath].Post.Responses[status].Content[media].Schema
	if len(definition) == 0 {
		t.Fatalf("published Create wire omits actual %s %s response schema", status, media)
	}
	compiler, err := jsonschema.NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(t.Context(), definition)
	if err != nil {
		t.Fatal("compile published Create response schema", err)
	}
	result, err := schema.Validate(t.Context(), body)
	if err != nil || !result.Valid {
		t.Fatalf("published Create %s %s schema rejects actual TLS transport envelope: %v", status, media, err)
	}
}

func FuzzManagedGroupsCreateBody(f *testing.F) {
	f.Add([]byte(managedGroupCreateInput))
	f.Add([]byte(`{"displayName":`))
	f.Add([]byte{})
	f.Add([]byte{0xff})
	f.Fuzz(func(t *testing.T, body []byte) {
		fixture := newManagedGroupCreateFixture()
		feature, err := scimhttp.NewManagedGroupsCreateFeature(fixture.config)
		if err != nil {
			t.Fatal(err)
		}
		h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
		if err != nil {
			t.Fatal(err)
		}
		w := managedServe(h, fixture.request(string(body)))
		if w.Code != 201 && w.Code != 400 && w.Code != 413 || strings.Contains(w.Body.String(), syntheticBearer) || fixture.executor.calls > 1 || fixture.executor.calls == 1 && (!bytes.Equal(fixture.executor.request.Body, body) || len(body) > 1024) {
			t.Fatalf("hostile Create body escaped bounded raw forwarding: %d", w.Code)
		}
	})
}
