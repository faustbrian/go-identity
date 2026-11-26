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

const managedUserCreateID = "AAAAAAAAAAAAAAAAAAAAAQ"
const managedUserCreateETag = `"opaque-create-version"`
const managedUserCreateLocation = "https://directory.example/scim/v2/Users/" + managedUserCreateID
const managedUserCreateInput = `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"create-person"}`
const managedUserCreateBody = `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"` + managedUserCreateID + `","userName":"create-person","meta":{"resourceType":"User","version":"\"opaque-create-version\"","location":"` + managedUserCreateLocation + `"}}`

// Only the public native execution port is doubled; this proves raw transport
// forwarding/admission/serialization, not native schema or PostgreSQL effects.
type managedUsersCreateExecutor struct{ *managedUsersExecutor }

func (e *managedUsersCreateExecutor) ExecuteManagedAdmittedCreate(ctx context.Context, tenant identity.TenantID, request scim.Request, admit scim.ProtocolAdmission) (scim.Response, error) {
	request.Body = bytes.Clone(request.Body)
	return e.ExecuteManagedAdmittedRead(ctx, tenant, request, admit)
}

var _ scimhttp.ManagedUsersCreateExecutor = (*scimpostgres.ManagedConnectionService)(nil)

type managedUserCreateFixture struct {
	config   scimhttp.ManagedUsersCreateConfig
	executor *managedUsersCreateExecutor
	base     protocolFixture
}

func newManagedUserCreateFixture() managedUserCreateFixture {
	base := newProtocolFixture()
	executor := &managedUsersCreateExecutor{&managedUsersExecutor{client: base.executor.client, response: scim.Response{Status: 201, ContentType: "application/scim+json", Body: []byte(managedUserCreateBody), ETag: managedUserCreateETag, Location: managedUserCreateLocation}}}
	return managedUserCreateFixture{base: base, executor: executor, config: scimhttp.ManagedUsersCreateConfig{Network: base.config.Network, Executor: executor, Rate: base.config.Rate, Limits: scim.DefaultLimits(), MaximumDuration: time.Second}}
}

func (f managedUserCreateFixture) router(t *testing.T) (http.Handler, identityhttp.OpenAPIDocument) {
	t.Helper()
	feature, err := scimhttp.NewManagedUsersCreateFeature(f.config)
	if err != nil {
		t.Fatal(err)
	}
	operations, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	return protocolRouter(t, f.config.Network, operations)
}

func (f managedUserCreateFixture) request(body string) *http.Request {
	return protocolRequest(http.MethodPost, managedUsersPath, body)
}

func TestManagedUsersCreateTLSRetainsNative201BodyETagLocationWithoutTransportCommand(t *testing.T) {
	f := newManagedUserCreateFixture()
	h, document := f.router(t)
	server := httptest.NewTLSServer(h)
	defer server.Close()
	client := server.Client()
	defer client.CloseIdleConnections()
	r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+managedUsersPath, strings.NewReader(managedUserCreateInput))
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
	if response.StatusCode != 201 || readErr != nil || closeErr != nil || string(body) != managedUserCreateBody || response.Header.Get("ETag") != managedUserCreateETag || response.Header.Get("Location") != managedUserCreateLocation || response.Header.Get("Content-Type") != "application/scim+json" || response.Header.Get("Set-Cookie") != "" || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("native Create did not survive actual TLS: status %d", response.StatusCode)
	}
	got := f.executor.request
	if got.Operation != scim.UserCreate || got.Credential.Token() != syntheticBearer || got.ResourceID != "" || got.IdempotencyKey != "" || got.IfMatch != "" || got.Query != (scim.Query{}) || got.ContentType != "application/scim+json" || string(got.Body) != managedUserCreateInput || f.executor.calls != 1 || f.base.backend.calls != 1 || len(f.base.backend.last.Requests) != 3 || f.executor.tenant != f.executor.client.TenantID {
		t.Fatal("Create changed native request/command custody or exact-once admission")
	}
	if len(document.Operations()) != 1 || document.Operations()[0].Record.OperationID != "identity.scim.user-create" || document.Operations()[0].Record.RatePolicy != "rate.protocol" || strings.Contains(string(document.JSON()), syntheticBearer) {
		t.Fatal("Create wire metadata differs from actual selection")
	}
}

func TestManagedUsersCreateTLSDenialsRemainSCIMErrorsBeforeNativeWork(t *testing.T) {
	f := newManagedUserCreateFixture()
	h, _ := f.router(t)
	server := httptest.NewTLSServer(h)
	defer server.Close()
	client := server.Client()
	defer client.CloseIdleConnections()
	for _, mode := range []string{"cookie-only", "encoding", "media", "key", "query"} {
		t.Run(mode, func(t *testing.T) {
			path := managedUsersPath
			if mode == "query" {
				path += "?attributes=userName"
			}
			r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+path, strings.NewReader(managedUserCreateInput))
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

func TestManagedUsersCreateBoundsRawBodyAndRejectsAmbiguousChannels(t *testing.T) {
	for _, mode := range []string{"empty", "oversized", "unknown-length-overflow", "query", "empty-query", "key", "cookie-key", "duplicate-bearer", "if-match", "range", "trailer", "cleartext", "bad-charset", "read-error", "no-progress"} {
		t.Run(mode, func(t *testing.T) {
			f := newManagedUserCreateFixture()
			h, _ := f.router(t)
			r := f.request(managedUserCreateInput)
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
				r.Header.Set("If-Match", managedUserCreateETag)
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
				r.Body = io.NopCloser(managedUsersCreateBrokenReader{})
			case "no-progress":
				r.Body = io.NopCloser(managedUsersCreateStalledReader{})
			}
			w := managedServe(h, r)
			if w.Code != want || f.executor.calls != 0 || f.base.backend.calls != 0 || w.Header().Get("Location") != "" || w.Header().Get("ETag") != "" {
				t.Fatalf("invalid Create %s reached native: %d want %d", mode, w.Code, want)
			}
		})
	}
	for _, media := range []string{"application/scim+json", "application/scim+json; charset=utf-8"} {
		t.Run(media, func(t *testing.T) {
			f := newManagedUserCreateFixture()
			h, _ := f.router(t)
			raw := `{"userName":"native owns duplicate/schema handling","UserName":"unchanged"}`
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

type managedUsersCreateBrokenReader struct{}

func (managedUsersCreateBrokenReader) Read([]byte) (int, error) {
	return 0, errors.New("private reader diagnostic")
}

type managedUsersCreateStalledReader struct{}

func (managedUsersCreateStalledReader) Read([]byte) (int, error) { return 0, nil }

func TestManagedUsersCreateRequiresCurrentNativeAuthorityOneChargeAndSafeCompleteOutput(t *testing.T) {
	for _, mode := range []string{"auth", "policy", "conflict", "wrong-tenant", "limited", "rate-unavailable", "skip", "double", "ignore", "late-error", "status", "media", "empty", "oversized", "bad-json", "etag", "location-origin", "location-query", "location-fragment", "location-encoded", "location-path", "location-id", "body-id", "body-version", "body-location", "body-schema"} {
		t.Run(mode, func(t *testing.T) {
			f := newManagedUserCreateFixture()
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
				f.executor.response.Location = strings.Replace(managedUserCreateLocation, "directory.example", "other.example", 1)
			case "location-query":
				f.executor.response.Location = managedUserCreateLocation + "?x=y"
			case "location-fragment":
				f.executor.response.Location = managedUserCreateLocation + "#fragment"
			case "location-encoded":
				f.executor.response.Location = strings.Replace(managedUserCreateLocation, "/Users/", "/Users/%41", 1)
			case "location-path":
				f.executor.response.Location = strings.Replace(managedUserCreateLocation, "/Users/", "/Groups/", 1)
			case "location-id":
				f.executor.response.Location = strings.Replace(managedUserCreateLocation, managedUserCreateID, "AAAAAAAAAAAAAAAAAAAAAg", 1)
			case "body-id":
				f.executor.response.Body = []byte(strings.Replace(managedUserCreateBody, `"id":"`+managedUserCreateID+`"`, `"id":"not-a-native-id"`, 1))
			case "body-version":
				f.executor.response.Body = []byte(strings.Replace(managedUserCreateBody, "opaque-create-version", "different-version", 1))
			case "body-location":
				f.executor.response.Body = []byte(strings.Replace(managedUserCreateBody, "directory.example", "other.example", 1))
			case "body-schema":
				f.executor.response.Body = []byte(strings.Replace(managedUserCreateBody, ":2.0:User", ":2.0:Group", 1))
			}
			h, _ := f.router(t)
			w := managedServe(h, f.request(managedUserCreateInput))
			if w.Code != want || w.Header().Get("ETag") != "" || w.Header().Get("Location") != "" || w.Header().Get("Set-Cookie") != "" || strings.Contains(w.Body.String(), managedUserCreateID) || strings.Contains(w.Body.String(), "private") {
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

func TestManagedUsersCreateCancellationAndPanicsCannotDiscloseCommittedOutput(t *testing.T) {
	for _, mode := range []string{"before", "after", "panic", "error"} {
		t.Run(mode, func(t *testing.T) {
			f := newManagedUserCreateFixture()
			r := f.request(managedUserCreateInput)
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
			if w.Code != 503 || f.base.backend.calls != charges || w.Header().Get("ETag") != "" || w.Header().Get("Location") != "" || strings.Contains(w.Body.String(), managedUserCreateID) || strings.Contains(w.Body.String(), "private") {
				t.Fatalf("Create cancellation/failure %s disclosed native output: %d", mode, w.Code)
			}
		})
	}
}

func TestManagedUsersCreateNeverRetriesOrCachesAndComposesWithNeighborReadsAndBulk(t *testing.T) {
	f := newManagedUserCreateFixture()
	create, err := scimhttp.NewManagedUsersCreateFeature(f.config)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{})
	if err != nil {
		t.Fatal(err)
	}
	if w := managedServe(empty, f.request(managedUserCreateInput)); w.Code != 404 {
		t.Fatal("unselected Create exposed a route")
	}
	h, _ := f.router(t)
	for range 2 {
		if w := managedServe(h, f.request(managedUserCreateInput)); w.Code != 201 {
			t.Fatal("fresh headerless Create attempt denied")
		}
	}
	if f.executor.calls != 2 || f.base.backend.calls != 2 || f.executor.request.IdempotencyKey != "" {
		t.Fatal("transport retried, cached or synthesized a native request key")
	}
	for _, path := range []string{managedUsersPath + "/", "/scim/v2/users", managedUserGetPath, bulkPath} {
		r := f.request(managedUserCreateInput)
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
	listFixture := newManagedUsersFixture()
	listFixture.config.Rate = f.config.Rate
	list, err := scimhttp.NewManagedUsersListFeature(listFixture.config)
	if err != nil {
		t.Fatal(err)
	}
	getFixture := newManagedUserGetFixture()
	getFixture.config.Rate = f.config.Rate
	get, err := scimhttp.NewManagedUsersGetFeature(getFixture.config)
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
	if len(doc.Operations()) != 5 || managedServe(h, listFixture.request("")).Code != 200 || managedServe(h, getFixture.request("")).Code != 200 || managedServe(h, protocolRequest(http.MethodPost, bulkPath, bulkRequestBody)).Code != 200 || managedServe(h, f.request(managedUserCreateInput)).Code != 201 || f.base.backend.calls != 6 {
		t.Fatal("canonical Create/Get/List/Bulk composition changed neighbor dispatch or shared quota")
	}
}

func TestManagedUsersCreateRejectsInvalidConfigurationWithoutOwnerIO(t *testing.T) {
	for _, mode := range []string{"zero", "nil-owner", "typed-nil-owner", "limits", "duration", "network", "rate"} {
		t.Run(mode, func(t *testing.T) {
			f := newManagedUserCreateFixture()
			switch mode {
			case "zero":
				f.config = scimhttp.ManagedUsersCreateConfig{}
			case "nil-owner":
				f.config.Executor = nil
			case "typed-nil-owner":
				f.config.Executor = (*managedUsersCreateExecutor)(nil)
			case "limits":
				f.config.Limits = scim.Limits{}
			case "duration":
				f.config.MaximumDuration = 31 * time.Second
			case "network":
				f.config.Network = identityhttp.NetworkConfig{}
			case "rate":
				f.config.Rate = scimhttp.ProtocolRateConfig{}
			}
			if _, err := scimhttp.NewManagedUsersCreateFeature(f.config); !errors.Is(err, identityhttp.ErrInvalidInput) || f.executor.calls != 0 || f.base.backend.calls != 0 {
				t.Fatal("invalid Create configuration accepted or owner called")
			}
		})
	}
}

func TestManagedUsersCreateWireAcceptsActualTransportErrors(t *testing.T) {
	f := newManagedUserCreateFixture()
	h, document := f.router(t)
	server := httptest.NewTLSServer(h)
	defer server.Close()
	client := server.Client()
	defer client.CloseIdleConnections()
	for _, mode := range []string{"chunked-overflow", "duplicate-bearer"} {
		t.Run(mode, func(t *testing.T) {
			input, status, media := managedUserCreateInput, 400, "application/json"
			if mode == "chunked-overflow" {
				input, status, media = strings.Repeat("x", 1025), 413, "application/scim+json"
			}
			r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+managedUsersPath, io.NopCloser(strings.NewReader(input)))
			if err != nil {
				t.Fatal(err)
			}
			r.Host = "directory.example"
			r.Header.Set("Content-Type", "application/scim+json")
			r.Header.Set("Authorization", "Bearer "+syntheticBearer)
			if mode == "chunked-overflow" {
				r.ContentLength, r.TransferEncoding = -1, []string{"chunked"}
			} else {
				r.Header.Add("Authorization", "Bearer "+syntheticBearer)
			}
			response, err := client.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			body, readErr := io.ReadAll(io.LimitReader(response.Body, 8192))
			closeErr := response.Body.Close()
			var envelope map[string]json.RawMessage
			if response.StatusCode != status || response.Header.Get("Content-Type") != media || readErr != nil || closeErr != nil || json.Unmarshal(body, &envelope) != nil || f.executor.calls != 0 || f.base.backend.calls != 0 {
				t.Fatalf("actual TLS transport denial %s changed: status %d", mode, response.StatusCode)
			}
			if mode == "chunked-overflow" && (len(envelope) != 2 || string(envelope["status"]) != `"413"`) || mode == "duplicate-bearer" && (len(envelope) != 1 || string(envelope["error"]) != `"invalid_request"`) {
				t.Fatal("transport denial changed its fixed safe envelope")
			}
			validateManagedUsersCreateWireResponse(t, document, strconv.Itoa(status), media, body)
		})
	}
}

func validateManagedUsersCreateWireResponse(t *testing.T, document identityhttp.OpenAPIDocument, status, media string, body []byte) {
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
	definition := wire.Paths[managedUsersPath].Post.Responses[status].Content[media].Schema
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

func FuzzManagedUsersCreateBody(f *testing.F) {
	f.Add([]byte(managedUserCreateInput))
	f.Add([]byte(`{"userName":`))
	f.Add([]byte{})
	f.Add([]byte{0xff})
	f.Fuzz(func(t *testing.T, body []byte) {
		fixture := newManagedUserCreateFixture()
		feature, err := scimhttp.NewManagedUsersCreateFeature(fixture.config)
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
