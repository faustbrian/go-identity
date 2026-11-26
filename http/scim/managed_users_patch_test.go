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

const managedUserPatchID = "AAAAAAAAAAAAAAAAAAAAAQ"
const managedUserPatchPath = "/scim/v2/Users/" + managedUserPatchID
const managedUserPatchOriginalETag = `"opaque-original-version:7"`
const managedUserPatchETag = `"opaque-patched-version:8"`
const managedUserPatchLocation = "https://directory.example" + managedUserPatchPath
const managedUserPatchInput = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"userName","value":"patch-person"},{"op":"add","path":"externalId","value":"patch-correlation"}]}`
const managedUserPatchBody = `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"` + managedUserPatchID + `","userName":"patch-person","externalId":"patch-correlation","meta":{"resourceType":"User","version":"\"opaque-patched-version:8\"","location":"` + managedUserPatchLocation + `"}}`

// Only the public native execution port is doubled. This proves bounded raw
// transport, admission and serialization, not native PATCH validation, current
// bearer authority, PostgreSQL effects or durable headerless replay.
type managedUsersPatchExecutor struct {
	*managedUsersExecutor
	afterAdmissionError error
}

func (e *managedUsersPatchExecutor) ExecuteManagedAdmittedPatch(ctx context.Context, tenant identity.TenantID, request scim.Request, admit scim.ProtocolAdmission) (scim.Response, error) {
	request.Body = bytes.Clone(request.Body)
	response, err := e.ExecuteManagedAdmittedRead(ctx, tenant, request, admit)
	if err != nil {
		return response, err
	}
	return response, e.afterAdmissionError
}

var _ scimhttp.ManagedUsersPatchExecutor = (*scimpostgres.ManagedConnectionService)(nil)

type managedUserPatchFixture struct {
	config   scimhttp.ManagedUsersPatchConfig
	executor *managedUsersPatchExecutor
	base     protocolFixture
}

func newManagedUserPatchFixture() managedUserPatchFixture {
	base := newProtocolFixture()
	executor := &managedUsersPatchExecutor{managedUsersExecutor: &managedUsersExecutor{client: base.executor.client, response: scim.Response{Status: 200, ContentType: "application/scim+json", Body: []byte(managedUserPatchBody), ETag: managedUserPatchETag, Location: managedUserPatchLocation}}}
	return managedUserPatchFixture{base: base, executor: executor, config: scimhttp.ManagedUsersPatchConfig{Network: base.config.Network, Executor: executor, Rate: base.config.Rate, Limits: scim.DefaultLimits(), MaximumDuration: time.Second}}
}

func (f managedUserPatchFixture) router(t *testing.T) (http.Handler, identityhttp.OpenAPIDocument) {
	t.Helper()
	feature, err := scimhttp.NewManagedUsersPatchFeature(f.config)
	if err != nil {
		t.Fatal(err)
	}
	operations, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	return protocolRouter(t, f.config.Network, operations)
}

func (f managedUserPatchFixture) request(body string) *http.Request {
	r := protocolRequest(http.MethodPatch, managedUserPatchPath, body)
	r.Header.Set("Content-Type", "application/scim+json")
	r.Header.Set("If-Match", managedUserPatchOriginalETag)
	return r
}

func TestManagedUsersPatchTLSRetainsExactNative200AndOriginalConditionalRequest(t *testing.T) {
	f := newManagedUserPatchFixture()
	h, document := f.router(t)
	server := httptest.NewTLSServer(h)
	defer server.Close()
	client := server.Client()
	defer client.CloseIdleConnections()
	r, err := http.NewRequestWithContext(t.Context(), http.MethodPatch, server.URL+managedUserPatchPath, strings.NewReader(managedUserPatchInput))
	if err != nil {
		t.Fatal(err)
	}
	r.Host = "directory.example"
	r.Header.Set("Authorization", "Bearer "+syntheticBearer)
	r.Header.Set("Content-Type", "application/scim+json")
	r.Header.Set("If-Match", managedUserPatchOriginalETag)
	r.AddCookie(&http.Cookie{Name: "session", Value: "ignored-cookie"})
	response, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	closeErr := response.Body.Close()
	if response.StatusCode != 200 || readErr != nil || closeErr != nil || string(body) != managedUserPatchBody || response.Header.Get("ETag") != managedUserPatchETag || response.Header.Get("Location") != managedUserPatchLocation || response.Header.Get("Content-Type") != "application/scim+json" || response.Header.Get("Set-Cookie") != "" || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("Patch did not retain native User/ETag/Location over TLS: status %d", response.StatusCode)
	}
	got := f.executor.request
	if got.Operation != scim.UserPatch || got.ResourceID != managedUserPatchID || got.IfMatch != managedUserPatchOriginalETag || got.Credential.Token() != syntheticBearer || got.IdempotencyKey != "" || got.Query != (scim.Query{}) || got.ContentType != "application/scim+json" || got.ContentEncoding != "" || string(got.Body) != managedUserPatchInput || f.executor.tenant != f.executor.client.TenantID || f.executor.calls != 1 || f.base.backend.calls != 1 || len(f.base.backend.last.Requests) != 3 {
		t.Fatal("Patch rewrote original native request or changed exact-once protocol quota")
	}
	if len(document.Operations()) != 1 || document.Operations()[0].Record.OperationID != "identity.scim.user-patch" || document.Operations()[0].Record.RatePolicy != "rate.protocol" || strings.Contains(string(document.JSON()), syntheticBearer) {
		t.Fatal("Patch OpenAPI differs from the explicitly selected native operation")
	}
	validateManagedUsersPatchWireResponse(t, document, "200", response.Header.Get("Content-Type"), body)
}

func TestManagedUsersPatchKeepsNativePreconditionsAndSingletonHeaderCustody(t *testing.T) {
	for _, candidate := range []struct {
		name, version string
		status        int
		duplicate     bool
	}{
		{name: "missing", status: 428},
		{name: "weak", version: `W/"weak"`, status: 400},
		{name: "wildcard", version: "*", status: 400},
		{name: "multiple tags", version: `"one","two"`, status: 400},
		{name: "duplicate field", version: managedUserPatchOriginalETag, status: 400, duplicate: true},
		{name: "stale", version: `"stale-native-version"`, status: 412},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			f := newManagedUserPatchFixture()
			charges, nativeCalls := 0, 1
			if candidate.duplicate {
				nativeCalls = 0
			} else if candidate.status == 412 {
				f.executor.afterAdmissionError = scim.NewError(412, "")
				charges = 1
			} else {
				f.executor.err = scim.NewError(candidate.status, "")
			}
			h, document := f.router(t)
			r := f.request(managedUserPatchInput)
			if candidate.version == "" {
				r.Header.Del("If-Match")
			} else {
				r.Header.Set("If-Match", candidate.version)
			}
			if candidate.duplicate {
				r.Header.Add("If-Match", candidate.version)
			}
			w := managedServe(h, r)
			if candidate.duplicate {
				if w.Code != http.StatusBadRequest || w.Header().Get("Content-Type") != "application/json" || !strings.Contains(w.Body.String(), `"invalid_request"`) {
					t.Fatal("outer framing did not reject duplicate If-Match", w.Code)
				}
			} else {
				assertProtocolError(t, w, candidate.status)
			}
			if f.executor.calls != nativeCalls || f.base.backend.calls != charges || nativeCalls == 1 && f.executor.request.IfMatch != scim.Version(candidate.version) || w.Header().Get("ETag") != "" || w.Header().Get("Location") != "" {
				t.Fatal("Patch transport parsed native preconditions, changed exact custody or charged before preflight")
			}
			validateManagedUsersPatchWireResponse(t, document, strconv.Itoa(w.Code), w.Header().Get("Content-Type"), w.Body.Bytes())
		})
	}
}

func TestManagedUsersPatchRejectsBadMediaBodyKeyAndCookieFallbackBeforeNative(t *testing.T) {
	for _, mode := range []string{"media", "charset", "encoding", "empty body", "body overflow", "key", "cookie-only"} {
		t.Run(mode, func(t *testing.T) {
			f := newManagedUserPatchFixture()
			h, document := f.router(t)
			r := f.request(managedUserPatchInput)
			want := 400
			switch mode {
			case "media":
				r.Header.Set("Content-Type", "application/json")
				want = 415
			case "charset":
				r.Header.Set("Content-Type", "application/scim+json; charset=latin-1")
				want = 415
			case "encoding":
				r.Header.Set("Content-Encoding", "gzip")
				want = 415
			case "empty body":
				r = f.request("")
			case "body overflow":
				r = f.request(strings.Repeat("x", 1025))
				want = 413
			case "key":
				r.Header.Set("Idempotency-Key", "not-selected")
			case "cookie-only":
				r.Header.Del("Authorization")
				r.AddCookie(&http.Cookie{Name: "session", Value: syntheticBearer})
				want = 401
			}
			w := managedServe(h, r)
			assertProtocolError(t, w, want)
			if f.executor.calls != 0 || f.base.backend.calls != 0 || w.Header().Get("ETag") != "" || w.Header().Get("Location") != "" || w.Header().Get("Set-Cookie") != "" || strings.Contains(w.Body.String(), syntheticBearer) {
				t.Fatal("invalid Patch envelope reached native/quota or disclosed source data")
			}
			validateManagedUsersPatchWireResponse(t, document, strconv.Itoa(w.Code), w.Header().Get("Content-Type"), w.Body.Bytes())
		})
	}
}

func TestManagedUsersPatchUsesMinimumNativeRawAndDecodedBodyBound(t *testing.T) {
	for _, owner := range []string{"native", "raw", "decoded"} {
		t.Run(owner, func(t *testing.T) {
			f := newManagedUserPatchFixture()
			f.config.Network.Limits.MaximumBodyBytes = 2048
			f.config.Network.Limits.MaximumDecodedBytes = 2048
			bound := 1024
			switch owner {
			case "native":
				bound = 128
				f.config.Limits.BodyBytes = bound
			case "raw":
				f.config.Network.Limits.MaximumBodyBytes = uint64(bound)
			case "decoded":
				f.config.Network.Limits.MaximumDecodedBytes = uint64(bound)
			}
			h, _ := f.router(t)
			w := managedServe(h, f.request(strings.Repeat("x", bound+1)))
			assertProtocolError(t, w, 413)
			if f.executor.calls != 0 || f.base.backend.calls != 0 {
				t.Fatal("Patch bypassed the smallest native/shared request-body budget")
			}
		})
	}
}

func TestManagedUsersPatchRequiresNativeAuthorityAndOneQuotaTicketBeforeOutput(t *testing.T) {
	for _, mode := range []string{"auth", "policy", "quota", "unavailable", "missing ticket", "second ticket", "native error", "wrong status", "wrong target", "wrong version", "wrong location"} {
		t.Run(mode, func(t *testing.T) {
			f := newManagedUserPatchFixture()
			want, charges := 503, 1
			switch mode {
			case "auth":
				f.executor.err, want, charges = scim.NewError(401, ""), 401, 0
			case "policy":
				f.executor.err, want, charges = scim.NewError(403, ""), 403, 0
			case "quota":
				f.base.backend.limited, want = true, 429
			case "unavailable":
				f.base.backend.unavailable = true
			case "missing ticket":
				f.executor.mode, charges = "skip", 0
			case "second ticket":
				f.executor.mode = "double"
			case "native error":
				f.executor.err, charges = errors.New("private native failure"), 0
			case "wrong status":
				f.executor.response.Status = 201
			case "wrong target":
				f.executor.response.Body = []byte(strings.Replace(managedUserPatchBody, managedUserPatchID, "AAAAAAAAAAAAAAAAAAAAAg", 1))
			case "wrong version":
				f.executor.response.ETag = managedUserPatchOriginalETag
			case "wrong location":
				f.executor.response.Location = "https://other.example" + managedUserPatchPath
			}
			h, document := f.router(t)
			w := managedServe(h, f.request(managedUserPatchInput))
			assertProtocolError(t, w, want)
			if f.base.backend.calls != charges || w.Header().Get("ETag") != "" || w.Header().Get("Location") != "" || w.Header().Get("Set-Cookie") != "" || strings.Contains(w.Body.String(), "private") || strings.Contains(w.Body.String(), managedUserPatchID) {
				t.Fatal("Patch denial disclosed native output or changed quota admission")
			}
			if mode == "quota" && w.Header().Get("Retry-After") != "3" || mode == "auth" && w.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Fatal("Patch denial lost retry/challenge metadata")
			}
			validateManagedUsersPatchWireResponse(t, document, strconv.Itoa(w.Code), w.Header().Get("Content-Type"), w.Body.Bytes())
		})
	}
}

func TestManagedUsersPatchSelectsOnlyCanonicalResourceRoute(t *testing.T) {
	f := newManagedUserPatchFixture()
	feature, err := scimhttp.NewManagedUsersPatchFeature(f.config)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{})
	if err != nil {
		t.Fatal(err)
	}
	if managedServe(empty, f.request(managedUserPatchInput)).Code != 404 || f.executor.calls != 0 {
		t.Fatal("unselected Patch exposed native execution")
	}
	h, _ := f.router(t)
	for _, path := range []string{"/scim/v2/Users", managedUserPatchPath + "/extra", "/scim/v2/Groups/" + managedUserPatchID} {
		r := protocolRequest(http.MethodPatch, path, managedUserPatchInput)
		if managedServe(h, r).Code != 404 || f.executor.calls != 0 {
			t.Fatal("Patch feature selected another resource route")
		}
	}
	r := f.request(managedUserPatchInput)
	r.Method = http.MethodPut
	if w := managedServe(h, r); w.Code != 405 || w.Header().Get("Allow") != "PATCH" || f.executor.calls != 0 || len(feature.Operations()) != 1 {
		t.Fatal("Patch feature widened its selected method or native port")
	}
}

func validateManagedUsersPatchWireResponse(t *testing.T, document identityhttp.OpenAPIDocument, status, media string, body []byte) {
	t.Helper()
	var wire struct {
		Paths map[string]struct {
			Patch struct {
				Responses map[string]struct {
					Content map[string]struct {
						Schema json.RawMessage `json:"schema"`
					} `json:"content"`
				} `json:"responses"`
			} `json:"patch"`
		} `json:"paths"`
	}
	if json.Unmarshal(document.JSON(), &wire) != nil {
		t.Fatal("Patch OpenAPI is not JSON")
	}
	definition := wire.Paths["/scim/v2/Users/{resource_id}"].Patch.Responses[status].Content[media].Schema
	if len(definition) == 0 {
		t.Fatalf("Patch OpenAPI omitted actual %s %s envelope", status, media)
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
		t.Fatalf("Patch OpenAPI %s %s rejected actual transport envelope: %v", status, media, err)
	}
}
