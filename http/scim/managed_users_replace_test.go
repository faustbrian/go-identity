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

const managedUserReplaceID = "AAAAAAAAAAAAAAAAAAAAAQ"
const managedUserReplacePath = "/scim/v2/Users/" + managedUserReplaceID
const managedUserReplaceOriginalETag = `"opaque-original-version:7"`
const managedUserReplaceETag = `"opaque-replaced-version:8"`
const managedUserReplaceLocation = "https://directory.example" + managedUserReplacePath
const managedUserReplaceInput = `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"replace-person","active":true}`
const managedUserReplaceBody = `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"` + managedUserReplaceID + `","userName":"replace-person","active":true,"meta":{"resourceType":"User","version":"\"opaque-replaced-version:8\"","location":"` + managedUserReplaceLocation + `"}}`

// Only the public native execution port is doubled. These tests prove bounded
// replacement transport, native precondition custody, admission and wire output;
// real bearer/current authority, omission semantics and durable replay remain
// native and Reference PostgreSQL acceptance.
type managedUsersReplaceExecutor struct {
	*managedUsersExecutor
	afterAdmissionError error
}

func (e *managedUsersReplaceExecutor) ExecuteManagedAdmittedReplace(ctx context.Context, tenant identity.TenantID, request scim.Request, admit scim.ProtocolAdmission) (scim.Response, error) {
	request.Body = bytes.Clone(request.Body)
	response, err := e.ExecuteManagedAdmittedRead(ctx, tenant, request, admit)
	if err != nil {
		return response, err
	}
	return response, e.afterAdmissionError
}

var _ scimhttp.ManagedUsersReplaceExecutor = (*scimpostgres.ManagedConnectionService)(nil)

type managedUserReplaceFixture struct {
	config   scimhttp.ManagedUsersReplaceConfig
	executor *managedUsersReplaceExecutor
	base     protocolFixture
}

func newManagedUserReplaceFixture() managedUserReplaceFixture {
	base := newProtocolFixture()
	executor := &managedUsersReplaceExecutor{managedUsersExecutor: &managedUsersExecutor{client: base.executor.client, response: scim.Response{Status: 200, ContentType: "application/scim+json", Body: []byte(managedUserReplaceBody), ETag: managedUserReplaceETag, Location: managedUserReplaceLocation}}}
	return managedUserReplaceFixture{base: base, executor: executor, config: scimhttp.ManagedUsersReplaceConfig{Network: base.config.Network, Executor: executor, Rate: base.config.Rate, Limits: scim.DefaultLimits(), MaximumDuration: time.Second}}
}

func (f managedUserReplaceFixture) router(t *testing.T) (http.Handler, identityhttp.OpenAPIDocument) {
	t.Helper()
	feature, err := scimhttp.NewManagedUsersReplaceFeature(f.config)
	if err != nil {
		t.Fatal(err)
	}
	operations, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	return protocolRouter(t, f.config.Network, operations)
}

func (f managedUserReplaceFixture) request(body string) *http.Request {
	r := protocolRequest(http.MethodPut, managedUserReplacePath, body)
	r.Header.Set("Content-Type", "application/scim+json")
	r.Header.Set("If-Match", managedUserReplaceOriginalETag)
	return r
}

func TestManagedUsersReplaceTLSRetainsExactNative200AndOriginalCompleteRequest(t *testing.T) {
	f := newManagedUserReplaceFixture()
	h, document := f.router(t)
	server := httptest.NewTLSServer(h)
	defer server.Close()
	client := server.Client()
	defer client.CloseIdleConnections()
	r, err := http.NewRequestWithContext(t.Context(), http.MethodPut, server.URL+managedUserReplacePath, strings.NewReader(managedUserReplaceInput))
	if err != nil {
		t.Fatal(err)
	}
	r.Host = "directory.example"
	r.Header.Set("Authorization", "Bearer "+syntheticBearer)
	r.Header.Set("Content-Type", "application/scim+json")
	r.Header.Set("If-Match", managedUserReplaceOriginalETag)
	r.AddCookie(&http.Cookie{Name: "session", Value: "ignored-cookie"})
	response, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	closeErr := response.Body.Close()
	if response.StatusCode != 200 || response.TLS == nil || readErr != nil || closeErr != nil || string(body) != managedUserReplaceBody || response.Header.Get("ETag") != managedUserReplaceETag || response.Header.Get("Location") != managedUserReplaceLocation || response.Header.Get("Content-Type") != "application/scim+json" || response.Header.Get("Set-Cookie") != "" || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("Replace did not retain exact native User/ETag/Location over TLS: status %d", response.StatusCode)
	}
	got := f.executor.request
	if got.Operation != scim.UserReplace || got.ResourceID != managedUserReplaceID || got.IfMatch != managedUserReplaceOriginalETag || got.Credential.Token() != syntheticBearer || got.IdempotencyKey != "" || got.Query != (scim.Query{}) || got.ContentType != "application/scim+json" || got.ContentEncoding != "" || string(got.Body) != managedUserReplaceInput || f.executor.tenant != f.executor.client.TenantID || f.executor.calls != 1 || f.base.backend.calls != 1 || len(f.base.backend.last.Requests) != 3 {
		t.Fatal("Replace rewrote the complete native request or changed exact-once shared protocol quota")
	}
	if len(document.Operations()) != 1 || document.Operations()[0].Record.OperationID != "identity.scim.user-replace" || document.Operations()[0].Record.RatePolicy != "rate.protocol" || strings.Contains(string(document.JSON()), syntheticBearer) {
		t.Fatal("Replace OpenAPI differs from explicit native operation selection")
	}
	validateManagedUsersReplaceWireResponse(t, document, "200", response.Header.Get("Content-Type"), body)
}

func TestManagedUsersReplaceKeepsNativePreconditionsAndSingletonHeaderCustody(t *testing.T) {
	for _, candidate := range []struct {
		name, version string
		status        int
		duplicate     bool
	}{
		{name: "missing", status: 428},
		{name: "weak", version: `W/"weak"`, status: 400},
		{name: "wildcard", version: "*", status: 400},
		{name: "multiple tags", version: `"one","two"`, status: 400},
		{name: "duplicate field", version: managedUserReplaceOriginalETag, status: 400, duplicate: true},
		{name: "stale", version: `"stale-native-version"`, status: 412},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			f := newManagedUserReplaceFixture()
			charges, nativeCalls := 0, 1
			if candidate.duplicate {
				nativeCalls = 0
			} else if candidate.status == 412 {
				f.executor.afterAdmissionError, charges = scim.NewError(412, ""), 1
			} else {
				f.executor.err = scim.NewError(candidate.status, "")
			}
			h, document := f.router(t)
			r := f.request(managedUserReplaceInput)
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
				if w.Code != 400 || w.Header().Get("Content-Type") != "application/json" || !strings.Contains(w.Body.String(), `"invalid_request"`) {
					t.Fatal("outer framing did not reject duplicate If-Match", w.Code)
				}
			} else {
				assertProtocolError(t, w, candidate.status)
			}
			if f.executor.calls != nativeCalls || f.base.backend.calls != charges || nativeCalls == 1 && f.executor.request.IfMatch != scim.Version(candidate.version) || w.Header().Get("ETag") != "" || w.Header().Get("Location") != "" {
				t.Fatal("Replace transport changed original precondition custody or native admission ordering")
			}
			validateManagedUsersReplaceWireResponse(t, document, strconv.Itoa(w.Code), w.Header().Get("Content-Type"), w.Body.Bytes())
		})
	}
}

func TestManagedUsersReplaceRejectsBadBodyMediaKeyAndCookieFallbackBeforeNative(t *testing.T) {
	for _, mode := range []string{"media", "encoding", "empty body", "overflow", "key", "cookie-only"} {
		t.Run(mode, func(t *testing.T) {
			f := newManagedUserReplaceFixture()
			h, document := f.router(t)
			r := f.request(managedUserReplaceInput)
			want := 400
			switch mode {
			case "media":
				r.Header.Set("Content-Type", "application/json")
				want = 415
			case "encoding":
				r.Header.Set("Content-Encoding", "gzip")
				want = 415
			case "empty body":
				r = f.request("")
			case "overflow":
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
				t.Fatal("invalid Replace reached native/quota or disclosed credential/resource data")
			}
			validateManagedUsersReplaceWireResponse(t, document, strconv.Itoa(w.Code), w.Header().Get("Content-Type"), w.Body.Bytes())
		})
	}
}

func TestManagedUsersReplaceUsesMinimumNativeRawAndDecodedBodyBound(t *testing.T) {
	for _, owner := range []string{"native", "raw", "decoded"} {
		t.Run(owner, func(t *testing.T) {
			f := newManagedUserReplaceFixture()
			f.config.Network.Limits.MaximumBodyBytes, f.config.Network.Limits.MaximumDecodedBytes = 2048, 2048
			bound := 1024
			switch owner {
			case "native":
				bound, f.config.Limits.BodyBytes = 128, 128
			case "raw":
				f.config.Network.Limits.MaximumBodyBytes = uint64(bound)
			case "decoded":
				f.config.Network.Limits.MaximumDecodedBytes = uint64(bound)
			}
			h, _ := f.router(t)
			w := managedServe(h, f.request(strings.Repeat("x", bound+1)))
			assertProtocolError(t, w, 413)
			if f.executor.calls != 0 || f.base.backend.calls != 0 {
				t.Fatal("Replace bypassed the smallest native/shared body budget")
			}
		})
	}
}

func TestManagedUsersReplaceRequiresNativeAuthorityOneTicketAndBoundOutput(t *testing.T) {
	for _, mode := range []string{"auth", "policy", "value", "conflict", "quota", "unavailable", "missing ticket", "second ticket", "native error", "wrong status", "wrong target", "wrong version", "wrong location"} {
		t.Run(mode, func(t *testing.T) {
			f := newManagedUserReplaceFixture()
			want, charges := 503, 1
			switch mode {
			case "auth":
				f.executor.err, want, charges = scim.NewError(401, ""), 401, 0
			case "policy":
				f.executor.err, want, charges = scim.NewError(403, ""), 403, 0
			case "value":
				f.executor.err, want, charges = scim.NewError(400, "invalidValue"), 400, 0
			case "conflict":
				f.executor.afterAdmissionError, want = scim.NewError(409, "uniqueness"), 409
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
				f.executor.response.Body = []byte(strings.Replace(managedUserReplaceBody, managedUserReplaceID, "AAAAAAAAAAAAAAAAAAAAAg", 1))
			case "wrong version":
				f.executor.response.ETag = managedUserReplaceOriginalETag
			case "wrong location":
				f.executor.response.Location = "https://other.example" + managedUserReplacePath
			}
			h, document := f.router(t)
			w := managedServe(h, f.request(managedUserReplaceInput))
			assertProtocolError(t, w, want)
			if f.base.backend.calls != charges || w.Header().Get("ETag") != "" || w.Header().Get("Location") != "" || w.Header().Get("Set-Cookie") != "" || strings.Contains(w.Body.String(), "private") || strings.Contains(w.Body.String(), managedUserReplaceID) {
				t.Fatal("Replace denial disclosed native output or changed one-ticket quota admission")
			}
			if mode == "quota" && w.Header().Get("Retry-After") != "3" || mode == "auth" && w.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Fatal("Replace denial lost retry/challenge metadata")
			}
			validateManagedUsersReplaceWireResponse(t, document, strconv.Itoa(w.Code), w.Header().Get("Content-Type"), w.Body.Bytes())
		})
	}
}

func FuzzManagedUsersReplaceRawBody(f *testing.F) {
	f.Add([]byte(managedUserReplaceInput))
	f.Add([]byte(`{"userName":`))
	f.Add([]byte{})
	f.Add([]byte{0xff})
	f.Fuzz(func(t *testing.T, body []byte) {
		fixture := newManagedUserReplaceFixture()
		feature, err := scimhttp.NewManagedUsersReplaceFeature(fixture.config)
		if err != nil {
			t.Fatal(err)
		}
		h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
		if err != nil {
			t.Fatal(err)
		}
		w := managedServe(h, fixture.request(string(body)))
		if w.Code != 200 && w.Code != 400 && w.Code != 413 || strings.Contains(w.Body.String(), syntheticBearer) || fixture.executor.calls > 1 ||
			fixture.executor.calls == 1 && (!bytes.Equal(fixture.executor.request.Body, body) || len(body) > 1024 || fixture.executor.request.IfMatch != managedUserReplaceOriginalETag) {
			t.Fatalf("hostile Replace body altered bounded raw transport: %d", w.Code)
		}
	})
}

func validateManagedUsersReplaceWireResponse(t *testing.T, document identityhttp.OpenAPIDocument, status, media string, body []byte) {
	t.Helper()
	var wire struct {
		Paths map[string]struct {
			Put struct {
				Responses map[string]struct {
					Content map[string]struct {
						Schema json.RawMessage `json:"schema"`
					} `json:"content"`
				} `json:"responses"`
			} `json:"put"`
		} `json:"paths"`
	}
	if json.Unmarshal(document.JSON(), &wire) != nil {
		t.Fatal("Replace OpenAPI is not JSON")
	}
	definition := wire.Paths["/scim/v2/Users/{resource_id}"].Put.Responses[status].Content[media].Schema
	if len(definition) == 0 {
		t.Fatalf("Replace OpenAPI omitted actual %s %s envelope", status, media)
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
		t.Fatalf("Replace OpenAPI %s %s rejected actual transport envelope: %v", status, media, err)
	}
}
