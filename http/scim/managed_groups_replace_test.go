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

const managedGroupReplaceID = "AAAAAAAAAAAAAAAAAAAAAQ"
const managedGroupReplacePath = "/scim/v2/Groups/" + managedGroupReplaceID
const managedGroupReplaceOriginalETag = `"opaque-original-version:7"`
const managedGroupReplaceETag = `"opaque-replaced-version:8"`
const managedGroupReplaceLocation = "https://directory.example" + managedGroupReplacePath
const managedGroupReplaceInput = `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"replace-person"}`
const managedGroupReplaceBody = `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"id":"` + managedGroupReplaceID + `","displayName":"replace-person","meta":{"resourceType":"Group","version":"\"opaque-replaced-version:8\"","location":"` + managedGroupReplaceLocation + `"}}`

// Only the public native execution port is doubled. These tests prove bounded
// replacement transport, native precondition custody, admission and wire output;
// real bearer/current authority, omission semantics and durable replay remain
// native and Reference PostgreSQL acceptance.
type managedGroupsReplaceExecutor struct {
	*managedUsersExecutor
	afterAdmissionError error
	maximum             int
}

func (e *managedGroupsReplaceExecutor) ExecuteManagedAdmittedGroupReplace(ctx context.Context, tenant identity.TenantID, request scim.Request, maximum int, admit scim.ProtocolAdmission) (scim.Response, error) {
	e.maximum = maximum
	request.Body = bytes.Clone(request.Body)
	response, err := e.ExecuteManagedAdmittedRead(ctx, tenant, request, admit)
	if err != nil {
		return response, err
	}
	return response, e.afterAdmissionError
}

var _ scimhttp.ManagedGroupsReplaceExecutor = (*scimpostgres.ManagedConnectionService)(nil)

type managedGroupReplaceFixture struct {
	config   scimhttp.ManagedGroupsReplaceConfig
	executor *managedGroupsReplaceExecutor
	base     protocolFixture
}

func newManagedGroupReplaceFixture() managedGroupReplaceFixture {
	base := newProtocolFixture()
	executor := &managedGroupsReplaceExecutor{managedUsersExecutor: &managedUsersExecutor{client: base.executor.client, response: scim.Response{Status: 200, ContentType: "application/scim+json", Body: []byte(managedGroupReplaceBody), ETag: managedGroupReplaceETag, Location: managedGroupReplaceLocation}}}
	return managedGroupReplaceFixture{base: base, executor: executor, config: scimhttp.ManagedGroupsReplaceConfig{Network: base.config.Network, Executor: executor, Rate: base.config.Rate, Limits: scim.DefaultLimits(), MaximumDuration: time.Second, MaximumMembers: scim.DefaultGroupMembers}}
}

func (f managedGroupReplaceFixture) router(t *testing.T) (http.Handler, identityhttp.OpenAPIDocument) {
	t.Helper()
	feature, err := scimhttp.NewManagedGroupsReplaceFeature(f.config)
	if err != nil {
		t.Fatal(err)
	}
	operations, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	return protocolRouter(t, f.config.Network, operations)
}

func (f managedGroupReplaceFixture) request(body string) *http.Request {
	r := protocolRequest(http.MethodPut, managedGroupReplacePath, body)
	r.Header.Set("Content-Type", "application/scim+json")
	r.Header.Set("If-Match", managedGroupReplaceOriginalETag)
	return r
}

func TestManagedGroupsReplaceTLSRetainsExactNative200AndOriginalCompleteRequest(t *testing.T) {
	f := newManagedGroupReplaceFixture()
	h, document := f.router(t)
	server := httptest.NewTLSServer(h)
	defer server.Close()
	client := server.Client()
	defer client.CloseIdleConnections()
	r, err := http.NewRequestWithContext(t.Context(), http.MethodPut, server.URL+managedGroupReplacePath, strings.NewReader(managedGroupReplaceInput))
	if err != nil {
		t.Fatal(err)
	}
	r.Host = "directory.example"
	r.Header.Set("Authorization", "Bearer "+syntheticBearer)
	r.Header.Set("Content-Type", "application/scim+json")
	r.Header.Set("If-Match", managedGroupReplaceOriginalETag)
	r.AddCookie(&http.Cookie{Name: "session", Value: "ignored-cookie"})
	response, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	closeErr := response.Body.Close()
	if response.StatusCode != 200 || response.TLS == nil || readErr != nil || closeErr != nil || string(body) != managedGroupReplaceBody || response.Header.Get("ETag") != managedGroupReplaceETag || response.Header.Get("Location") != managedGroupReplaceLocation || response.Header.Get("Content-Type") != "application/scim+json" || response.Header.Get("Set-Cookie") != "" || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("Replace did not retain exact native Group/ETag/Location over TLS: status %d", response.StatusCode)
	}
	got := f.executor.request
	if got.Operation != scim.GroupReplace || got.ResourceID != managedGroupReplaceID || got.IfMatch != managedGroupReplaceOriginalETag || got.Credential.Token() != syntheticBearer || got.IdempotencyKey != "" || got.Query != (scim.Query{}) || got.ContentType != "application/scim+json" || got.ContentEncoding != "" || string(got.Body) != managedGroupReplaceInput || f.executor.maximum != scim.DefaultGroupMembers || f.executor.tenant != f.executor.client.TenantID || f.executor.calls != 1 || f.base.backend.calls != 1 || len(f.base.backend.last.Requests) != 3 {
		t.Fatal("Replace rewrote the complete native request or changed exact-once shared protocol quota")
	}
	if len(document.Operations()) != 1 || document.Operations()[0].Record.OperationID != "identity.scim.group-replace" || document.Operations()[0].Record.RatePolicy != "rate.protocol" || strings.Contains(string(document.JSON()), syntheticBearer) {
		t.Fatal("Replace OpenAPI differs from explicit native operation selection")
	}
	validateManagedGroupsReplaceWireResponse(t, document, "200", response.Header.Get("Content-Type"), body)
}

func TestManagedGroupsReplaceKeepsNativePreconditionsAndSingletonHeaderCustody(t *testing.T) {
	for _, candidate := range []struct {
		name, version string
		status        int
		duplicate     bool
	}{
		{name: "missing", status: 428},
		{name: "weak", version: `W/"weak"`, status: 400},
		{name: "wildcard", version: "*", status: 400},
		{name: "multiple tags", version: `"one","two"`, status: 400},
		{name: "duplicate field", version: managedGroupReplaceOriginalETag, status: 400, duplicate: true},
		{name: "stale", version: `"stale-native-version"`, status: 412},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			f := newManagedGroupReplaceFixture()
			charges, nativeCalls := 0, 1
			if candidate.duplicate {
				nativeCalls = 0
			} else if candidate.status == 412 {
				f.executor.afterAdmissionError, charges = scim.NewError(412, ""), 1
			} else {
				f.executor.err = scim.NewError(candidate.status, "")
			}
			h, document := f.router(t)
			r := f.request(managedGroupReplaceInput)
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
			validateManagedGroupsReplaceWireResponse(t, document, strconv.Itoa(w.Code), w.Header().Get("Content-Type"), w.Body.Bytes())
		})
	}
}

func TestManagedGroupsReplaceRejectsBadBodyMediaKeyAndCookieFallbackBeforeNative(t *testing.T) {
	for _, mode := range []string{"media", "encoding", "empty body", "overflow", "key", "cookie-only", "query", "empty-query", "trailer", "range", "if-none-match", "cleartext"} {
		t.Run(mode, func(t *testing.T) {
			f := newManagedGroupReplaceFixture()
			h, document := f.router(t)
			r := f.request(managedGroupReplaceInput)
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
			case "query":
				r.URL.RawQuery = "attributes=displayName"
				r.RequestURI = r.URL.RequestURI()
			case "empty-query":
				r.URL.ForceQuery = true
				r.RequestURI = r.URL.RequestURI()
			case "trailer":
				r.Trailer = http.Header{"X-Trailer": []string{"forbidden"}}
			case "range", "if-none-match":
				r.Header.Set(mode, "forbidden")
			case "cleartext":
				r.TLS, r.URL.Scheme, want = nil, "http", 403
			}
			w := managedServe(h, r)
			if w.Code != want {
				t.Fatalf("invalid Group Replace %s: status %d want %d", mode, w.Code, want)
			}
			if f.executor.calls != 0 || f.base.backend.calls != 0 || w.Header().Get("ETag") != "" || w.Header().Get("Location") != "" || w.Header().Get("Set-Cookie") != "" || strings.Contains(w.Body.String(), syntheticBearer) {
				t.Fatal("invalid Replace reached native/quota or disclosed credential/resource data")
			}
			validateManagedGroupsReplaceWireResponse(t, document, strconv.Itoa(w.Code), w.Header().Get("Content-Type"), w.Body.Bytes())
		})
	}
}

func TestManagedGroupsReplaceUsesMinimumNativeRawAndDecodedBodyBound(t *testing.T) {
	for _, owner := range []string{"native", "raw", "decoded"} {
		t.Run(owner, func(t *testing.T) {
			f := newManagedGroupReplaceFixture()
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

func TestManagedGroupsReplaceRequiresNativeAuthorityOneTicketAndBoundOutput(t *testing.T) {
	for _, mode := range []string{"auth", "policy", "value", "conflict", "quota", "unavailable", "missing ticket", "second ticket", "wrong tenant", "ignored quota", "native error", "late error", "wrong status", "wrong media", "empty output", "oversized output", "wrong target", "wrong version", "weak version", "wrong location", "body location", "body type", "body schema"} {
		t.Run(mode, func(t *testing.T) {
			f := newManagedGroupReplaceFixture()
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
			case "wrong tenant":
				f.executor.client.TenantID, want, charges = "other-tenant", 403, 0
			case "ignored quota":
				f.executor.mode, f.base.backend.limited = "ignore", true
			case "native error":
				f.executor.err, charges = errors.New("private native failure"), 0
			case "late error":
				f.executor.mode = "late-error"
			case "wrong status":
				f.executor.response.Status = 201
			case "wrong media":
				f.executor.response.ContentType = "application/json"
			case "empty output":
				f.executor.response.Body = nil
			case "oversized output":
				f.executor.response.Body = bytes.Repeat([]byte("x"), f.config.Limits.ResponseBytes+1)
			case "wrong target":
				f.executor.response.Body = []byte(strings.Replace(managedGroupReplaceBody, managedGroupReplaceID, "AAAAAAAAAAAAAAAAAAAAAg", 1))
			case "wrong version":
				f.executor.response.ETag = managedGroupReplaceOriginalETag
			case "weak version":
				f.executor.response.ETag = `W/"weak"`
			case "wrong location":
				f.executor.response.Location = "https://other.example" + managedGroupReplacePath
			case "body location":
				f.executor.response.Body = []byte(strings.Replace(managedGroupReplaceBody, managedGroupReplaceLocation, "https://other.example"+managedGroupReplacePath, 1))
			case "body type":
				f.executor.response.Body = []byte(strings.Replace(managedGroupReplaceBody, `"resourceType":"Group"`, `"resourceType":"User"`, 1))
			case "body schema":
				f.executor.response.Body = []byte(strings.Replace(managedGroupReplaceBody, "core:2.0:Group", "core:2.0:User", 1))
			}
			h, document := f.router(t)
			w := managedServe(h, f.request(managedGroupReplaceInput))
			assertProtocolError(t, w, want)
			if f.base.backend.calls != charges || w.Header().Get("ETag") != "" || w.Header().Get("Location") != "" || w.Header().Get("Set-Cookie") != "" || strings.Contains(w.Body.String(), "private") || strings.Contains(w.Body.String(), managedGroupReplaceID) {
				t.Fatal("Replace denial disclosed native output or changed one-ticket quota admission")
			}
			if mode == "quota" && w.Header().Get("Retry-After") != "3" || mode == "auth" && w.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Fatal("Replace denial lost retry/challenge metadata")
			}
			validateManagedGroupsReplaceWireResponse(t, document, strconv.Itoa(w.Code), w.Header().Get("Content-Type"), w.Body.Bytes())
		})
	}
}

func TestManagedGroupsReplaceCancellationAndHeaderlessRetryKeepNativeOwnership(t *testing.T) {
	for _, phase := range []string{"before", "after", "panic"} {
		t.Run(phase, func(t *testing.T) {
			f := newManagedGroupReplaceFixture()
			r := f.request(managedGroupReplaceInput)
			ctx, cancel := context.WithCancel(r.Context())
			defer cancel()
			charges := 0
			switch phase {
			case "before":
				f.executor.before = cancel
			case "after":
				f.executor.after, charges = cancel, 1
			case "panic":
				f.executor.before = func() { panic("private native panic") }
			}
			h, document := f.router(t)
			w := managedServe(h, r.WithContext(ctx))
			if w.Code != 503 || f.base.backend.calls != charges || w.Header().Get("ETag") != "" || w.Header().Get("Location") != "" || strings.Contains(w.Body.String(), "private") || strings.Contains(w.Body.String(), managedGroupReplaceID) {
				t.Fatal("cancelled or panicking Group Replace disclosed its output")
			}
			validateManagedGroupsReplaceWireResponse(t, document, "503", w.Header().Get("Content-Type"), w.Body.Bytes())
		})
	}
	f := newManagedGroupReplaceFixture()
	h, _ := f.router(t)
	first := managedServe(h, f.request(managedGroupReplaceInput))
	second := managedServe(h, f.request(managedGroupReplaceInput))
	if first.Code != 200 || second.Code != 200 || first.Body.String() != managedGroupReplaceBody || second.Body.String() != managedGroupReplaceBody || second.Header().Get("ETag") != managedGroupReplaceETag || f.executor.calls != 2 || f.base.backend.calls != 2 || f.executor.request.IfMatch != managedGroupReplaceOriginalETag || f.executor.request.IdempotencyKey != "" {
		t.Fatal("transport cached, retried or replaced the native original headerless command")
	}
}

func TestManagedGroupsReplaceOnlySelectsCanonicalPUTAndRequiresRouterProvenance(t *testing.T) {
	f := newManagedGroupReplaceFixture()
	h, _ := f.router(t)
	for _, path := range []string{"/scim/v2/Groups", managedGroupReplacePath + "/", managedGroupReplacePath + "/extra", "/scim/v2/Groups/.search", "/scim/v2/Groups/..", "/scim/v2/Groups/%41AAAAAAAAAAAAAAAAAAAAQ", "/scim/v2/Groups/a%2Fb", "/scim/v2/Users/" + managedGroupReplaceID} {
		r := protocolRequest(http.MethodPut, path, managedGroupReplaceInput)
		r.SetPathValue("resource_id", managedGroupReplaceID)
		if w := managedServe(h, r); w.Code != 404 || f.executor.calls != 0 {
			t.Fatalf("unselected/noncanonical Group Replace path reached native: %s %d", path, w.Code)
		}
	}
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPatch, http.MethodDelete, http.MethodOptions} {
		r := f.request(managedGroupReplaceInput)
		r.Method = method
		if w := managedServe(h, r); w.Code != 405 || w.Header().Get("Allow") != "PUT" || f.executor.calls != 0 {
			t.Fatalf("unselected Group method reached native: %s %d", method, w.Code)
		}
	}
	feature, err := scimhttp.NewManagedGroupsReplaceFeature(f.config)
	if err != nil {
		t.Fatal(err)
	}
	if w := managedServe(feature.Operations()[0].Handler, f.request(managedGroupReplaceInput)); w.Code != 404 || f.executor.calls != 0 {
		t.Fatal("direct Group Replace accepted absent router provenance")
	}
	r := f.request(managedGroupReplaceInput)
	r.SetPathValue("resource_id", "forged")
	if w := managedServe(h, r); w.Code != 200 || f.executor.request.ResourceID != managedGroupReplaceID {
		t.Fatal("router did not replace forged Group resource provenance")
	}
}

func TestManagedGroupsReplaceRejectsInvalidConfigurationWithoutIOAndRedactsCustody(t *testing.T) {
	for _, mode := range []string{"nil", "typed-nil", "network", "limits", "rate", "deadline", "long-deadline", "negative-members", "oversized-members"} {
		f := newManagedGroupReplaceFixture()
		switch mode {
		case "nil":
			f.config.Executor = nil
		case "typed-nil":
			f.config.Executor = (*managedGroupsReplaceExecutor)(nil)
		case "network":
			f.config.Network = identityhttp.NetworkConfig{}
		case "limits":
			f.config.Limits = scim.Limits{}
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
		if _, err := scimhttp.NewManagedGroupsReplaceFeature(f.config); !errors.Is(err, identityhttp.ErrInvalidInput) || f.executor.calls != 0 || f.base.backend.calls != 0 {
			t.Fatalf("invalid Group Replace setup accepted or caused IO: %s", mode)
		}
	}
	f := newManagedGroupReplaceFixture()
	f.config.MaximumMembers = 0
	h, _ := f.router(t)
	if w := managedServe(h, f.request(managedGroupReplaceInput)); w.Code != 200 || f.executor.maximum != 0 {
		t.Fatal("explicit empty-only Group ceiling was replaced by a default")
	}
	if _, err := json.Marshal(f.config); !errors.Is(err, identityhttp.ErrInvalidInput) {
		t.Fatal("native runtime custody was implicitly exportable")
	}
}

func FuzzManagedGroupsReplaceRawBody(f *testing.F) {
	f.Add([]byte(managedGroupReplaceInput))
	f.Add([]byte(`{"displayName":`))
	f.Add([]byte{})
	f.Add([]byte{0xff})
	f.Fuzz(func(t *testing.T, body []byte) {
		fixture := newManagedGroupReplaceFixture()
		feature, err := scimhttp.NewManagedGroupsReplaceFeature(fixture.config)
		if err != nil {
			t.Fatal(err)
		}
		h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
		if err != nil {
			t.Fatal(err)
		}
		w := managedServe(h, fixture.request(string(body)))
		if w.Code != 200 && w.Code != 400 && w.Code != 413 || strings.Contains(w.Body.String(), syntheticBearer) || fixture.executor.calls > 1 ||
			fixture.executor.calls == 1 && (!bytes.Equal(fixture.executor.request.Body, body) || len(body) > 1024 || fixture.executor.request.IfMatch != managedGroupReplaceOriginalETag) {
			t.Fatalf("hostile Replace body altered bounded raw transport: %d", w.Code)
		}
	})
}

func validateManagedGroupsReplaceWireResponse(t *testing.T, document identityhttp.OpenAPIDocument, status, media string, body []byte) {
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
	definition := wire.Paths["/scim/v2/Groups/{resource_id}"].Put.Responses[status].Content[media].Schema
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
