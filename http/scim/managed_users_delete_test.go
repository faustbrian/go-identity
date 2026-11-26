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
)

const managedUserDeletePath = "/scim/v2/Users/source-user"
const managedUserDeleteETag = `"opaque-delete-version:7"`

// Only the published native execution port is doubled. Durable source
// withdrawal, native If-Match policy and replay remain native acceptance.
type managedUsersDeleteExecutor struct {
	*managedUsersExecutor
	afterAdmissionError error
}

func (e *managedUsersDeleteExecutor) ExecuteManagedAdmittedDelete(ctx context.Context, tenant identity.TenantID, request scim.Request, admit scim.ProtocolAdmission) (scim.Response, error) {
	response, err := e.ExecuteManagedAdmittedRead(ctx, tenant, request, admit)
	if err != nil {
		return response, err
	}
	return response, e.afterAdmissionError
}

type managedUserDeleteFixture struct {
	config   scimhttp.ManagedUsersDeleteConfig
	executor *managedUsersDeleteExecutor
	base     protocolFixture
}

func newManagedUserDeleteFixture() managedUserDeleteFixture {
	base := newProtocolFixture()
	executor := &managedUsersDeleteExecutor{managedUsersExecutor: &managedUsersExecutor{client: base.executor.client, response: scim.Response{Status: http.StatusNoContent}}}
	return managedUserDeleteFixture{base: base, executor: executor, config: scimhttp.ManagedUsersDeleteConfig{Network: base.config.Network, Executor: executor, Rate: base.config.Rate, Limits: scim.DefaultLimits(), MaximumDuration: time.Second}}
}

func (f managedUserDeleteFixture) router(t *testing.T) (http.Handler, identityhttp.OpenAPIDocument) {
	t.Helper()
	feature, err := scimhttp.NewManagedUsersDeleteFeature(f.config)
	if err != nil {
		t.Fatal(err)
	}
	operations, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	return protocolRouter(t, f.config.Network, operations)
}

func (f managedUserDeleteFixture) request() *http.Request {
	r := protocolRequest(http.MethodDelete, managedUserDeletePath, "")
	r.Header.Set("If-Match", managedUserDeleteETag)
	return r
}

func TestManagedUsersDeleteTLSRetainsBodyless204AndExactNativeConditionalRequest(t *testing.T) {
	f := newManagedUserDeleteFixture()
	h, document := f.router(t)
	server := httptest.NewTLSServer(h)
	defer server.Close()
	client := server.Client()
	defer client.CloseIdleConnections()
	for range 2 {
		r, err := http.NewRequestWithContext(t.Context(), http.MethodDelete, server.URL+managedUserDeletePath, nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Host = "directory.example"
		r.Header.Set("Authorization", "Bearer "+syntheticBearer)
		r.Header.Set("If-Match", managedUserDeleteETag)
		r.AddCookie(&http.Cookie{Name: "session", Value: "ignored-cookie"})
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 8192))
		closeErr := response.Body.Close()
		if response.StatusCode != 204 || readErr != nil || closeErr != nil || len(body) != 0 || response.Header.Get("ETag") != "" || response.Header.Get("Location") != "" || response.Header.Get("Content-Type") != "" || response.Header.Get("Set-Cookie") != "" || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("Delete did not retain exact native empty 204: status %d", response.StatusCode)
		}
	}
	got := f.executor.request
	if got.Operation != scim.UserDelete || got.ResourceID != "source-user" || got.IfMatch != managedUserDeleteETag || got.Credential.Token() != syntheticBearer || got.IdempotencyKey != "" || got.Query != (scim.Query{}) || got.Body != nil || got.ContentType != "" || got.ContentEncoding != "" || f.executor.calls != 2 || f.base.backend.calls != 2 || len(f.base.backend.last.Requests) != 3 || f.executor.tenant != f.executor.client.TenantID {
		t.Fatal("Delete rewrote native precondition/scope, synthesized a command or cached/retried admission")
	}
	if len(document.Operations()) != 1 || document.Operations()[0].Record.OperationID != "identity.scim.user-delete" || document.Operations()[0].Record.RatePolicy != "rate.protocol" || strings.Contains(string(document.JSON()), syntheticBearer) {
		t.Fatal("Delete OpenAPI differs from the selected native protocol operation")
	}
	var wire struct {
		Paths map[string]map[string]struct {
			Responses map[string]struct {
				Content json.RawMessage `json:"content"`
				Headers json.RawMessage `json:"headers"`
			} `json:"responses"`
		} `json:"paths"`
	}
	if json.Unmarshal(document.JSON(), &wire) != nil {
		t.Fatal("Delete document is not JSON")
	}
	success, ok := wire.Paths["/scim/v2/Users/{resource_id}"]["delete"].Responses["204"]
	if !ok || len(success.Content) != 0 || len(success.Headers) != 0 {
		t.Fatal("Delete OpenAPI invented a success representation, ETag or Location")
	}
}

func TestManagedUsersDeleteTLSDenialsMatchPublishedWireWithoutNativeOutput(t *testing.T) {
	for _, mode := range []string{"missing-version", "stale-version", "duplicate-version", "cookie-only", "limited", "unavailable"} {
		t.Run(mode, func(t *testing.T) {
			f := newManagedUserDeleteFixture()
			want, nativeCalls, charges := 400, 1, 0
			switch mode {
			case "missing-version":
				f.executor.err, want = scim.NewError(428, ""), 428
			case "stale-version":
				f.executor.afterAdmissionError, want, charges = scim.NewError(412, ""), 412, 1
			case "duplicate-version":
				nativeCalls = 0
			case "cookie-only":
				want, nativeCalls = 401, 0
			case "limited":
				f.base.backend.limited, want, charges = true, 429, 1
			case "unavailable":
				f.base.backend.unavailable, want, charges = true, 503, 1
			}
			h, document := f.router(t)
			server := httptest.NewTLSServer(h)
			defer server.Close()
			client := server.Client()
			defer client.CloseIdleConnections()
			r, err := http.NewRequestWithContext(t.Context(), http.MethodDelete, server.URL+managedUserDeletePath, nil)
			if err != nil {
				t.Fatal(err)
			}
			r.Host = "directory.example"
			r.Header.Set("Authorization", "Bearer "+syntheticBearer)
			r.Header.Set("If-Match", managedUserDeleteETag)
			switch mode {
			case "missing-version":
				r.Header.Del("If-Match")
			case "duplicate-version":
				r.Header.Add("If-Match", managedUserDeleteETag)
			case "cookie-only":
				r.Header.Del("Authorization")
				r.AddCookie(&http.Cookie{Name: "session", Value: syntheticBearer})
			}
			response, err := client.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			body, readErr := io.ReadAll(io.LimitReader(response.Body, 8192))
			closeErr := response.Body.Close()
			if response.StatusCode != want || readErr != nil || closeErr != nil || f.executor.calls != nativeCalls || f.base.backend.calls != charges || response.Header.Get("ETag") != "" || response.Header.Get("Location") != "" || response.Header.Get("Set-Cookie") != "" || strings.Contains(string(body), syntheticBearer) || strings.Contains(string(body), "source-user") {
				t.Fatalf("Delete TLS denial %s lost envelope/custody: status %d want %d", mode, response.StatusCode, want)
			}
			validateManagedUsersDeleteWireResponse(t, document, strconv.Itoa(response.StatusCode), response.Header.Get("Content-Type"), body)
		})
	}
}

func TestManagedUsersDeleteRejectsAlternateChannelsBeforeNativeOrQuota(t *testing.T) {
	for _, mode := range []string{"query", "empty-query", "body", "unknown-length-body", "trailer", "encoding", "key", "empty-key", "cookie-key", "duplicate-bearer", "cookie-only", "proxy-bearer", "duplicate-if-match", "aliased-if-match", "if-none-match", "range", "cleartext", "public-host", "unknown-host"} {
		t.Run(mode, func(t *testing.T) {
			f := newManagedUserDeleteFixture()
			h, document := f.router(t)
			r := f.request()
			want := 400
			switch mode {
			case "query":
				r.URL.RawQuery = "access_token=forbidden"
				r.RequestURI = r.URL.RequestURI()
			case "empty-query":
				r.URL.ForceQuery = true
				r.RequestURI = r.URL.RequestURI()
			case "body", "unknown-length-body":
				r.Body = io.NopCloser(strings.NewReader("{}"))
				r.ContentLength = 2
				if mode == "unknown-length-body" {
					r.ContentLength = -1
					r.TransferEncoding = []string{"chunked"}
				}
			case "trailer":
				r.Trailer = http.Header{"If-Match": []string{managedUserDeleteETag}}
			case "encoding":
				r.Header.Set("Content-Encoding", "identity")
				want = 415
			case "key", "empty-key":
				value := "forbidden"
				if mode == "empty-key" {
					value = ""
				}
				r.Header.Set("Idempotency-Key", value)
			case "cookie-key":
				r.AddCookie(&http.Cookie{Name: "Idempotency-Key", Value: "forbidden"})
			case "duplicate-bearer":
				r.Header.Add("Authorization", "Bearer "+syntheticBearer)
			case "cookie-only":
				r.Header.Del("Authorization")
				r.AddCookie(&http.Cookie{Name: "session", Value: syntheticBearer})
				want = 401
			case "proxy-bearer":
				r.Header.Set("Proxy-Authorization", "Bearer "+syntheticBearer)
				want = 401
			case "duplicate-if-match":
				r.Header.Add("If-Match", managedUserDeleteETag)
			case "aliased-if-match":
				r.Header["if-match"] = []string{managedUserDeleteETag}
			case "if-none-match":
				r.Header.Set("If-None-Match", managedUserDeleteETag)
			case "range":
				r.Header.Set("Range", "bytes=0-1")
			case "cleartext":
				r.TLS, r.URL.Scheme = nil, "http"
				want = 403
			case "public-host":
				r.Host, r.URL.Host = "login.example", "login.example"
				want = 403
			case "unknown-host":
				r.Host, r.URL.Host = "unknown.example", "unknown.example"
				want = 421
			}
			w := managedServe(h, r)
			if w.Code != want || f.executor.calls != 0 || f.base.backend.calls != 0 || w.Header().Get("ETag") != "" || w.Header().Get("Location") != "" || strings.Contains(w.Body.String(), syntheticBearer) {
				t.Fatalf("Delete alternate channel %s reached native/quota: status %d want %d", mode, w.Code, want)
			}
			validateManagedUsersDeleteWireResponse(t, document, strconv.Itoa(w.Code), w.Header().Get("Content-Type"), w.Body.Bytes())
		})
	}
}

func TestManagedUsersDeletePreservesNativePreconditionDenialsWithoutLocalVersionParser(t *testing.T) {
	for _, candidate := range []struct {
		version string
		status  int
	}{{"", 428}, {`W/"weak"`, 400}, {"*", 400}, {`"one", "two"`, 400}, {`"stale-native-version"`, 412}} {
		t.Run(strconv.Itoa(candidate.status)+candidate.version, func(t *testing.T) {
			f := newManagedUserDeleteFixture()
			charges := 0
			if candidate.status == 412 {
				// Live comparison is native write-time work, after admission;
				// malformed/missing preconditions fail native preflight earlier.
				f.executor.afterAdmissionError = scim.NewError(412, "")
				charges = 1
			} else {
				f.executor.err = scim.NewError(candidate.status, "")
			}
			h, document := f.router(t)
			r := f.request()
			if candidate.version == "" {
				r.Header.Del("If-Match")
			} else {
				r.Header.Set("If-Match", candidate.version)
			}
			w := managedServe(h, r)
			assertProtocolError(t, w, candidate.status)
			if f.executor.calls != 1 || f.executor.request.IfMatch != scim.Version(candidate.version) || f.base.backend.calls != charges || w.Header().Get("ETag") != "" || w.Header().Get("Location") != "" {
				t.Fatal("transport changed native If-Match custody, denial or admission ordering")
			}
			validateManagedUsersDeleteWireResponse(t, document, strconv.Itoa(w.Code), w.Header().Get("Content-Type"), w.Body.Bytes())
		})
	}
}

func TestManagedUsersDeleteRequiresNativeAuthorityOneGateAndExactEmptyOutcome(t *testing.T) {
	for _, mode := range []string{"auth", "policy", "wrong-tenant", "limited", "unavailable", "skip", "double", "ignore", "late-error", "error", "status200", "status201", "body", "media", "etag", "location"} {
		t.Run(mode, func(t *testing.T) {
			f := newManagedUserDeleteFixture()
			want, charges := 503, 1
			switch mode {
			case "auth":
				f.executor.err = scim.NewError(401, "")
				want, charges = 401, 0
			case "policy":
				f.executor.err = scim.NewError(403, "")
				want, charges = 403, 0
			case "wrong-tenant":
				f.executor.client.TenantID = "other-tenant"
				want, charges = 403, 0
			case "limited":
				f.base.backend.limited = true
				want = 429
			case "unavailable":
				f.base.backend.unavailable = true
			case "skip":
				f.executor.mode, charges = mode, 0
			case "double", "late-error":
				f.executor.mode = mode
			case "ignore":
				f.executor.mode = mode
				f.base.backend.limited = true
			case "error":
				f.executor.err, charges = errors.New("private native failure"), 0
			case "status200":
				f.executor.response.Status = 200
			case "status201":
				f.executor.response.Status = 201
			case "body":
				f.executor.response.Body = []byte(`{"private":"partial"}`)
			case "media":
				f.executor.response.ContentType = "application/scim+json"
			case "etag":
				f.executor.response.ETag = managedUserDeleteETag
			case "location":
				f.executor.response.Location = "https://directory.example" + managedUserDeletePath
			}
			h, document := f.router(t)
			w := managedServe(h, f.request())
			assertProtocolError(t, w, want)
			if f.base.backend.calls != charges || w.Header().Get("ETag") != "" || w.Header().Get("Location") != "" || w.Header().Get("Set-Cookie") != "" || strings.Contains(w.Body.String(), "private") || strings.Contains(w.Body.String(), "source-user") {
				t.Fatalf("Delete owner/admission failure %s disclosed partial data or changed quota", mode)
			}
			if mode == "limited" && w.Header().Get("Retry-After") != "3" || mode == "auth" && w.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Fatal("Delete changed retry/challenge metadata")
			}
			validateManagedUsersDeleteWireResponse(t, document, strconv.Itoa(w.Code), w.Header().Get("Content-Type"), w.Body.Bytes())
		})
	}
}

func TestManagedUsersDeleteOriginalCancellationAndOwnerPanicWithholdSuccess(t *testing.T) {
	for _, mode := range []string{"before", "after", "panic"} {
		t.Run(mode, func(t *testing.T) {
			f := newManagedUserDeleteFixture()
			r := f.request()
			ctx, cancel := context.WithCancel(r.Context())
			defer cancel()
			r = r.WithContext(ctx)
			charges := 0
			switch mode {
			case "before":
				f.executor.before = cancel
			case "after":
				f.executor.after, charges = cancel, 1
			case "panic":
				f.executor.before = func() { panic("private native failure") }
			}
			h, _ := f.router(t)
			w := managedServe(h, r)
			assertProtocolError(t, w, 503)
			if f.base.backend.calls != charges || strings.Contains(w.Body.String(), "private") || w.Header().Get("ETag") != "" {
				t.Fatal("Delete cancellation/panic disclosed output or continued admission")
			}
		})
	}
}

func TestManagedUsersDeleteIsOptInWithCanonicalResourceProvenanceAndMethods(t *testing.T) {
	f := newManagedUserDeleteFixture()
	feature, err := scimhttp.NewManagedUsersDeleteFeature(f.config)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{})
	if err != nil {
		t.Fatal(err)
	}
	if managedServe(empty, f.request()).Code != 404 || managedServe(feature.Operations()[0].Handler, f.request()).Code != 404 || f.executor.calls != 0 {
		t.Fatal("unselected or router-less Delete reached native authority")
	}
	h, document := f.router(t)
	for _, path := range []string{"/scim/v2/Users", managedUserDeletePath + "/", managedUserDeletePath + "/extra", "/scim/v2/Users/.search", "/scim/v2/Users/..", "/scim/v2/users/source-user", "/scim/v2/Users/%73ource-user", "/scim/v2/Users/a%2Fb"} {
		r := protocolRequest(http.MethodDelete, path, "")
		r.SetPathValue("resource_id", "source-user")
		if w := managedServe(h, r); w.Code != 404 || f.executor.calls != 0 {
			t.Fatalf("Delete noncanonical alias reached native: %d", w.Code)
		}
	}
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodOptions} {
		r := f.request()
		r.Method = method
		w := managedServe(h, r)
		if w.Code != 405 || w.Header().Get("Allow") != "DELETE" || f.executor.calls != 0 {
			t.Fatalf("Delete exposed implicit method %s: %d", method, w.Code)
		}
		if method != http.MethodHead {
			validateManagedUsersDeleteWireResponse(t, document, "405", w.Header().Get("Content-Type"), w.Body.Bytes())
		}
	}
	r := f.request()
	r.SetPathValue("resource_id", "forged")
	if managedServe(h, r).Code != 204 || f.executor.request.ResourceID != "source-user" || r.PathValue("resource_id") != "forged" {
		t.Fatal("Delete lost router path provenance or mutated caller path values")
	}
}

func TestManagedUsersDeleteRejectsInvalidConfigWithoutOwnerIO(t *testing.T) {
	for _, mode := range []string{"zero", "nil-owner", "typed-nil-owner", "network", "limits", "duration", "rate"} {
		t.Run(mode, func(t *testing.T) {
			f := newManagedUserDeleteFixture()
			switch mode {
			case "zero":
				f.config = scimhttp.ManagedUsersDeleteConfig{}
			case "nil-owner":
				f.config.Executor = nil
			case "typed-nil-owner":
				f.config.Executor = (*managedUsersDeleteExecutor)(nil)
			case "network":
				f.config.Network = identityhttp.NetworkConfig{}
			case "limits":
				f.config.Limits = scim.Limits{}
			case "duration":
				f.config.MaximumDuration = 31 * time.Second
			case "rate":
				f.config.Rate = scimhttp.ProtocolRateConfig{}
			}
			if _, err := scimhttp.NewManagedUsersDeleteFeature(f.config); !errors.Is(err, identityhttp.ErrInvalidInput) || f.executor.calls != 0 || f.base.backend.calls != 0 {
				t.Fatal("invalid Delete config accepted or owner invoked")
			}
		})
	}
	f := newManagedUserDeleteFixture()
	if strings.Contains(fmt.Sprintf("%#v", f.config), "synthetic") {
		t.Fatal("Delete config formatting revealed borrowed custody")
	}
	if _, err := json.Marshal(f.config); err == nil {
		t.Fatal("Delete config implicitly exported runtime owners")
	}
}

func TestManagedUsersDeleteComposesWithGetAndCollectionWithoutChangingSharedQuota(t *testing.T) {
	f := newManagedUserDeleteFixture()
	remove, err := scimhttp.NewManagedUsersDeleteFeature(f.config)
	if err != nil {
		t.Fatal(err)
	}
	getFixture := newManagedUserGetFixture()
	getFixture.config.Rate = f.config.Rate
	get, err := scimhttp.NewManagedUsersGetFeature(getFixture.config)
	if err != nil {
		t.Fatal(err)
	}
	createFixture := newManagedUserCreateFixture()
	createFixture.config.Rate = f.config.Rate
	create, err := scimhttp.NewManagedUsersCreateFeature(createFixture.config)
	if err != nil {
		t.Fatal(err)
	}
	operations := append(remove.Operations(), get.Operations()...)
	operations = append(operations, create.Operations()...)
	combined, err := identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "scim", Operations: operations})
	if err != nil {
		t.Fatal(err)
	}
	descriptors, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{combined}})
	if err != nil {
		t.Fatal(err)
	}
	h, document := protocolRouter(t, f.config.Network, descriptors)
	if managedServe(h, f.request()).Code != 204 || managedServe(h, getFixture.request("")).Code != 200 || managedServe(h, createFixture.request(managedUserCreateInput)).Code != 201 || len(document.Operations()) != 3 || f.base.backend.calls != 3 {
		t.Fatal("conditional Delete changed neighboring routes or their shared admission")
	}
	r := f.request()
	r.Method = http.MethodPatch
	if w := managedServe(h, r); w.Code != 405 || w.Header().Get("Allow") != "DELETE, GET" {
		t.Fatal("combined resource Allow changed with selected Delete")
	}
}

func validateManagedUsersDeleteWireResponse(t *testing.T, document identityhttp.OpenAPIDocument, status, media string, body []byte) {
	t.Helper()
	var wire struct {
		Paths map[string]struct {
			Delete struct {
				Responses map[string]struct {
					Content map[string]struct {
						Schema json.RawMessage `json:"schema"`
					} `json:"content"`
				} `json:"responses"`
			} `json:"delete"`
		} `json:"paths"`
	}
	if json.Unmarshal(document.JSON(), &wire) != nil {
		t.Fatal("Delete OpenAPI is not JSON")
	}
	definition := wire.Paths["/scim/v2/Users/{resource_id}"].Delete.Responses[status].Content[media].Schema
	if len(definition) == 0 {
		t.Fatalf("Delete OpenAPI omitted actual %s %s envelope", status, media)
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
		t.Fatalf("Delete OpenAPI %s %s rejected actual transport envelope: %v", status, media, err)
	}
}

func FuzzManagedUsersDeleteIfMatchCustody(f *testing.F) {
	for _, value := range []string{managedUserDeleteETag, "", `W/"weak"`, "*", `"one","two"`, "bad\r\nheader", string([]byte{0xff})} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		fixture := newManagedUserDeleteFixture()
		feature, err := scimhttp.NewManagedUsersDeleteFeature(fixture.config)
		if err != nil {
			t.Fatal(err)
		}
		h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
		if err != nil {
			t.Fatal(err)
		}
		r := fixture.request()
		r.Header.Set("If-Match", value)
		w := managedServe(h, r)
		if w.Code != 204 && w.Code != 400 || fixture.executor.calls > 1 || fixture.executor.calls == 1 && fixture.executor.request.IfMatch != scim.Version(value) || strings.Contains(w.Body.String(), syntheticBearer) {
			t.Fatalf("Delete If-Match lost bounded exact custody: status %d", w.Code)
		}
	})
}
