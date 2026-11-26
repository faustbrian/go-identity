package scimhttp_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	scimhttp "github.com/faustbrian/go-identity/http/scim"
	ratelimit "github.com/faustbrian/go-rate-limit/v2"
	scim "github.com/faustbrian/go-scim"
)

const (
	bulkPath           = "/scim/v2/Bulk"
	providerConfigPath = "/scim/v2/ServiceProviderConfig"
	syntheticBearer    = "synthetic-scim-bearer"
	bulkRequestBody    = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],"Operations":[{"method":"POST","path":"/Users","bulkId":"synthetic-user","data":{"userName":"synthetic-user"}}]}`
	bulkResponseBody   = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkResponse"],"Operations":[]}`
	providerConfigBody = `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],"bulk":{"supported":true,"maxOperations":1000,"maxPayloadSize":1048576}}`
)

// This seam proves transport composition, not native command execution or SQL
// atomicity. The executor supplies its authenticated native client before the
// real feature may debit the strict shared backend and return a success.
type protocolExecutor struct {
	policy                            scim.BulkPolicy
	client                            scim.ProtocolClient
	bulkCalls, configCalls, successes int
	request                           scim.BulkRequest
	configCredential                  authentication.BearerCredential
}

func (e *protocolExecutor) BulkPolicies() (scim.BulkPolicy, scim.BulkResponsePolicy) {
	return e.policy, scim.DefaultBulkResponsePolicy()
}

func (e *protocolExecutor) ExecuteBulkProtocol(ctx context.Context, request scim.BulkRequest, admit scim.ProtocolAdmission) ([]byte, error) {
	e.bulkCalls++
	e.request = scim.BulkRequest{Credential: request.Credential, Body: append([]byte(nil), request.Body...)}
	if request.IdempotencyKey != nil {
		key := *request.IdempotencyKey
		e.request.IdempotencyKey = &key
	}
	if err := admit(ctx, e.client); err != nil {
		return nil, err
	}
	e.successes++
	return []byte(bulkResponseBody), nil
}

func (e *protocolExecutor) ReadBulkServiceProviderConfig(ctx context.Context, credential authentication.BearerCredential, admit scim.ProtocolAdmission) (scim.Response, error) {
	e.configCalls++
	e.configCredential = credential
	if err := admit(ctx, e.client); err != nil {
		return scim.Response{}, err
	}
	e.successes++
	return scim.Response{Status: http.StatusOK, ContentType: "application/scim+json", Body: []byte(providerConfigBody)}, nil
}

type strictProtocolBackend struct {
	ratelimit.StrictBackend
	calls       int
	last        ratelimit.AtomicBatchRequest
	limited     bool
	unavailable bool
}

func (*strictProtocolBackend) Name() string { return "synthetic-scim-rate" }

func (b *strictProtocolBackend) AdmitAtomicStrict(ctx context.Context, request ratelimit.AtomicBatchRequest) (ratelimit.AtomicBatchDecision, error) {
	if _, bounded := ctx.Deadline(); !bounded {
		panic("unbounded protocol admission")
	}
	b.calls++
	b.last = request
	b.last.Requests = append([]ratelimit.Request(nil), request.Requests...)
	if b.unavailable {
		return ratelimit.AtomicBatchDecision{}, ratelimit.ErrUnavailable
	}
	decision := ratelimit.AtomicBatchDecision{CommandID: request.CommandID, Allowed: !b.limited, Decisions: make([]ratelimit.Decision, len(request.Requests))}
	for i, bucket := range request.Requests {
		decision.Decisions[i] = ratelimit.Decision{
			Allowed: !b.limited, Remaining: bucket.Policy.Limit() - bucket.Cost,
			Limit: bucket.Policy.Limit(), Reset: bucket.Now.Add(bucket.Policy.Period()), Reason: ratelimit.ReasonAllowed,
		}
		if b.limited {
			decision.Decisions[i].Remaining = 0
			decision.Decisions[i].Reason = ratelimit.ReasonLimited
			decision.Decisions[i].RetryAfter = 2500 * time.Millisecond
		}
	}
	if b.limited {
		return decision, ratelimit.ErrRejected
	}
	return decision, nil
}

type protocolFixture struct {
	executor *protocolExecutor
	backend  *strictProtocolBackend
	config   scimhttp.BulkFeatureConfig
}

func newProtocolFixture() protocolFixture {
	executor := &protocolExecutor{policy: scim.DefaultBulkPolicy(), client: scim.ProtocolClient{ID: "synthetic-client", TenantID: "synthetic-tenant"}}
	backend := &strictProtocolBackend{}
	network := identityhttp.NetworkConfig{
		Limits:               identityhttp.Limits{MaximumHeaderBytes: 4096, MaximumURLBytes: 1024, MaximumBodyBytes: 1024, MaximumDecodedBytes: 1024, MaximumFields: 32, MaximumDepth: 8},
		MaximumForwardedHops: 8,
		TenantHosts:          []identityhttp.TenantHost{{Host: "directory.example", TenantID: "synthetic-tenant"}, {Host: "other.example", TenantID: "other-tenant"}},
		PublicHosts:          []string{"login.example"},
	}
	return protocolFixture{executor: executor, backend: backend, config: scimhttp.BulkFeatureConfig{
		Network: network, Executor: executor, MaximumDuration: time.Second,
		Rate: scimhttp.ProtocolRateConfig{Shared: backend, Namespace: "synthetic-scim", Key: [32]byte{1}, Now: func() time.Time { return time.Unix(1800000000, 0) }, MaximumDuration: time.Second},
	}}
}

func (f protocolFixture) router(t *testing.T) (http.Handler, identityhttp.OpenAPIDocument) {
	t.Helper()
	feature, err := scimhttp.NewBulkFeature(f.config)
	if err != nil {
		t.Fatal(err)
	}
	operations, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	return protocolRouter(t, f.config.Network, operations)
}

func protocolRouter(t *testing.T, network identityhttp.NetworkConfig, operations []identityhttp.OperationDescriptor) (http.Handler, identityhttp.OpenAPIDocument) {
	t.Helper()
	handler, document, err := identityhttp.NewRouter(identityhttp.TransportPolicy{
		Network: network, HandlerTimeout: time.Second, Document: identityhttp.DocumentConfig{Title: "Synthetic identity", Version: "1"},
	}, operations, nil)
	if err != nil {
		t.Fatal(err)
	}
	return handler, document
}

func protocolRequest(method, path, body string) *http.Request {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	request := httptest.NewRequest(method, "https://directory.example"+path, reader)
	request.RequestURI = request.URL.RequestURI()
	request.RemoteAddr = "198.51.100.7:1234"
	request.Header.Set("Authorization", "Bearer "+syntheticBearer)
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/scim+json")
	}
	return request
}

func serveProtocol(handler http.Handler, request *http.Request) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func assertProtocolError(t *testing.T, response *httptest.ResponseRecorder, status int) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, status, response.Body.String())
	}
	if response.Header().Get("Content-Type") != "application/scim+json" {
		t.Fatalf("protocol error media = %q", response.Header().Get("Content-Type"))
	}
	var body struct {
		Schemas []string `json:"schemas"`
		Status  string   `json:"status"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || len(body.Schemas) != 1 || body.Schemas[0] != "urn:ietf:params:scim:api:messages:2.0:Error" || body.Status != strconv.Itoa(status) {
		t.Fatalf("not an RFC 7644 error: %s", response.Body.String())
	}
	if strings.Contains(response.Body.String(), syntheticBearer) || strings.Contains(response.Body.String(), `"Operations"`) || strings.Contains(response.Body.String(), `"supported":true`) {
		t.Fatal("failure disclosed credential or successful executor output")
	}
}

func TestBulkFeatureSelectedRouterExecutesProtocolAndPreservesOriginalInputs(t *testing.T) {
	f := newProtocolFixture()
	handler, document := f.router(t)
	if f.executor.bulkCalls != 0 || f.executor.configCalls != 0 || f.backend.calls != 0 {
		t.Fatal("construction performed executor or rate IO")
	}
	operations := document.Operations()
	if len(operations) != 2 || operations[0].Record.OperationID != "identity.scim.bulk" || operations[0].Route.Method != "POST" || operations[0].Route.Path != bulkPath || operations[1].Record.OperationID != "identity.scim.service-provider-config" || operations[1].Route.Method != "GET" || operations[1].Route.Path != providerConfigPath {
		t.Fatal("selected protocol operation inventory differs from execution")
	}
	for _, key := range []string{"", "synthetic-original-key"} {
		request := protocolRequest(http.MethodPost, bulkPath, bulkRequestBody)
		request.Header.Set("Content-Type", "application/scim+json; charset=utf-8")
		if key != "" {
			request.Header.Set("Idempotency-Key", key)
		}
		response := serveProtocol(handler, request)
		if response.Code != http.StatusOK || response.Body.String() != bulkResponseBody || response.Header().Get("Content-Type") != "application/scim+json" || len(response.Result().Cookies()) != 0 {
			t.Fatalf("selected Bulk did not return native protocol output: %d %s", response.Code, response.Body.String())
		}
		if string(f.executor.request.Body) != bulkRequestBody || f.executor.request.Credential.Token() != syntheticBearer {
			t.Fatal("transport changed original Bulk input or bearer")
		}
		if key == "" {
			if f.executor.request.IdempotencyKey != nil {
				t.Fatal("transport manufactured an absent optional key")
			}
		} else {
			original, err := identity.NewIdempotencyKey([]byte(key))
			if err != nil || f.executor.request.IdempotencyKey == nil {
				t.Fatal("transport lost original optional key")
			}
			want, _ := original.Digest([32]byte{2})
			got, err := f.executor.request.IdempotencyKey.Digest([32]byte{2})
			if err != nil || got != want {
				t.Fatal("transport replaced supplied key bytes")
			}
		}
	}
	response := serveProtocol(handler, protocolRequest(http.MethodGet, providerConfigPath, ""))
	if response.Code != http.StatusOK || response.Body.String() != providerConfigBody || response.Header().Get("Content-Type") != "application/scim+json" || f.executor.configCredential.Token() != syntheticBearer {
		t.Fatal("selected discovery did not use native bearer execution")
	}
	if f.executor.bulkCalls != 2 || f.executor.configCalls != 1 || f.executor.successes != 3 || f.backend.calls != 3 || len(f.backend.last.Requests) != 3 {
		t.Fatal("successful protocol attempts bypassed atomic admission")
	}
}

func TestBulkFeatureDisabledSelectionAndOrdinaryEnvelopeRemainUntouched(t *testing.T) {
	f := newProtocolFixture()
	disabled, document := protocolRouter(t, f.config.Network, nil)
	if len(document.Operations()) != 0 {
		t.Fatal("disabled feature advertised operations")
	}
	for _, request := range []*http.Request{protocolRequest(http.MethodPost, bulkPath, bulkRequestBody), protocolRequest(http.MethodGet, providerConfigPath, "")} {
		if response := serveProtocol(disabled, request); response.Code != http.StatusNotFound {
			t.Fatalf("disabled selection status = %d", response.Code)
		}
	}
	handler, _ := f.router(t)
	for _, path := range []string{"/scim/v2/Users", "/scim/v2/Groups", "/v1/scim/connection-get"} {
		if response := serveProtocol(handler, protocolRequest(http.MethodGet, path, "")); response.Code != http.StatusNotFound {
			t.Fatalf("unselected route %s status = %d", path, response.Code)
		}
	}
	for _, target := range []http.Handler{disabled, handler} {
		request := protocolRequest(http.MethodPost, "/ordinary", strings.Repeat("x", 1025))
		if response := serveProtocol(target, request); response.Code != http.StatusBadRequest {
			t.Fatalf("ordinary route lost 1 KiB envelope: %d", response.Code)
		}
		request = protocolRequest(http.MethodPost, "/ordinary", "{}")
		request.Header.Set("Content-Encoding", "gzip")
		if response := serveProtocol(target, request); response.Code != http.StatusBadRequest {
			t.Fatalf("ordinary route gained SCIM encoding exception: %d", response.Code)
		}
	}
	if f.executor.bulkCalls != 0 || f.executor.configCalls != 0 || f.backend.calls != 0 {
		t.Fatal("disabled, unselected or ordinary route reached the feature")
	}
}

func TestBulkFeatureRequiresHTTPSAndStrictBearerWithoutCookieFallback(t *testing.T) {
	for _, path := range []string{bulkPath, providerConfigPath} {
		method, body := http.MethodPost, bulkRequestBody
		if path == providerConfigPath {
			method, body = http.MethodGet, ""
		}
		for _, authorization := range []string{"", "Basic synthetic", "Bearer", "Bearer synthetic invalid"} {
			t.Run(path+"/"+authorization, func(t *testing.T) {
				f := newProtocolFixture()
				handler, _ := f.router(t)
				request := protocolRequest(method, path, body)
				request.Header.Del("Authorization")
				if authorization != "" {
					request.Header.Set("Authorization", authorization)
				}
				request.AddCookie(&http.Cookie{Name: "session", Value: "synthetic-session"})
				response := serveProtocol(handler, request)
				assertProtocolError(t, response, http.StatusUnauthorized)
				if f.executor.bulkCalls != 0 || f.executor.configCalls != 0 || f.backend.calls != 0 {
					t.Fatal("invalid bearer reached executor or rate backend")
				}
			})
		}
		f := newProtocolFixture()
		handler, _ := f.router(t)
		request := protocolRequest(method, path, body)
		request.TLS = nil
		request.URL.Scheme = "http"
		if response := serveProtocol(handler, request); response.Code != http.StatusForbidden || f.executor.bulkCalls != 0 || f.executor.configCalls != 0 || f.backend.calls != 0 {
			t.Fatal("insecure transport reached protocol execution")
		}
	}
}

func TestBulkFeatureRejectsInvalidRepresentationAndProtocolEnvelopeBeforeExecution(t *testing.T) {
	for _, test := range []struct {
		name    string
		request func() *http.Request
		status  int
	}{
		{"missing body", func() *http.Request { return protocolRequest(http.MethodPost, bulkPath, "") }, 400},
		{"ordinary JSON", func() *http.Request {
			r := protocolRequest(http.MethodPost, bulkPath, bulkRequestBody)
			r.Header.Set("Content-Type", "application/json")
			return r
		}, 415},
		{"wrong charset", func() *http.Request {
			r := protocolRequest(http.MethodPost, bulkPath, bulkRequestBody)
			r.Header.Set("Content-Type", "application/scim+json; charset=iso-8859-1")
			return r
		}, 415},
		{"encoded", func() *http.Request {
			r := protocolRequest(http.MethodPost, bulkPath, bulkRequestBody)
			r.Header.Set("Content-Encoding", "gzip")
			return r
		}, 415},
		{"Bulk query", func() *http.Request {
			return protocolRequest(http.MethodPost, bulkPath+"?access_token=synthetic-query", bulkRequestBody)
		}, 400},
		{"discovery query", func() *http.Request {
			return protocolRequest(http.MethodGet, providerConfigPath+"?tenant=synthetic-tenant", "")
		}, 400},
		{"discovery body", func() *http.Request { return protocolRequest(http.MethodGet, providerConfigPath, "{}") }, 400},
		{"discovery key", func() *http.Request {
			r := protocolRequest(http.MethodGet, providerConfigPath, "")
			r.Header.Set("Idempotency-Key", "synthetic-original-key")
			return r
		}, 400},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newProtocolFixture()
			handler, _ := f.router(t)
			assertProtocolError(t, serveProtocol(handler, test.request()), test.status)
			if f.executor.bulkCalls != 0 || f.executor.configCalls != 0 || f.backend.calls != 0 {
				t.Fatal("invalid input reached executor or debit")
			}
		})
	}
	for _, header := range []string{"Authorization", "Idempotency-Key"} {
		f := newProtocolFixture()
		handler, _ := f.router(t)
		request := protocolRequest(http.MethodPost, bulkPath, bulkRequestBody)
		request.Header[header] = []string{"synthetic-first", "synthetic-second"}
		if response := serveProtocol(handler, request); response.Code != http.StatusBadRequest || f.executor.bulkCalls != 0 || f.backend.calls != 0 {
			t.Fatal("duplicate sensitive header reached executor or debit")
		}
	}
}

func TestBulkFeatureBoundsDeclaredAndChunkedPayloadsInsideSelectedRouter(t *testing.T) {
	for _, custom := range []bool{false, true} {
		for _, chunked := range []bool{false, true} {
			t.Run("custom="+strconv.FormatBool(custom)+"/chunked="+strconv.FormatBool(chunked), func(t *testing.T) {
				f := newProtocolFixture()
				if custom {
					f.executor.policy.MaxPayloadBytes = 16 << 10
					f.executor.policy.MaxOperationBytes = 1024
				}
				handler, _ := f.router(t)
				for _, size := range []int{1025, f.executor.policy.MaxPayloadBytes, f.executor.policy.MaxPayloadBytes + 1} {
					body := strings.Repeat(" ", size-len(bulkRequestBody)) + bulkRequestBody
					request := protocolRequest(http.MethodPost, bulkPath, body)
					if chunked {
						request.ContentLength = -1
						request.TransferEncoding = []string{"chunked"}
					}
					beforeCalls, beforeDebits := f.executor.bulkCalls, f.backend.calls
					response := serveProtocol(handler, request)
					if size > f.executor.policy.MaxPayloadBytes {
						assertProtocolError(t, response, http.StatusRequestEntityTooLarge)
						if f.executor.bulkCalls != beforeCalls || f.backend.calls != beforeDebits {
							t.Fatal("oversized request reached executor or debit")
						}
					} else if response.Code != http.StatusOK || len(f.executor.request.Body) != size || f.backend.calls != beforeDebits+1 {
						t.Fatalf("selected SCIM body bound rejected admitted size %d: %d", size, response.Code)
					}
				}
			})
		}
	}
}

func TestBulkFeatureRejectsWrongHostTenantBeforeRateDebit(t *testing.T) {
	for _, path := range []string{bulkPath, providerConfigPath} {
		for _, host := range []string{"other.example", "login.example"} {
			f := newProtocolFixture()
			handler, _ := f.router(t)
			method, body := http.MethodPost, bulkRequestBody
			if path == providerConfigPath {
				method, body = http.MethodGet, ""
			}
			request := protocolRequest(method, path, body)
			request.Host, request.URL.Host = host, host
			assertProtocolError(t, serveProtocol(handler, request), http.StatusForbidden)
			if f.backend.calls != 0 || f.executor.successes != 0 {
				t.Fatal("foreign or public host debited authenticated client or returned success")
			}
		}
	}
}

func TestBulkFeatureRateRejectionAndOutageFailClosedWithoutSuccessBody(t *testing.T) {
	for _, path := range []string{bulkPath, providerConfigPath} {
		for _, limited := range []bool{true, false} {
			f := newProtocolFixture()
			f.backend.limited, f.backend.unavailable = limited, !limited
			handler, _ := f.router(t)
			method, body := http.MethodPost, bulkRequestBody
			if path == providerConfigPath {
				method, body = http.MethodGet, ""
			}
			response := serveProtocol(handler, protocolRequest(method, path, body))
			status, retry := http.StatusServiceUnavailable, ""
			if limited {
				status, retry = http.StatusTooManyRequests, "3"
			}
			assertProtocolError(t, response, status)
			if response.Header().Get("Retry-After") != retry || f.backend.calls != 1 || f.executor.successes != 0 {
				t.Fatal("rejected admission retried, lost retry hint or returned success")
			}
		}
	}
}

func TestBulkFeatureOpenAPIMatchesOptionalKeyBearerAndSCIMMedia(t *testing.T) {
	f := newProtocolFixture()
	_, document := f.router(t)
	var wire struct {
		Paths map[string]map[string]struct {
			Security   []map[string][]string `json:"security"`
			Parameters []struct {
				Name, In string
				Required bool
			} `json:"parameters"`
			RequestBody struct {
				Required bool
				Content  map[string]json.RawMessage
			} `json:"requestBody"`
			Responses map[string]struct{ Content map[string]json.RawMessage } `json:"responses"`
		} `json:"paths"`
		Components struct {
			SecuritySchemes map[string]struct{ Type, Scheme string } `json:"securitySchemes"`
		} `json:"components"`
	}
	if err := json.Unmarshal(document.JSON(), &wire); err != nil {
		t.Fatal(err)
	}
	if len(wire.Paths) != 2 {
		t.Fatal("wire advertises unselected protocol paths")
	}
	for path, method := range map[string]string{bulkPath: "post", providerConfigPath: "get"} {
		operation, exists := wire.Paths[path][method]
		if !exists || len(operation.Security) != 1 || len(operation.Security[0]) != 1 {
			t.Fatal("selected operation does not require exactly bearer security")
		}
		for name := range operation.Security[0] {
			if scheme := wire.Components.SecuritySchemes[name]; scheme.Type != "http" || scheme.Scheme != "bearer" {
				t.Fatal("wire authentication differs from strict bearer execution")
			}
		}
		optionalKey := false
		for _, parameter := range operation.Parameters {
			if strings.EqualFold(parameter.Name, "Idempotency-Key") {
				if path != bulkPath || parameter.In != "header" || parameter.Required {
					t.Fatal("wire requires an optional Bulk key or permits discovery key")
				}
				optionalKey = true
			}
		}
		if path == bulkPath && (!optionalKey || !operation.RequestBody.Required || len(operation.RequestBody.Content) != 1 || operation.RequestBody.Content["application/scim+json"] == nil) {
			t.Fatal("Bulk wire lost optional key or required SCIM request representation")
		}
		if path == providerConfigPath && len(operation.RequestBody.Content) != 0 {
			t.Fatal("discovery wire advertises a forbidden body")
		}
		for status, response := range operation.Responses {
			if len(response.Content) != 1 || response.Content["application/scim+json"] == nil {
				t.Fatalf("%s response %s does not use only SCIM media", path, status)
			}
		}
		if _, exists := operation.Responses["200"]; !exists {
			t.Fatal("wire omits successful native protocol result")
		}
	}
}
