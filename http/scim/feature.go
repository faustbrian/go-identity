// Package scimhttp selects SCIM Bulk and its matching discovery over the
// existing identity HTTPS router and a caller-supplied native executor.
package scimhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	identityhttp "github.com/faustbrian/go-identity/http"
	scim "github.com/faustbrian/go-scim"
)

const (
	bulkOperation      = "identity.scim.bulk"
	discoveryOperation = "identity.scim.service-provider-config"
	scimMedia          = "application/scim+json"
)

// BulkExecutor owns the authenticated SCIM connection, request parsing,
// persistence, response preflight and replay. It supplies both routes from one
// effective policy and calls the borrowed admission exactly once after current
// authentication and authorization and before work or disclosure. Inputs and
// admission are borrowed synchronously and must not be retained. The executor
// must be safe for concurrent requests and honor their context bounds.
type BulkExecutor interface {
	BulkPolicies() (scim.BulkPolicy, scim.BulkResponsePolicy)
	ExecuteBulkProtocol(context.Context, scim.BulkRequest, scim.ProtocolAdmission) ([]byte, error)
	ReadBulkServiceProviderConfig(context.Context, authentication.BearerCredential, scim.ProtocolAdmission) (scim.Response, error)
}

// BulkFeatureConfig binds a native executor and a shared atomic protocol rate
// store to exact HTTPS tenant hosts. The owner must outlive the feature; the
// feature does not manage pool, backend or server lifecycle.
type BulkFeatureConfig struct {
	Network         identityhttp.NetworkConfig
	Executor        BulkExecutor
	Rate            ProtocolRateConfig
	MaximumDuration time.Duration
}

// Format redacts borrowed dependencies and rate-key custody.
func (BulkFeatureConfig) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, "scimhttp.BulkFeatureConfig(redacted)")
}

// MarshalJSON prevents implicit export of the feature configuration.
func (BulkFeatureConfig) MarshalJSON() ([]byte, error) { return nil, identityhttp.ErrInvalidInput }

type bulkHTTP struct {
	network      *identityhttp.NetworkResolver
	decoder      *identityhttp.RequestDecoder
	executor     BulkExecutor
	rate         *protocolRate
	request      scim.BulkPolicy
	response     scim.BulkResponsePolicy
	maximumDelay time.Duration
}

// NewBulkFeature explicitly selects POST /scim/v2/Bulk and GET
// /scim/v2/ServiceProviderConfig, with matching OpenAPI. It does not select
// CRUD, add an authenticator, or configure proxy trust on the outer router.
// Install the two operations with the same Network policy and server
// deadlines. Trusted middleware that needs a separate authentication phase
// cannot be bound to these native-owned handlers.
func NewBulkFeature(c BulkFeatureConfig) (feature identityhttp.Feature, err error) {
	defer func() {
		if recover() != nil {
			feature, err = identityhttp.Feature{}, identityhttp.ErrInvalidInput
		}
	}()
	if c.Executor == nil || len(c.Network.TenantHosts) == 0 ||
		c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	request, response := c.Executor.BulkPolicies()
	if request.MaxOperations < 1 || request.MaxOperations > 1000 ||
		request.MaxPayloadBytes < 16384 || request.MaxPayloadBytes > 2<<20 ||
		request.MaxOperationBytes < 1024 || request.MaxOperationBytes > 1<<20 || request.MaxOperationBytes > request.MaxPayloadBytes ||
		response.MaxBytes < 16384 || response.MaxBytes > 4<<20 ||
		response.ErrorDetailBytes < 0 || response.ErrorDetailBytes > scim.DefaultLimits().ErrorDetailBytes {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	network, decoder, err := identityhttp.NewSCIMRequestBoundary(c.Network)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	rate, err := newProtocolRate(c.Rate)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	h := bulkHTTP{network: network, decoder: decoder, executor: c.Executor, rate: rate,
		request: request, response: response, maximumDelay: c.MaximumDuration}
	ops := make([]identityhttp.OperationDescriptor, 0, 2)
	for _, id := range []string{bulkOperation, discoveryOperation} {
		op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{
			Owner: "scim", OperationID: id, Handler: h.handler(id),
			CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}, MaximumSerializedBytes: 4 << 20,
		})
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op.Wire = scimOperationWire(id, request)
		ops = append(ops, op)
	}
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "scim", Operations: ops})
}

func (h *bulkHTTP) handler(operation string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), h.maximumDelay)
		defer cancel()
		result, denial := h.execute(r.WithContext(ctx), operation)
		if ctx.Err() != nil {
			result, denial = nil, scim.NewError(503, "")
		}
		writeProtocolResponse(w, result, denial)
	})
}

func (h *bulkHTTP) execute(r *http.Request, operation string) (result []byte, denial *scim.Error) {
	defer func() {
		if recover() != nil {
			result, denial = nil, scim.NewError(503, "")
		}
	}()
	facts, err := h.network.Resolve(r)
	if err != nil {
		if errors.Is(err, identityhttp.ErrUnavailable) {
			return nil, scim.NewError(503, "")
		}
		return nil, scim.NewError(400, "invalidValue")
	}
	if facts.Scheme() != "https" || facts.Realm() != identityhttp.RealmTenant {
		return nil, scim.NewError(403, "")
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		return nil, scim.NewError(400, "invalidValue")
	}
	if _, present := protocolHeader(r, "If-Match"); present {
		return nil, scim.NewError(400, "invalidValue")
	}
	credential, _, err := h.decoder.Bearer(r, identityhttp.HeaderRequired)
	if err != nil {
		return nil, scim.NewError(401, "")
	}
	keyRule := identityhttp.HeaderForbidden
	if operation == bulkOperation {
		keyRule = identityhttp.HeaderOptional
	}
	key, hasKey, err := h.decoder.IdempotencyKey(r, keyRule)
	if err != nil {
		return nil, scim.NewError(400, "invalidValue")
	}
	calls, allowed := 0, false
	admit := func(ctx context.Context, client scim.ProtocolClient) *scim.Error {
		calls++
		if calls != 1 {
			return scim.NewError(503, "")
		}
		if client.TenantID != facts.TenantID() {
			return scim.NewError(403, "")
		}
		out := h.rate.admit(ctx, client, facts.ClientIP())
		allowed = out == nil
		return out
	}

	maximum := h.response.MaxBytes
	if operation == bulkOperation {
		body, bodyError := readBulkBody(r, h.request.MaxPayloadBytes)
		if bodyError != nil {
			return nil, bodyError
		}
		defer clear(body)
		request := scim.BulkRequest{Credential: credential, Body: body}
		if hasKey {
			request.IdempotencyKey = &key
		}
		result, err = h.executor.ExecuteBulkProtocol(r.Context(), request, admit)
	} else {
		if r.ContentLength != 0 || r.Body != nil && r.Body != http.NoBody {
			return nil, scim.NewError(400, "invalidValue")
		}
		if _, present := protocolHeader(r, "Content-Encoding"); present {
			return nil, scim.NewError(415, "")
		}
		var response scim.Response
		response, err = h.executor.ReadBulkServiceProviderConfig(r.Context(), credential, admit)
		if err == nil && (response.Status != 200 || response.ContentType != scimMedia) {
			return nil, scim.NewError(503, "")
		}
		result, maximum = response.Body, 4<<20
	}
	if err != nil {
		var protocol *scim.Error
		if errors.As(err, &protocol) && protocol != nil {
			return nil, protocol
		}
		return nil, scim.NewError(503, "")
	}
	if calls != 1 || !allowed || len(result) == 0 || len(result) > maximum {
		return nil, scim.NewError(503, "")
	}
	return result, nil
}

func readBulkBody(r *http.Request, maximum int) ([]byte, *scim.Error) {
	if r.Body == nil || r.Body == http.NoBody || r.ContentLength == 0 {
		return nil, scim.NewError(400, "invalidSyntax")
	}
	if encoding, present := protocolHeader(r, "Content-Encoding"); present && !strings.EqualFold(encoding, "identity") {
		return nil, scim.NewError(415, "")
	}
	contentType, _ := protocolHeader(r, "Content-Type")
	media, parameters, err := mime.ParseMediaType(contentType)
	if err != nil || media != scimMedia {
		return nil, scim.NewError(415, "")
	}
	for key, value := range parameters {
		if key != "charset" || !strings.EqualFold(value, "utf-8") {
			return nil, scim.NewError(415, "")
		}
	}
	if r.ContentLength > int64(maximum) {
		return nil, scim.NewError(413, "")
	}
	reader := &protocolBodyReader{ctx: r.Context(), body: r.Body}
	body, err := io.ReadAll(io.LimitReader(reader, int64(maximum)+1))
	if err != nil {
		clear(body)
		return nil, scim.NewError(400, "invalidSyntax")
	}
	if len(body) > maximum {
		clear(body)
		return nil, scim.NewError(413, "")
	}
	if len(body) == 0 || r.ContentLength >= 0 && int64(len(body)) != r.ContentLength {
		clear(body)
		return nil, scim.NewError(400, "invalidSyntax")
	}
	return body, nil
}

type protocolBodyReader struct {
	ctx        context.Context
	body       io.Reader
	noProgress int
}

func (r *protocolBodyReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := r.body.Read(p)
	if n == 0 && err == nil {
		r.noProgress++
		if r.noProgress == 100 {
			return 0, io.ErrNoProgress
		}
	} else {
		r.noProgress = 0
	}
	return n, err
}

// The network boundary already rejected duplicated or case-aliased sensitive
// headers. Read their exact values, including explicit empty presence.
func protocolHeader(r *http.Request, name string) (string, bool) {
	for key, values := range r.Header {
		if strings.EqualFold(key, name) && len(values) == 1 {
			return values[0], true
		}
	}
	return "", false
}

func writeProtocolResponse(w http.ResponseWriter, result []byte, denial *scim.Error) {
	w.Header().Set("Content-Type", scimMedia)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if denial == nil {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(result)
		return
	}
	if denial.StatusCode() == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	if seconds := denial.RetryAfterSeconds(); seconds != 0 && denial.StatusCode() == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", strconv.FormatUint(uint64(seconds), 10))
	}
	encoded, err := json.Marshal(denial)
	if err != nil {
		denial = scim.NewError(503, "")
		encoded, _ = json.Marshal(denial)
	}
	w.WriteHeader(denial.StatusCode())
	_, _ = w.Write(encoded)
}
