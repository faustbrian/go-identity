package scimhttp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	scim "github.com/faustbrian/go-scim"
)

const managedUsersPatchOperation = "identity.scim.user-patch"

// ManagedUsersPatchExecutor owns issued-bearer authorization, native PatchOp
// and If-Match validation, atomic mutation, and canonical command replay. It
// invokes admission once synchronously after current authority and preflight,
// before command or write effects, with the configured client and tenant. It
// must honor ctx, support concurrent calls and retain no borrowed invocation.
type ManagedUsersPatchExecutor interface {
	ExecuteManagedAdmittedPatch(context.Context, identity.TenantID, scim.Request, scim.ProtocolAdmission) (scim.Response, error)
}

// ManagedUsersPatchConfig selects conditional managed User PATCH. Network and
// Limits match the deployed router and native SCIM profile. Rate borrows the
// shared atomic protocol backend, namespace and key. MaximumDuration is
// 1ms..30s and never extends an earlier deadline. Owners outlive requests.
type ManagedUsersPatchConfig struct {
	Network         identityhttp.NetworkConfig
	Executor        ManagedUsersPatchExecutor
	Rate            ProtocolRateConfig
	Limits          scim.Limits
	MaximumDuration time.Duration
}

// Format redacts borrowed credentials and runtime configuration.
func (ManagedUsersPatchConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("scimhttp.ManagedUsersPatchConfig(redacted)"))
}

// MarshalJSON refuses implicit runtime configuration export.
func (ManagedUsersPatchConfig) MarshalJSON() ([]byte, error) {
	return nil, identityhttp.ErrInvalidInput
}

// MarshalText refuses implicit runtime configuration export.
func (ManagedUsersPatchConfig) MarshalText() ([]byte, error) {
	return nil, identityhttp.ErrInvalidInput
}

// NewManagedUsersPatchFeature selects only PATCH /scim/v2/Users/{resource_id}.
// The router supplies the canonical target. This handler borrows exactly one
// bearer, the original If-Match value and bounded raw PatchOp; it accepts no
// query, trailer, client request key or cookie authority. It returns the
// native 200 User, ETag and Location only after one allowed quota admission.
// Native preconditions and recovery are authoritative and no automatic retry
// or response cache is installed. Construction performs no owner I/O.
func NewManagedUsersPatchFeature(c ManagedUsersPatchConfig) (identityhttp.Feature, error) {
	if missingManagedOwner(c.Executor) {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	return newManagedUsersConditionalFeature(c.Network, c.Rate, c.Limits, c.MaximumDuration, http.MethodPatch,
		scim.UserPatch, managedUsersPatchOperation, c.Executor.ExecuteManagedAdmittedPatch, managedUsersPatchWire)
}

type managedUsersConditionalExecutor func(context.Context, identity.TenantID, scim.Request, scim.ProtocolAdmission) (scim.Response, error)

func newManagedUsersConditionalFeature(networkConfig identityhttp.NetworkConfig, rateConfig ProtocolRateConfig, limits scim.Limits, duration time.Duration,
	method string, operation scim.Operation, operationID string, executor managedUsersConditionalExecutor,
	wire func(scim.Limits, int) *identityhttp.WireOperation,
) (identityhttp.Feature, error) {
	if len(networkConfig.TenantHosts) == 0 || duration < time.Millisecond || duration > 30*time.Second {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	if _, err := scim.ParseMappingPath("userName", nil, limits); err != nil {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	network, decoder, err := identityhttp.NewSCIMRequestBoundary(networkConfig)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	rate, err := newProtocolRate(rateConfig)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	maximumBody := min(limits.BodyBytes, int(networkConfig.Limits.MaximumBodyBytes), int(networkConfig.Limits.MaximumDecodedBytes))
	h := managedUsersConditionalHTTP{network: network, decoder: decoder, executor: executor, rate: rate, limits: limits,
		bodyMaximum: maximumBody, duration: duration, method: method, operation: operation}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{
		Owner: "scim", OperationID: operationID, Handler: http.HandlerFunc(h.serve),
		CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}, MaximumSerializedBytes: uint64(limits.ResponseBytes),
	})
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op.Wire = wire(limits, maximumBody)
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "scim", Operations: []identityhttp.OperationDescriptor{op}})
}

type managedUsersConditionalHTTP struct {
	network     *identityhttp.NetworkResolver
	decoder     *identityhttp.RequestDecoder
	executor    managedUsersConditionalExecutor
	rate        *protocolRate
	limits      scim.Limits
	bodyMaximum int
	duration    time.Duration
	method      string
	operation   scim.Operation
}

func (h *managedUsersConditionalHTTP) serve(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.duration)
	defer cancel()
	response, denial := h.execute(r.WithContext(ctx))
	if ctx.Err() != nil {
		response, denial = scim.Response{}, scim.NewError(503, "")
	}
	if denial == nil {
		w.Header().Set("ETag", string(response.ETag))
		w.Header().Set("Location", response.Location)
	}
	writeProtocolResponse(w, response.Body, denial)
}

func (h *managedUsersConditionalHTTP) execute(r *http.Request) (response scim.Response, denial *scim.Error) {
	defer func() {
		if recover() != nil {
			response, denial = scim.Response{}, scim.NewError(503, "")
		}
	}()
	resourceID := r.PathValue("resource_id")
	if resourceID == "" || r.URL.Path != "/scim/v2/Users/"+resourceID || r.URL.RawPath != "" || r.URL.EscapedPath() != r.URL.Path {
		return scim.Response{}, scim.NewError(404, "")
	}
	if r.Method != h.method {
		return scim.Response{}, scim.NewError(405, "")
	}
	if len(resourceID) > h.limits.StringBytes {
		return scim.Response{}, scim.NewError(400, "invalidValue")
	}
	facts, err := h.network.Resolve(r)
	if err != nil {
		if errors.Is(err, identityhttp.ErrUnavailable) {
			return scim.Response{}, scim.NewError(503, "")
		}
		return scim.Response{}, scim.NewError(400, "invalidValue")
	}
	if facts.Scheme() != "https" || facts.Realm() != identityhttp.RealmTenant {
		return scim.Response{}, scim.NewError(403, "")
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Trailer) != 0 {
		return scim.Response{}, scim.NewError(400, "invalidValue")
	}
	for header := range r.Header {
		switch strings.ToLower(header) {
		case "if-none-match", "if-modified-since", "if-unmodified-since", "if-range", "range":
			return scim.Response{}, scim.NewError(400, "invalidValue")
		}
	}
	if _, _, err := h.decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil {
		return scim.Response{}, scim.NewError(400, "invalidValue")
	}
	credential, _, err := h.decoder.Bearer(r, identityhttp.HeaderRequired)
	if err != nil {
		return scim.Response{}, scim.NewError(401, "")
	}
	body, bodyError := readBulkBody(r, h.bodyMaximum)
	if bodyError != nil {
		return scim.Response{}, bodyError
	}
	defer clear(body)
	// Chunked input may populate Trailer only after the body has been read.
	if len(r.Trailer) != 0 {
		return scim.Response{}, scim.NewError(400, "invalidValue")
	}
	ifMatch, _ := protocolHeader(r, "If-Match")
	contentType, _ := protocolHeader(r, "Content-Type")
	encoding, _ := protocolHeader(r, "Content-Encoding")
	request := scim.Request{Operation: h.operation, Credential: credential, ResourceID: resourceID, IfMatch: scim.Version(ifMatch), Body: body, ContentType: contentType, ContentEncoding: encoding}
	calls, admitted := 0, false
	gate := func(ctx context.Context, client scim.ProtocolClient) *scim.Error {
		calls++
		if calls != 1 {
			return scim.NewError(503, "")
		}
		if client.TenantID != facts.TenantID() {
			return scim.NewError(403, "")
		}
		denial := h.rate.admit(ctx, client, facts.ClientIP())
		admitted = denial == nil
		return denial
	}
	response, err = h.executor(r.Context(), facts.TenantID(), request, gate)
	if err != nil {
		var protocol *scim.Error
		if errors.As(err, &protocol) && protocol != nil {
			return scim.Response{}, protocol
		}
		return scim.Response{}, scim.NewError(503, "")
	}
	if calls != 1 || !admitted || response.Status != http.StatusOK || response.ContentType != scimMedia ||
		len(response.Body) == 0 || len(response.Body) > h.limits.ResponseBytes || !validManagedUsersGetETag(response.ETag) ||
		response.Location != facts.Origin()+r.URL.Path || !validManagedUsersCreateResource(response, facts.Origin()) || r.Context().Err() != nil {
		return scim.Response{}, scim.NewError(503, "")
	}
	return response, nil
}
