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

const managedGroupsReplaceOperation = "identity.scim.group-replace"

// ManagedGroupsReplaceExecutor owns native SCIM schema validation, current issued
// bearer/connection/organization authority, mapping, original command/replay and
// durable effects. It owns complete replacement, strong If-Match validation and
// comparison, atomic CAS and exact-scope typed member integrity. It invokes
// admission exactly once synchronously after schema validation and current
// authorization, before mapping or command effects, with its configured
// service-account client and tenant. Inputs and callback are
// borrowed during this bounded call only; a returned success body is detached
// from the borrowed input. maximumMembers is trusted configuration, not request
// input. Implementers must honor ctx, support concurrent calls, retain no
// invocation and start no detached work. Errors disclose no partial
// response; a failure need not establish rollback of an uncertain native effect.
type ManagedGroupsReplaceExecutor interface {
	ExecuteManagedAdmittedGroupReplace(context.Context, identity.TenantID, scim.Request, int, scim.ProtocolAdmission) (scim.Response, error)
}

// ManagedGroupsReplaceConfig explicitly selects the managed Group Replace port.
// Network must match the outer HTTPS router; Limits must match the native
// profile. The native Provisioning.BaseURL must be the canonical effective
// HTTPS origin plus /scim/v2, and native Group IDs must be canonical SubjectIDs.
// MaximumMembers matches the native ceiling: 0..scim.DefaultGroupMembers.
// Zero allows only empty Groups and is never a default. Rate borrows the same
// strict atomic backend, namespace and digest key as other selected SCIM protocol
// operations. Owners must be concurrency-safe and outlive requests.
// No backend/server lifetime is transferred. MaximumDuration is 1ms..30s;
// earlier request/native deadlines win. Construction performs no IO.
type ManagedGroupsReplaceConfig struct {
	Network         identityhttp.NetworkConfig
	Executor        ManagedGroupsReplaceExecutor
	Rate            ProtocolRateConfig
	Limits          scim.Limits
	MaximumDuration time.Duration
	MaximumMembers  int
}

// Format redacts borrowed native, network and rate-key custody.
func (ManagedGroupsReplaceConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("scimhttp.ManagedGroupsReplaceConfig(redacted)"))
}

// MarshalJSON refuses implicit runtime configuration export.
func (ManagedGroupsReplaceConfig) MarshalJSON() ([]byte, error) {
	return nil, identityhttp.ErrInvalidInput
}

// MarshalText refuses implicit runtime configuration export.
func (ManagedGroupsReplaceConfig) MarshalText() ([]byte, error) {
	return nil, identityhttp.ErrInvalidInput
}

// NewManagedGroupsReplaceFeature selects only PUT
// /scim/v2/Groups/{resource_id}, with explicit issued-bearer authority, original
// If-Match custody and no Idempotency-Key or caller command allocation.
// Omission exposes no route/metadata. Combine disjoint Operations under one
// canonical feature ID "scim" for coexistence. Raw body bytes are bounded by
// native, transport raw-body and decoded-byte limits before forwarding to the
// root schema owner; the transport does not parse a writable Group or map fields.
// Headerless retry recovery remains native-owned; each request obtains fresh
// native authority and quota admission. Success preserves native body, ETag
// and Location after validating their binding to the selected HTTPS origin and
// canonical resource. No cookie authority, query,
// retry, response cache or other operation is selected. The server retains body
// closure and raw-IO/write deadlines. Separate generic authentication middleware
// cannot bind this native-owned authority/admission window.
func NewManagedGroupsReplaceFeature(c ManagedGroupsReplaceConfig) (identityhttp.Feature, error) {
	if missingManagedOwner(c.Executor) {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	return newManagedGroupsConditionalFeature(managedGroupsConditionalConfig{
		network: c.Network, rate: c.Rate, limits: c.Limits, duration: c.MaximumDuration, maximumMembers: c.MaximumMembers,
	}, scim.GroupReplace, c.Executor.ExecuteManagedAdmittedGroupReplace)
}

type managedGroupsConditionalConfig struct {
	network        identityhttp.NetworkConfig
	rate           ProtocolRateConfig
	limits         scim.Limits
	duration       time.Duration
	maximumMembers int
}

type managedGroupWriteExecutor func(context.Context, identity.TenantID, scim.Request, int, scim.ProtocolAdmission) (scim.Response, error)

func newManagedGroupsConditionalFeature(c managedGroupsConditionalConfig, operation scim.Operation, executor managedGroupWriteExecutor) (identityhttp.Feature, error) {
	if len(c.network.TenantHosts) == 0 || c.duration < time.Millisecond || c.duration > 30*time.Second || c.maximumMembers < 0 || c.maximumMembers > scim.DefaultGroupMembers {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	if _, err := scim.ParseMappingPath("displayName", nil, c.limits); err != nil {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	network, decoder, err := identityhttp.NewSCIMRequestBoundary(c.network)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	rate, err := newProtocolRate(c.rate)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	maximumBody := min(c.limits.BodyBytes, int(c.network.Limits.MaximumBodyBytes), int(c.network.Limits.MaximumDecodedBytes))
	var method, operationID string
	var wire *identityhttp.WireOperation
	switch operation {
	case scim.GroupReplace:
		method, operationID = http.MethodPut, managedGroupsReplaceOperation
		wire = managedGroupsReplaceWire(c.limits, maximumBody, c.maximumMembers)
	case scim.GroupPatch:
		method, operationID = http.MethodPatch, managedGroupsPatchOperation
		wire = managedGroupsPatchWire(c.limits, maximumBody, c.maximumMembers)
	default:
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	h := managedGroupsConditionalHTTP{method: method, operation: operation, network: network, decoder: decoder, executor: executor, rate: rate,
		bodyMaximum: maximumBody, resourceMaximum: c.limits.StringBytes, responseMaximum: c.limits.ResponseBytes, duration: c.duration, maximumMembers: c.maximumMembers}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{
		Owner: "scim", OperationID: operationID, Handler: http.HandlerFunc(h.serve),
		CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}, MaximumSerializedBytes: uint64(c.limits.ResponseBytes),
	})
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op.Wire = wire
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "scim", Operations: []identityhttp.OperationDescriptor{op}})
}

type managedGroupsConditionalHTTP struct {
	method          string
	operation       scim.Operation
	network         *identityhttp.NetworkResolver
	decoder         *identityhttp.RequestDecoder
	executor        managedGroupWriteExecutor
	rate            *protocolRate
	bodyMaximum     int
	resourceMaximum int
	responseMaximum int
	duration        time.Duration
	maximumMembers  int
}

func (h *managedGroupsConditionalHTTP) serve(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.duration)
	defer cancel()
	response, denial := h.execute(r.WithContext(ctx))
	if ctx.Err() != nil {
		response, denial = scim.Response{}, scim.NewError(503, "")
	}
	if denial != nil {
		writeProtocolResponse(w, nil, denial)
		return
	}
	w.Header().Set("Content-Type", scimMedia)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("ETag", string(response.ETag))
	w.Header().Set("Location", response.Location)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(response.Body)
}

func (h *managedGroupsConditionalHTTP) execute(r *http.Request) (response scim.Response, denial *scim.Error) {
	defer func() {
		if recover() != nil {
			response, denial = scim.Response{}, scim.NewError(503, "")
		}
	}()
	resourceID := r.PathValue("resource_id")
	if resourceID == "" || r.URL.Path != "/scim/v2/Groups/"+resourceID || r.URL.RawPath != "" || r.URL.EscapedPath() != r.URL.Path {
		return scim.Response{}, scim.NewError(404, "")
	}
	if r.Method != h.method {
		return scim.Response{}, scim.NewError(405, "")
	}
	if len(resourceID) > h.resourceMaximum {
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
	// The existing SCIM reader bounds raw bytes, charset/identity encoding,
	// length consistency and stalled readers; schema decoding stays native-owned.
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
	response, err = h.executor(r.Context(), facts.TenantID(), request, h.maximumMembers, gate)
	if err != nil {
		var protocol *scim.Error
		if errors.As(err, &protocol) && protocol != nil {
			return scim.Response{}, protocol
		}
		return scim.Response{}, scim.NewError(503, "")
	}
	if calls != 1 || !admitted || response.Status != http.StatusOK || response.ContentType != scimMedia ||
		len(response.Body) == 0 || len(response.Body) > h.responseMaximum || !validManagedUsersGetETag(response.ETag) ||
		response.Location != facts.Origin()+r.URL.Path || !validManagedGroupsCreateResource(response, facts.Origin()) || r.Context().Err() != nil {
		return scim.Response{}, scim.NewError(503, "")
	}
	return response, nil
}
