package scimhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	scim "github.com/faustbrian/go-scim"
)

const managedUsersCreateOperation = "identity.scim.user-create"

// ManagedUsersCreateExecutor owns native SCIM schema validation, current issued
// bearer/connection/organization authority, mapping, original command/replay and
// durable effects. It invokes admission exactly once synchronously after schema
// validation and current authorization, before mapping or command effects, with
// its configured service-account client and tenant. Inputs and callback are
// borrowed during this bounded call only; a returned success body is detached
// from the borrowed input. Implementers must honor ctx, support concurrent calls,
// retain no invocation and start no detached work. Errors disclose no partial
// response; a failure need not establish rollback of an uncertain native effect.
type ManagedUsersCreateExecutor interface {
	ExecuteManagedAdmittedCreate(context.Context, identity.TenantID, scim.Request, scim.ProtocolAdmission) (scim.Response, error)
}

// ManagedUsersCreateConfig explicitly selects the managed User Create port.
// Network must match the outer HTTPS router; Limits must match the native
// profile. The native Provisioning.BaseURL must be the canonical effective
// HTTPS origin plus /scim/v2, and native User IDs must be canonical SubjectIDs.
// Rate borrows the same strict atomic backend, namespace and digest key as
// other selected SCIM protocol operations. Owners must be concurrency-safe and
// outlive requests. No backend/server lifetime is transferred. MaximumDuration
// is 1ms..30s; earlier request/native deadlines win. Construction performs no IO.
type ManagedUsersCreateConfig struct {
	Network         identityhttp.NetworkConfig
	Executor        ManagedUsersCreateExecutor
	Rate            ProtocolRateConfig
	Limits          scim.Limits
	MaximumDuration time.Duration
}

// Format redacts borrowed native, network and rate-key custody.
func (ManagedUsersCreateConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("scimhttp.ManagedUsersCreateConfig(redacted)"))
}

// MarshalJSON refuses implicit runtime configuration export.
func (ManagedUsersCreateConfig) MarshalJSON() ([]byte, error) {
	return nil, identityhttp.ErrInvalidInput
}

// MarshalText refuses implicit runtime configuration export.
func (ManagedUsersCreateConfig) MarshalText() ([]byte, error) {
	return nil, identityhttp.ErrInvalidInput
}

// NewManagedUsersCreateFeature selects only POST /scim/v2/Users, with explicit
// issued-bearer authority and no Idempotency-Key or caller command allocation.
// Omission exposes no route/metadata. Combine disjoint Operations under one
// canonical feature ID "scim" for coexistence. Raw body bytes are bounded by
// native, transport raw-body and decoded-byte limits before forwarding to the
// root schema owner; the transport does not parse a writable User or map fields.
// Success preserves native body/ETag/Location after validating their binding to
// the selected HTTPS origin and canonical resource. No cookie authority, query,
// retry, response cache or other operation is selected. The server retains body
// closure and raw-IO/write deadlines. Separate generic authentication middleware
// cannot bind this native-owned authority/admission window.
func NewManagedUsersCreateFeature(c ManagedUsersCreateConfig) (identityhttp.Feature, error) {
	if missingManagedOwner(c.Executor) || len(c.Network.TenantHosts) == 0 || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	if _, err := scim.ParseMappingPath("userName", nil, c.Limits); err != nil {
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
	maximumBody := min(c.Limits.BodyBytes, int(c.Network.Limits.MaximumBodyBytes), int(c.Network.Limits.MaximumDecodedBytes))
	h := managedUsersCreateHTTP{network: network, decoder: decoder, executor: c.Executor, rate: rate,
		bodyMaximum: maximumBody, responseMaximum: c.Limits.ResponseBytes, duration: c.MaximumDuration}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{
		Owner: "scim", OperationID: managedUsersCreateOperation, Handler: http.HandlerFunc(h.serve),
		CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}, MaximumSerializedBytes: uint64(c.Limits.ResponseBytes),
	})
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op.Wire = managedUsersCreateWire(c.Limits, maximumBody)
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "scim", Operations: []identityhttp.OperationDescriptor{op}})
}

type managedUsersCreateHTTP struct {
	network         *identityhttp.NetworkResolver
	decoder         *identityhttp.RequestDecoder
	executor        ManagedUsersCreateExecutor
	rate            *protocolRate
	bodyMaximum     int
	responseMaximum int
	duration        time.Duration
}

func (h *managedUsersCreateHTTP) serve(w http.ResponseWriter, r *http.Request) {
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
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write(response.Body)
}

func (h *managedUsersCreateHTTP) execute(r *http.Request) (response scim.Response, denial *scim.Error) {
	defer func() {
		if recover() != nil {
			response, denial = scim.Response{}, scim.NewError(503, "")
		}
	}()
	if r.URL.Path != "/scim/v2/Users" || r.URL.RawPath != "" || r.URL.EscapedPath() != r.URL.Path {
		return scim.Response{}, scim.NewError(404, "")
	}
	if r.Method != http.MethodPost {
		return scim.Response{}, scim.NewError(405, "")
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
		case "if-match", "if-none-match", "if-modified-since", "if-unmodified-since", "if-range", "range":
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
	contentType, _ := protocolHeader(r, "Content-Type")
	encoding, _ := protocolHeader(r, "Content-Encoding")
	request := scim.Request{Operation: scim.UserCreate, Credential: credential, Body: body, ContentType: contentType, ContentEncoding: encoding}
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
	response, err = h.executor.ExecuteManagedAdmittedCreate(r.Context(), facts.TenantID(), request, gate)
	if err != nil {
		var protocol *scim.Error
		if errors.As(err, &protocol) && protocol != nil {
			return scim.Response{}, protocol
		}
		return scim.Response{}, scim.NewError(503, "")
	}
	if calls != 1 || !admitted || response.Status != http.StatusCreated || response.ContentType != scimMedia ||
		len(response.Body) == 0 || len(response.Body) > h.responseMaximum || !validManagedUsersGetETag(response.ETag) ||
		!validManagedUsersCreateResource(response, facts.Origin()) || r.Context().Err() != nil {
		return scim.Response{}, scim.NewError(503, "")
	}
	return response, nil
}

func validManagedUsersCreateResource(response scim.Response, origin string) bool {
	var resource struct {
		Schemas []string `json:"schemas"`
		ID      string   `json:"id"`
		Meta    struct {
			ResourceType string `json:"resourceType"`
			Version      string `json:"version"`
			Location     string `json:"location"`
		} `json:"meta"`
	}
	if json.Unmarshal(response.Body, &resource) != nil {
		return false
	}
	// The managed PostgreSQL preparation owner issues native SubjectIDs. An
	// exact trusted-origin/path comparison forbids redirect and escaped aliases
	// without rewriting the owner's authoritative Location or resource body.
	if _, err := identity.ParseSubjectID(resource.ID); err != nil || response.Location != origin+"/scim/v2/Users/"+resource.ID ||
		resource.Meta.ResourceType != "User" || resource.Meta.Location != response.Location || resource.Meta.Version != string(response.ETag) {
		return false
	}
	coreSchemas := 0
	for _, schema := range resource.Schemas {
		if schema == "urn:ietf:params:scim:schemas:core:2.0:User" {
			coreSchemas++
		}
	}
	return coreSchemas == 1
}
