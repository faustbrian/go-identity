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

const managedGroupsCreateOperation = "identity.scim.group-create"

// ManagedGroupsCreateExecutor owns native SCIM schema validation, current issued
// bearer/connection/organization authority, mapping, original command/replay and
// durable effects. It invokes admission exactly once synchronously after schema
// validation and current authorization, before mapping or command effects, with
// its configured service-account client and tenant. Inputs and callback are
// borrowed during this bounded call only; a returned success body is detached
// from the borrowed input. maximumMembers is trusted configuration, not request
// input. Implementers must honor ctx, support concurrent calls, retain no
// invocation and start no detached work. Errors disclose no partial
// response; a failure need not establish rollback of an uncertain native effect.
type ManagedGroupsCreateExecutor interface {
	ExecuteManagedAdmittedGroupCreate(context.Context, identity.TenantID, scim.Request, int, scim.ProtocolAdmission) (scim.Response, error)
}

// ManagedGroupsCreateConfig explicitly selects the managed Group Create port.
// Network must match the outer HTTPS router; Limits must match the native
// profile. The native Provisioning.BaseURL must be the canonical effective
// HTTPS origin plus /scim/v2, and native Group IDs must be canonical SubjectIDs.
// MaximumMembers matches the native ceiling: 0..scim.DefaultGroupMembers.
// Zero allows only empty Groups and is never a default. Rate borrows the same
// strict atomic backend, namespace and digest key as other selected SCIM protocol
// operations. Owners must be concurrency-safe and
// outlive requests. No backend/server lifetime is transferred. MaximumDuration
// is 1ms..30s; earlier request/native deadlines win. Construction performs no IO.
type ManagedGroupsCreateConfig struct {
	Network         identityhttp.NetworkConfig
	Executor        ManagedGroupsCreateExecutor
	Rate            ProtocolRateConfig
	Limits          scim.Limits
	MaximumDuration time.Duration
	MaximumMembers  int
}

// Format redacts borrowed native, network and rate-key custody.
func (ManagedGroupsCreateConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("scimhttp.ManagedGroupsCreateConfig(redacted)"))
}

// MarshalJSON refuses implicit runtime configuration export.
func (ManagedGroupsCreateConfig) MarshalJSON() ([]byte, error) {
	return nil, identityhttp.ErrInvalidInput
}

// MarshalText refuses implicit runtime configuration export.
func (ManagedGroupsCreateConfig) MarshalText() ([]byte, error) {
	return nil, identityhttp.ErrInvalidInput
}

// NewManagedGroupsCreateFeature selects only POST /scim/v2/Groups, with explicit
// issued-bearer authority and no Idempotency-Key or caller command allocation.
// Omission exposes no route/metadata. Combine disjoint Operations under one
// canonical feature ID "scim" for coexistence. Raw body bytes are bounded by
// native, transport raw-body and decoded-byte limits before forwarding to the
// root schema owner; the transport does not parse a writable Group or map fields.
// Success preserves native body/ETag/Location after validating their binding to
// the selected HTTPS origin and canonical resource. No cookie authority, query,
// retry, response cache or other operation is selected. The server retains body
// closure and raw-IO/write deadlines. Separate generic authentication middleware
// cannot bind this native-owned authority/admission window.
func NewManagedGroupsCreateFeature(c ManagedGroupsCreateConfig) (identityhttp.Feature, error) {
	if missingManagedOwner(c.Executor) || len(c.Network.TenantHosts) == 0 || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || c.MaximumMembers < 0 || c.MaximumMembers > scim.DefaultGroupMembers {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	if _, err := scim.ParseMappingPath("displayName", nil, c.Limits); err != nil {
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
	h := managedGroupsCreateHTTP{network: network, decoder: decoder, executor: c.Executor, rate: rate,
		bodyMaximum: maximumBody, responseMaximum: c.Limits.ResponseBytes, duration: c.MaximumDuration, maximumMembers: c.MaximumMembers}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{
		Owner: "scim", OperationID: managedGroupsCreateOperation, Handler: http.HandlerFunc(h.serve),
		CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}, MaximumSerializedBytes: uint64(c.Limits.ResponseBytes),
	})
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op.Wire = managedGroupsCreateWire(c.Limits, maximumBody, c.MaximumMembers)
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "scim", Operations: []identityhttp.OperationDescriptor{op}})
}

type managedGroupsCreateHTTP struct {
	network         *identityhttp.NetworkResolver
	decoder         *identityhttp.RequestDecoder
	executor        ManagedGroupsCreateExecutor
	rate            *protocolRate
	bodyMaximum     int
	responseMaximum int
	duration        time.Duration
	maximumMembers  int
}

func (h *managedGroupsCreateHTTP) serve(w http.ResponseWriter, r *http.Request) {
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

func (h *managedGroupsCreateHTTP) execute(r *http.Request) (response scim.Response, denial *scim.Error) {
	defer func() {
		if recover() != nil {
			response, denial = scim.Response{}, scim.NewError(503, "")
		}
	}()
	if r.URL.Path != "/scim/v2/Groups" || r.URL.RawPath != "" || r.URL.EscapedPath() != r.URL.Path {
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
	request := scim.Request{Operation: scim.GroupCreate, Credential: credential, Body: body, ContentType: contentType, ContentEncoding: encoding}
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
	response, err = h.executor.ExecuteManagedAdmittedGroupCreate(r.Context(), facts.TenantID(), request, h.maximumMembers, gate)
	if err != nil {
		var protocol *scim.Error
		if errors.As(err, &protocol) && protocol != nil {
			return scim.Response{}, protocol
		}
		return scim.Response{}, scim.NewError(503, "")
	}
	if calls != 1 || !admitted || response.Status != http.StatusCreated || response.ContentType != scimMedia ||
		len(response.Body) == 0 || len(response.Body) > h.responseMaximum || !validManagedUsersGetETag(response.ETag) ||
		!validManagedGroupsCreateResource(response, facts.Origin()) || r.Context().Err() != nil {
		return scim.Response{}, scim.NewError(503, "")
	}
	return response, nil
}

func validManagedGroupsCreateResource(response scim.Response, origin string) bool {
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
	if _, err := identity.ParseSubjectID(resource.ID); err != nil || response.Location != origin+"/scim/v2/Groups/"+resource.ID ||
		resource.Meta.ResourceType != "Group" || resource.Meta.Location != response.Location || resource.Meta.Version != string(response.ETag) {
		return false
	}
	coreSchemas := 0
	for _, schema := range resource.Schemas {
		if schema == "urn:ietf:params:scim:schemas:core:2.0:Group" {
			coreSchemas++
		}
	}
	return coreSchemas == 1
}
