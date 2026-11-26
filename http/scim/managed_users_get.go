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

const managedUsersGetOperation = "identity.scim.user-get"

// ManagedUsersGetExecutor owns current issued-bearer authentication, persisted
// connection and organization/policy authority, native User projection and its
// final disclosure fence. It invokes admission exactly once synchronously after
// authorization and before resource IO, using its own configured client/tenant.
// Inputs and callback are borrowed only during this bounded call. Implementers
// must honor ctx, support concurrent calls, retain no invocation, start no
// detached work and disclose no partial response on error. This leaf selects
// only UserGet, never another operation or a transport-owned authority window.
type ManagedUsersGetExecutor interface {
	ExecuteManagedAdmittedRead(context.Context, identity.TenantID, scim.Request, scim.ProtocolAdmission) (scim.Response, error)
}

// ManagedUsersGetConfig explicitly selects the native managed User Get. Network
// must match the outer HTTPS router and Limits the native executor's effective
// SCIM profile. Rate borrows the same strict atomic backend, namespace and digest
// key as other selected SCIM protocol routes. Owners must be concurrency-safe
// and outlive requests; no pool/backend/server lifetime is transferred.
// MaximumDuration is 1ms..30s; earlier request/native authority deadlines win.
// Construction validates configuration without owner IO.
type ManagedUsersGetConfig struct {
	Network         identityhttp.NetworkConfig
	Executor        ManagedUsersGetExecutor
	Rate            ProtocolRateConfig
	Limits          scim.Limits
	MaximumDuration time.Duration
}

// Format redacts borrowed native, network and rate-key custody.
func (ManagedUsersGetConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("scimhttp.ManagedUsersGetConfig(redacted)"))
}

// MarshalJSON refuses implicit runtime configuration export.
func (ManagedUsersGetConfig) MarshalJSON() ([]byte, error) { return nil, identityhttp.ErrInvalidInput }

// MarshalText refuses implicit runtime configuration export.
func (ManagedUsersGetConfig) MarshalText() ([]byte, error) { return nil, identityhttp.ErrInvalidInput }

// NewManagedUsersGetFeature selects only GET /scim/v2/Users/{resource_id}, with
// canonical router-supplied PathValue provenance and native SCIM-token authority.
// Omission exposes no route or metadata. Combine disjoint Operations under one
// canonical feature ID "scim" for coexistence. Only projection query scalars are
// accepted; the native owner retains schema semantics and current authority
// through admission and disclosure. No body is read, goroutine started, request
// retried, cookie authority accepted or implicit method enabled. Outer server
// raw-IO/write deadlines remain required. Separate generic authentication
// middleware cannot bind this native-owned handler.
func NewManagedUsersGetFeature(c ManagedUsersGetConfig) (identityhttp.Feature, error) {
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
	h := managedUsersGetHTTP{network: network, decoder: decoder, executor: c.Executor, rate: rate, limits: c.Limits, duration: c.MaximumDuration}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "scim", OperationID: managedUsersGetOperation, Handler: http.HandlerFunc(h.serve), CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}, MaximumSerializedBytes: uint64(c.Limits.ResponseBytes)})
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op.Wire = managedUsersGetWire(c.Limits)
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "scim", Operations: []identityhttp.OperationDescriptor{op}})
}

type managedUsersGetHTTP struct {
	network  *identityhttp.NetworkResolver
	decoder  *identityhttp.RequestDecoder
	executor ManagedUsersGetExecutor
	rate     *protocolRate
	limits   scim.Limits
	duration time.Duration
}

func (h *managedUsersGetHTTP) serve(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.duration)
	defer cancel()
	response, denial := h.execute(r.WithContext(ctx))
	if ctx.Err() != nil {
		response, denial = scim.Response{}, scim.NewError(503, "")
	}
	if denial == nil {
		w.Header().Set("ETag", string(response.ETag))
	}
	// Native meta.location remains part of the unchanged representation. GET
	// does not need the mutation response's redundant Location transport header.
	writeProtocolResponse(w, response.Body, denial)
}

func (h *managedUsersGetHTTP) execute(r *http.Request) (response scim.Response, denial *scim.Error) {
	defer func() {
		if recover() != nil {
			response, denial = scim.Response{}, scim.NewError(503, "")
		}
	}()
	resourceID := r.PathValue("resource_id")
	if resourceID == "" || r.URL.Path != "/scim/v2/Users/"+resourceID || r.URL.RawPath != "" || r.URL.EscapedPath() != r.URL.Path {
		return scim.Response{}, scim.NewError(404, "")
	}
	if r.Method != http.MethodGet {
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
	if r.URL.ForceQuery || r.ContentLength != 0 || r.Body != nil && r.Body != http.NoBody || len(r.TransferEncoding) != 0 || len(r.Trailer) != 0 {
		return scim.Response{}, scim.NewError(400, "invalidValue")
	}
	for header := range r.Header {
		switch strings.ToLower(header) {
		case "content-encoding":
			return scim.Response{}, scim.NewError(415, "")
		case "if-match", "if-none-match", "if-modified-since", "if-unmodified-since", "if-range", "range":
			return scim.Response{}, scim.NewError(400, "invalidValue")
		}
	}
	query, err := managedUsersGetQuery(h.decoder, r)
	if err != nil {
		return scim.Response{}, scim.NewError(400, "invalidValue")
	}
	if _, _, err := h.decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil {
		return scim.Response{}, scim.NewError(400, "invalidValue")
	}
	credential, _, err := h.decoder.Bearer(r, identityhttp.HeaderRequired)
	if err != nil {
		return scim.Response{}, scim.NewError(401, "")
	}
	request := scim.Request{Operation: scim.UserGet, Credential: credential, ResourceID: resourceID, Query: query}
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
	response, err = h.executor.ExecuteManagedAdmittedRead(r.Context(), facts.TenantID(), request, gate)
	if err != nil {
		var protocol *scim.Error
		if errors.As(err, &protocol) && protocol != nil {
			return scim.Response{}, protocol
		}
		return scim.Response{}, scim.NewError(503, "")
	}
	if calls != 1 || !admitted || response.Status != 200 || response.ContentType != scimMedia || !validManagedUsersGetETag(response.ETag) || len(response.Body) == 0 || len(response.Body) > h.limits.ResponseBytes || !json.Valid(response.Body) || r.Context().Err() != nil {
		return scim.Response{}, scim.NewError(503, "")
	}
	return response, nil
}

func managedUsersGetQuery(decoder *identityhttp.RequestDecoder, r *http.Request) (scim.Query, error) {
	parameters, err := decoder.Query(r)
	if err != nil {
		return scim.Query{}, err
	}
	query := scim.Query{}
	for name, entries := range parameters {
		if len(entries) != 1 {
			return scim.Query{}, identityhttp.ErrInvalidInput
		}
		switch name {
		case "attributes":
			query.Attributes = entries[0]
		case "excludedAttributes":
			query.ExcludedAttributes = entries[0]
		default:
			return scim.Query{}, identityhttp.ErrInvalidInput
		}
	}
	return query, nil
}

func validManagedUsersGetETag(version scim.Version) bool {
	// go-scim's Version contract and schema.go validVersion require a strong
	// quoted visible-ASCII value, 3..256 bytes. Preserve it without normalization.
	value := string(version)
	if len(value) < 3 || len(value) > 256 || value[0] != '"' || value[len(value)-1] != '"' {
		return false
	}
	for i := 1; i < len(value)-1; i++ {
		if value[i] < 33 || value[i] > 126 || value[i] == '"' || value[i] == '\\' {
			return false
		}
	}
	return true
}
