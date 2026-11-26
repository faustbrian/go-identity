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

const (
	managedGroupsGetOperation  = "identity.scim.group-get"
	managedGroupsListOperation = "identity.scim.group-list"
)

// ManagedGroupsReadExecutor owns current issued-bearer, managed connection,
// organization and operation authority, native Group schema/projection and
// snapshot semantics, and the final disclosure fence. It invokes admission
// exactly once synchronously after authorization and before resource IO, using
// its configured client/tenant. Inputs and callback are borrowed only for this
// bounded call; implementations must honor ctx, support concurrent calls,
// retain no invocation, start no detached work and disclose no partial response
// on error. maximumMembers is trusted configuration, never request input.
type ManagedGroupsReadExecutor interface {
	ExecuteManagedAdmittedGroupRead(context.Context, identity.TenantID, scim.Request, int, scim.ProtocolAdmission) (scim.Response, error)
}

// ManagedGroupsReadConfig independently selects native Group Get and List.
// Network must match the outer HTTPS router and Limits the native profile.
// MaximumMembers must match the selected native Group member ceiling:
// 0..scim.DefaultGroupMembers, with zero allowing only empty Groups, not a
// default. Rate borrows the same strict atomic backend, namespace and digest
// key as other selected SCIM protocol routes. Owners must be concurrency-safe
// and outlive requests; no pool/backend/server lifetime is transferred.
// MaximumDuration is 1ms..30s; earlier request/native authority deadlines win.
// Construction validates configuration without owner IO.
type ManagedGroupsReadConfig struct {
	Network         identityhttp.NetworkConfig
	Executor        ManagedGroupsReadExecutor
	Rate            ProtocolRateConfig
	Limits          scim.Limits
	MaximumDuration time.Duration
	MaximumMembers  int
	EnableGet       bool
	EnableList      bool
}

// Format redacts borrowed native, network and rate-key custody.
func (ManagedGroupsReadConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("scimhttp.ManagedGroupsReadConfig(redacted)"))
}

// MarshalJSON refuses implicit runtime configuration export.
func (ManagedGroupsReadConfig) MarshalJSON() ([]byte, error) {
	return nil, identityhttp.ErrInvalidInput
}

// MarshalText refuses implicit runtime configuration export.
func (ManagedGroupsReadConfig) MarshalText() ([]byte, error) {
	return nil, identityhttp.ErrInvalidInput
}

// NewManagedGroupsReadFeature opts independently into GET /scim/v2/Groups and
// GET /scim/v2/Groups/{resource_id}. At least one must be selected; omission
// installs no route or metadata. Combine disjoint Operations under canonical
// feature ID "scim" for coexistence. Get accepts only projection scalars; List
// forwards bounded RFC filter/sort/page/projection scalars to the native owner.
// No cookie authority, body, conditional/range read, write, search or discovery
// is selected. No body is read, goroutine started or request retried. Separate
// generic authentication middleware cannot bind this native-owned handler;
// outer server raw-IO/write deadlines remain required.
func NewManagedGroupsReadFeature(c ManagedGroupsReadConfig) (identityhttp.Feature, error) {
	if !c.EnableGet && !c.EnableList || missingManagedOwner(c.Executor) || len(c.Network.TenantHosts) == 0 || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || c.MaximumMembers < 0 || c.MaximumMembers > scim.DefaultGroupMembers {
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
	var operations []identityhttp.OperationDescriptor
	for _, selection := range []struct {
		id      string
		enabled bool
		kind    scim.Operation
	}{{managedGroupsGetOperation, c.EnableGet, scim.GroupGet}, {managedGroupsListOperation, c.EnableList, scim.GroupList}} {
		if !selection.enabled {
			continue
		}
		h := managedGroupsReadHTTP{network: network, decoder: decoder, executor: c.Executor, rate: rate, limits: c.Limits, duration: c.MaximumDuration, maximumMembers: c.MaximumMembers, operation: selection.kind}
		op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "scim", OperationID: selection.id, Handler: http.HandlerFunc(h.serve), CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}, MaximumSerializedBytes: uint64(c.Limits.ResponseBytes)})
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op.Wire = managedGroupsReadWire(c.Limits, c.MaximumMembers, selection.kind)
		operations = append(operations, op)
	}
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "scim", Operations: operations})
}

type managedGroupsReadHTTP struct {
	network        *identityhttp.NetworkResolver
	decoder        *identityhttp.RequestDecoder
	executor       ManagedGroupsReadExecutor
	rate           *protocolRate
	limits         scim.Limits
	duration       time.Duration
	maximumMembers int
	operation      scim.Operation
}

func (h *managedGroupsReadHTTP) serve(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.duration)
	defer cancel()
	response, denial := h.execute(r.WithContext(ctx))
	if ctx.Err() != nil {
		response, denial = scim.Response{}, scim.NewError(503, "")
	}
	if denial == nil && h.operation == scim.GroupGet {
		w.Header().Set("ETag", string(response.ETag))
	}
	// Native meta.location remains in the unchanged Get representation; reads
	// do not emit the mutation response's redundant Location header.
	writeProtocolResponse(w, response.Body, denial)
}

func (h *managedGroupsReadHTTP) execute(r *http.Request) (response scim.Response, denial *scim.Error) {
	defer func() {
		if recover() != nil {
			response, denial = scim.Response{}, scim.NewError(503, "")
		}
	}()
	resourceID, path := "", "/scim/v2/Groups"
	if h.operation == scim.GroupGet {
		resourceID = r.PathValue("resource_id")
		if resourceID == "" {
			return scim.Response{}, scim.NewError(404, "")
		}
		path += "/" + resourceID
	}
	if r.URL.Path != path || r.URL.RawPath != "" || r.URL.EscapedPath() != r.URL.Path {
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
	var query scim.Query
	if h.operation == scim.GroupGet {
		query, err = managedUsersGetQuery(h.decoder, r)
	} else {
		query, err = managedUsersListQuery(h.decoder, r)
	}
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
	request := scim.Request{Operation: h.operation, Credential: credential, ResourceID: resourceID, Query: query}
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
	response, err = h.executor.ExecuteManagedAdmittedGroupRead(r.Context(), facts.TenantID(), request, h.maximumMembers, gate)
	if err != nil {
		var protocol *scim.Error
		if errors.As(err, &protocol) && protocol != nil {
			return scim.Response{}, protocol
		}
		return scim.Response{}, scim.NewError(503, "")
	}
	if calls != 1 || !admitted || response.Status != 200 || response.ContentType != scimMedia || len(response.Body) == 0 || len(response.Body) > h.limits.ResponseBytes || !json.Valid(response.Body) || r.Context().Err() != nil {
		return scim.Response{}, scim.NewError(503, "")
	}
	if h.operation == scim.GroupGet {
		if !validManagedUsersGetETag(response.ETag) {
			return scim.Response{}, scim.NewError(503, "")
		}
	} else if response.ETag != "" || response.Location != "" {
		return scim.Response{}, scim.NewError(503, "")
	}
	return response, nil
}
