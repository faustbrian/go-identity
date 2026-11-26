package scimhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	scim "github.com/faustbrian/go-scim"
)

const managedUsersListOperation = "identity.scim.user-list"

// ManagedUsersListExecutor owns the issued SCIM bearer's current connection,
// organization/policy authority, RFC query semantics and complete native User
// snapshot. It invokes admission exactly once synchronously after current
// authorization and before resource IO/disclosure, with its configured client
// and tenant, never request-selected identity. Inputs and callback are borrowed
// only during this bounded call; implementations must honor ctx, support
// concurrency, retain no invocation and start no detached work. Errors disclose
// no partial response. The HTTP feature selects only UserList from this port.
type ManagedUsersListExecutor interface {
	ExecuteManagedAdmittedRead(context.Context, identity.TenantID, scim.Request, scim.ProtocolAdmission) (scim.Response, error)
}

// ManagedUsersListConfig opts into one native-owned protocol read. Limits must
// match the native executor's effective SCIM profile; Network must match the
// outer HTTPS router. Rate borrows the same strict atomic backend, namespace
// and digest key as other selected SCIM protocol routes. Owners must outlive
// requests and support concurrent calls; no pool/backend/server lifetime is
// transferred. MaximumDuration is 1ms..30s; earlier request/native authority
// deadlines win. Construction validates configuration without owner IO.
type ManagedUsersListConfig struct {
	Network         identityhttp.NetworkConfig
	Executor        ManagedUsersListExecutor
	Rate            ProtocolRateConfig
	Limits          scim.Limits
	MaximumDuration time.Duration
}

// Format redacts borrowed executor, network and rate-key custody.
func (ManagedUsersListConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("scimhttp.ManagedUsersListConfig(redacted)"))
}

// MarshalJSON refuses implicit runtime configuration export.
func (ManagedUsersListConfig) MarshalJSON() ([]byte, error) { return nil, identityhttp.ErrInvalidInput }

// MarshalText refuses implicit runtime configuration export.
func (ManagedUsersListConfig) MarshalText() ([]byte, error) { return nil, identityhttp.ErrInvalidInput }

// NewManagedUsersListFeature selects exactly GET /scim/v2/Users with RFC scalar
// query forwarding and native SCIM-token authority. It selects no User Get,
// writes, search, Groups or discovery. Omission exposes no route/metadata.
// Combine disjoint Operations under one canonical feature ID "scim" for Bulk
// or management coexistence. Separate generic authentication middleware cannot
// bind this native-owned handler; the native owner retains the only authority
// window through admission and final disclosure. Server raw IO/write deadlines
// remain required; no body is read, goroutine started or request retried here.
func NewManagedUsersListFeature(c ManagedUsersListConfig) (identityhttp.Feature, error) {
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
	h := managedUsersListHTTP{network: network, decoder: decoder, executor: c.Executor, rate: rate, maximum: c.Limits.ResponseBytes, duration: c.MaximumDuration}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "scim", OperationID: managedUsersListOperation, Handler: http.HandlerFunc(h.serve), CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}, MaximumSerializedBytes: uint64(c.Limits.ResponseBytes)})
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op.Wire = managedUsersListWire(c.Limits)
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "scim", Operations: []identityhttp.OperationDescriptor{op}})
}

type managedUsersListHTTP struct {
	network  *identityhttp.NetworkResolver
	decoder  *identityhttp.RequestDecoder
	executor ManagedUsersListExecutor
	rate     *protocolRate
	maximum  int
	duration time.Duration
}

func (h *managedUsersListHTTP) serve(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.duration)
	defer cancel()
	result, denial := h.execute(r.WithContext(ctx))
	if ctx.Err() != nil {
		result, denial = nil, scim.NewError(503, "")
	}
	writeProtocolResponse(w, result, denial)
}

func (h *managedUsersListHTTP) execute(r *http.Request) (body []byte, denial *scim.Error) {
	defer func() {
		if recover() != nil {
			body, denial = nil, scim.NewError(503, "")
		}
	}()
	if r.URL.Path != "/scim/v2/Users" || r.URL.EscapedPath() != r.URL.Path {
		return nil, scim.NewError(404, "")
	}
	if r.Method != http.MethodGet {
		return nil, scim.NewError(405, "")
	}
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
	if r.URL.ForceQuery || r.ContentLength != 0 || r.Body != nil && r.Body != http.NoBody || len(r.TransferEncoding) != 0 || len(r.Trailer) != 0 {
		return nil, scim.NewError(400, "invalidValue")
	}
	if _, present := protocolHeader(r, "Content-Encoding"); present {
		return nil, scim.NewError(415, "")
	}
	if _, present := protocolHeader(r, "If-Match"); present {
		return nil, scim.NewError(400, "invalidValue")
	}
	query, err := managedUsersListQuery(h.decoder, r)
	if err != nil {
		return nil, scim.NewError(400, "invalidValue")
	}
	if _, _, err := h.decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil {
		return nil, scim.NewError(400, "invalidValue")
	}
	credential, _, err := h.decoder.Bearer(r, identityhttp.HeaderRequired)
	if err != nil {
		return nil, scim.NewError(401, "")
	}
	request := scim.Request{Operation: scim.UserList, Credential: credential, Query: query}
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
	response, err := h.executor.ExecuteManagedAdmittedRead(r.Context(), facts.TenantID(), request, gate)
	if err != nil {
		var protocol *scim.Error
		if errors.As(err, &protocol) && protocol != nil {
			return nil, protocol
		}
		return nil, scim.NewError(503, "")
	}
	if calls != 1 || !admitted || response.Status != 200 || response.ContentType != scimMedia || response.ETag != "" || response.Location != "" || len(response.Body) == 0 || len(response.Body) > h.maximum || !json.Valid(response.Body) || r.Context().Err() != nil {
		return nil, scim.NewError(503, "")
	}
	return response.Body, nil
}

func managedUsersListQuery(decoder *identityhttp.RequestDecoder, r *http.Request) (scim.Query, error) {
	parameters, err := decoder.Query(r)
	if err != nil {
		return scim.Query{}, err
	}
	query := scim.Query{}
	for name, entries := range parameters {
		if len(entries) != 1 {
			return scim.Query{}, identityhttp.ErrInvalidInput
		}
		value := entries[0]
		switch name {
		case "filter":
			query.Filter = value
		case "sortBy":
			query.SortBy = value
		case "sortOrder":
			query.SortOrder = value
		case "attributes":
			query.Attributes = value
		case "excludedAttributes":
			query.ExcludedAttributes = value
		case "startIndex", "count":
			// RFC 7644 3.4.2.4 gives below-one startIndex and negative count
			// defined semantics. Preserve them and omission for the native owner;
			// reject only malformed/overflowing machine integers at this boundary.
			number, err := strconv.ParseInt(value, 10, strconv.IntSize)
			if err != nil {
				return scim.Query{}, identityhttp.ErrInvalidInput
			}
			n := int(number)
			if name == "startIndex" {
				query.StartIndex = n
			} else {
				query.Count = &n
			}
		default:
			return scim.Query{}, identityhttp.ErrInvalidInput
		}
	}
	return query, nil
}
