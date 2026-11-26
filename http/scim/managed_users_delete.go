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

const managedUsersDeleteOperation = "identity.scim.user-delete"

// ManagedUsersDeleteExecutor owns issued-bearer authentication, current managed
// connection/organization/policy authority, native target/If-Match validation,
// canonical command recovery and durable source withdrawal. It invokes admission
// exactly once synchronously after authorization and request preflight, before
// command or write effects, using its configured client and tenant. Inputs and
// callback are borrowed only during this bounded call. Implementers must honor
// ctx, support concurrent calls, retain no invocation and start no detached work.
// Only UserDelete is selected. Success is exactly an empty 204; an error exposes
// no partial output and does not itself establish rollback of an uncertain effect.
type ManagedUsersDeleteExecutor interface {
	ExecuteManagedAdmittedDelete(context.Context, identity.TenantID, scim.Request, scim.ProtocolAdmission) (scim.Response, error)
}

// ManagedUsersDeleteConfig explicitly selects conditional managed User Delete.
// Network must match the outer HTTPS router and Limits the effective native
// SCIM profile. Rate borrows the same strict atomic backend, namespace and digest
// key as other selected SCIM protocol routes. Owners must be concurrency-safe
// and outlive requests; no backend/server lifetime is transferred.
// MaximumDuration is 1ms..30s; earlier request/native authority deadlines win.
// Construction validates configuration without owner IO.
type ManagedUsersDeleteConfig struct {
	Network         identityhttp.NetworkConfig
	Executor        ManagedUsersDeleteExecutor
	Rate            ProtocolRateConfig
	Limits          scim.Limits
	MaximumDuration time.Duration
}

// Format redacts borrowed native, network and rate-key custody.
func (ManagedUsersDeleteConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("scimhttp.ManagedUsersDeleteConfig(redacted)"))
}

// MarshalJSON refuses implicit runtime configuration export.
func (ManagedUsersDeleteConfig) MarshalJSON() ([]byte, error) {
	return nil, identityhttp.ErrInvalidInput
}

// MarshalText refuses implicit runtime configuration export.
func (ManagedUsersDeleteConfig) MarshalText() ([]byte, error) {
	return nil, identityhttp.ErrInvalidInput
}

// NewManagedUsersDeleteFeature selects only DELETE /scim/v2/Users/{resource_id}
// with canonical router-supplied PathValue provenance and issued SCIM bearer
// authority. Omission exposes no route or metadata. Combine disjoint Operations
// under one canonical feature ID "scim" for coexistence. A singleton If-Match is
// forwarded unchanged; the native owner retains required/strong-version policy,
// current comparison and tombstone-backed headerless replay. No query, body,
// trailer, Idempotency-Key, cookie authority, retry or response cache is selected.
// The handler reads no body and starts no goroutine. Outer server raw-IO/write
// deadlines remain required. Generic authentication middleware cannot replace
// the native-owned authority/admission window.
func NewManagedUsersDeleteFeature(c ManagedUsersDeleteConfig) (identityhttp.Feature, error) {
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
	h := managedUsersDeleteHTTP{network: network, decoder: decoder, executor: c.Executor, rate: rate, limits: c.Limits, duration: c.MaximumDuration}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{
		Owner: "scim", OperationID: managedUsersDeleteOperation, Handler: http.HandlerFunc(h.serve),
		CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}, MaximumSerializedBytes: uint64(c.Limits.ResponseBytes),
	})
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op.Wire = managedUsersDeleteWire(c.Limits)
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "scim", Operations: []identityhttp.OperationDescriptor{op}})
}

type managedUsersDeleteHTTP struct {
	network  *identityhttp.NetworkResolver
	decoder  *identityhttp.RequestDecoder
	executor ManagedUsersDeleteExecutor
	rate     *protocolRate
	limits   scim.Limits
	duration time.Duration
}

func (h *managedUsersDeleteHTTP) serve(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.duration)
	defer cancel()
	_, denial := h.execute(r.WithContext(ctx))
	if ctx.Err() != nil {
		denial = scim.NewError(503, "")
	}
	if denial != nil {
		writeProtocolResponse(w, nil, denial)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusNoContent)
}

func (h *managedUsersDeleteHTTP) execute(r *http.Request) (response scim.Response, denial *scim.Error) {
	defer func() {
		if recover() != nil {
			response, denial = scim.Response{}, scim.NewError(503, "")
		}
	}()
	resourceID := r.PathValue("resource_id")
	if resourceID == "" || r.URL.Path != "/scim/v2/Users/"+resourceID || r.URL.RawPath != "" || r.URL.EscapedPath() != r.URL.Path {
		return scim.Response{}, scim.NewError(404, "")
	}
	if r.Method != http.MethodDelete {
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
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.ContentLength != 0 || r.Body != nil && r.Body != http.NoBody || len(r.TransferEncoding) != 0 || len(r.Trailer) != 0 {
		return scim.Response{}, scim.NewError(400, "invalidValue")
	}
	for header := range r.Header {
		switch strings.ToLower(header) {
		case "content-encoding":
			return scim.Response{}, scim.NewError(415, "")
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
	// Resolve/decoder reject duplicate security-sensitive headers. Native SCIM
	// owns required and strong If-Match semantics; do not trim or reinterpret it.
	ifMatch, _ := protocolHeader(r, "If-Match")
	request := scim.Request{Operation: scim.UserDelete, Credential: credential, ResourceID: resourceID, IfMatch: scim.Version(ifMatch)}
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
	response, err = h.executor.ExecuteManagedAdmittedDelete(r.Context(), facts.TenantID(), request, gate)
	if err != nil {
		var protocol *scim.Error
		if errors.As(err, &protocol) && protocol != nil {
			return scim.Response{}, protocol
		}
		return scim.Response{}, scim.NewError(503, "")
	}
	if calls != 1 || !admitted || response.Status != http.StatusNoContent || len(response.Body) != 0 || response.ContentType != "" || response.ETag != "" || response.Location != "" || r.Context().Err() != nil {
		return scim.Response{}, scim.NewError(503, "")
	}
	return response, nil
}
