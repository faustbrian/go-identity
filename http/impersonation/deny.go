package impersonationhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/impersonation"
	impersonationpg "github.com/faustbrian/go-identity/impersonation/postgres"
	"github.com/faustbrian/go-identity/session"
)

const denyPath = "/v1/impersonation/deny"

var denyOperation = identity.FeatureOperation{
	Owner: "identity/impersonation", OperationID: "identity.impersonation.deny",
	SchemaID: "impersonation-deny", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired,
}

// DenyService owns original session authentication and action authorization,
// protected denial effects, and the command journal. PrepareDenial must not
// mutate durable state. It supplies the authenticated actor for the rate debit.
type DenyService interface {
	PrepareDenial(context.Context, impersonationpg.DenyInput) (impersonationpg.PreparedCommand, error)
	Execute(context.Context, impersonationpg.PreparedCommand) (identity.CommandResult, error)
}

// DenyRate is the shared, audited canonical administrative quota. It accepts
// resolver-owned tenant and IP facts and the admitted ordinary actor. Nil
// error means admitted and has no retry hint; audited limit responses carry
// whole seconds. The owner must support concurrent bounded calls.
type DenyRate interface {
	Configured() bool
	AdmitImpersonationDeny(context.Context, identityhttp.NetworkFacts, identity.UserID) (time.Duration, error)
}

type DenyConfig struct {
	Network            identityhttp.NetworkConfig
	TrustedOrigins     []identityhttp.Origin
	OriginalCookieName string
	Native             DenyService
	Rate               DenyRate
	MaximumDuration    time.Duration
}

// NewDenyFeature selects only the exact HTTPS administrator denial route.
// It requires the native owner and the already-configured shared quota.
func NewDenyFeature(c DenyConfig) (identityhttp.Feature, error) {
	return newDenyFeatureForQuorum(c, 1)
}

// NewConfigurableDenyFeature selects denial of pending versions 1..required
// for an explicit quorum of 2..32 approvals. Native authorization and the
// shared administrative quota remain required before any denial is executed.
func NewConfigurableDenyFeature(c DenyConfig, requiredApprovals int) (identityhttp.Feature, error) {
	if requiredApprovals < 2 || requiredApprovals > 32 {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	return newDenyFeatureForQuorum(c, requiredApprovals)
}

func newDenyFeatureForQuorum(c DenyConfig, requiredApprovals int) (identityhttp.Feature, error) {
	ingress, err := newCookieIngress(c.Network, c.TrustedOrigins, c.OriginalCookieName, c.MaximumDuration)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op, err := denyDescriptorForQuorum(ingress, c.Native, c.Rate, requiredApprovals)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/impersonation", Operations: []identityhttp.OperationDescriptor{op}})
}

func denyDescriptor(ingress cookieIngress, native DenyService, rate DenyRate) (identityhttp.OperationDescriptor, error) {
	return denyDescriptorForQuorum(ingress, native, rate, 1)
}

func denyDescriptorForQuorum(ingress cookieIngress, native DenyService, rate DenyRate, requiredApprovals int) (identityhttp.OperationDescriptor, error) {
	if missingOwner(native) || missingOwner(rate) || !rate.Configured() {
		return identityhttp.OperationDescriptor{}, identityhttp.ErrInvalidInput
	}
	op, err := canonicalCookieOperation(denyOperation.OperationID, denyHandler{cookieIngress: ingress, native: native, rate: rate, maximumPendingVersion: uint64(requiredApprovals)})
	if err == nil {
		op.Wire = denyWireForPendingVersions(ingress.parentCookie, requiredApprovals)
	}
	return op, err
}

type denyHandler struct {
	cookieIngress
	native                DenyService
	rate                  DenyRate
	maximumPendingVersion uint64
}

type denyResponse struct {
	Denied    bool                  `json:"denied"`
	Outcome   string                `json:"commitOutcome"`
	CommandID identity.CommandID    `json:"commandID,omitempty"`
	GrantID   impersonation.GrantID `json:"grantID,omitempty"`
	Error     string                `json:"error,omitempty"`
}

func (h denyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r == nil || r.URL == nil {
		writeJSON(w, 400, denyFailure("invalid_request"))
		return
	}
	if r.URL.EscapedPath() != denyPath || r.URL.Path != denyPath {
		writeJSON(w, 404, denyFailure("not_found"))
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, 405, denyFailure("method_not_allowed"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.duration)
	defer cancel()
	if err := h.denyRequest(w, r.WithContext(ctx)); err != nil {
		status, code := transportError(err)
		writeJSON(w, status, denyFailure(code))
	}
}

func (h denyHandler) denyRequest(w http.ResponseWriter, r *http.Request) error {
	input, facts, err := h.decodeDenial(r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	if err := ctx.Err(); err != nil {
		return err
	}
	prepared, err := h.native.PrepareDenial(ctx, input)
	if err != nil {
		return err
	}
	binding, err := prepared.Binding()
	if err != nil || !validDenialBinding(binding, input) {
		return identity.UnavailableError{}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	retry, err := h.rate.AdmitImpersonationDeny(ctx, facts, identity.UserID(binding.ActorID))
	if err := ctx.Err(); err != nil {
		return err
	}
	if errors.Is(err, identityhttp.ErrRateLimited) && retry >= time.Second && retry <= time.Minute && retry%time.Second == 0 {
		w.Header().Set("Retry-After", strconv.FormatInt(int64(retry/time.Second), 10))
		writeJSON(w, http.StatusTooManyRequests, denyFailure("rate_limited"))
		return nil
	}
	if err != nil || retry != 0 {
		return identity.UnavailableError{}
	}
	result, err := h.native.Execute(ctx, prepared)
	writeDenialForVersion(ctx, w, binding, result, err, input.ExpectedVersion)
	return nil
}

func (h denyHandler) decodeDenial(r *http.Request) (impersonationpg.DenyInput, identityhttp.NetworkFacts, error) {
	var input impersonationpg.DenyInput
	var empty identityhttp.NetworkFacts
	if r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Trailer) != 0 {
		return input, empty, identityhttp.DecodeError{}
	}
	if _, _, err := h.decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil {
		return input, empty, err
	}
	facts, err := h.facts(r)
	if err != nil {
		return input, empty, err
	}
	actor, _, err := h.decoder.CookieBearer(r, h.parentCookie, identityhttp.HeaderRequired)
	if err != nil {
		return input, empty, err
	}
	fields, err := identityhttp.DecodeJSON[map[string]json.RawMessage](h.decoder, r)
	if err != nil {
		return input, empty, err
	}
	var grantID, reason string
	var expected uint64
	if len(fields) != 3 || json.Unmarshal(fields["grantID"], &grantID) != nil ||
		json.Unmarshal(fields["expectedVersion"], &expected) != nil || expected < 1 || expected > h.maximumPendingVersion ||
		json.Unmarshal(fields["reason"], &reason) != nil {
		return input, empty, identityhttp.DecodeError{}
	}
	grant, err := identity.ParseCommandID(grantID)
	if err != nil {
		return input, empty, identityhttp.DecodeError{}
	}
	private, err := impersonation.NewReason(reason)
	if err != nil {
		return input, empty, err
	}
	csrf, _, err := identityhttp.DecodeCSRF(h.csrf, r, session.ParseCSRFToken)
	if err != nil {
		return input, empty, err
	}
	command, err := identity.NewCommandID()
	if err != nil {
		return input, empty, err
	}
	return impersonationpg.DenyInput{
		Authentication: impersonationpg.Authentication{Tenant: facts.TenantID(), Bearer: actor, CSRF: csrf},
		CommandID:      command, GrantID: impersonation.GrantID(grant), ExpectedVersion: expected, Reason: private,
		Network: facts.ClientIP().String(),
	}, facts, nil
}

func validDenialBinding(b identity.CommandBinding, input impersonationpg.DenyInput) bool {
	return b.CommandID == input.CommandID && b.CorrelationID == string(input.CommandID) &&
		b.TenantID == input.Authentication.Tenant && b.RecordID == string(input.GrantID) &&
		b.ActorKind == authorization.SubjectUser && identity.UserID(b.ActorID) != b.UserID &&
		b.ValidateFor(denyOperation) == nil
}

func writeDenial(ctx context.Context, w http.ResponseWriter, binding identity.CommandBinding, result identity.CommandResult, err error) {
	writeDenialForVersion(ctx, w, binding, result, err, 1)
}

func writeDenialForVersion(ctx context.Context, w http.ResponseWriter, binding identity.CommandBinding, result identity.CommandResult, err error, before uint64) {
	if ctx.Err() != nil && err == nil {
		err = ctx.Err()
	}
	out := denyFailure("unavailable")
	status := http.StatusServiceUnavailable
	switch {
	case result.Binding == binding && validCookieReceipt(result, denyOperation, binding.TenantID, before):
		out.CommandID, out.Outcome = binding.CommandID, commitOutcome(result.Outcome)
		switch {
		case err != nil:
			status, out.Error = transportError(err)
		case result.Outcome == identity.CommitOutcomeCommitted:
			out.Denied, out.GrantID, out.Error = true, impersonation.GrantID(binding.RecordID), ""
			status = http.StatusOK
		case result.Outcome == identity.CommitOutcomeConflict || result.Outcome == identity.CommitOutcomeInProgress || result.Outcome == identity.CommitOutcomeNotCommitted:
			status, out.Error = http.StatusConflict, "conflict"
		}
	case err != nil && result.Outcome == identity.CommitOutcomeInvalid:
		status, out.Error = transportError(err)
	}
	writeJSON(w, status, out)
}

func denyFailure(code string) denyResponse { return denyResponse{Outcome: "none", Error: code} }
