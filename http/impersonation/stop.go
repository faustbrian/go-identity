// Package impersonationhttp adds explicitly selected cookie transport to
// native impersonation grant commands. It does not authenticate ordinary sessions.
package impersonationhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/impersonation"
	impersonationpg "github.com/faustbrian/go-identity/impersonation/postgres"
	"github.com/faustbrian/go-identity/session"
)

const (
	// ChildCookieName is the dedicated HttpOnly derived credential cookie.
	ChildCookieName = "__Host-identity_impersonation"
	// ChildCSRFCookieName is the separately readable child synchronizer cookie.
	ChildCSRFCookieName = "__Host-identity_impersonation_csrf"
	stopPath            = "/v1/impersonation/stop"
)

var stopOperation = identity.FeatureOperation{
	Owner: "identity/impersonation", OperationID: "identity.impersonation.stop",
	SchemaID: "impersonation-stop", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired,
}

// StopService owns exact native child/session authorization, rate, protected
// effects and replay. Supply the opted-in PostgreSQL service; a substitute
// must implement the same guarantees, honor context and allow concurrent use.
type StopService interface {
	PrepareStop(context.Context, impersonationpg.StopInput) (impersonationpg.PreparedStop, error)
	ExecuteStop(context.Context, impersonationpg.PreparedStop, authentication.BearerCredential) (impersonationpg.StopResult, error)
}

type StopConfig struct {
	Network            identityhttp.NetworkConfig
	TrustedOrigins     []identityhttp.Origin
	OriginalCookieName string
	Native             StopService
	MaximumDuration    time.Duration
}

// NewStopFeature selects only the exact HTTPS child-cookie self-stop route.
// Construction validates the transport profile and never performs I/O.
func NewStopFeature(c StopConfig) (identityhttp.Feature, error) {
	return newStopFeatureForQuorum(c, 1)
}

// NewConfigurableStopFeature selects child-bound Stop for an explicit quorum
// of 2..32 approvals. Only its exact active-version transition clears cookies.
func NewConfigurableStopFeature(c StopConfig, requiredApprovals int) (identityhttp.Feature, error) {
	if requiredApprovals < 2 || requiredApprovals > 32 {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	return newStopFeatureForQuorum(c, requiredApprovals)
}

func newStopFeatureForQuorum(c StopConfig, requiredApprovals int) (identityhttp.Feature, error) {
	if missingOwner(c.Native) {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	ingress, err := newCookieIngress(c.Network, c.TrustedOrigins, c.OriginalCookieName, c.MaximumDuration)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op, err := stopDescriptorForQuorum(ingress, c.Native, requiredApprovals)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/impersonation", Operations: []identityhttp.OperationDescriptor{op}})
}

func stopDescriptor(ingress cookieIngress, native StopService) (identityhttp.OperationDescriptor, error) {
	return stopDescriptorForQuorum(ingress, native, 1)
}

func stopDescriptorForQuorum(ingress cookieIngress, native StopService, requiredApprovals int) (identityhttp.OperationDescriptor, error) {
	op, err := canonicalCookieOperation(stopOperation.OperationID, stopHandler{cookieIngress: ingress, native: native, activeVersion: uint64(requiredApprovals) + 2})
	if err == nil {
		op.Wire = stopWire()
		if requiredApprovals > 1 {
			op.Wire = configurableStopWire(requiredApprovals)
		}
	}
	return op, err
}

type stopHandler struct {
	cookieIngress
	native        StopService
	activeVersion uint64
}

type stopResponse struct {
	Stopped       bool               `json:"stopped"`
	ParentResumed bool               `json:"parentResumed"`
	Outcome       string             `json:"commitOutcome"`
	CommandID     identity.CommandID `json:"commandID,omitempty"`
	Error         string             `json:"error,omitempty"`
}

func (h stopHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r == nil || r.URL == nil {
		writeJSON(w, 400, stopFailure("invalid_request"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.duration)
	defer cancel()
	r = r.WithContext(ctx)
	if r.URL.EscapedPath() != stopPath || r.URL.Path != stopPath {
		writeJSON(w, 404, stopFailure("not_found"))
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, 405, stopFailure("method_not_allowed"))
		return
	}
	if err := h.stopRequest(w, r); err != nil {
		status, code := transportError(err)
		writeJSON(w, status, stopFailure(code))
	}
}

func (h stopHandler) stopRequest(w http.ResponseWriter, r *http.Request) error {
	if r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Trailer) != 0 {
		return identityhttp.DecodeError{}
	}
	if _, _, err := h.decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil {
		return err
	}
	facts, err := h.facts(r)
	if err != nil {
		return err
	}
	child, _, err := h.decoder.CookieBearer(r, ChildCookieName, identityhttp.HeaderRequired)
	if err != nil {
		return err
	}
	parent, _, err := h.decoder.CookieBearer(r, h.parentCookie, identityhttp.HeaderOptional)
	if err != nil {
		return err
	}
	if _, err := identityhttp.DecodeJSON[struct{}](h.decoder, r); err != nil {
		return err
	}
	csrf, _, err := identityhttp.DecodeCSRF(h.csrf, r, session.ParseCSRFToken)
	if err != nil {
		return err
	}
	commandID, err := identity.NewCommandID()
	if err != nil {
		return err
	}
	ctx := r.Context()
	prepared, err := h.native.PrepareStop(ctx, impersonationpg.StopInput{
		Authentication: impersonationpg.StopAuthentication{Tenant: facts.TenantID(), Bearer: child.Token(), CSRF: csrf},
		CommandID:      commandID, Network: facts.ClientIP().String(),
	})
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	result, err := h.native.ExecuteStop(ctx, prepared, parent)
	if ctx.Err() != nil && err == nil {
		err = ctx.Err()
	}
	out := stopFailure("unavailable")
	status := http.StatusServiceUnavailable
	if result.Receipt.Binding.CommandID == commandID && validCookieReceipt(result.Receipt, stopOperation, facts.TenantID(), h.activeVersion) {
		out.CommandID = commandID
		out.Outcome = commitOutcome(result.Receipt.Outcome)
		if err == nil && result.Receipt.Outcome == identity.CommitOutcomeCommitted {
			out.Stopped, out.Error = true, ""
			out.ParentResumed = result.Parent.ValidateAt(time.Now()) == nil
			for _, name := range []string{ChildCookieName, ChildCSRFCookieName} {
				http.SetCookie(w, &http.Cookie{Name: name, Path: "/", Secure: true, HttpOnly: name == ChildCookieName,
					SameSite: http.SameSiteStrictMode, MaxAge: -1, Expires: time.Unix(1, 0).UTC()})
			}
			status = http.StatusOK
		} else if err != nil {
			status, out.Error = transportError(err)
		} else if result.Receipt.Outcome == identity.CommitOutcomeConflict || result.Receipt.Outcome == identity.CommitOutcomeInProgress || result.Receipt.Outcome == identity.CommitOutcomeNotCommitted {
			status, out.Error = http.StatusConflict, "conflict"
		}
	} else if err != nil && result.Receipt.Outcome == identity.CommitOutcomeInvalid {
		status, out.Error = transportError(err)
	}
	writeJSON(w, status, out)
	return nil
}

func validStopReceipt(r identity.CommandResult, command identity.CommandID, tenant identity.TenantID) bool {
	return r.Binding.CommandID == command && validCookieReceipt(r, stopOperation, tenant, 3)
}

func validCookieReceipt(r identity.CommandResult, op identity.FeatureOperation, tenant identity.TenantID, before uint64) bool {
	b := r.Binding
	if r.Validate() != nil || b.TenantID != tenant || b.ActorKind != authorization.SubjectUser ||
		b.UserID == identity.UserID(b.ActorID) || b.CorrelationID != string(b.CommandID) ||
		b.ValidateFor(op) != nil || r.Feature == nil || r.Feature.Operation != op {
		return false
	}
	record, err := identity.ParseCommandID(b.RecordID)
	return err == nil && record != b.CommandID && (r.Outcome != identity.CommitOutcomeCommitted ||
		r.Feature.BeforeVersion == before && r.Feature.AfterVersion == before+1)
}

func commitOutcome(outcome identity.CommitOutcome) string {
	switch outcome {
	case identity.CommitOutcomeCommitted:
		return "committed"
	case identity.CommitOutcomeUnknown:
		return "unknown"
	case identity.CommitOutcomeNotCommitted:
		return "not_committed"
	case identity.CommitOutcomeConflict:
		return "conflict"
	case identity.CommitOutcomeInProgress:
		return "in_progress"
	default:
		return "none"
	}
}

func transportError(err error) (int, string) {
	var invalid identity.InvalidInputError
	var conflict identity.ConflictError
	var pending identity.InProgressError
	switch {
	case errors.Is(err, errMisdirected):
		return http.StatusMisdirectedRequest, "misdirected_request"
	case errors.Is(err, identityhttp.CSRFError{}), errors.Is(err, identityhttp.OriginError{}), errors.Is(err, identity.ForbiddenError{}), errors.Is(err, session.ErrCSRFDenied), errors.Is(err, session.ErrUnauthenticated), errors.Is(err, impersonation.ErrExpired):
		return http.StatusForbidden, "denied"
	case errors.Is(err, identityhttp.DecodeError{}), errors.As(err, &invalid), errors.Is(err, impersonation.ErrInvalidInput):
		return http.StatusBadRequest, "invalid_request"
	case errors.As(err, &conflict), errors.As(err, &pending), errors.Is(err, impersonation.ErrConflict):
		return http.StatusConflict, "conflict"
	default:
		return http.StatusServiceUnavailable, "unavailable"
	}
}

func stopFailure(code string) stopResponse { return stopResponse{Outcome: "none", Error: code} }

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
