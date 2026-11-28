// Package impersonationhttp adds explicitly selected cookie transport to
// native impersonation grant commands. It does not authenticate ordinary sessions.
package impersonationhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
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
	if missingStopOwner(c.Native) || !strings.HasPrefix(c.OriginalCookieName, "__Host-") ||
		c.OriginalCookieName == "__Host-" || len(c.OriginalCookieName) > 128 ||
		c.OriginalCookieName == ChildCookieName || c.OriginalCookieName == ChildCSRFCookieName ||
		(&http.Cookie{Name: c.OriginalCookieName, Value: "x", Path: "/", Secure: true}).Valid() != nil ||
		c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	network, err := identityhttp.NewNetworkResolver(c.Network)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	decoder, err := identityhttp.NewRequestDecoder(c.Network.Limits)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	guard, err := identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{
		Network: network, TrustedOrigins: c.TrustedOrigins, RefererFallback: identityhttp.RefererFallbackDeny,
	})
	if err != nil {
		return identityhttp.Feature{}, err
	}
	csrf, err := identityhttp.NewCSRFDecoder(identityhttp.CSRFDecoderConfig{Origins: guard, FormField: "csrf_token"})
	if err != nil {
		return identityhttp.Feature{}, err
	}
	handler := stopHandler{network: network, decoder: decoder, origin: guard, csrf: csrf, native: c.Native, parentCookie: c.OriginalCookieName, duration: c.MaximumDuration}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{
		Owner: "identity/impersonation", OperationID: stopOperation.OperationID, Handler: handler,
		CSRF:                   identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny},
		MaximumSerializedBytes: 16384,
	})
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op.Wire = stopWire()
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/impersonation", Operations: []identityhttp.OperationDescriptor{op}})
}

func missingStopOwner(owner StopService) bool {
	if owner == nil {
		return true
	}
	switch v := reflect.ValueOf(owner); v.Kind() {
	case reflect.Pointer, reflect.Chan, reflect.Func, reflect.Map, reflect.Slice, reflect.Interface:
		return v.IsNil()
	default:
		return false
	}
}

type stopHandler struct {
	network      *identityhttp.NetworkResolver
	decoder      *identityhttp.RequestDecoder
	origin       *identityhttp.OriginGuard
	csrf         *identityhttp.CSRFDecoder
	native       StopService
	parentCookie string
	duration     time.Duration
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
		writeStop(w, 400, stopFailure("invalid_request"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.duration)
	defer cancel()
	r = r.WithContext(ctx)
	if r.URL.EscapedPath() != stopPath || r.URL.Path != stopPath {
		writeStop(w, 404, stopFailure("not_found"))
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeStop(w, 405, stopFailure("method_not_allowed"))
		return
	}
	if err := h.stopRequest(w, r); err != nil {
		status, code := stopError(err)
		writeStop(w, status, stopFailure(code))
	}
}

func (h stopHandler) stopRequest(w http.ResponseWriter, r *http.Request) error {
	if r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Trailer) != 0 {
		return identityhttp.DecodeError{}
	}
	if _, _, err := h.decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil {
		return err
	}
	facts, err := h.network.Resolve(r)
	if err != nil || facts.Scheme() != "https" || facts.TenantID() == "" {
		if err != nil && !errors.Is(err, identityhttp.DecodeError{}) {
			return err
		}
		writeStop(w, 421, stopFailure("misdirected_request"))
		return nil
	}
	origin, err := h.origin.Check(r)
	if err != nil || string(origin) != facts.Origin() {
		if err != nil {
			return err
		}
		return identityhttp.OriginError{}
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
	if validStopReceipt(result.Receipt, commandID, facts.TenantID()) {
		out.CommandID = commandID
		out.Outcome = stopOutcome(result.Receipt.Outcome)
		if err == nil && result.Receipt.Outcome == identity.CommitOutcomeCommitted {
			out.Stopped, out.Error = true, ""
			out.ParentResumed = result.Parent.ValidateAt(time.Now()) == nil
			for _, name := range []string{ChildCookieName, ChildCSRFCookieName} {
				http.SetCookie(w, &http.Cookie{Name: name, Path: "/", Secure: true, HttpOnly: name == ChildCookieName,
					SameSite: http.SameSiteStrictMode, MaxAge: -1, Expires: time.Unix(1, 0).UTC()})
			}
			status = http.StatusOK
		} else if err != nil {
			status, out.Error = stopError(err)
		} else if result.Receipt.Outcome == identity.CommitOutcomeConflict || result.Receipt.Outcome == identity.CommitOutcomeInProgress || result.Receipt.Outcome == identity.CommitOutcomeNotCommitted {
			status, out.Error = http.StatusConflict, "conflict"
		}
	} else if err != nil && result.Receipt.Outcome == identity.CommitOutcomeInvalid {
		status, out.Error = stopError(err)
	}
	writeStop(w, status, out)
	return nil
}

func validStopReceipt(r identity.CommandResult, command identity.CommandID, tenant identity.TenantID) bool {
	b := r.Binding
	if r.Validate() != nil || b.CommandID != command || b.TenantID != tenant || b.ActorKind != authorization.SubjectUser ||
		b.UserID == identity.UserID(b.ActorID) || b.CorrelationID != string(command) ||
		b.ValidateFor(stopOperation) != nil || r.Feature == nil || r.Feature.Operation != stopOperation {
		return false
	}
	record, err := identity.ParseCommandID(b.RecordID)
	return err == nil && record != command && (r.Outcome != identity.CommitOutcomeCommitted ||
		r.Feature.BeforeVersion == 3 && r.Feature.AfterVersion == 4)
}

func stopOutcome(outcome identity.CommitOutcome) string {
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

func stopError(err error) (int, string) {
	var invalid identity.InvalidInputError
	var conflict identity.ConflictError
	var pending identity.InProgressError
	switch {
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

func writeStop(w http.ResponseWriter, status int, body stopResponse) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
