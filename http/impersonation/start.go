package impersonationhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/impersonation"
	impersonationpg "github.com/faustbrian/go-identity/impersonation/postgres"
	"github.com/faustbrian/go-identity/session"
)

const startPath = "/v1/impersonation/start"

var startOperation = identity.FeatureOperation{
	Owner: "identity/impersonation", OperationID: "identity.impersonation.start",
	SchemaID: "impersonation-start", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired,
}

// StartService owns keyed native grant activation and exactly-once credential
// delivery for an independently approved grant. Supply the selected native
// keyed service. It must honor context and support concurrent invocations.
type StartService interface {
	Start(context.Context, impersonationpg.KeyedStartInput) (impersonationpg.StoppableActivationResult, error)
}

type StartConfig struct {
	Network            identityhttp.NetworkConfig
	TrustedOrigins     []identityhttp.Origin
	OriginalCookieName string
	Native             StartService
	MaximumDuration    time.Duration
}

// NewStartFeature selects only the approved-grant Start route. It does not
// select any other impersonation operation or perform runtime I/O.
func NewStartFeature(c StartConfig) (identityhttp.Feature, error) {
	return newStartFeature(c, nil, nil, nil)
}

// NewConfigurableStartFeature selects Start for one explicit positive quorum
// of 2..32 approvals. The native owner must select that same immutable policy;
// only its exact approved-version receipt can produce a successful response.
func NewConfigurableStartFeature(c StartConfig, requiredApprovals int) (identityhttp.Feature, error) {
	if requiredApprovals < 2 || requiredApprovals > 32 {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	return newStartFeatureForQuorum(c, nil, nil, nil, requiredApprovals)
}

// NewStartStopFeature selects Start and Stop together with the same HTTPS,
// Origin, original-cookie and deadline configuration. Both owners are required.
func NewStartStopFeature(c StartConfig, stop StopService) (identityhttp.Feature, error) {
	if missingOwner(stop) {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	return newStartFeature(c, stop, nil, nil)
}

// NewStartStopDenyFeature selects all three operations over the same HTTPS
// ingress. Each remains owned by its native service and only Deny uses rate.
func NewStartStopDenyFeature(c StartConfig, stop StopService, deny DenyService, rate DenyRate) (identityhttp.Feature, error) {
	if missingOwner(stop) || missingOwner(deny) || missingOwner(rate) {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	return newStartFeature(c, stop, deny, rate)
}

func newStartFeature(c StartConfig, stop StopService, deny DenyService, rate DenyRate) (identityhttp.Feature, error) {
	return newStartFeatureForQuorum(c, stop, deny, rate, 1)
}

func newStartFeatureForQuorum(c StartConfig, stop StopService, deny DenyService, rate DenyRate, requiredApprovals int) (identityhttp.Feature, error) {
	if missingOwner(c.Native) {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	ingress, err := newCookieIngress(c.Network, c.TrustedOrigins, c.OriginalCookieName, c.MaximumDuration)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	approvedVersion := uint64(requiredApprovals) + 1
	start, err := canonicalCookieOperation(startOperation.OperationID, startHandler{cookieIngress: ingress, native: c.Native, approvedVersion: approvedVersion})
	if err != nil {
		return identityhttp.Feature{}, err
	}
	start.Wire = startWireForVersion(c.OriginalCookieName, approvedVersion)
	ops := []identityhttp.OperationDescriptor{start}
	if stop != nil {
		op, err := stopDescriptor(ingress, stop)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		ops = append(ops, op)
	}
	if deny != nil {
		op, err := denyDescriptor(ingress, deny, rate)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		ops = append(ops, op)
	}
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/impersonation", Operations: ops})
}

type startHandler struct {
	cookieIngress
	native          StartService
	approvedVersion uint64
}

type startResponse struct {
	Started          bool                  `json:"started"`
	CredentialIssued bool                  `json:"credentialIssued"`
	Outcome          string                `json:"commitOutcome"`
	CommandID        identity.CommandID    `json:"commandID,omitempty"`
	GrantID          impersonation.GrantID `json:"grantID,omitempty"`
	ActorID          identity.ActorID      `json:"actorID,omitempty"`
	TargetID         identity.UserID       `json:"targetID,omitempty"`
	Error            string                `json:"error,omitempty"`
}

func (h startHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r == nil || r.URL == nil {
		writeJSON(w, 400, startFailure("invalid_request"))
		return
	}
	if r.URL.EscapedPath() != startPath || r.URL.Path != startPath {
		writeJSON(w, 404, startFailure("not_found"))
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, 405, startFailure("method_not_allowed"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.duration)
	defer cancel()
	input, err := h.decodeStart(r.WithContext(ctx))
	if err != nil {
		status, code := transportError(err)
		writeJSON(w, status, startFailure(code))
		return
	}
	if err := ctx.Err(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, startFailure("unavailable"))
		return
	}
	result, err := h.native.Start(ctx, input)
	h.writeStart(ctx, w, input, result, err)
}

func (h startHandler) decodeStart(r *http.Request) (impersonationpg.KeyedStartInput, error) {
	var zero impersonationpg.KeyedStartInput
	if r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Trailer) != 0 {
		return zero, identityhttp.DecodeError{}
	}
	key, _, err := h.decoder.IdempotencyKey(r, identityhttp.HeaderRequired)
	if err != nil {
		return zero, err
	}
	facts, err := h.facts(r)
	if err != nil {
		return zero, err
	}
	ordinary, _, err := h.decoder.CookieBearer(r, h.parentCookie, identityhttp.HeaderRequired)
	if err != nil {
		return zero, err
	}
	fields, err := identityhttp.DecodeJSON[map[string]json.RawMessage](h.decoder, r)
	if err != nil {
		return zero, err
	}
	var grantID string
	var version uint64
	if len(fields) != 2 || json.Unmarshal(fields["grantID"], &grantID) != nil ||
		json.Unmarshal(fields["expectedVersion"], &version) != nil || version != h.approvedVersion {
		return zero, identityhttp.DecodeError{}
	}
	if _, err := identity.ParseCommandID(grantID); err != nil {
		return zero, identityhttp.DecodeError{}
	}
	csrf, _, err := identityhttp.DecodeCSRF(h.csrf, r, session.ParseCSRFToken)
	if err != nil {
		return zero, err
	}
	return impersonationpg.KeyedStartInput{
		Authentication: impersonationpg.Authentication{Tenant: facts.TenantID(), Bearer: ordinary, CSRF: csrf},
		GrantID:        impersonation.GrantID(grantID), ExpectedVersion: version, Network: facts.ClientIP().String(), Key: key,
	}, nil
}

func (h startHandler) writeStart(ctx context.Context, w http.ResponseWriter, input impersonationpg.KeyedStartInput, result impersonationpg.StoppableActivationResult, err error) {
	if ctx.Err() != nil && err == nil {
		err = ctx.Err()
	}
	out := startFailure("unavailable")
	status := http.StatusServiceUnavailable
	receipt := result.Receipt
	if receipt.Binding.RecordID != string(input.GrantID) || !validCookieReceipt(receipt, startOperation, input.Authentication.Tenant, h.approvedVersion) {
		if err != nil && receipt.Outcome == identity.CommitOutcomeInvalid {
			status, out.Error = transportError(err)
		}
		writeJSON(w, status, out)
		return
	}
	out.CommandID, out.Outcome = receipt.Binding.CommandID, commitOutcome(receipt.Outcome)
	switch {
	case err != nil:
		status, out.Error = transportError(err)
	case receipt.Outcome == identity.CommitOutcomeCommitted:
		cookies, ok := startCookies(result)
		if ok && ctx.Err() == nil {
			for _, cookie := range cookies {
				http.SetCookie(w, cookie)
			}
			status, out.Error, out.Started = http.StatusOK, "", true
			out.CredentialIssued = len(cookies) == 2
			out.GrantID, out.ActorID, out.TargetID = input.GrantID, receipt.Binding.ActorID, receipt.Binding.UserID
		}
	case receipt.Outcome == identity.CommitOutcomeConflict || receipt.Outcome == identity.CommitOutcomeInProgress || receipt.Outcome == identity.CommitOutcomeNotCommitted:
		status, out.Error = http.StatusConflict, "conflict"
	}
	writeJSON(w, status, out)
}

func startFailure(code string) startResponse { return startResponse{Outcome: "none", Error: code} }

// Hold both headers until the entire first-delivery pair is valid. Receipt-only
// recovery changes neither the ordinary nor the already held child cookies.
func startCookies(result impersonationpg.StoppableActivationResult) ([]*http.Cookie, bool) {
	noBearer := result.Credential == (impersonationpg.DerivedCredential{})
	noCSRF := result.StopCSRF == (session.CSRFToken{})
	if noBearer || noCSRF {
		return nil, noBearer && noCSRF
	}
	bearer, err := result.Credential.Reveal()
	if err != nil {
		return nil, false
	}
	csrf, err := result.StopCSRF.Reveal()
	if err != nil {
		return nil, false
	}
	cookies := []*http.Cookie{
		{Name: ChildCookieName, Value: bearer, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 900},
		{Name: ChildCSRFCookieName, Value: csrf, Path: "/", Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: 900},
	}
	for _, cookie := range cookies {
		if cookie.Valid() != nil || cookie.Value == "" {
			return nil, false
		}
	}
	return cookies, true
}
