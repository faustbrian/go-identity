package sessionhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
)

const adminSessionRevokeOperation = "identity.admin.session-revoke"
const adminSessionRevokePath = "/v1/admin/session-revoke"

// AdminSessionRevokeInput borrows original ordinary-session custody and exact
// target intent for one bounded native call. It grants no actor authority and
// must not be logged, persisted or retained beyond that call.
type AdminSessionRevokeInput struct {
	TenantID        identity.TenantID
	TargetSubjectID identity.SubjectID
	SessionID       string
	Bearer          authentication.BearerCredential
	CSRF            session.CSRFToken
}

// Format suppresses original credentials and private target intent.
func (AdminSessionRevokeInput) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "sessionhttp.AdminSessionRevokeInput(redacted)")
}

// MarshalJSON denies implicit original-credential serialization.
func (AdminSessionRevokeInput) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText denies implicit text and map-key custody export.
func (AdminSessionRevokeInput) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// AdminSessionRevokeOutput distinguishes a confirmed mutation (true and a
// positive native version) from a non-disclosing no-op (false and zero).
// Every error invalidates the entire output, including any apparent success.
type AdminSessionRevokeOutput struct {
	Revoked bool
	Version uint64
}

// AdminSessionRevokeOwner authenticates the original ordinary session and
// authorizes the exact target before synchronously calling admission once with
// its derived actor. It must honor admission errors, validate stored-session
// CSRF atomically with native work, never retain the callback, and support
// concurrent bounded calls. Unknown outcomes must return an error, never a
// confirmed mutation or no-op. This repeat operation owns no transport key.
type AdminSessionRevokeOwner interface {
	AdminSessionRevokeWithAdmission(context.Context, AdminSessionRevokeInput, func(context.Context, identity.UserID) error) (AdminSessionRevokeOutput, error)
}

// AdminSessionRevokeConfig opts into one administrator mutation. Network and
// origins are copied immutable policies. Native and the shared listing quota
// are borrowed and must outlive concurrent requests. MaximumDuration is
// 1ms..30s and never extends an earlier inbound deadline.
type AdminSessionRevokeConfig struct {
	Network            identityhttp.NetworkConfig
	TrustedOrigins     []identityhttp.Origin
	OriginalCookieName string
	Native             AdminSessionRevokeOwner
	Rate               AdminSessionListRate
	MaximumDuration    time.Duration
}

// NewAdminSessionRevokeFeature constructs only selected canonical repeat POST
// /v1/admin/session-revoke without IO or implicit registration. An exact mapped
// HTTPS Origin, original __Host- cookie and stored-session X-CSRF-Token are
// required without fallback. Strict JSON contains only userID and sessionID;
// query, trailers, idempotency keys and alternate credentials deny before native
// work. Responses never issue or clear cookies, expose credentials, or turn
// native errors into success. No-op wire responses omit the zero version.
func NewAdminSessionRevokeFeature(c AdminSessionRevokeConfig) (identityhttp.Feature, error) {
	if adminStatusMissing(c.Native) || adminStatusMissing(c.Rate) || !c.Rate.Configured() ||
		c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second ||
		!strings.HasPrefix(c.OriginalCookieName, "__Host-") || c.OriginalCookieName == "__Host-" || len(c.OriginalCookieName) > 128 ||
		c.OriginalCookieName == "__Host-identity_impersonation" || c.OriginalCookieName == "__Host-identity_impersonation_csrf" ||
		(&http.Cookie{Name: c.OriginalCookieName, Value: "x", Path: "/", Secure: true}).Valid() != nil {
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
	origin, err := identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{Network: network, TrustedOrigins: c.TrustedOrigins, RefererFallback: identityhttp.RefererFallbackDeny})
	if err != nil {
		return identityhttp.Feature{}, err
	}
	csrf, err := identityhttp.NewCSRFDecoder(identityhttp.CSRFDecoderConfig{Origins: origin, FormField: "csrf_token"})
	if err != nil {
		return identityhttp.Feature{}, err
	}
	h := adminSessionRevokeHandler{network: network, decoder: decoder, origin: origin, csrf: csrf, cookie: c.OriginalCookieName, native: c.Native, rate: c.Rate, duration: c.MaximumDuration}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{
		Owner: "identity/session", OperationID: adminSessionRevokeOperation, Handler: h,
		CSRF:                   identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny},
		MaximumSerializedBytes: 1024,
	})
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op.Wire = adminSessionRevokeWire(c.OriginalCookieName)
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/session", Operations: []identityhttp.OperationDescriptor{op}})
}

type adminSessionRevokeHandler struct {
	network  *identityhttp.NetworkResolver
	decoder  *identityhttp.RequestDecoder
	origin   *identityhttp.OriginGuard
	csrf     *identityhttp.CSRFDecoder
	cookie   string
	native   AdminSessionRevokeOwner
	rate     AdminSessionListRate
	duration time.Duration
}

func (h adminSessionRevokeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r == nil || r.URL == nil {
		writeAdminSessionListError(w, 400, "invalid_request")
		return
	}
	if r.URL.Path != adminSessionRevokePath || r.URL.EscapedPath() != adminSessionRevokePath {
		writeAdminSessionListError(w, 404, "not_found")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeAdminSessionListError(w, 405, "method_not_allowed")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.duration)
	defer cancel()
	input, facts, err := h.decode(r.WithContext(ctx))
	if err != nil {
		status, code := adminSessionListError(err)
		writeAdminSessionListError(w, status, code)
		return
	}
	if ctx.Err() != nil {
		writeAdminSessionListError(w, 503, "unavailable")
		return
	}
	var attempted bool
	var admissionErr error
	var retry time.Duration
	result, err := h.native.AdminSessionRevokeWithAdmission(ctx, input, func(bounded context.Context, actor identity.UserID) error {
		if attempted || bounded == nil || bounded.Err() != nil || ctx.Err() != nil || !adminSessionListID(string(actor)) {
			attempted, retry, admissionErr = true, 0, identity.UnavailableError{}
			return admissionErr
		}
		deadline, hasDeadline := bounded.Deadline()
		outerDeadline, _ := ctx.Deadline()
		if !hasDeadline || deadline.After(outerDeadline) {
			attempted, retry, admissionErr = true, 0, identity.UnavailableError{}
			return admissionErr
		}
		attempted = true
		retry, admissionErr = h.rate.AdmitSessionAdministration(bounded, facts, adminSessionRevokeOperation, actor)
		if errors.Is(admissionErr, identityhttp.ErrRateLimited) && retry >= time.Second && retry <= time.Minute && retry%time.Second == 0 {
			return admissionErr
		}
		if admissionErr != nil || retry != 0 {
			admissionErr = identity.UnavailableError{}
		}
		return admissionErr
	})
	switch {
	case ctx.Err() != nil:
		writeAdminSessionListError(w, 503, "unavailable")
	case errors.Is(admissionErr, identityhttp.ErrRateLimited):
		w.Header().Set("Retry-After", strconv.FormatInt(int64(retry/time.Second), 10))
		writeAdminSessionListError(w, 429, "rate_limited")
	case admissionErr != nil:
		writeAdminSessionListError(w, 503, "unavailable")
	case err != nil:
		// A native error invalidates even a plausible partial result; unknown
		// commit must never look like either a confirmed revoke or a no-op.
		status, code := adminSessionListError(err)
		writeAdminSessionListError(w, status, code)
	case !attempted || result.Revoked != (result.Version > 0):
		writeAdminSessionListError(w, 503, "unavailable")
	default:
		body, marshalErr := json.Marshal(struct {
			Revoked bool   `json:"revoked"`
			Version uint64 `json:"version,omitempty"`
		}{Revoked: result.Revoked, Version: result.Version})
		if marshalErr != nil || ctx.Err() != nil {
			writeAdminSessionListError(w, 503, "unavailable")
			return
		}
		response(w, 200, string(body))
	}
}

func (h adminSessionRevokeHandler) decode(r *http.Request) (AdminSessionRevokeInput, identityhttp.NetworkFacts, error) {
	var empty AdminSessionRevokeInput
	var noFacts identityhttp.NetworkFacts
	if r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Trailer) != 0 {
		return empty, noFacts, identityhttp.DecodeError{}
	}
	if _, _, err := h.decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil {
		return empty, noFacts, err
	}
	facts, err := h.network.Resolve(r)
	if err != nil {
		var malformed identityhttp.DecodeError
		if errors.As(err, &malformed) {
			err = adminStatusMisdirected{}
		}
		return empty, noFacts, err
	}
	if facts.Realm() != identityhttp.RealmTenant || facts.Scheme() != "https" || facts.TenantID() == "" {
		return empty, noFacts, adminStatusMisdirected{}
	}
	if _, err := h.origin.CheckBound(r, identityhttp.Origin(facts.Origin())); err != nil {
		return empty, noFacts, err
	}
	bearer, _, err := h.decoder.CookieBearer(r, h.cookie, identityhttp.HeaderRequired)
	if err != nil {
		return empty, noFacts, err
	}
	if _, err := session.ParseToken(bearer.Token()); err != nil {
		return empty, noFacts, identityhttp.DecodeError{}
	}
	fields, err := identityhttp.DecodeJSON[map[string]json.RawMessage](h.decoder, r)
	if err != nil {
		return empty, noFacts, err
	}
	var userID, sessionID string
	if len(fields) != 2 || !adminStatusValue(fields["userID"], &userID) || !adminSessionListID(userID) ||
		!adminStatusValue(fields["sessionID"], &sessionID) || !adminSessionListID(sessionID) {
		return empty, noFacts, identityhttp.DecodeError{}
	}
	csrf, _, err := identityhttp.DecodeCSRF(h.csrf, r, session.ParseCSRFToken)
	if err != nil {
		return empty, noFacts, err
	}
	return AdminSessionRevokeInput{TenantID: facts.TenantID(), TargetSubjectID: identity.SubjectID(userID), SessionID: sessionID, Bearer: bearer, CSRF: csrf}, facts, nil
}
