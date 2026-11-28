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

const adminSessionRevokeAllOperation = "identity.admin.session-revoke-all"
const adminSessionRevokeAllPath = "/v1/admin/session-revoke-all"

// AdminSessionRevokeAllInput borrows original ordinary-session custody and the
// exact target for one native call. It grants no actor authority and must not
// be logged, persisted or retained beyond that call.
type AdminSessionRevokeAllInput struct {
	TenantID        identity.TenantID
	TargetSubjectID identity.SubjectID
	Bearer          authentication.BearerCredential
	CSRF            session.CSRFToken
}

// Format suppresses original credentials and private target intent.
func (AdminSessionRevokeAllInput) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "sessionhttp.AdminSessionRevokeAllInput(redacted)")
}

// MarshalJSON denies implicit original-credential serialization.
func (AdminSessionRevokeAllInput) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText denies implicit text and map-key custody export.
func (AdminSessionRevokeAllInput) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// AdminSessionRevokeAllOutput confirms a session-only subject transition.
// RevokedCount is the exact native count in 0..100000, and SubjectVersion is
// positive even when no sessions remained. Every error invalidates all output.
type AdminSessionRevokeAllOutput struct {
	RevokedCount   uint32
	SubjectVersion uint64
}

// AdminSessionRevokeAllOwner authenticates the original ordinary session and
// authorizes the exact target before synchronously calling admission once with
// its derived actor. It must honor admission errors, validate stored-session
// CSRF atomically with native work, never retain the callback, and support
// concurrent bounded calls. Each success, including zero sessions, confirms a
// new session-only subject version; unknown outcomes must return an error.
// This repeat operation owns no transport key or cross-owner cascade.
type AdminSessionRevokeAllOwner interface {
	AdminSessionRevokeAllWithAdmission(context.Context, AdminSessionRevokeAllInput, func(context.Context, identity.UserID) error) (AdminSessionRevokeAllOutput, error)
}

// AdminSessionRevokeAllConfig opts into one administrator session-set mutation.
// Network and origins are copied immutable policies. Native and the shared
// administrative quota are borrowed and must outlive concurrent requests.
// MaximumDuration is 1ms..30s and never extends an earlier inbound deadline.
type AdminSessionRevokeAllConfig struct {
	Network            identityhttp.NetworkConfig
	TrustedOrigins     []identityhttp.Origin
	OriginalCookieName string
	Native             AdminSessionRevokeAllOwner
	Rate               AdminSessionListRate
	MaximumDuration    time.Duration
}

// NewAdminSessionRevokeAllFeature constructs only selected canonical repeat
// POST /v1/admin/session-revoke-all without IO or implicit registration. An
// exact mapped HTTPS Origin, original __Host- cookie and stored-session
// X-CSRF-Token are required without fallback. Strict JSON contains only userID;
// query, trailers, idempotency keys and alternate credentials deny before native
// work. Responses never alter cookies or expose credentials. Native errors and
// unknown outcomes never become confirmed counts or subject transitions.
func NewAdminSessionRevokeAllFeature(c AdminSessionRevokeAllConfig) (identityhttp.Feature, error) {
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
	h := adminSessionRevokeAllHandler{network: network, decoder: decoder, origin: origin, csrf: csrf, cookie: c.OriginalCookieName, native: c.Native, rate: c.Rate, duration: c.MaximumDuration}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{
		Owner: "identity/session", OperationID: adminSessionRevokeAllOperation, Handler: h,
		CSRF:                   identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny},
		MaximumSerializedBytes: 1024,
	})
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op.Wire = adminSessionRevokeAllWire(c.OriginalCookieName)
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/session", Operations: []identityhttp.OperationDescriptor{op}})
}

type adminSessionRevokeAllHandler struct {
	network  *identityhttp.NetworkResolver
	decoder  *identityhttp.RequestDecoder
	origin   *identityhttp.OriginGuard
	csrf     *identityhttp.CSRFDecoder
	cookie   string
	native   AdminSessionRevokeAllOwner
	rate     AdminSessionListRate
	duration time.Duration
}

func (h adminSessionRevokeAllHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r == nil || r.URL == nil {
		writeAdminSessionListError(w, 400, "invalid_request")
		return
	}
	if r.URL.Path != adminSessionRevokeAllPath || r.URL.EscapedPath() != adminSessionRevokeAllPath {
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
	result, err := h.native.AdminSessionRevokeAllWithAdmission(ctx, input, func(bounded context.Context, actor identity.UserID) error {
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
		retry, admissionErr = h.rate.AdmitSessionAdministration(bounded, facts, adminSessionRevokeAllOperation, actor)
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
		// Unknown commit invalidates even a plausible count and version; a
		// fabricated zero count would falsely confirm another transition.
		status, code := adminSessionListError(err)
		writeAdminSessionListError(w, status, code)
	case !attempted || result.RevokedCount > 100000 || result.SubjectVersion == 0:
		writeAdminSessionListError(w, 503, "unavailable")
	default:
		body, marshalErr := json.Marshal(struct {
			RevokedCount   uint32 `json:"revokedCount"`
			SubjectVersion uint64 `json:"subjectVersion"`
		}{RevokedCount: result.RevokedCount, SubjectVersion: result.SubjectVersion})
		if marshalErr != nil || ctx.Err() != nil {
			writeAdminSessionListError(w, 503, "unavailable")
			return
		}
		response(w, 200, string(body))
	}
}

func (h adminSessionRevokeAllHandler) decode(r *http.Request) (AdminSessionRevokeAllInput, identityhttp.NetworkFacts, error) {
	var empty AdminSessionRevokeAllInput
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
	var userID string
	if len(fields) != 1 || !adminStatusValue(fields["userID"], &userID) || !adminSessionListID(userID) {
		return empty, noFacts, identityhttp.DecodeError{}
	}
	csrf, _, err := identityhttp.DecodeCSRF(h.csrf, r, session.ParseCSRFToken)
	if err != nil {
		return empty, noFacts, err
	}
	return AdminSessionRevokeAllInput{TenantID: facts.TenantID(), TargetSubjectID: identity.SubjectID(userID), Bearer: bearer, CSRF: csrf}, facts, nil
}
