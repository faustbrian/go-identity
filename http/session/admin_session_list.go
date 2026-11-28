package sessionhttp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
)

const adminSessionListOperation = "identity.admin.session-list"
const adminSessionListPath = "/v1/admin/session-list"

// AdminSessionListOwner authenticates the original ordinary session and checks
// exact current target permission before calling admission synchronously once.
// It must honor admission errors, never retain the callback, and return only
// an owned safe page under the unchanged original validity deadline. Borrowed
// implementations must support concurrent requests and honor cancellation.
type AdminSessionListOwner interface {
	AdminSessionListWithAdmission(context.Context, session.AdminSessionListRequest, func(context.Context, identity.UserID) error) (session.AdminSessionListResult, error)
}

// AdminSessionListRate is the configured shared audited administrative quota,
// not a separate read budget. Success has no retry hint; ErrRateLimited must
// carry 1..60 whole seconds. Every other error or malformed hint fails closed.
type AdminSessionListRate interface {
	Configured() bool
	AdmitSessionAdministration(context.Context, identityhttp.NetworkFacts, string, identity.UserID) (time.Duration, error)
}

// AdminSessionListConfig selects one original-cookie administrator read.
// Network policy is copied; borrowed native/rate owners must outlive requests.
// MaximumDuration is 1ms..30s and never extends an earlier inbound deadline.
type AdminSessionListConfig struct {
	Network            identityhttp.NetworkConfig
	OriginalCookieName string
	Native             AdminSessionListOwner
	Rate               AdminSessionListRate
	MaximumDuration    time.Duration
}

// NewAdminSessionListFeature constructs only GET /v1/admin/session-list without
// IO or implicit registration. The HTTPS mapped tenant and original cookie are
// the only authority channel. Body, caller actor/tenant overrides, CSRF inputs,
// idempotency keys and alternate credentials deny before native work. The core
// derives the actor before quota admission. Responses never alter cookies or
// expose credentials; native errors never disclose a partial page.
func NewAdminSessionListFeature(c AdminSessionListConfig) (identityhttp.Feature, error) {
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
	h := adminSessionListHandler{network: network, decoder: decoder, cookie: c.OriginalCookieName, native: c.Native, rate: c.Rate, duration: c.MaximumDuration}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{
		Owner: "identity/session", OperationID: adminSessionListOperation, Handler: h,
		CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone},
		// 100 entries can each contain 256 display bytes expanded by JSON's
		// HTML escaping, plus their timestamps and fixed field names.
		MaximumSerializedBytes: 256 << 10,
	})
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op.Wire = adminSessionListWire(c.OriginalCookieName)
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/session", Operations: []identityhttp.OperationDescriptor{op}})
}

type adminSessionListHandler struct {
	network  *identityhttp.NetworkResolver
	decoder  *identityhttp.RequestDecoder
	cookie   string
	native   AdminSessionListOwner
	rate     AdminSessionListRate
	duration time.Duration
}

type adminSessionListDevice struct {
	SessionID  string    `json:"sessionID"`
	Label      string    `json:"label"`
	LastSeenAt time.Time `json:"lastSeenAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
	Current    bool      `json:"current"`
	Inactive   bool      `json:"inactive"`
}

type adminSessionListResponse struct {
	Sessions   []adminSessionListDevice `json:"sessions"`
	NextCursor string                   `json:"nextCursor"`
}

func (h adminSessionListHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r == nil || r.URL == nil {
		writeAdminSessionListError(w, 400, "invalid_request")
		return
	}
	if r.URL.Path != adminSessionListPath || r.URL.EscapedPath() != adminSessionListPath {
		writeAdminSessionListError(w, 404, "not_found")
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
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
	var attempted bool
	var actor identity.UserID
	var admissionContext context.Context
	var admissionErr error
	var retry time.Duration
	result, err := h.native.AdminSessionListWithAdmission(ctx, input, func(bounded context.Context, authenticated identity.UserID) error {
		if attempted || bounded == nil || bounded.Err() != nil || ctx.Err() != nil || !adminSessionListID(string(authenticated)) {
			attempted, retry, admissionErr = true, 0, identity.UnavailableError{}
			return admissionErr
		}
		deadline, boundedDeadline := bounded.Deadline()
		outerDeadline, _ := ctx.Deadline()
		if !boundedDeadline || deadline.After(outerDeadline) {
			attempted, retry, admissionErr = true, 0, identity.UnavailableError{}
			return admissionErr
		}
		attempted, actor, admissionContext = true, authenticated, bounded
		retry, admissionErr = h.rate.AdmitSessionAdministration(bounded, facts, adminSessionListOperation, actor)
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
		status, code := adminSessionListError(err)
		writeAdminSessionListError(w, status, code)
	case !attempted || admissionContext == nil:
		writeAdminSessionListError(w, 503, "unavailable")
	default:
		out, valid := projectAdminSessionList(result, input, actor)
		if !valid {
			writeAdminSessionListError(w, 503, "unavailable")
			return
		}
		body, marshalErr := json.Marshal(out)
		if marshalErr != nil || ctx.Err() != nil {
			writeAdminSessionListError(w, 503, "unavailable")
			return
		}
		response(w, 200, string(body))
	}
}

func (h adminSessionListHandler) decode(r *http.Request) (session.AdminSessionListRequest, identityhttp.NetworkFacts, error) {
	var empty session.AdminSessionListRequest
	var noFacts identityhttp.NetworkFacts
	// As in the quorum read, net/http owns zero-length HTTP/2 stream framing.
	// Reading that stream here would turn a bodyless read into unbounded IO.
	if r.ContentLength != 0 || len(r.TransferEncoding) != 0 || len(r.Trailer) != 0 ||
		r.ProtoMajor != 2 && r.Body != nil && r.Body != http.NoBody {
		return empty, noFacts, identityhttp.DecodeError{}
	}
	for name := range r.Header {
		if strings.EqualFold(name, "X-CSRF-Token") {
			return empty, noFacts, identityhttp.DecodeError{}
		}
	}
	if _, _, err := h.decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil {
		return empty, noFacts, err
	}
	query, err := h.decoder.Query(r)
	if err != nil {
		return empty, noFacts, err
	}
	if len(query) < 2 || len(query) > 3 || !adminSessionListID(query.Get("targetSubjectID")) {
		return empty, noFacts, identityhttp.DecodeError{}
	}
	for name := range query {
		if name != "targetSubjectID" && name != "limit" && name != "cursor" {
			return empty, noFacts, identityhttp.DecodeError{}
		}
	}
	rawLimit := query.Get("limit")
	if len(rawLimit) < 1 || len(rawLimit) > 3 {
		return empty, noFacts, identityhttp.DecodeError{}
	}
	limit, err := strconv.ParseUint(rawLimit, 10, 16)
	if err != nil || limit < 1 || limit > 100 || strconv.FormatUint(limit, 10) != rawLimit {
		return empty, noFacts, identityhttp.DecodeError{}
	}
	cursor := query.Get("cursor")
	if _, present := query["cursor"]; present && cursor == "" {
		return empty, noFacts, identityhttp.DecodeError{}
	}
	if _, _, valid := adminSessionListCursor(cursor); !valid {
		return empty, noFacts, identityhttp.DecodeError{}
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
	bearer, present, err := h.decoder.CookieBearer(r, h.cookie, identityhttp.HeaderOptional)
	if err != nil {
		return empty, noFacts, err
	}
	if !present {
		return empty, noFacts, identity.ForbiddenError{}
	}
	token, err := session.ParseToken(bearer.Token())
	if err != nil {
		return empty, noFacts, identityhttp.DecodeError{}
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		return empty, noFacts, identityhttp.DecodeError{}
	}
	return session.AdminSessionListRequest{TenantID: facts.TenantID(), Credential: credential, TargetSubjectID: identity.SubjectID(query.Get("targetSubjectID")), Cursor: cursor, Limit: uint16(limit)}, facts, nil
}

func adminSessionListID(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for i := range len(value) {
		if value[i] < 33 || value[i] > 126 {
			return false
		}
	}
	return true
}

func adminSessionListCursor(cursor string) (string, [32]byte, bool) {
	var scope [32]byte
	if cursor == "" {
		return "", scope, true
	}
	// session/list.go's v1 locator is one version byte, a 32-byte scope
	// digest, and 1..128 visible ASCII marker bytes. It grants no authority.
	if len(cursor) > 216 {
		return "", scope, false
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(cursor)
	if err != nil || len(data) < 34 || len(data) > 161 || data[0] != 1 || base64.RawURLEncoding.EncodeToString(data) != cursor || !adminSessionListID(string(data[33:])) {
		return "", scope, false
	}
	copy(scope[:], data[1:33])
	return string(data[33:]), scope, true
}

func projectAdminSessionList(result session.AdminSessionListResult, input session.AdminSessionListRequest, actor identity.UserID) (adminSessionListResponse, bool) {
	if result.Sessions == nil || len(result.Sessions) > int(input.Limit) {
		return adminSessionListResponse{}, false
	}
	last, scope, valid := adminSessionListCursor(input.Cursor)
	if !valid {
		return adminSessionListResponse{}, false
	}
	out := adminSessionListResponse{Sessions: make([]adminSessionListDevice, len(result.Sessions)), NextCursor: result.NextCursor}
	currentCount := 0
	for i, device := range result.Sessions {
		if !adminSessionListID(device.SessionID) || device.SessionID <= last || !adminSessionListLabel(device.Label) ||
			!adminSessionListInstant(device.LastSeenAt) || !adminSessionListInstant(device.ExpiresAt) || !device.ExpiresAt.After(device.LastSeenAt) {
			return adminSessionListResponse{}, false
		}
		if device.Current {
			currentCount++
			if currentCount > 1 || device.Inactive || identity.SubjectID(actor) != input.TargetSubjectID {
				return adminSessionListResponse{}, false
			}
		}
		last = device.SessionID
		out.Sessions[i] = adminSessionListDevice{SessionID: device.SessionID, Label: device.Label, LastSeenAt: device.LastSeenAt, ExpiresAt: device.ExpiresAt, Current: device.Current, Inactive: device.Inactive}
	}
	if result.NextCursor != "" {
		marker, nextScope, valid := adminSessionListCursor(result.NextCursor)
		if !valid || len(result.Sessions) != int(input.Limit) || marker != last || input.Cursor != "" && nextScope != scope {
			return adminSessionListResponse{}, false
		}
	}
	return out, true
}

func adminSessionListLabel(label string) bool {
	if len(label) > 128 || !utf8.ValidString(label) {
		return false
	}
	for _, r := range label {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func adminSessionListInstant(instant time.Time) bool {
	return !instant.IsZero() && instant.Year() >= 1 && instant.Year() <= 9999 && instant.Location() == time.UTC
}

func adminSessionListError(err error) (int, string) {
	if errors.Is(err, session.ErrInvalidInput) || errors.Is(err, session.ErrInvalidToken) {
		return 400, "invalid_request"
	}
	status, code := adminStatusError(err)
	if status == 409 {
		return 503, "unavailable"
	}
	return status, code
}

func writeAdminSessionListError(w http.ResponseWriter, status int, code string) {
	body, _ := json.Marshal(struct {
		Error string `json:"error"`
	}{Error: code})
	response(w, status, string(body))
}
