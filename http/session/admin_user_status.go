package sessionhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
)

// AdminUserStatusInput holds original ordinary session custody and canonical
// keyed intent. Ban has no caller-supplied version; unban requires one and
// forbids reason/expiry. This value must not be logged, persisted or retained
// beyond the bounded native call. Transport validation grants no authority.
type AdminUserStatusInput struct {
	TenantID        identity.TenantID
	Bearer          authentication.BearerCredential
	CSRF            session.CSRFToken
	Key             identity.IdempotencyKey
	UserID          identity.UserID
	ExpectedVersion uint64
	Reason          string
	ExpiresAt       time.Time
}

// Format suppresses all original credentials and private intent.
func (AdminUserStatusInput) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "sessionhttp.AdminUserStatusInput(redacted)")
}

// MarshalJSON rejects implicit serialization of original credential custody.
func (AdminUserStatusInput) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText rejects implicit text and map-key credential export.
func (AdminUserStatusInput) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// AdminUserStatusService owns current original-session authentication, exact
// action authorization, transactional synchronizer validation and keyed native
// status intent. It calls admission synchronously with its derived actor once,
// after authentication/permission and before request-key or operation work.
// It must honor an admission error, never retain the callback and support
// concurrent bounded calls. A returned cascade is historical pending admission,
// not evidence of cleanup or restored credentials.
type AdminUserStatusService interface {
	BanUserWithAdmission(context.Context, AdminUserStatusInput, func(context.Context, identity.UserID) error) (identity.UserStatusResult, error)
	UnbanUserWithAdmission(context.Context, AdminUserStatusInput, func(context.Context, identity.UserID) error) (identity.UserStatusResult, error)
}

// AdminUserStatusRate is the configured shared audited administrative quota.
// Success returns no retry hint. ErrRateLimited requires 1..60 whole seconds;
// all other errors or malformed hints fail closed without advertising retry.
type AdminUserStatusRate interface {
	Configured() bool
	AdmitUserStatus(context.Context, identityhttp.NetworkFacts, string, identity.UserID) (time.Duration, error)
}

// AdminUserStatusConfig selects independently opt-in native ban/unban routes.
// Network/origins are copied immutable policies; owners are borrowed and must
// outlive concurrent requests. MaximumDuration is 1ms..30s and never extends an
// inbound deadline. Only the original __Host- cookie is an authority channel.
type AdminUserStatusConfig struct {
	Network            identityhttp.NetworkConfig
	TrustedOrigins     []identityhttp.Origin
	OriginalCookieName string
	Native             AdminUserStatusService
	Rate               AdminUserStatusRate
	MaximumDuration    time.Duration
	Ban, Unban         bool
}

// NewAdminUserStatusFeature constructs only selected canonical identity-owned
// POST administrator status routes without IO or implicit root registration.
// Exact HTTPS mapped tenant, explicit Origin, original cookie, stored-session
// X-CSRF-Token and one Idempotency-Key are required. Only strict canonical JSON
// is admitted; query, trailers and alternate credentials deny. Every native
// error or noncommitted outcome is non-2xx; no cookies or secrets are returned.
func NewAdminUserStatusFeature(c AdminUserStatusConfig) (identityhttp.Feature, error) {
	if !c.Ban && !c.Unban || adminStatusMissing(c.Native) || adminStatusMissing(c.Rate) || !c.Rate.Configured() ||
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
	operations := make([]identityhttp.OperationDescriptor, 0, 2)
	for _, selected := range []struct {
		enabled         bool
		operation, path string
		target          identity.Status
	}{
		{c.Ban, "identity.admin.user-ban", "/v1/admin/user-ban", identity.StatusBanned},
		{c.Unban, "identity.admin.user-unban", "/v1/admin/user-unban", identity.StatusActive},
	} {
		if !selected.enabled {
			continue
		}
		h := adminStatusHandler{network: network, decoder: decoder, origin: origin, csrf: csrf, cookie: c.OriginalCookieName, native: c.Native, rate: c.Rate, duration: c.MaximumDuration, operation: selected.operation, path: selected.path, target: selected.target}
		op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{
			Owner: "identity", OperationID: selected.operation, Handler: h,
			CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny}, MaximumSerializedBytes: 16384,
		})
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op.Wire = adminUserStatusWire(selected.operation, c.OriginalCookieName, selected.target)
		operations = append(operations, op)
	}
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity", Operations: operations})
}

func adminStatusMissing(owner any) bool {
	if owner == nil {
		return true
	}
	value := reflect.ValueOf(owner)
	switch value.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Func, reflect.Map, reflect.Chan, reflect.Slice:
		return value.IsNil()
	}
	return false
}

type adminStatusHandler struct {
	network                 *identityhttp.NetworkResolver
	decoder                 *identityhttp.RequestDecoder
	origin                  *identityhttp.OriginGuard
	csrf                    *identityhttp.CSRFDecoder
	cookie, operation, path string
	target                  identity.Status
	native                  AdminUserStatusService
	rate                    AdminUserStatusRate
	duration                time.Duration
}

type adminStatusUser struct {
	ID       identity.UserID   `json:"id"`
	TenantID identity.TenantID `json:"tenantID"`
	Status   identity.Status   `json:"status"`
	Version  uint64            `json:"version"`
}

type adminStatusOwner struct {
	Owner  string `json:"owner"`
	Status string `json:"status"`
}

type adminStatusRevocation struct {
	CascadeID           identity.CascadeID `json:"cascadeID"`
	Generation          uint64             `json:"generation"`
	AuthorityVersion    uint64             `json:"authorityVersion"`
	Status              string             `json:"status"`
	Owners              []adminStatusOwner `json:"owners"`
	ExternalLimitations []string           `json:"externalLimitations"`
}

type adminStatusResponse struct {
	CommandID     identity.CommandID     `json:"commandID,omitempty"`
	CommitOutcome string                 `json:"commitOutcome"`
	User          *adminStatusUser       `json:"user,omitempty"`
	Revocation    *adminStatusRevocation `json:"revocation,omitempty"`
	Error         string                 `json:"error,omitempty"`
}

func (h adminStatusHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r == nil || r.URL == nil {
		writeAdminStatus(w, 400, adminStatusResponse{CommitOutcome: "none", Error: "invalid_request"})
		return
	}
	if r.URL.Path != h.path || r.URL.EscapedPath() != h.path {
		writeAdminStatus(w, 404, adminStatusResponse{CommitOutcome: "none", Error: "not_found"})
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeAdminStatus(w, 405, adminStatusResponse{CommitOutcome: "none", Error: "method_not_allowed"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.duration)
	defer cancel()
	input, facts, err := h.decode(r.WithContext(ctx))
	if err != nil {
		status, code := adminStatusError(err)
		writeAdminStatus(w, status, adminStatusResponse{CommitOutcome: "none", Error: code})
		return
	}
	if ctx.Err() != nil {
		writeAdminStatus(w, 503, adminStatusResponse{CommitOutcome: "none", Error: "unavailable"})
		return
	}
	attempted := false
	var retry time.Duration
	var admissionErr error
	admit := func(bounded context.Context, actor identity.UserID) error {
		if attempted || bounded == nil || bounded.Err() != nil || ctx.Err() != nil || !adminStatusID(string(actor)) {
			attempted, retry, admissionErr = true, 0, identity.UnavailableError{}
			return admissionErr
		}
		outerDeadline, _ := ctx.Deadline()
		deadline, hasDeadline := bounded.Deadline()
		if !hasDeadline || deadline.After(outerDeadline) {
			attempted, retry, admissionErr = true, 0, identity.UnavailableError{}
			return admissionErr
		}
		attempted = true
		retry, admissionErr = h.rate.AdmitUserStatus(bounded, facts, h.operation, actor)
		if errors.Is(admissionErr, identityhttp.ErrRateLimited) && retry >= time.Second && retry <= time.Minute && retry%time.Second == 0 {
			return admissionErr
		}
		if admissionErr != nil || retry != 0 {
			admissionErr = identity.UnavailableError{}
		}
		return admissionErr
	}
	var result identity.UserStatusResult
	if h.target == identity.StatusBanned {
		result, err = h.native.BanUserWithAdmission(ctx, input, admit)
	} else {
		result, err = h.native.UnbanUserWithAdmission(ctx, input, admit)
	}
	if !attempted {
		status, code := 503, "unavailable"
		if err != nil {
			status, code = adminStatusError(err)
		}
		if ctx.Err() != nil {
			status, code = 503, "unavailable"
		}
		writeAdminStatus(w, status, adminStatusResponse{CommitOutcome: "none", Error: code})
		return
	}
	if admissionErr != nil {
		status, code := 503, "unavailable"
		if ctx.Err() == nil && errors.Is(admissionErr, identityhttp.ErrRateLimited) {
			status, code = 429, "rate_limited"
			w.Header().Set("Retry-After", strconv.FormatInt(int64(retry/time.Second), 10))
		}
		writeAdminStatus(w, status, adminStatusResponse{CommitOutcome: "none", Error: code})
		return
	}
	if ctx.Err() != nil {
		h.writeResult(w, input, result, ctx.Err())
		return
	}
	h.writeResult(w, input, result, err)
}

func (h adminStatusHandler) decode(r *http.Request) (AdminUserStatusInput, identityhttp.NetworkFacts, error) {
	var input AdminUserStatusInput
	var empty identityhttp.NetworkFacts
	if r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Trailer) != 0 {
		return input, empty, identityhttp.DecodeError{}
	}
	key, _, err := h.decoder.IdempotencyKey(r, identityhttp.HeaderRequired)
	if err != nil {
		return input, empty, err
	}
	facts, err := h.network.Resolve(r)
	if err != nil {
		var malformed identityhttp.DecodeError
		if errors.As(err, &malformed) {
			return input, empty, adminStatusMisdirected{}
		}
		return input, empty, err
	}
	if facts.Realm() != identityhttp.RealmTenant || facts.Scheme() != "https" || facts.TenantID() == "" {
		return input, empty, adminStatusMisdirected{}
	}
	if _, err := h.origin.CheckBound(r, identityhttp.Origin(facts.Origin())); err != nil {
		return input, empty, err
	}
	bearer, _, err := h.decoder.CookieBearer(r, h.cookie, identityhttp.HeaderRequired)
	if err != nil {
		return input, empty, err
	}
	// The preserved M24 request schemas select JSON only. DecodeJSON owns
	// complete framing, duplicate-name and media validation, before native IO.
	fields, err := identityhttp.DecodeJSON[map[string]json.RawMessage](h.decoder, r)
	if err != nil {
		return input, empty, err
	}
	var id string
	if !adminStatusValue(fields["userID"], &id) || !adminStatusID(id) {
		return input, empty, identityhttp.DecodeError{}
	}
	input = AdminUserStatusInput{TenantID: facts.TenantID(), Bearer: bearer, Key: key, UserID: identity.UserID(id)}
	if h.target == identity.StatusBanned {
		if len(fields) < 2 || len(fields) > 3 || !adminStatusValue(fields["reason"], &input.Reason) || !adminStatusReason(input.Reason) {
			return AdminUserStatusInput{}, empty, identityhttp.DecodeError{}
		}
		if raw, present := fields["expiresAt"]; present {
			var instant string
			if !adminStatusValue(raw, &instant) || !adminStatusInstant(instant) {
				return AdminUserStatusInput{}, empty, identityhttp.DecodeError{}
			}
			input.ExpiresAt, err = time.Parse(time.RFC3339Nano, instant)
			if err != nil || input.ExpiresAt.IsZero() || input.ExpiresAt.Year() < 1 || input.ExpiresAt.Year() > 9999 || input.ExpiresAt.Nanosecond()%1000 != 0 {
				return AdminUserStatusInput{}, empty, identityhttp.DecodeError{}
			}
		} else if len(fields) != 2 {
			return AdminUserStatusInput{}, empty, identityhttp.DecodeError{}
		}
	} else if len(fields) != 2 || !adminStatusValue(fields["expectedVersion"], &input.ExpectedVersion) || input.ExpectedVersion == 0 || input.ExpectedVersion == ^uint64(0) {
		return AdminUserStatusInput{}, empty, identityhttp.DecodeError{}
	}
	input.CSRF, _, err = identityhttp.DecodeCSRF(h.csrf, r, session.ParseCSRFToken)
	if err != nil {
		return AdminUserStatusInput{}, empty, err
	}
	return input, facts, nil
}

func adminStatusValue(raw json.RawMessage, destination any) bool {
	return len(raw) != 0 && string(raw) != "null" && json.Unmarshal(raw, destination) == nil
}

func adminStatusInstant(value string) bool {
	// time.Parse accepts comma separators and silently truncates fractions past
	// nanoseconds. The M24 explicit UTC microsecond profile must not lose intent.
	if len(value) < 20 || len(value) > 27 || value[4] != '-' || value[7] != '-' || value[10] != 'T' || value[13] != ':' || value[16] != ':' || value[len(value)-1] != 'Z' {
		return false
	}
	if len(value) != 20 && (len(value) < 22 || value[19] != '.') {
		return false
	}
	for i := range len(value) - 1 {
		switch i {
		case 4, 7, 10, 13, 16, 19:
			continue
		}
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

func adminStatusID(value string) bool {
	return (identity.User{ID: identity.UserID(value), TenantID: "structural", Status: identity.StatusActive, Version: 1}).Validate("structural") == nil
}

func adminStatusReason(value string) bool {
	if len(value) < 1 || len(value) > 512 || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func (h adminStatusHandler) writeResult(w http.ResponseWriter, input AdminUserStatusInput, result identity.UserStatusResult, err error) {
	out := adminStatusResponse{CommitOutcome: "none", Error: "unavailable"}
	status := 503
	validateProjection := adminStatusHasProjection(result) || err == nil && result.CommitOutcome == identity.CommitOutcomeCommitted
	if validateProjection && (result.CommitOutcome != identity.CommitOutcomeCommitted || !h.validResult(result, input)) {
		writeAdminStatus(w, status, out)
		return
	}
	_, commandErr := identity.ParseCommandID(string(result.CommandID))
	if commandErr == nil && result.CommitOutcome >= identity.CommitOutcomeNotCommitted && result.CommitOutcome <= identity.CommitOutcomeInProgress {
		out.CommandID, out.CommitOutcome = result.CommandID, logoutOutcome(result.CommitOutcome)
	}
	switch {
	case err != nil:
		status, out.Error = adminStatusError(err)
	case out.CommandID == "":
	case result.CommitOutcome == identity.CommitOutcomeConflict || result.CommitOutcome == identity.CommitOutcomeInProgress || result.CommitOutcome == identity.CommitOutcomeNotCommitted:
		status, out.Error = 409, "conflict"
	case result.CommitOutcome == identity.CommitOutcomeCommitted:
		out.User = &adminStatusUser{ID: result.User.ID, TenantID: result.User.TenantID, Status: result.User.Status, Version: result.User.Version}
		revocation := result.Revocation
		owners := make([]adminStatusOwner, len(revocation.Owners))
		for i, owner := range revocation.Owners {
			owners[i] = adminStatusOwner{Owner: owner.Owner, Status: "pending"}
		}
		out.Revocation = &adminStatusRevocation{CascadeID: revocation.CascadeID, Generation: revocation.Generation, AuthorityVersion: revocation.AuthorityVersion, Status: "pending", Owners: owners, ExternalLimitations: []string{}}
		status, out.Error = 200, ""
	}
	writeAdminStatus(w, status, out)
}

func adminStatusHasProjection(result identity.UserStatusResult) bool {
	r := result.Revocation
	return result.User != (identity.User{}) || r.CascadeID != "" || r.Generation != 0 || r.AuthorityVersion != 0 ||
		r.Status != 0 || len(r.Owners) != 0 || len(r.ExternalLimitations) != 0
}

func (h adminStatusHandler) validResult(result identity.UserStatusResult, input AdminUserStatusInput) bool {
	if result.User.Validate(input.TenantID) != nil || result.User.ID != input.UserID || result.User.Status != h.target || result.User.Version <= 1 || h.target == identity.StatusActive && (input.ExpectedVersion == ^uint64(0) || result.User.Version != input.ExpectedVersion+1) {
		return false
	}
	r := result.Revocation
	if _, err := identity.ParseCascadeID(string(r.CascadeID)); err != nil || r.Generation != 1 || r.AuthorityVersion <= 1 || r.Status != identity.RevocationPending || len(r.ExternalLimitations) != 0 {
		return false
	}
	consumers := (identity.UserStatusCommand{Binding: identity.CommandBinding{OperationID: h.operation}}).RequiredConsumers()
	if len(r.Owners) != len(consumers) {
		return false
	}
	for i, owner := range r.Owners {
		if owner.Owner != consumers[i] || owner.Status != identity.RevocationPending {
			return false
		}
	}
	return true
}

type adminStatusMisdirected struct{}

func (adminStatusMisdirected) Error() string { return "identity.http.misdirected_request" }

func adminStatusError(err error) (int, string) {
	var invalid identity.InvalidInputError
	var decode identityhttp.DecodeError
	var origin identityhttp.OriginError
	var csrf identityhttp.CSRFError
	var forbidden identity.ForbiddenError
	var unauthenticated identity.UnauthenticatedError
	var conflict identity.ConflictError
	var notCommitted identity.NotCommittedError
	var progress identity.InProgressError
	var host adminStatusMisdirected
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return 503, "unavailable"
	case errors.As(err, &host):
		return 421, "misdirected_request"
	case errors.As(err, &origin), errors.As(err, &csrf), errors.As(err, &forbidden), errors.As(err, &unauthenticated), errors.Is(err, session.ErrUnauthenticated), errors.Is(err, session.ErrCSRFDenied):
		return 403, "denied"
	case errors.As(err, &invalid), errors.As(err, &decode), errors.Is(err, identityhttp.ErrInvalidInput):
		return 400, "invalid_request"
	case errors.As(err, &conflict), errors.As(err, &notCommitted), errors.As(err, &progress):
		return 409, "conflict"
	default:
		return 503, "unavailable"
	}
}

func writeAdminStatus(w http.ResponseWriter, status int, out adminStatusResponse) {
	body, err := json.Marshal(out)
	if err != nil {
		response(w, 503, `{"commitOutcome":"none","error":"unavailable"}`)
		return
	}
	response(w, status, string(body))
}
