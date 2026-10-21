package anonymoushttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
)

// DeletionService authenticates original guest/CSRF possession for the stable
// rate scope, then independently owns deletion and historical keyed retries.
// Rate metadata is not active-session authority; no transport-selected subject
// or application store may substitute for this borrowed bounded native owner.
type DeletionService interface {
	anonymous.Deleter
	DeletionRateSource(context.Context, anonymous.DeletionRequest) (identity.UserID, error)
}

// DeletionConfig explicitly selects cookie-only guest self-deletion. Service,
// shared Rate and prompt trusted Now are borrowed concurrency-safe owners.
// Cookie/Origin/Device must match original issuance; no permanent credential
// fallback is admitted. MaximumDuration is 1ms..30s, bounded by the caller.
// Construction freezes configuration without IO or owner callbacks.
type DeletionConfig struct {
	Network         identityhttp.NetworkConfig
	Service         DeletionService
	Rate            *identityhttp.KeyedSecretRateLimiter
	Cookie          session.CookiePolicy
	Origin          identityhttp.Origin
	Device          session.BrowserDeviceConfig
	Now             func() time.Time
	MaximumDuration time.Duration
}

// Format hides borrowed composition and network policy.
func (DeletionConfig) Format(s fmt.State, _ rune) {
	io.WriteString(s, "anonymoushttp.DeletionConfig(redacted)")
}

// MarshalJSON denies implicit composition export.
func (DeletionConfig) MarshalJSON() ([]byte, error) { return nil, anonymous.ErrDisclosure }

// MarshalText denies implicit text/map-key export.
func (DeletionConfig) MarshalText() ([]byte, error) { return nil, anonymous.ErrDisclosure }

// CommandRecovery is detached original command metadata, never permission to
// disclose history, execute another operation or restore active authority.
type CommandRecovery struct {
	CommandID   identity.CommandID        `json:"commandID"`
	TenantID    identity.TenantID         `json:"tenantID"`
	UserID      identity.UserID           `json:"userID"`
	ActorID     identity.ActorID          `json:"actorID"`
	ActorKind   authorization.SubjectKind `json:"actorKind"`
	OperationID string                    `json:"operationID"`
	RecordID    string                    `json:"recordID"`
}

// DeletionResponse separates known commitment from HTTP delivery. Only an
// error-free known commit reports Deleted and clears the selected guest cookie.
// Unknown preserves original recovery and possession without automatic retry.
type DeletionResponse struct {
	Deleted       bool               `json:"deleted"`
	CommitOutcome string             `json:"commitOutcome"`
	CommandID     identity.CommandID `json:"commandID,omitempty"`
	Recovery      *CommandRecovery   `json:"recovery,omitempty"`
	Replayed      bool               `json:"replayed,omitempty"`
	Error         string             `json:"error,omitempty"`
}

type deletionState struct {
	facts   identityhttp.NetworkFacts
	request anonymous.DeletionRequest
	device  session.BrowserDevice
	user    identity.UserID
}

// NewDeletionHandler selects only POST /v1/anonymous/delete. Closed JSON
// requires positive expectedVersion and a registered visible reason (<=64
// bytes). Exactly one Idempotency-Key, original guest cookie, signed device,
// exact HTTPS Origin and sole X-CSRF-Token are required. Native possession
// supplies the rate subject; the browser cannot choose a user or cleanup mode.
// All protected work remains with the native owner. Metadata-only same-key
// retries can use original self-revoked custody without reviving authentication.
// Responses are no-store/nosniff JSON; only confirmed success clears exactly
// the configured guest cookie. No session, CSRF credential or redirect is issued.
// The server retains body/connection cleanup and bounded raw IO ownership.
func NewDeletionHandler(c DeletionConfig) (http.Handler, error) {
	if nilOwner(c.Service) || !c.Rate.Configured() || c.Now == nil || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second {
		return nil, identityhttp.ErrInvalidInput
	}
	cookie, err := c.Cookie.DeletionAttributes()
	if err != nil || cookie.Name == "__Host-identity_flow" || cookie.Name == "__Host-identity_device" {
		return nil, identityhttp.ErrInvalidInput
	}
	devices, err := session.NewBrowserDeviceCodec(c.Device)
	if err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	network, err := identityhttp.NewNetworkResolver(c.Network)
	if err != nil {
		return nil, err
	}
	origins, err := identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{Network: network, TrustedOrigins: []identityhttp.Origin{c.Origin}, RefererFallback: identityhttp.RefererFallbackDeny})
	if err != nil {
		return nil, err
	}
	csrf, err := identityhttp.NewCSRFDecoder(identityhttp.CSRFDecoderConfig{Origins: origins, FormField: "csrf_token"})
	if err != nil {
		return nil, err
	}
	decoder, err := identityhttp.NewRequestDecoder(c.Network.Limits)
	if err != nil {
		return nil, err
	}
	reject := func(writer http.ResponseWriter, req *http.Request, e error) {
		a := attemptFor(req)
		out := &a.deletion
		f := failure{status: 503, code: "unavailable"}
		var specific failure
		if errors.Is(e, identityhttp.ErrInvalidInput) {
			f = failure{status: 400, code: "invalid_request"}
		}
		if errors.As(e, &specific) {
			f = specific
		}
		if f.status == 405 {
			writer.Header().Set("Allow", http.MethodPost)
		}
		if f.retry > 0 {
			writer.Header().Set("Retry-After", strconv.FormatInt(int64((min(max(f.retry, time.Second), time.Hour)+time.Second-1)/time.Second), 10))
		}
		a.cookies, a.csrf, a.fresh = nil, "", nil
		out.Deleted = false
		out.Error = f.code
		writeResponse(writer, f.status, out)
	}
	pipeline, e := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[deletionState]{MaximumDuration: c.MaximumDuration, Reject: reject,
		Decode: func(req *http.Request) (deletionState, error) {
			attemptFor(req).ctx = req.Context()
			var s deletionState
			if req.URL.Path != "/v1/anonymous/delete" || req.URL.EscapedPath() != req.URL.Path {
				return s, failure{status: 404, code: "not_found"}
			}
			if req.Method != http.MethodPost {
				return s, failure{status: 405, code: "method_not_allowed"}
			}
			if req.URL.RawQuery != "" || req.URL.ForceQuery || len(req.Trailer) != 0 {
				return s, identityhttp.ErrInvalidInput
			}
			key, present, err := decoder.IdempotencyKey(req, identityhttp.HeaderRequired)
			if err != nil || !present {
				return s, identityhttp.ErrInvalidInput
			}
			if _, _, err = decoder.Bearer(req, identityhttp.HeaderForbidden); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			facts, err := network.Resolve(req)
			if err != nil || facts.Realm() != identityhttp.RealmTenant {
				return s, failure{status: 421, code: "misdirected_request"}
			}
			if facts.Scheme() != "https" {
				return s, identityhttp.ErrInvalidInput
			}
			bearer, present, err := decoder.CookieBearer(req, cookie.Name, identityhttp.HeaderRequired)
			if err != nil || !present {
				return s, identityhttp.ErrInvalidInput
			}
			token, err := session.ParseToken(bearer.Token())
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			credential, err := session.NewCredential(session.CredentialCookie, token)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			synchronizer, _, err := identityhttp.DecodeCSRF(csrf, req, session.ParseCSRFToken)
			if err != nil {
				return s, failure{status: 403, code: "origin_or_csrf_denied"}
			}
			device, present, err := decoder.CookieBearer(req, "__Host-identity_device", identityhttp.HeaderRequired)
			if err != nil || !present {
				return s, identityhttp.ErrInvalidInput
			}
			s.device, err = devices.Resolve(req.Context(), c.Now(), facts.TenantID(), string(c.Origin), device.Token())
			if err != nil {
				return s, failure{status: 403, code: "denied"}
			}
			body, err := identityhttp.DecodeJSON[map[string]json.RawMessage](decoder, req)
			if err != nil || len(body) != 2 {
				return s, identityhttp.ErrInvalidInput
			}
			version, ok := body["expectedVersion"]
			reason, found := body["reason"]
			if !ok || !found || string(version) == "null" || string(reason) == "null" {
				return s, identityhttp.ErrInvalidInput
			}
			var expected uint64
			var code string
			if json.Unmarshal(version, &expected) != nil || json.Unmarshal(reason, &code) != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.request = anonymous.DeletionRequest{TenantID: facts.TenantID(), Credential: credential, CSRFToken: synchronizer, ExpectedVersion: expected, Reason: code, Origin: string(c.Origin), Network: facts.ClientIP().String(), Device: s.device.DeviceID(), IdempotencyKey: key}
			if s.request.Validate() != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.facts = facts
			return s, nil
		},
		Authenticate: func(req *http.Request, s deletionState) (deletionState, error) {
			user, err := c.Service.DeletionRateSource(req.Context(), s.request)
			if err != nil {
				var denied identity.ForbiddenError
				if errors.As(err, &denied) {
					return s, failure{status: 403, code: "denied"}
				}
				return s, identityhttp.ErrUnavailable
			}
			if !visible(string(user), 128) {
				return s, identityhttp.ErrUnavailable
			}
			s.user = user
			return s, nil
		},
		Admit: func(req *http.Request, s deletionState) error {
			if !s.device.ExpiresAt().After(c.Now()) {
				return identityhttp.ErrUnavailable
			}
			return rateError(c.Rate.Admit(req.Context(), s.facts, identityhttp.KeyedSecretRateRequest{OperationID: "identity.anonymous.delete", UserID: s.user, IdempotencyKey: s.request.IdempotencyKey}))
		},
		Handle: func(writer http.ResponseWriter, req *http.Request, s deletionState) {
			a := attemptFor(req)
			out := &a.deletion
			if !s.device.ExpiresAt().After(c.Now()) {
				reject(writer, req, identityhttp.ErrUnavailable)
				return
			}
			result, err := c.Service.Delete(req.Context(), s.request)
			out.CommitOutcome = outcome(result.Outcome)
			out.Replayed = result.Replayed
			q := result.Recovery
			if q.CommandID != "" {
				if _, e := identity.ParseCommandID(string(q.CommandID)); e != nil || q.TenantID != s.request.TenantID || q.UserID != s.user || q.ActorID != identity.ActorID(s.user) || q.ActorKind != authorization.SubjectUser || q.OperationID != "identity.anonymous.delete" || q.RecordID != string(s.user) || q.AnonymousFlowID != "" || q.LinkMode != 0 {
					reject(writer, req, identityhttp.ErrUnavailable)
					return
				}
				out.CommandID = q.CommandID
				out.Recovery = &CommandRecovery{q.CommandID, q.TenantID, q.UserID, q.ActorID, q.ActorKind, q.OperationID, q.RecordID}
			}
			if err != nil || req.Context().Err() != nil {
				f := failure{status: 503, code: "unavailable"}
				if req.Context().Err() == nil && result.Outcome != identity.CommitOutcomeUnknown {
					var denied identity.ForbiddenError
					var conflict identity.ConflictError
					var busy identity.InProgressError
					switch {
					case errors.As(err, &denied):
						f = failure{status: 403, code: "denied"}
					case errors.As(err, &conflict):
						f = failure{status: 409, code: "conflict"}
					case errors.As(err, &busy):
						f = failure{status: 409, code: "in_progress", retry: busy.RetryAfter}
					}
				}
				reject(writer, req, f)
				return
			}
			if result.Outcome != identity.CommitOutcomeCommitted || out.Recovery == nil {
				f := failure{status: 503, code: "unavailable"}
				switch result.Outcome {
				case identity.CommitOutcomeNotCommitted:
					f = failure{status: 403, code: "denied"}
				case identity.CommitOutcomeConflict:
					f = failure{status: 409, code: "conflict"}
				case identity.CommitOutcomeInProgress:
					f = failure{status: 409, code: "in_progress", retry: result.RetryAfter}
				}
				reject(writer, req, f)
				return
			}
			out.Deleted = true
			a.cookies = []string{cookie.String()}
			a.fresh = func() bool { return c.Now().Before(s.device.ExpiresAt()) }
			a.revoke = func() { out.Deleted = false; out.Error = "unavailable" }
			writeResponse(writer, 200, out)
		},
	})
	if e != nil {
		return nil, e
	}
	return &browserPipeline{pipeline: pipeline}, nil
}
