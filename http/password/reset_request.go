package passwordhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-identifier/v2"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
)

// ResetRequestService borrows native reset and its frozen destination parser.
// Rate-source normalization performs no account lookup or mutation. ResetRequest
// independently owns recipient selection, original correlation and atomic
// issuance/delivery; transport admission cannot grant recovery permission.
type ResetRequestService interface {
	password.ResetService
	ResetRequestRateSource(context.Context, identifier.Input) (string, error)
}

// ResetRequestConfig selects enumeration-safe request transport. CallbackURL
// is a fixed allowed HTTPS target, never a request-selected redirect. Device
// selects the existing signed browser cookie, not a raw device header. Borrowed
// Service, Rate and Now must be concurrent-safe and outlive requests. Duration
// is 1ms..30s and cannot extend an inbound deadline. Construction performs no IO.
type ResetRequestConfig struct {
	Network         identityhttp.NetworkConfig
	Service         ResetRequestService
	Rate            *identityhttp.AuthRateLimiter
	Origin          identityhttp.Origin
	CallbackURL     string
	Device          session.BrowserDeviceConfig
	ActorID         identity.ActorID
	PolicyRevision  authorization.Revision
	Now             func() time.Time
	MaximumDuration time.Duration
}

// Format redacts borrowed runtime configuration.
func (ResetRequestConfig) Format(s fmt.State, _ rune) {
	io.WriteString(s, "passwordhttp.ResetRequestConfig(redacted)")
}

// MarshalJSON denies implicit runtime export.
func (ResetRequestConfig) MarshalJSON() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// MarshalText denies implicit textual export.
func (ResetRequestConfig) MarshalText() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// LogValue returns only a fixed marker.
func (ResetRequestConfig) LogValue() slog.Value {
	return slog.StringValue("passwordhttp.ResetRequestConfig(redacted)")
}

// ResetRequestRecovery preserves original attempt correlation for proof-free
// native recovery. Neither these identifiers nor the retry key authorize reads.
type ResetRequestRecovery struct {
	AttemptID identity.CommandID        `json:"attemptID"`
	TenantID  identity.TenantID         `json:"tenantID"`
	ActorID   identity.ActorID          `json:"actorID"`
	ActorKind authorization.SubjectKind `json:"actorKind"`
}

// ResetRequestResponse acknowledges accepted work identically for eligible and
// suppressed recipients. No address, token, password, key or session is emitted.
// An unknown outcome is not permission to issue another attempt.
type ResetRequestResponse struct {
	Accepted      bool                  `json:"accepted"`
	CommitOutcome string                `json:"commitOutcome"`
	CommandID     identity.CommandID    `json:"commandID,omitempty"`
	Recovery      *ResetRequestRecovery `json:"recovery,omitempty"`
	Error         string                `json:"error,omitempty"`
}

type resetRequestAttempt struct {
	out     ResetRequestResponse
	entered bool
}
type resetRequestAttemptKey struct{}

// ResetRequestState holds immutable request-local custody for synchronous
// hooks. It is not authority, cannot be exported, and must not be retained.
type ResetRequestState struct {
	facts      identityhttp.NetworkFacts
	request    password.ResetRequestRequest
	device     session.BrowserDevice
	identifier string
	attempt    *resetRequestAttempt
}

// Attempt returns detached credential-free metadata; entered does not imply commit.
func (s ResetRequestState) Attempt() (ResetRequestResponse, bool) {
	if s.attempt == nil {
		return ResetRequestResponse{CommitOutcome: "none"}, false
	}
	out := s.attempt.out
	if out.Recovery != nil {
		copy := *out.Recovery
		out.Recovery = &copy
	}
	return out, s.attempt.entered
}

// Format redacts original intent and key custody.
func (ResetRequestState) Format(s fmt.State, _ rune) {
	io.WriteString(s, "passwordhttp.ResetRequestState(redacted)")
}

// MarshalJSON denies state export.
func (ResetRequestState) MarshalJSON() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// MarshalText denies state export.
func (ResetRequestState) MarshalText() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// LogValue returns a fixed marker.
func (ResetRequestState) LogValue() slog.Value {
	return slog.StringValue("passwordhttp.ResetRequestState(redacted)")
}

func resetRequestAttemptFor(r *http.Request) *resetRequestAttempt {
	if a, ok := r.Context().Value(resetRequestAttemptKey{}).(*resetRequestAttempt); ok {
		return a
	}
	return &resetRequestAttempt{out: ResetRequestResponse{CommitOutcome: "none"}}
}

// NewResetRequestHandler selects POST /v1/password/reset-request. Closed JSON
// requires commandID, identifier and exact callbackURL, plus one Idempotency-Key
// header and the existing signed browser-device cookie. Original commandID must
// remain unchanged across explicit retries; no automatic retry/recovery runs.
func NewResetRequestHandler(c ResetRequestConfig) (http.Handler, error) {
	return NewResetRequestHandlerWithMiddleware(c, nil)
}

// NewResetRequestHandlerWithMiddleware binds existing typed owner phases. Hooks
// cannot replace frozen input, select a recipient or grant native authority.
func NewResetRequestHandlerWithMiddleware(c ResetRequestConfig, m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if c.Service == nil || c.Rate == nil || !c.Rate.Configured() || c.Now == nil || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || c.PolicyRevision == 0 {
		return nil, identityhttp.ErrInvalidInput
	}
	u, e := url.Parse(c.CallbackURL)
	if e != nil || u == nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || strings.Contains(c.CallbackURL, "#") || !visible(c.CallbackURL, 1, 2048) {
		return nil, identityhttp.ErrInvalidInput
	}
	network, e := identityhttp.NewNetworkResolver(c.Network)
	if e != nil {
		return nil, e
	}
	decoder, e := identityhttp.NewRequestDecoder(c.Network.Limits)
	if e != nil {
		return nil, e
	}
	origin, e := identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{Network: network, TrustedOrigins: []identityhttp.Origin{c.Origin}, RefererFallback: identityhttp.RefererFallbackDeny})
	if e != nil {
		return nil, e
	}
	devices, e := session.NewBrowserDeviceCodec(c.Device)
	if e != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	caller := func(tenant identity.TenantID, correlation string) authorization.DecisionContext {
		return authorization.DecisionContext{CorrelationID: correlation, PolicyRevision: c.PolicyRevision, Request: authorization.Request{Tenant: authorization.TenantID(tenant), Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: authorization.SubjectID(c.ActorID)}, Action: "identity.password.reset-request", Resource: authorization.Resource{Type: "identity.request-admission", ID: "identity.password.reset-request"}}}
	}
	if caller("configuration", "").Validate() != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	reject := func(w http.ResponseWriter, r *http.Request, err error) {
		a := resetRequestAttemptFor(r)
		a.out.Accepted = false
		f := failure{status: 503, code: "unavailable"}
		if errors.Is(err, identityhttp.ErrInvalidInput) {
			f = failure{status: 400, code: "invalid_request"}
		}
		var specific failure
		if errors.As(err, &specific) {
			f = specific
		}
		if f.status == 405 {
			w.Header().Set("Allow", http.MethodPost)
		}
		if f.retry > 0 {
			w.Header().Set("Retry-After", strconv.FormatInt(int64((min(max(f.retry, time.Second), time.Hour)+time.Second-1)/time.Second), 10))
		}
		a.out.Error = f.code
		w.WriteHeader(f.status)
		json.NewEncoder(w).Encode(a.out)
	}
	p, e := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[ResetRequestState]{MaximumDuration: c.MaximumDuration, Middleware: m, Reject: reject,
		Decode: func(r *http.Request) (ResetRequestState, error) {
			s := ResetRequestState{attempt: resetRequestAttemptFor(r)}
			if r.URL.Path != "/v1/password/reset-request" || r.URL.EscapedPath() != r.URL.Path {
				return s, failure{status: 404, code: "not_found"}
			}
			if r.Method != http.MethodPost {
				return s, failure{status: 405, code: "method_not_allowed"}
			}
			if r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Trailer) != 0 {
				return s, identityhttp.ErrInvalidInput
			}
			key, present, err := decoder.IdempotencyKey(r, identityhttp.HeaderRequired)
			if err != nil || !present {
				return s, identityhttp.ErrInvalidInput
			}
			for name := range r.Header {
				if strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "X-CSRF-Token") {
					return s, identityhttp.ErrInvalidInput
				}
			}
			facts, err := network.Resolve(r)
			if err != nil || facts.Realm() != identityhttp.RealmTenant {
				return s, failure{status: 421, code: "misdirected_request"}
			}
			if facts.Scheme() != "https" {
				return s, failure{status: 403, code: "https_required"}
			}
			if _, err = origin.Check(r); err != nil {
				return s, failure{status: 403, code: "origin_denied"}
			}
			now := c.Now()
			if now.IsZero() {
				return s, identityhttp.ErrUnavailable
			}
			device, present, err := decoder.CookieBearer(r, "__Host-identity_device", identityhttp.HeaderRequired)
			if err != nil || !present {
				return s, identityhttp.ErrInvalidInput
			}
			s.device, err = devices.Resolve(r.Context(), now, facts.TenantID(), facts.Origin(), device.Token())
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			body, err := identityhttp.DecodeJSON[map[string]json.RawMessage](decoder, r)
			if err != nil || len(body) != 3 {
				return s, identityhttp.ErrInvalidInput
			}
			var command, input, callback string
			for name, dst := range map[string]*string{"commandID": &command, "identifier": &input, "callbackURL": &callback} {
				raw, ok := body[name]
				if !ok || string(raw) == "null" || json.Unmarshal(raw, dst) != nil {
					return s, identityhttp.ErrInvalidInput
				}
			}
			id, err := identity.ParseCommandID(command)
			if err != nil || callback != c.CallbackURL {
				return s, identityhttp.ErrInvalidInput
			}
			identifierInput, err := identifier.NewInput(input)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			correlation, err := identity.NewCommandID()
			if err != nil {
				return s, identityhttp.ErrUnavailable
			}
			s.facts = facts
			s.request = password.ResetRequestRequest{TenantID: facts.TenantID(), CommandID: id, Identifier: identifierInput, CallbackURL: callback, IdempotencyKey: key, Caller: caller(facts.TenantID(), string(correlation)), Origin: string(c.Origin), Network: facts.ClientIP().String(), Device: s.device.DeviceID()}
			if s.request.Validate() != nil {
				return s, identityhttp.ErrInvalidInput
			}
			return s, nil
		},
		Authenticate: func(r *http.Request, s ResetRequestState) (ResetRequestState, error) {
			if err := signinRateError(c.Rate.AdmitDeliveryIP(r.Context(), s.facts, "identity.password.reset-request")); err != nil {
				return s, err
			}
			canonical, err := c.Service.ResetRequestRateSource(r.Context(), s.request.Identifier)
			if err != nil || r.Context().Err() != nil {
				return s, identityhttp.ErrUnavailable
			}
			s.identifier = canonical
			return s, nil
		},
		Admit: func(r *http.Request, s ResetRequestState) error {
			if !s.device.ExpiresAt().After(c.Now()) {
				return identityhttp.ErrUnavailable
			}
			return signinRateError(c.Rate.AdmitDeliveryIdentifier(r.Context(), s.facts, identityhttp.AuthRateRequest{OperationID: "identity.password.reset-request", Identifier: s.identifier}))
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s ResetRequestState) {
			if !s.device.ExpiresAt().After(c.Now()) {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			a := s.attempt
			a.entered = true
			a.out.CommitOutcome = "unknown"
			result, err := c.Service.ResetRequest(r.Context(), s.request)
			if result.Validate() != nil {
				var conflict identity.ConflictError
				if errors.As(err, &conflict) && r.Context().Err() == nil {
					reject(w, r, failure{status: 409, code: "conflict"})
					return
				}
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			a.out.CommandID = result.CommandID
			a.out.CommitOutcome = signinOutcome(result.Outcome)
			a.out.Recovery = &ResetRequestRecovery{AttemptID: s.request.CommandID, TenantID: s.request.TenantID, ActorID: c.ActorID, ActorKind: authorization.SubjectServiceAccount}
			if err != nil || r.Context().Err() != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			switch result.Outcome {
			case identity.CommitOutcomeCommitted:
				a.out.Accepted = true
				w.WriteHeader(200)
				json.NewEncoder(w).Encode(a.out)
			case identity.CommitOutcomeConflict:
				reject(w, r, failure{status: 409, code: "conflict"})
			case identity.CommitOutcomeInProgress:
				reject(w, r, failure{status: 409, code: "in_progress", retry: time.Second})
			case identity.CommitOutcomeNotCommitted:
				reject(w, r, failure{status: 403, code: "denied"})
			default:
				reject(w, r, identityhttp.ErrUnavailable)
			}
		},
	})
	if e != nil {
		return nil, e
	}
	return &resetRequestPipeline{pipeline: p}, nil
}

type resetRequestPipeline struct{ pipeline http.Handler }

func (p *resetRequestPipeline) WithOperationMiddleware(m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if p == nil || p.pipeline == nil {
		return nil, identityhttp.ErrInvalidInput
	}
	h, e := identityhttp.WithOperationMiddleware(p.pipeline, m)
	if e != nil {
		return nil, e
	}
	return &resetRequestPipeline{pipeline: h}, nil
}
func (p *resetRequestPipeline) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a := &resetRequestAttempt{out: ResetRequestResponse{CommitOutcome: "none"}}
	r = r.WithContext(context.WithValue(r.Context(), resetRequestAttemptKey{}, a))
	servePasswordPipeline(w, r, p.pipeline)
}
