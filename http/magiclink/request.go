// Package magiclinkhttp provides explicitly selected magic-link HTTP operations.
// It supplies no UI and imports no native database adapter.
package magiclinkhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/magiclink"
	"github.com/faustbrian/go-identity/session"
)

// RequestService borrows native request processing and its frozen address parser.
// Normalization must perform no recipient lookup. Request independently owns
// browser custody, eligibility, risk, issuance and atomic encrypted delivery.
type RequestService interface {
	Request(context.Context, magiclink.RequestRequest) (magiclink.RequestResult, error)
	RequestRateSource(context.Context, email.AddressInput) (string, error)
}

// RequestConfig selects only request initiation. CallbackURL is a fixed allowed
// HTTPS destination, not a redirect. Service and Rate are concurrent-safe borrowed
// owners that must outlive requests. MaximumDuration is 1ms..30s; inbound deadlines
// win. The existing __Host-identity_flow cookie is required, but only the native
// workflow authenticates its current custody. Device must match the selected
// original-flow initializer's signed browser correlation profile. Now is a
// prompt trusted clock. A device signal is not MFA or authentication authority.
// Construction performs no IO.
type RequestConfig struct {
	Network         identityhttp.NetworkConfig
	Service         RequestService
	Rate            *identityhttp.AuthRateLimiter
	Origin          identityhttp.Origin
	CallbackURL     string
	ActorID         identity.ActorID
	PolicyRevision  authorization.Revision
	Device          session.BrowserDeviceConfig
	Now             func() time.Time
	MaximumDuration time.Duration
}

// RequestResponse acknowledges accepted processing, never recipient eligibility
// or delivery. Once native work is entered, CommandID retains the original
// attempt for proof-free recovery; known native results replace it with the
// original journal command. Unknown does not authorize a new request key.
type RequestResponse struct {
	Accepted      bool               `json:"accepted"`
	CommitOutcome string             `json:"commitOutcome"`
	CommandID     identity.CommandID `json:"commandID,omitempty"`
	Error         string             `json:"error,omitempty"`
}
type attemptKey struct{}
type requestAttempt struct{ out RequestResponse }
type requestState struct {
	facts     identityhttp.NetworkFacts
	request   magiclink.RequestRequest
	canonical string
}
type failure struct {
	status int
	code   string
	retry  time.Duration
}

func (failure) Error() string { return "identity.magiclink.http.denied" }
func attempt(r *http.Request) *requestAttempt {
	return r.Context().Value(attemptKey{}).(*requestAttempt)
}
func bounded(s string, max int) bool {
	if len(s) == 0 || len(s) > max {
		return false
	}
	for _, b := range []byte(s) {
		if b < 33 || b > 126 {
			return false
		}
	}
	return true
}
func outcome(o identity.CommitOutcome) string {
	switch o {
	case identity.CommitOutcomeCommitted:
		return "committed"
	case identity.CommitOutcomeNotCommitted:
		return "not_committed"
	case identity.CommitOutcomeConflict:
		return "conflict"
	case identity.CommitOutcomeInProgress:
		return "in_progress"
	}
	return "unknown"
}
func rateError(out identityhttp.AuthRateResult, err error) error {
	if errors.Is(err, identityhttp.ErrRateLimited) {
		return failure{429, "rate_limited", out.RetryAfter}
	}
	if err != nil || !out.Allowed {
		return identityhttp.ErrUnavailable
	}
	return nil
}

// NewRequestHandler selects POST /v1/magic-link/request only. Closed JSON
// requires commandID, email, intent, callbackURL and preAuthID, with exactly one
// Idempotency-Key and browser-flow cookie. Tenant, actor, origin and network are
// derived from trusted configuration/request facts, never JSON. It neither
// sends mail, issues a session, redirects nor retries native work.
func NewRequestHandler(c RequestConfig) (http.Handler, error) {
	return NewRequestHandlerWithMiddleware(c, nil)
}

// NewRequestHandlerWithMiddleware binds actual decode, normalization, admission
// and native-call phases. Hooks cannot replace private input or grant authority.
func NewRequestHandlerWithMiddleware(c RequestConfig, m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if c.Service == nil || c.Rate == nil || !c.Rate.Configured() || c.Now == nil || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || c.PolicyRevision == 0 {
		return nil, identityhttp.ErrInvalidInput
	}
	u, err := url.Parse(c.CallbackURL)
	if err != nil || u == nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || strings.Contains(c.CallbackURL, "#") || !bounded(c.CallbackURL, 2048) {
		return nil, identityhttp.ErrInvalidInput
	}
	network, err := identityhttp.NewNetworkResolver(c.Network)
	if err != nil {
		return nil, err
	}
	decoder, err := identityhttp.NewRequestDecoder(c.Network.Limits)
	if err != nil {
		return nil, err
	}
	devices, err := session.NewBrowserDeviceCodec(c.Device)
	if err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	origin, err := identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{Network: network, TrustedOrigins: []identityhttp.Origin{c.Origin}, RefererFallback: identityhttp.RefererFallbackDeny})
	if err != nil {
		return nil, err
	}
	caller := func(tenant identity.TenantID, correlation string) authorization.DecisionContext {
		return authorization.DecisionContext{CorrelationID: correlation, PolicyRevision: c.PolicyRevision, Request: authorization.Request{Tenant: authorization.TenantID(tenant), Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: authorization.SubjectID(c.ActorID)}, Action: "identity.magic-link.request", Resource: authorization.Resource{Type: "identity.request-admission", ID: "identity.magic-link.request"}}}
	}
	if caller("configuration", "").Validate() != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	reject := func(w http.ResponseWriter, r *http.Request, err error) {
		a := attempt(r)
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
		_ = json.NewEncoder(w).Encode(a.out)
	}
	p, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[requestState]{MaximumDuration: c.MaximumDuration, Middleware: m, Reject: reject,
		Decode: func(r *http.Request) (requestState, error) {
			var s requestState
			if r.URL.Path != "/v1/magic-link/request" || r.URL.EscapedPath() != r.URL.Path {
				return s, failure{status: 404, code: "not_found"}
			}
			if r.Method != http.MethodPost {
				return s, failure{status: 405, code: "method_not_allowed"}
			}
			if r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Trailer) != 0 {
				return s, identityhttp.ErrInvalidInput
			}
			key, present, e := decoder.IdempotencyKey(r, identityhttp.HeaderRequired)
			if e != nil || !present {
				return s, identityhttp.ErrInvalidInput
			}
			for name := range r.Header {
				if strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "Proxy-Authorization") || strings.EqualFold(name, "X-CSRF-Token") {
					return s, identityhttp.ErrInvalidInput
				}
			}
			facts, e := network.Resolve(r)
			if e != nil || facts.Realm() != identityhttp.RealmTenant {
				return s, failure{status: 421, code: "misdirected_request"}
			}
			if facts.Scheme() != "https" {
				return s, failure{status: 403, code: "https_required"}
			}
			if _, e = origin.Check(r); e != nil {
				return s, failure{status: 403, code: "origin_denied"}
			}
			cookie, present, e := decoder.CookieBearer(r, "__Host-identity_flow", identityhttp.HeaderRequired)
			if e != nil || !present {
				return s, identityhttp.ErrInvalidInput
			}
			deviceCookie, devicePresent, e := decoder.CookieBearer(r, "__Host-identity_device", identityhttp.HeaderRequired)
			if e != nil || !devicePresent {
				return s, identityhttp.ErrInvalidInput
			}
			device, e := devices.Resolve(r.Context(), c.Now(), facts.TenantID(), facts.Origin(), deviceCookie.Token())
			if e != nil {
				return s, identityhttp.ErrInvalidInput
			}
			body, e := identityhttp.DecodeJSON[map[string]json.RawMessage](decoder, r)
			if e != nil || len(body) != 5 {
				return s, identityhttp.ErrInvalidInput
			}
			var command, rawEmail, intent, callback, flow string
			for name, dst := range map[string]*string{"commandID": &command, "email": &rawEmail, "intent": &intent, "callbackURL": &callback, "preAuthID": &flow} {
				raw, ok := body[name]
				if !ok || string(raw) == "null" || json.Unmarshal(raw, dst) != nil {
					return s, identityhttp.ErrInvalidInput
				}
			}
			id, e := identity.ParseCommandID(command)
			if e != nil || callback != c.CallbackURL {
				return s, identityhttp.ErrInvalidInput
			}
			preAuth, e := identity.ParsePreAuthTransactionID(flow)
			if e != nil {
				return s, identityhttp.ErrInvalidInput
			}
			var selected magiclink.Intent
			switch intent {
			case "signin-only":
				selected = magiclink.SignInOnly
			case "signup-if-allowed":
				selected = magiclink.SignupIfAllowed
			default:
				return s, identityhttp.ErrInvalidInput
			}
			correlation, e := identity.NewCommandID()
			if e != nil {
				return s, identityhttp.ErrUnavailable
			}
			s.facts = facts
			s.request = magiclink.RequestRequest{TenantID: facts.TenantID(), CommandID: id, Email: email.AddressInput(rawEmail), Intent: selected, Callback: callback, IdempotencyKey: key, PreAuthID: preAuth, Cookie: cookie, Caller: caller(facts.TenantID(), string(correlation)), Origin: string(c.Origin), Network: facts.ClientIP().String(), Device: device.DeviceID()}
			if s.request.Validate() != nil {
				return s, identityhttp.ErrInvalidInput
			}
			return s, nil
		},
		Authenticate: func(r *http.Request, s requestState) (requestState, error) {
			if e := rateError(c.Rate.AdmitDeliveryIP(r.Context(), s.facts, "identity.magic-link.request")); e != nil {
				return s, e
			}
			canonical, e := c.Service.RequestRateSource(r.Context(), s.request.Email)
			if e != nil || r.Context().Err() != nil {
				return s, identityhttp.ErrUnavailable
			}
			s.canonical = canonical
			return s, nil
		},
		Admit: func(r *http.Request, s requestState) error {
			return rateError(c.Rate.AdmitDeliveryIdentifier(r.Context(), s.facts, identityhttp.AuthRateRequest{OperationID: "identity.magic-link.request", Identifier: s.canonical}))
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s requestState) {
			a := attempt(r)
			a.out.CommandID = s.request.CommandID
			a.out.CommitOutcome = "unknown"
			result, e := c.Service.Request(r.Context(), s.request)
			if result.Validate() != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			a.out.CommandID = result.CommandID
			a.out.CommitOutcome = outcome(result.Outcome)
			if e != nil || r.Context().Err() != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			switch result.Outcome {
			case identity.CommitOutcomeCommitted:
				a.out.Accepted = true
				w.WriteHeader(200)
				_ = json.NewEncoder(w).Encode(a.out)
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
	if err != nil {
		return nil, err
	}
	return &requestPipeline{pipeline: p}, nil
}
