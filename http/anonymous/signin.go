package anonymoushttp

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

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
)

// SigninService is the borrowed native workflow and original-possession rate
// source. Source authenticates the same frozen flow intent as Signin without
// generating identity, admission evidence or commands. Signin independently
// owns live admission, atomic effects and metadata-only keyed retries.
type SigninService interface {
	anonymous.Issuer
	SigninRateSource(context.Context, anonymous.SigninRequest) (string, error)
}

// SigninConfig explicitly selects browser guest creation, not another identity
// method. Service and shared Rate are borrowed concurrency-safe native owners.
// Origin, callback, lifetime and signed Device must match original pre-auth
// issuance. FlowCookie is __Host-identity_flow; SessionCookie must be distinct
// from it and the device cookie. ActorID/PolicyRevision/Audience are trusted
// deployment values, never browser input. Now is a trusted prompt clock.
// MaximumDuration is 1ms..30s; earlier inbound deadlines always win. Construction
// copies policy and performs no IO, callback, entropy or owner admission.
type SigninConfig struct {
	Network                   identityhttp.NetworkConfig
	Service                   SigninService
	Rate                      *identityhttp.AuthRateLimiter
	Origin                    identityhttp.Origin
	CallbackURL               string
	Lifetime                  session.LifetimeConfig
	FlowCookie, SessionCookie session.CookiePolicy
	Device                    session.BrowserDeviceConfig
	ActorID                   identity.ActorID
	PolicyRevision            authorization.Revision
	Audience                  string
	Now                       func() time.Time
	MaximumDuration           time.Duration
}

// Format hides runtime dependencies and deployment custody.
func (SigninConfig) Format(s fmt.State, _ rune) {
	io.WriteString(s, "anonymoushttp.SigninConfig(redacted)")
}

// MarshalJSON rejects implicit runtime configuration export.
func (SigninConfig) MarshalJSON() ([]byte, error) { return nil, anonymous.ErrDisclosure }

// MarshalText rejects implicit text/map-key export.
func (SigninConfig) MarshalText() ([]byte, error) { return nil, anonymous.ErrDisclosure }

// SigninRecovery is original credential-free command correlation. It grants
// neither disclosure nor permission to execute another command. Recover through
// the selected native API with original possession; no recovery route is added.
type SigninRecovery struct {
	CommandID identity.CommandID            `json:"commandID"`
	TenantID  identity.TenantID             `json:"tenantID"`
	FlowID    identity.PreAuthTransactionID `json:"flowID"`
	ActorID   identity.ActorID              `json:"actorID"`
	ActorKind authorization.SubjectKind     `json:"actorKind"`
}

// SigninResponse distinguishes fresh guest credential delivery from historical
// commitment. Replayed known commitment returns metadata, never another token.
// SignedIn never claims verified-user authentication. Unknown is not rollback.
type SigninResponse struct {
	SignedIn      bool               `json:"signedIn"`
	CommitOutcome string             `json:"commitOutcome"`
	CommandID     identity.CommandID `json:"commandID,omitempty"`
	Recovery      *SigninRecovery    `json:"recovery,omitempty"`
	Replayed      bool               `json:"replayed,omitempty"`
	Error         string             `json:"error,omitempty"`
}

type failure struct {
	status int
	code   string
	retry  time.Duration
}

func (f failure) Error() string { return "anonymoushttp." + f.code }

type signinState struct {
	facts   identityhttp.NetworkFacts
	request anonymous.SigninRequest
	device  session.BrowserDevice
	source  string
}

// NewSigninHandler constructs only POST /v1/anonymous/signin. Closed JSON
// requires flowID/callbackURL and optional boolean remember. Exactly one
// header-only Idempotency-Key, original flow cookie, signed device cookie and
// exact HTTPS tenant/origin are required. Authorization and CSRF alternatives
// are rejected. IP admission precedes the native authenticated source, then
// source admission precedes one native call. No automatic retry occurs.
// Only fresh error-free acknowledged commitment emits the configured guest
// cookie and X-CSRF-Token. Replays/errors emit credential-free metadata only.
// Responses are no-store/nosniff JSON. The server owns body/connection cleanup
// and bounded raw IO. Selecting this handler does not select any other route.
func NewSigninHandler(c SigninConfig) (http.Handler, error) {
	if nilOwner(c.Service) || !c.Rate.Configured() || c.Now == nil || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || c.PolicyRevision == 0 || !visible(string(c.ActorID), 128) || !visible(c.Audience, 256) {
		return nil, identityhttp.ErrInvalidInput
	}
	if _, err := session.ResolveRememberPolicy(session.RememberDefault, c.Lifetime); err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	flow, err := c.FlowCookie.DeletionAttributes()
	if err != nil || flow.Name != "__Host-identity_flow" {
		return nil, identityhttp.ErrInvalidInput
	}
	guest, err := c.SessionCookie.DeletionAttributes()
	if err != nil || guest.Name == flow.Name || guest.Name == "__Host-identity_device" {
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
	origin, err := identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{Network: network, TrustedOrigins: []identityhttp.Origin{c.Origin}, RefererFallback: identityhttp.RefererFallbackDeny})
	if err != nil {
		return nil, err
	}
	decoder, err := identityhttp.NewRequestDecoder(c.Network.Limits)
	if err != nil {
		return nil, err
	}
	reject := func(writer http.ResponseWriter, req *http.Request, e error) {
		a := attemptFor(req)
		out := &a.signin
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
		out.SignedIn = false
		out.Error = f.code
		a.cookies, a.csrf, a.fresh = nil, "", nil
		writeResponse(writer, f.status, out)
	}
	pipeline, e := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[signinState]{MaximumDuration: c.MaximumDuration, Reject: reject,
		Decode: func(req *http.Request) (signinState, error) {
			attemptFor(req).ctx = req.Context()
			var s signinState
			if req.URL.Path != "/v1/anonymous/signin" || req.URL.EscapedPath() != req.URL.Path {
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
			facts, err := network.Resolve(req)
			if err != nil || facts.Realm() != identityhttp.RealmTenant {
				return s, failure{status: 421, code: "misdirected_request"}
			}
			if facts.Scheme() != "https" {
				return s, identityhttp.ErrInvalidInput
			}
			if _, err = origin.Check(req); err != nil {
				return s, failure{status: 403, code: "origin_denied"}
			}
			if _, _, err = decoder.Bearer(req, identityhttp.HeaderForbidden); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			for name := range req.Header {
				if strings.EqualFold(name, "X-CSRF-Token") {
					return s, identityhttp.ErrInvalidInput
				}
			}
			bearer, present, err := decoder.CookieBearer(req, flow.Name, identityhttp.HeaderRequired)
			if err != nil || !present {
				return s, identityhttp.ErrInvalidInput
			}
			if _, err = session.ParseToken(bearer.Token()); err != nil {
				return s, identityhttp.ErrInvalidInput
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
			if err != nil || len(body) < 2 || len(body) > 3 {
				return s, identityhttp.ErrInvalidInput
			}
			var id, callback string
			for name, dst := range map[string]*string{"flowID": &id, "callbackURL": &callback} {
				raw, ok := body[name]
				if !ok || string(raw) == "null" || json.Unmarshal(raw, dst) != nil {
					return s, identityhttp.ErrInvalidInput
				}
			}
			choice := session.RememberDefault
			if raw, ok := body["remember"]; ok {
				var remember bool
				if string(raw) == "null" || json.Unmarshal(raw, &remember) != nil {
					return s, identityhttp.ErrInvalidInput
				}
				choice = session.BrowserSession
				if remember {
					choice = session.PersistentSession
				}
			} else if len(body) != 2 {
				return s, identityhttp.ErrInvalidInput
			}
			flowID, err := identity.ParsePreAuthTransactionID(id)
			if err != nil || callback != c.CallbackURL {
				return s, identityhttp.ErrInvalidInput
			}
			remember, err := session.ResolveRememberPolicy(choice, c.Lifetime)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			caller := authorization.DecisionContext{PolicyRevision: c.PolicyRevision, Request: authorization.Request{Tenant: authorization.TenantID(facts.TenantID()), Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: authorization.SubjectID(c.ActorID)}, Action: "identity.anonymous.signin", Resource: authorization.Resource{Type: "identity.request-admission", ID: "identity.anonymous.signin"}, Environment: authorization.Environment{Time: c.Now().UTC()}}}
			s.request = anonymous.SigninRequest{TenantID: facts.TenantID(), PreAuthID: flowID, Cookie: bearer, Remember: remember, Origin: string(c.Origin), CallbackURL: callback, Caller: caller, Network: facts.ClientIP().String(), Device: s.device.DeviceID(), IdempotencyKey: key}
			if s.request.Validate() != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.facts = facts
			return s, nil
		},
		Authenticate: func(req *http.Request, s signinState) (signinState, error) {
			if e := rateError(c.Rate.AdmitSigninIP(req.Context(), s.facts, "identity.anonymous.signin")); e != nil {
				return s, e
			}
			source, err := c.Service.SigninRateSource(req.Context(), s.request)
			if err != nil {
				var denied identity.ForbiddenError
				if errors.As(err, &denied) {
					return s, failure{status: 403, code: "denied"}
				}
				return s, identityhttp.ErrUnavailable
			}
			s.source = source
			return s, nil
		},
		Admit: func(req *http.Request, s signinState) error {
			if !s.device.ExpiresAt().After(c.Now()) {
				return identityhttp.ErrUnavailable
			}
			return rateError(c.Rate.AdmitSigninIdentifier(req.Context(), s.facts, identityhttp.AuthRateRequest{OperationID: "identity.anonymous.signin", Identifier: s.source}))
		},
		Handle: func(writer http.ResponseWriter, req *http.Request, s signinState) {
			a := attemptFor(req)
			out := &a.signin
			started := c.Now()
			if !s.device.ExpiresAt().After(c.Now()) {
				reject(writer, req, identityhttp.ErrUnavailable)
				return
			}
			result, err := c.Service.Signin(req.Context(), s.request)
			out.CommitOutcome = outcome(result.Outcome)
			out.Replayed = result.Replayed
			if q, flowID, e := result.Recovery.Bindings(); e == nil {
				if q.TenantID != s.request.TenantID || flowID != s.request.PreAuthID || q.ActorID != c.ActorID || q.ActorKind != authorization.SubjectServiceAccount {
					reject(writer, req, identityhttp.ErrUnavailable)
					return
				}
				out.CommandID = q.CommandID
				out.Recovery = &SigninRecovery{q.CommandID, q.TenantID, flowID, q.ActorID, q.ActorKind}
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
			if result.Replayed {
				writeResponse(writer, 200, out)
				return
			}
			cookie, csrf, err := signinDelivery(c, s.request, result, c.Now())
			if err != nil || req.Context().Err() != nil {
				reject(writer, req, identityhttp.ErrUnavailable)
				return
			}
			out.SignedIn = true
			a.cookies, a.csrf = []string{cookie}, csrf
			a.fresh = func() bool {
				now := c.Now()
				_, err := result.Session.Session.Lifetime(now)
				return !now.Before(started) && now.Before(started.Add(20*time.Second)) && now.Before(s.device.ExpiresAt()) && err == nil
			}
			a.revoke = func() { out.SignedIn = false; out.Error = "unavailable" }
			writeResponse(writer, 200, out)
		},
	})
	if e != nil {
		return nil, e
	}
	return &browserPipeline{pipeline: pipeline}, nil
}

func signinDelivery(c SigninConfig, r anonymous.SigninRequest, out anonymous.SigninResult, now time.Time) (string, string, error) {
	s, err := out.Session.Session.Bindings()
	q, _, scopeErr := out.Recovery.Bindings()
	if err != nil || scopeErr != nil || out.Session.CommandID != q.CommandID || out.Session.Replayed || out.Session.CommitOutcome != identity.CommitOutcomeCommitted || s.TenantID != r.TenantID || s.Audience != c.Audience || s.Remember != r.Remember || s.Authentication.Kind != session.AuthenticationAnonymous || s.IssuedAt.After(now) {
		return "", "", identityhttp.ErrUnavailable
	}
	return sessionDelivery(c.SessionCookie, out.Session, out.CSRFToken, now)
}

func sessionDelivery(cookie session.CookiePolicy, out session.IssueResult, token session.CSRFToken, now time.Time) (string, string, error) {
	s, err := out.Session.Bindings()
	if err != nil || out.Replayed || out.CommitOutcome != identity.CommitOutcomeCommitted || s.IssuedAt.After(now) {
		return "", "", identityhttp.ErrUnavailable
	}
	lifetime, err := out.Session.Lifetime(now)
	if err != nil {
		return "", "", identityhttp.ErrUnavailable
	}
	attributes, err := cookie.Attributes(s.Remember, now, lifetime.AbsoluteExpiresAt)
	if err != nil {
		return "", "", identityhttp.ErrUnavailable
	}
	issued := out.Cookie
	if issued.Name != attributes.Name || issued.Path != attributes.Path || issued.Domain != "" || !issued.Secure || !issued.HttpOnly || issued.SameSite != attributes.SameSite || issued.Partitioned || issued.Quoted || issued.RawExpires != "" || (attributes.MaxAge == 0 && (issued.MaxAge != 0 || !issued.Expires.IsZero())) || (attributes.MaxAge > 0 && (issued.MaxAge <= 0 || issued.Expires.IsZero() || issued.Expires.After(lifetime.AbsoluteExpiresAt))) {
		return "", "", identityhttp.ErrUnavailable
	}
	csrf, err := token.Reveal()
	if err != nil {
		return "", "", identityhttp.ErrUnavailable
	}
	wire, err := out.Token.Reveal()
	if err != nil {
		return "", "", identityhttp.ErrUnavailable
	}
	if _, err = session.ParseToken(wire); err != nil {
		return "", "", identityhttp.ErrUnavailable
	}
	attributes.Value = wire
	return attributes.String(), csrf, nil
}
func nilOwner(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Func, reflect.Map, reflect.Slice, reflect.Chan:
		return r.IsNil()
	}
	return false
}
func visible(s string, max int) bool {
	if len(s) == 0 || len(s) > max {
		return false
	}
	for i := range len(s) {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
func rateError(r identityhttp.AuthRateResult, e error) error {
	if errors.Is(e, identityhttp.ErrRateLimited) {
		return failure{status: 429, code: "rate_limited", retry: r.RetryAfter}
	}
	if e != nil || !r.Allowed {
		return identityhttp.ErrUnavailable
	}
	return nil
}
func outcome(o identity.CommitOutcome) string {
	switch o {
	case identity.CommitOutcomeNotCommitted:
		return "not_committed"
	case identity.CommitOutcomeCommitted:
		return "committed"
	case identity.CommitOutcomeUnknown:
		return "unknown"
	case identity.CommitOutcomeConflict:
		return "conflict"
	case identity.CommitOutcomeInProgress:
		return "in_progress"
	}
	return "none"
}
func writeResponse(w http.ResponseWriter, status int, out any) {
	// The custody wrapper can normalize delivery at the actual commitment edge.
	// Serialize the resulting metadata rather than a pre-commit value copy.
	w.WriteHeader(status)
	body, err := json.Marshal(out)
	if err != nil {
		return
	}
	w.Write(append(body, '\n'))
}
