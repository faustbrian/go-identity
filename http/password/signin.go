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

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-identifier"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
	primitive "github.com/faustbrian/go-password"
)

// SigninService is the borrowed native workflow and original-flow rate-source
// owner. Source must use the identical normalization/custody checks as Signin,
// without account lookup, comparison or mutation. Signin independently repeats
// admission and owns atomic consumption. Implementations honor bounded contexts
// and concurrent calls. This consumer port does not require a concrete adapter.
type SigninService interface {
	password.SigninService
	SigninRateSource(context.Context, password.SigninRequest) (string, error)
}

// SigninConfig selects browser password login. Service and Rate are retained
// borrowed owners; construction performs no IO. Origin and CallbackURL must
// match the original pre-auth issuer; Lifetime resolves the identical remember
// default. FlowCookie must be __Host-identity_flow; session/device names must be
// distinct. Device must match initialization's signed correlation profile.
// ActorID/PolicyRevision/Audience are trusted deployment policy, not a human
// principal. Now is prompt and concurrency-safe. MaximumDuration is 1ms..30s;
// earlier deadlines win. This profile issues cookies, never JSON/URL bearers.
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

// Format redacts runtime composition.
func (SigninConfig) Format(s fmt.State, _ rune) {
	io.WriteString(s, "passwordhttp.SigninConfig(redacted)")
}

// MarshalJSON denies implicit runtime export.
func (SigninConfig) MarshalJSON() ([]byte, error) { return nil, password.ErrSensitiveSerialization }

// MarshalText denies implicit runtime export.
func (SigninConfig) MarshalText() ([]byte, error) { return nil, password.ErrSensitiveSerialization }

// LogValue returns a fixed redacted marker.
func (SigninConfig) LogValue() slog.Value {
	return slog.StringValue("passwordhttp.SigninConfig(redacted)")
}

// SigninRecovery contains original password-free correlation for direct native
// recovery. It is not permission to read history or resubmit the password.
type SigninRecovery struct {
	CommandID identity.CommandID            `json:"commandID"`
	TenantID  identity.TenantID             `json:"tenantID"`
	FlowID    identity.PreAuthTransactionID `json:"flowID"`
	ActorID   identity.ActorID              `json:"actorID"`
	ActorKind authorization.SubjectKind     `json:"actorKind"`
}

// SigninResponse excludes identifiers, passwords and session/CSRF credentials.
// SignedIn means fresh delivery, not current authorization. Known command
// history survives delivery errors; none does not establish rollback.
type SigninResponse struct {
	SignedIn      bool               `json:"signedIn"`
	CommandID     identity.CommandID `json:"commandID,omitempty"`
	SessionID     string             `json:"sessionID,omitempty"`
	CommitOutcome string             `json:"commitOutcome"`
	Recovery      *SigninRecovery    `json:"recovery,omitempty"`
	Error         string             `json:"error,omitempty"`
}

// NewSigninHandler selects only POST /v1/password/signin. Closed JSON requires
// flowID, identifier, password and callbackURL, with optional boolean remember.
// Exact HTTPS mapped tenant/Origin, original flow cookie and signed device are
// required. No Authorization, retry key, query, trailers or CSRF alternative.
// IP admission precedes native source, then canonical identifier admission and
// one Signin call. No automatic retry. Only fresh error-free known commitment
// emits the original session cookie and synchronizer; all other exits emit none.
func NewSigninHandler(c SigninConfig) (http.Handler, error) {
	return NewSigninHandlerWithMiddleware(c, nil)
}

// NewSigninHandlerWithMiddleware binds typed immutable execution phases.
// Hooks observe safe attempt metadata, cannot replace input or mint credentials,
// and must not retain sensitive request headers or request-local state.
func NewSigninHandlerWithMiddleware(c SigninConfig, middleware []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if nilOwner(c.Service) || !c.Rate.Configured() || c.Now == nil || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || c.Audience == "" || len(c.Audience) > 256 || len(c.CallbackURL) > 2048 {
		return nil, identityhttp.ErrInvalidInput
	}
	for i := range len(c.Audience) {
		if c.Audience[i] <= 32 || c.Audience[i] >= 127 {
			return nil, identityhttp.ErrInvalidInput
		}
	}
	if c.CallbackURL != "" {
		u, err := url.Parse(c.CallbackURL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.Opaque != "" || u.User != nil || strings.Contains(c.CallbackURL, "#") {
			return nil, identityhttp.ErrInvalidInput
		}
		for i := range len(c.CallbackURL) {
			if c.CallbackURL[i] <= 32 || c.CallbackURL[i] >= 127 {
				return nil, identityhttp.ErrInvalidInput
			}
		}
	}
	network, err := identityhttp.NewNetworkResolver(c.Network)
	if err != nil {
		return nil, err
	}
	decoder, err := identityhttp.NewRequestDecoder(c.Network.Limits)
	if err != nil {
		return nil, err
	}
	origin, err := identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{Network: network, TrustedOrigins: []identityhttp.Origin{c.Origin}, RefererFallback: identityhttp.RefererFallbackDeny})
	if err != nil {
		return nil, err
	}
	flowCookie, err := c.FlowCookie.DeletionAttributes()
	if err != nil || flowCookie.Name != "__Host-identity_flow" {
		return nil, identityhttp.ErrInvalidInput
	}
	cookie, err := c.SessionCookie.DeletionAttributes()
	if err != nil || cookie.Name == flowCookie.Name || cookie.Name == "__Host-identity_device" {
		return nil, identityhttp.ErrInvalidInput
	}
	devices, err := session.NewBrowserDeviceCodec(c.Device)
	if err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	if _, err = session.ResolveRememberPolicy(session.RememberDefault, c.Lifetime); err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	caller := func(tenant identity.TenantID, correlation string) authorization.DecisionContext {
		return authorization.DecisionContext{CorrelationID: correlation, PolicyRevision: c.PolicyRevision, Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: authorization.SubjectID(c.ActorID)}, Tenant: authorization.TenantID(tenant), Action: "identity.password.signin", Resource: authorization.Resource{Type: "identity.request-admission", ID: "identity.password.signin"}}}
	}
	if caller("configuration", "").Validate() != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	reject := func(w http.ResponseWriter, r *http.Request, err error) {
		a := signinAttemptFor(r)
		a.cookie, a.csrf = "", ""
		a.out.SignedIn = false
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
		writeSigninResponse(w, f.status, a.out)
	}
	pipeline, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[SigninState]{MaximumDuration: c.MaximumDuration, Middleware: middleware, Reject: reject,
		Decode: func(r *http.Request) (SigninState, error) {
			s := SigninState{attempt: signinAttemptFor(r)}
			if r.URL.Path != "/v1/password/signin" || r.URL.EscapedPath() != r.URL.Path {
				return s, failure{status: 404, code: "not_found"}
			}
			if r.Method != http.MethodPost {
				return s, failure{status: 405, code: "method_not_allowed"}
			}
			if r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Trailer) != 0 {
				return s, identityhttp.ErrInvalidInput
			}
			if _, _, err := decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil {
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
			bearer, present, err := decoder.CookieBearer(r, flowCookie.Name, identityhttp.HeaderRequired)
			if err != nil || !present {
				return s, identityhttp.ErrInvalidInput
			}
			device, present, err := decoder.CookieBearer(r, "__Host-identity_device", identityhttp.HeaderRequired)
			if err != nil || !present {
				return s, identityhttp.ErrInvalidInput
			}
			s.device, err = devices.Resolve(r.Context(), c.Now(), facts.TenantID(), facts.Origin(), device.Token())
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			body, err := identityhttp.DecodeJSON[map[string]json.RawMessage](decoder, r)
			if err != nil {
				if r.Context().Err() != nil {
					return s, identityhttp.ErrUnavailable
				}
				return s, identityhttp.ErrInvalidInput
			}
			if len(body) < 4 || len(body) > 5 {
				return s, identityhttp.ErrInvalidInput
			}
			var flowID, identifierText, value, callback string
			for name, dst := range map[string]*string{"flowID": &flowID, "identifier": &identifierText, "password": &value, "callbackURL": &callback} {
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
			} else if len(body) != 4 {
				return s, identityhttp.ErrInvalidInput
			}
			id, err := identity.ParsePreAuthTransactionID(flowID)
			if err != nil || callback != c.CallbackURL || len(value) == 0 || len(value) > 1<<20 {
				return s, identityhttp.ErrInvalidInput
			}
			input, err := identifier.NewInput(identifierText)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			remember, err := session.ResolveRememberPolicy(choice, c.Lifetime)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			raw := []byte(value)
			secret, err := primitive.NewSecret(raw)
			clear(raw)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.attempt.secret = secret
			correlation, err := identity.NewCommandID()
			if err != nil {
				return s, identityhttp.ErrUnavailable
			}
			s.request = password.SigninRequest{TenantID: facts.TenantID(), PreAuthID: id, Cookie: bearer, Identifier: input, Password: secret, Remember: remember, Origin: string(c.Origin), CallbackURL: callback, Caller: caller(facts.TenantID(), string(correlation)), Network: facts.ClientIP().String(), Device: s.device.DeviceID()}
			if s.request.Validate() != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.facts = facts
			return s, nil
		},
		Authenticate: func(r *http.Request, s SigninState) (SigninState, error) {
			if err := signinRateError(c.Rate.AdmitSigninIP(r.Context(), s.facts, "identity.password.signin")); err != nil {
				return s, err
			}
			canonical, err := c.Service.SigninRateSource(r.Context(), s.request)
			if err != nil || r.Context().Err() != nil {
				return s, identityhttp.ErrUnavailable
			}
			s.identifier = canonical
			return s, nil
		},
		Admit: func(r *http.Request, s SigninState) error {
			if !s.device.ExpiresAt().After(c.Now()) {
				return identityhttp.ErrUnavailable
			}
			return signinRateError(c.Rate.AdmitSigninIdentifier(r.Context(), s.facts, identityhttp.AuthRateRequest{OperationID: "identity.password.signin", Identifier: s.identifier}))
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s SigninState) {
			if !s.device.ExpiresAt().After(c.Now()) {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			a := s.attempt
			a.attempted = true
			a.ctx = r.Context()
			a.out.CommitOutcome = "unknown"
			result, err := c.Service.Signin(r.Context(), s.request)
			if result.Validate() != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			q, flow, e := result.Recovery.Bindings()
			if e != nil || flow != s.request.PreAuthID || q.TenantID != s.request.TenantID || q.UserID != "" || q.AnonymousFlowID != string(flow) || q.ActorID != c.ActorID || q.ActorKind != authorization.SubjectServiceAccount {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			a.out.CommandID = q.CommandID
			a.out.CommitOutcome = signinOutcome(result.Issuance.CommitOutcome)
			a.out.Recovery = &SigninRecovery{q.CommandID, q.TenantID, flow, q.ActorID, q.ActorKind}
			a.out.SessionID = result.SessionID
			if err != nil || r.Context().Err() != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			if result.Issuance.CommitOutcome != identity.CommitOutcomeCommitted {
				f := failure{status: 503, code: "unavailable"}
				switch result.Issuance.CommitOutcome {
				case identity.CommitOutcomeNotCommitted:
					f = failure{status: 403, code: "denied"}
				case identity.CommitOutcomeConflict:
					f = failure{status: 409, code: "conflict"}
				case identity.CommitOutcomeInProgress:
					f = failure{status: 409, code: "in_progress", retry: result.Issuance.RetryAfter}
				}
				reject(w, r, f)
				return
			}
			if result.Issuance.Replayed || !s.device.ExpiresAt().After(c.Now()) {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			cookie, csrf, e := signinDelivery(c, s.request, result, c.Now())
			if e != nil || r.Context().Err() != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			a.cookie, a.csrf = cookie, csrf
			a.out.SignedIn = true
			writeSigninResponse(w, 200, a.out)
		},
	})
	if err != nil {
		return nil, err
	}
	return &signinPipeline{pipeline: pipeline}, nil
}

func signinDelivery(c SigninConfig, r password.SigninRequest, out password.SigninResult, now time.Time) (string, string, error) {
	spec, err := out.Issuance.Session.Bindings()
	if err != nil || spec.TenantID != r.TenantID || spec.Audience != c.Audience || spec.Remember != r.Remember || spec.IssuedAt.After(now) {
		return "", "", identityhttp.ErrUnavailable
	}
	p := spec.Authentication.Proof
	if p.ID != auth.ProofID(out.Issuance.CommandID) || p.Validate(auth.ProofUse{Tenant: string(r.TenantID), Subject: string(spec.UserID), Purpose: "session-issue", Audience: c.Audience, Now: now}) != nil {
		return "", "", identityhttp.ErrUnavailable
	}
	if _, err = spec.Remember.Evaluate(now, spec.IssuedAt, spec.LastActivityAt, p.IssuedAt); err != nil {
		return "", "", identityhttp.ErrUnavailable
	}
	state, err := out.Issuance.Session.CSRFState().Bindings()
	if err != nil || state.Binding != (session.CSRFBinding{TenantID: r.TenantID, SessionID: spec.SessionID, SessionVersion: spec.Version}) {
		return "", "", identityhttp.ErrUnavailable
	}
	attributes, err := c.SessionCookie.Attributes(spec.Remember, now, spec.IssuedAt.Add(spec.Remember.AbsoluteTTL()))
	issued := out.Issuance.Cookie
	if err != nil || issued.Name != attributes.Name || issued.Path != attributes.Path || issued.Domain != "" || !issued.Secure || !issued.HttpOnly || issued.SameSite != attributes.SameSite || issued.Partitioned || issued.Quoted || issued.RawExpires != "" || (attributes.MaxAge == 0 && (issued.MaxAge != 0 || !issued.Expires.IsZero())) || (attributes.MaxAge > 0 && (issued.MaxAge <= 0 || issued.Expires.IsZero() || issued.Expires.After(spec.IssuedAt.Add(spec.Remember.AbsoluteTTL())))) {
		return "", "", identityhttp.ErrUnavailable
	}
	csrf, err := out.CSRFToken.Reveal()
	if err != nil {
		return "", "", identityhttp.ErrUnavailable
	}
	wire, err := out.Issuance.Token.Reveal()
	if err != nil {
		return "", "", identityhttp.ErrUnavailable
	}
	if _, err = session.ParseToken(wire); err != nil {
		return "", "", identityhttp.ErrUnavailable
	}
	attributes.Value = wire
	return attributes.String(), csrf, nil
}
