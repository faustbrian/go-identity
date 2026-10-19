// Package otphttp provides explicitly selected OTP HTTP integrations. It does
// not own challenges, persistence, normalization or session issuance.
package otphttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/session"
)

// SigninConfig freezes the original public pre-auth login profile. Borrowed
// Service and Source must be the same selected native workflow owner; Source
// authenticates original custody without code comparisons or mutations, while
// Service independently revalidates it during atomic consumption. Rate is a
// retained shared strict owner. All owners must honor bounded contexts and be
// safe for concurrent requests; construction transfers no resource ownership.
// ActorID and positive PolicyRevision are trusted deployment policy, not user
// identity. The fixed action/resource is identity.otp.signin/request-admission.
// FlowCookie must be __Host-identity_flow. SessionCookie must be distinct;
// Audience must match the selected issuer. Now is a trusted prompt clock and
// MaximumDuration is 1ms..30s, never extending an inbound deadline.
type SigninConfig struct {
	Network                   identityhttp.NetworkConfig
	Service                   otp.SigninService
	Source                    otp.SigninSourceService
	Rate                      *identityhttp.AuthRateLimiter
	Origin                    identityhttp.Origin
	FlowCookie, SessionCookie session.CookiePolicy
	ActorID                   identity.ActorID
	PolicyRevision            authorization.Revision
	Audience                  string
	Now                       func() time.Time
	MaximumDuration           time.Duration
}

// Format prevents implicit traversal of runtime composition and borrowed owners.
func (SigninConfig) Format(s fmt.State, _ rune) { io.WriteString(s, "otphttp.SigninConfig(redacted)") }

// MarshalJSON denies implicit runtime configuration export.
func (SigninConfig) MarshalJSON() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

// MarshalText denies implicit runtime configuration export.
func (SigninConfig) MarshalText() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

// SigninRecovery carries only original code-free correlation for direct native
// recovery. It is neither permission nor a new attempt. Recovery never issues
// credentials; do not resubmit Signin after an ambiguous result.
type SigninRecovery struct {
	SendCommandID    identity.CommandID `json:"sendCommandID"`
	Attempt          SigninAttempt      `json:"attempt"`
	ExpectedVersion  uint64             `json:"expectedVersion"`
	DigestKeyVersion uint32             `json:"digestKeyVersion"`
	ScopeDigest      [32]byte           `json:"scopeDigest"`
}

// SigninAttempt is an explicit code-free projection, not opaque owner export.
// Native recovery authenticates every field against retained original custody.
type SigninAttempt struct {
	CommandID             identity.CommandID `json:"commandID"`
	TenantID              identity.TenantID  `json:"tenantID"`
	AttemptID             string             `json:"attemptID"`
	Fingerprint           string             `json:"fingerprint"`
	FingerprintKeyVersion uint32             `json:"fingerprintKeyVersion"`
}

// SigninResponse deliberately excludes code, destination, bearer and CSRF
// material. Cookie and X-CSRF-Token deliver fresh native credentials only on
// exact committed success. SessionID is historical metadata, not authority.
// none means no authoritative observation, never inferred rollback.
type SigninResponse struct {
	SignedIn      bool               `json:"signedIn"`
	CommandID     identity.CommandID `json:"commandID,omitempty"`
	SessionID     string             `json:"sessionID,omitempty"`
	CommitOutcome string             `json:"commitOutcome"`
	Recovery      *SigninRecovery    `json:"recovery,omitempty"`
	Error         string             `json:"error,omitempty"`
}

// NewSigninHandler constructs POST /v1/otp/signin without IO or registration.
// Closed JSON requires flowID, sendCommandID and code only. Exact HTTPS tenant
// host, Origin and one original flow cookie are mandatory; Authorization,
// Idempotency-Key, query and trailers are forbidden. The native source, not a
// replacement identifier, supplies the rate.signin destination. There is one
// consuming call and no retry/recovery fallback. Errors, panic, cancellation,
// replay, unknown outcomes and malformed native output emit no credentials.
// Responses are no-store/nosniff JSON: 200 success, 400 input, 403 origin,
// 404 path, 405 method, 421 host, 429 rate and 503 unavailable/generic denial.
// This handler alone does not advertise an optional feature or establish the
// complete Send, recovery, OpenAPI or reference-login acceptance.
func NewSigninHandler(c SigninConfig) (http.Handler, error) {
	return NewSigninHandlerWithMiddleware(c, nil)
}

// NewSigninHandlerWithMiddleware retains original signin security with real
// typed execution phases. Decode acquires bounded immutable input; Authenticate
// admits trusted IP and discovers original native custody; Admit debits only the
// canonical identifier; Handle makes the sole consuming call. Hooks cannot
// replace private input or manufacture session/CSRF delivery. After-handler
// observes attempts, not an assertion of commitment. Detached request headers
// remain sensitive; hooks must not log or retain them.
func NewSigninHandlerWithMiddleware(c SigninConfig, middleware []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	return newSigninHandler(c, middleware, false)
}

// NewPhoneSigninHandler selects only POST /v1/phone/signin using the original
// phone SMS-code owner and original-source reader. Both must be the same native
// phone workflow; neither may be an email OTP owner or a caller destination.
// The original flow, rate, timeout and guarded credential-delivery semantics
// are the same as NewSigninHandler, with a fixed phone action and SMS-only
// source/authentication provenance. No route or feature is registered here.
func NewPhoneSigninHandler(c SigninConfig) (http.Handler, error) {
	return NewPhoneSigninHandlerWithMiddleware(c, nil)
}

// NewPhoneSigninHandlerWithMiddleware retains the same real typed execution
// phases, without exposing a caller-configurable workflow/path substitution.
func NewPhoneSigninHandlerWithMiddleware(c SigninConfig, middleware []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	return newSigninHandler(c, middleware, true)
}

func newSigninHandler(c SigninConfig, middleware []identityhttp.MiddlewareDescriptor, phone bool) (http.Handler, error) {
	if nilOwner(c.Service) || nilOwner(c.Source) || !c.Rate.Configured() || c.Now == nil || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || c.Audience == "" {
		return nil, identityhttp.ErrInvalidInput
	}
	action, path := authorization.Action("identity.otp.signin"), "/v1/otp/signin"
	if phone {
		action, path = "identity.phone.signin", "/v1/phone/signin"
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
	if err != nil || cookie.Name == flowCookie.Name {
		return nil, identityhttp.ErrInvalidInput
	}
	caller := func(tenant identity.TenantID) authorization.DecisionContext {
		return authorization.DecisionContext{PolicyRevision: c.PolicyRevision, Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: authorization.SubjectID(c.ActorID)}, Tenant: authorization.TenantID(tenant), Action: action, Resource: authorization.Resource{Type: "identity.request-admission", ID: authorization.ResourceID(action)}}}
	}
	if caller("configuration").Validate() != nil || len(c.Audience) > 256 {
		return nil, identityhttp.ErrInvalidInput
	}

	reject := func(w http.ResponseWriter, r *http.Request, err error) {
		a := signinAttemptFor(r)
		a.cookie, a.csrf = "", ""
		a.out.SignedIn = false
		failure := signinFailure{status: 503, code: "unavailable"}
		if errors.Is(err, identityhttp.ErrInvalidInput) {
			failure = signinFailure{status: 400, code: "invalid_request"}
		}
		var specific signinFailure
		if errors.As(err, &specific) {
			failure = specific
		}
		if failure.status == 405 {
			w.Header().Set("Allow", http.MethodPost)
		}
		if failure.retry > 0 {
			w.Header().Set("Retry-After", strconv.FormatInt(int64((min(max(failure.retry, time.Second), time.Hour)+time.Second-1)/time.Second), 10))
		}
		signinResponse(w, a, failure.status, failure.code)
	}
	pipeline, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[SigninState]{
		MaximumDuration: c.MaximumDuration, Middleware: middleware, Reject: reject,
		Decode: func(r *http.Request) (SigninState, error) {
			s := SigninState{attempt: signinAttemptFor(r)}
			ctx := r.Context()
			if r.URL.Path != path || r.URL.EscapedPath() != r.URL.Path {
				return s, signinFailure{status: 404, code: "not_found"}
			}
			if r.Method != http.MethodPost {
				return s, signinFailure{status: 405, code: "method_not_allowed"}
			}
			if r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Trailer) != 0 {
				return s, signinFailure{status: 400, code: "invalid_request"}
			}
			if _, _, err := decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil {
				return s, signinFailure{status: 400, code: "invalid_request"}
			}
			facts, err := network.Resolve(r)
			if err != nil || facts.Realm() != identityhttp.RealmTenant {
				return s, signinFailure{status: 421, code: "misdirected_request"}
			}
			if facts.Scheme() != "https" {
				return s, signinFailure{status: 400, code: "invalid_request"}
			}
			if _, err := origin.Check(r); err != nil {
				return s, signinFailure{status: 403, code: "origin_denied"}
			}
			bearer, present, err := decoder.CookieBearer(r, flowCookie.Name, identityhttp.HeaderRequired)
			if err != nil || !present {
				return s, signinFailure{status: 400, code: "invalid_request"}
			}
			input, err := identityhttp.DecodeJSON[map[string]json.RawMessage](decoder, r)
			if err != nil {
				if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return s, identityhttp.ErrUnavailable
				}
				return s, identityhttp.ErrInvalidInput
			}
			if len(input) != 3 {
				return s, signinFailure{status: 400, code: "invalid_request"}
			}
			var flowID, commandID, code string
			for key, dst := range map[string]*string{"flowID": &flowID, "sendCommandID": &commandID, "code": &code} {
				raw, ok := input[key]
				if !ok || string(raw) == "null" || json.Unmarshal(raw, dst) != nil {
					return s, signinFailure{status: 400, code: "invalid_request"}
				}
			}
			id, err := identity.ParsePreAuthTransactionID(flowID)
			if err != nil {
				return s, signinFailure{status: 400, code: "invalid_request"}
			}
			command, err := identity.ParseCommandID(commandID)
			if err != nil {
				return s, signinFailure{status: 400, code: "invalid_request"}
			}
			flow, err := otp.NewPreAuthSendFlow(id, bearer)
			if err != nil {
				return s, signinFailure{status: 400, code: "invalid_request"}
			}
			opaqueCode, err := auth.NewOneTimeCode(code)
			if err != nil {
				return s, signinFailure{status: 400, code: "invalid_request"}
			}
			s.request = otp.SigninRequest{TenantID: facts.TenantID(), Caller: caller(facts.TenantID()), Flow: flow, SendCommandID: command, Code: opaqueCode}
			if s.request.Validate() != nil {
				return s, signinFailure{status: 400, code: "invalid_request"}
			}

			s.facts = facts
			return s, nil
		},
		Authenticate: func(r *http.Request, s SigninState) (SigninState, error) {
			if err := signinRateError(c.Rate.AdmitSigninIP(r.Context(), s.facts, string(action))); err != nil {
				return s, err
			}
			request := s.request
			source, err := c.Source.ResolveSigninSource(r.Context(), otp.SigninSourceRequest{TenantID: request.TenantID, Caller: request.Caller, Flow: request.Flow, SendCommandID: request.SendCommandID})
			binding, e := source.Bindings()
			if err != nil || e != nil || r.Context().Err() != nil || binding.TenantID != request.TenantID || binding.SendCommandID != request.SendCommandID || phone && binding.Channel != otp.ChannelSMS {
				return s, identityhttp.ErrUnavailable
			}
			s.identifier = binding.Destination.Value()
			return s, nil
		},
		Admit: func(r *http.Request, s SigninState) error {
			return signinRateError(c.Rate.AdmitSigninIdentifier(r.Context(), s.facts, identityhttp.AuthRateRequest{OperationID: string(action), Identifier: s.identifier}))
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s SigninState) {
			a := s.attempt
			a.attempted = true
			a.ctx = r.Context()
			out := &a.out
			ctx := r.Context()
			request := s.request
			command := request.SendCommandID
			respond := func(status int, code string) {
				a.cookie, a.csrf = "", ""
				a.out.SignedIn = false
				signinResponse(w, a, status, code)
			}
			out.CommitOutcome = "unknown"
			result, err := c.Service.Signin(ctx, request)
			if _, e := identity.ParseCommandID(string(result.Issuance.CommandID)); e == nil {
				out.CommandID = result.Issuance.CommandID
				out.CommitOutcome = outcome(result.Issuance.CommitOutcome)
			}
			if b, e := result.Recovery.Bindings(); e == nil && b.SendCommandID == command && b.Attempt.TenantID == request.TenantID && (result.Issuance.CommandID == "" || b.Attempt.CommandID == result.Issuance.CommandID) {
				if result.Issuance.CommandID == "" {
					out.CommandID = b.Attempt.CommandID
					out.CommitOutcome = "none"
				}
				out.Recovery = &SigninRecovery{SendCommandID: b.SendCommandID, Attempt: SigninAttempt{CommandID: b.Attempt.CommandID, TenantID: b.Attempt.TenantID, AttemptID: string(b.Attempt.AttemptID), Fingerprint: string(b.Attempt.Fingerprint), FingerprintKeyVersion: b.Attempt.FingerprintKeyVersion}, ExpectedVersion: b.ExpectedVersion, DigestKeyVersion: b.DigestKeyVersion, ScopeDigest: b.ScopeDigest}
			}
			if err != nil || ctx.Err() != nil || out.CommandID == "" || result.Issuance.CommandID != out.CommandID || out.Recovery == nil || result.Issuance.CommitOutcome != identity.CommitOutcomeCommitted || result.Issuance.Replayed {
				respond(503, "unavailable")
				return
			}
			spec, e := result.Issuance.Session.Bindings()
			now := c.Now()
			if e != nil || spec.TenantID != request.TenantID || spec.Audience != c.Audience || spec.SessionID != result.SessionID || spec.IssuedAt.After(now) || !now.Before(spec.IssuedAt.Add(spec.Remember.AbsoluteTTL())) || result.Issuance.Cookie.Value != "" {
				respond(503, "unavailable")
				return
			}
			metadata, e := result.Issuance.Session.OTPAuthentication().Bindings()
			csrfState, csrfErr := result.Issuance.Session.CSRFState().Bindings()
			if e != nil || metadata.CommandID != out.CommandID || metadata.SendCommandID != command || !now.Before(metadata.ValidUntil) || phone && metadata.IdentifierKind != identity.IdentifierPhone || csrfErr != nil || csrfState.Binding != (session.CSRFBinding{TenantID: request.TenantID, SessionID: result.SessionID, SessionVersion: spec.Version}) {
				respond(503, "unavailable")
				return
			}
			if _, e = spec.Remember.Evaluate(now, spec.IssuedAt, spec.LastActivityAt, metadata.AuthenticatedAt); e != nil {
				respond(503, "unavailable")
				return
			}
			attributes, e := c.SessionCookie.Attributes(spec.Remember, now, spec.IssuedAt.Add(spec.Remember.AbsoluteTTL()))
			issuedCookie := result.Issuance.Cookie
			// Match the fixed scope/security tuple, then serialize the selected
			// policy at delivery time. Native persistence attributes may be older;
			// recomputing only remaining lifetime cannot extend original expiry.
			if e != nil || issuedCookie.Name != attributes.Name || issuedCookie.Path != attributes.Path || issuedCookie.Domain != "" || !issuedCookie.Secure || !issuedCookie.HttpOnly || issuedCookie.SameSite != attributes.SameSite || issuedCookie.Partitioned || len(issuedCookie.Unparsed) != 0 || issuedCookie.Raw != "" || issuedCookie.RawExpires != "" || (attributes.MaxAge == 0 && (issuedCookie.MaxAge != 0 || !issuedCookie.Expires.IsZero())) || (attributes.MaxAge > 0 && (issuedCookie.MaxAge <= 0 || issuedCookie.Expires.IsZero() || issuedCookie.Expires.After(spec.IssuedAt.Add(spec.Remember.AbsoluteTTL())))) {
				respond(503, "unavailable")
				return
			}
			csrf, e := result.CSRFToken.Reveal()
			if e != nil {
				respond(503, "unavailable")
				return
			}
			wire, e := result.Issuance.Token.Reveal()
			if e != nil {
				respond(503, "unavailable")
				return
			}
			if _, e = session.ParseToken(wire); e != nil || ctx.Err() != nil {
				respond(503, "unavailable")
				return
			}
			attributes.Value = wire
			out.SignedIn = true
			out.SessionID = result.SessionID
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			a.cookie = attributes.String()
			a.csrf = csrf
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(out)

		},
	})
	if err != nil {
		return nil, err
	}
	return &signinPipeline{pipeline: pipeline}, nil
}

func nilOwner(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return r.IsNil()
	}
	return false
}
func outcome(o identity.CommitOutcome) string {
	switch o {
	case identity.CommitOutcomeCommitted:
		return "committed"
	case identity.CommitOutcomeNotCommitted:
		return "not_committed"
	case identity.CommitOutcomeUnknown:
		return "unknown"
	case identity.CommitOutcomeConflict:
		return "conflict"
	case identity.CommitOutcomeInProgress:
		return "in_progress"
	}
	return "unknown"
}
