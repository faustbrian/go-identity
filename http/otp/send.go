package otphttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	email "github.com/faustbrian/go-identity/email"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/session"
)

// EmailSigninSendConfig explicitly selects public pre-auth email signin Send.
// Network, Device and Address are validated/copied. Service and Rate are
// borrowed concurrency-safe owners honoring bounded contexts. Service must own
// primary flow authentication, counted risk/IP/device/identifier admission,
// durable idempotency and issuance/suppression; this transport replaces none.
// FlowCookie must be __Host-identity_flow. Device uses the same dedicated
// configuration as selected initiation; Send never creates missing custody.
// ActorID, positive PolicyRevision and TargetID are trusted deployment values,
// not user/tenant identity. Now is a prompt trusted concurrency-safe clock;
// MaximumDuration is 1ms..30s and never extends an inbound deadline. Other
// channels, purposes, authenticated sessions and MFA are not selected here.
type EmailSigninSendConfig struct {
	Network         identityhttp.NetworkConfig
	Service         otp.Service
	Rate            *identityhttp.AuthRateLimiter
	Origin          identityhttp.Origin
	FlowCookie      session.CookiePolicy
	Device          session.BrowserDeviceConfig
	Address         email.AddressPolicy
	ActorID         identity.ActorID
	PolicyRevision  authorization.Revision
	TargetID        string
	Now             func() time.Time
	MaximumDuration time.Duration
}

// Format redacts runtime composition and retained key policy.
func (EmailSigninSendConfig) Format(s fmt.State, _ rune) {
	io.WriteString(s, "otphttp.EmailSigninSendConfig(redacted)")
}

// MarshalJSON denies implicit runtime configuration export.
func (EmailSigninSendConfig) MarshalJSON() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

// MarshalText denies implicit runtime configuration export.
func (EmailSigninSendConfig) MarshalText() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

// LogValue redacts configuration diagnostics.
func (EmailSigninSendConfig) LogValue() slog.Value {
	return slog.StringValue("otphttp.EmailSigninSendConfig(redacted)")
}

// SendResponse exposes enumeration-safe original command status, not challenge,
// recipient or delivery state. Accepted means native issuance or suppression
// committed, never that a recipient exists or a message was delivered. Unknown
// remains unknown; retain the original key/input when resolving a native retry.
// No cookie, code, destination, device or session authority is returned.
type SendResponse struct {
	Accepted      bool               `json:"accepted"`
	CommandID     identity.CommandID `json:"commandID,omitempty"`
	CommitOutcome string             `json:"commitOutcome"`
	Error         string             `json:"error,omitempty"`
}

type sendAttempt struct {
	out       SendResponse
	attempted bool
}
type sendAttemptKey struct{}
type sendInput struct {
	facts   identityhttp.NetworkFacts
	request otp.SendRequest
	device  session.BrowserDevice
	attempt *sendAttempt
}

// SendState retains opaque request-local custody. It is not an authenticated
// user or reusable clearance. Copies may be observed by synchronous middleware;
// only detached safe attempted status is exposed. Do not retain beyond request.
type SendState struct{ input *sendInput }

// Attempt returns safe detached metadata; true means the native call was
// entered, not commitment or delivery. Zero has no attempted Send.
func (s SendState) Attempt() (SendResponse, bool) {
	if s.input == nil || s.input.attempt == nil {
		return SendResponse{CommitOutcome: "none"}, false
	}
	return s.input.attempt.out, s.input.attempt.attempted
}

// Format prevents traversal of private destination and credential custody.
func (SendState) Format(s fmt.State, _ rune) { io.WriteString(s, "otphttp.SendState(redacted)") }

// MarshalJSON denies implicit request-state export.
func (SendState) MarshalJSON() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

// MarshalText denies implicit request-state export.
func (SendState) MarshalText() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

// LogValue redacts request-state diagnostics.
func (SendState) LogValue() slog.Value { return slog.StringValue("otphttp.SendState(redacted)") }

// NewEmailSigninSendHandler constructs only POST /v1/otp/send for selected email
// signin. Closed JSON requires flowID and email. Exactly one Idempotency-Key is
// required and mapped unchanged; query/trailers/Authorization and all body
// alternatives deny. Exact HTTPS mapped tenant/Origin, original flow and valid
// existing device custody are mandatory. No fallback creates a replacement.
// Email owns normalization; trusted IP and scoped device feed native admission.
// Shared rate.delivery precedes one Send, with no automatic retries. Responses
// are no-store/nosniff JSON: 202 accepted, 400 input, 403 origin, 404 path,
// 405 method, 421 host, 429 rate, 409 conflict/in-progress, 503 unavailable.
// Errors preserve safe original outcome without claiming rollback or delivery.
// This constructor selects no feature metadata or full OTP/reference journey.
func NewEmailSigninSendHandler(c EmailSigninSendConfig) (http.Handler, error) {
	return NewEmailSigninSendHandlerWithMiddleware(c, nil)
}

// NewEmailSigninSendHandlerWithMiddleware retains real typed phases. Decode
// acquires immutable input, Authenticate is public/no-user, Admit owns transport
// delivery budgets, Handle calls the native owner once. Hooks cannot replace
// source custody or emit credentials, including cookie/CSRF response trailers.
func NewEmailSigninSendHandlerWithMiddleware(c EmailSigninSendConfig, middleware []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if nilOwner(c.Service) || !c.Rate.Configured() || c.Now == nil || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || !sendTarget(c.TargetID) {
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
	origin, err := identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{Network: network, TrustedOrigins: []identityhttp.Origin{c.Origin}, RefererFallback: identityhttp.RefererFallbackDeny})
	if err != nil {
		return nil, err
	}
	flowCookie, err := c.FlowCookie.DeletionAttributes()
	if err != nil || flowCookie.Name != "__Host-identity_flow" {
		return nil, identityhttp.ErrInvalidInput
	}
	devices, err := session.NewBrowserDeviceCodec(c.Device)
	if err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	addresses, err := email.NewAddressParser(c.Address)
	if err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	caller := func(tenant identity.TenantID) authorization.DecisionContext {
		return authorization.DecisionContext{PolicyRevision: c.PolicyRevision, Request: authorization.Request{Tenant: authorization.TenantID(tenant), Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: authorization.SubjectID(c.ActorID)}, Action: "identity.otp.send", Resource: authorization.Resource{Type: "identity.request-admission", ID: "identity.otp.send"}}}
	}
	if caller("configuration").Validate() != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	attemptFor := func(r *http.Request) *sendAttempt {
		if r != nil {
			if a, ok := r.Context().Value(sendAttemptKey{}).(*sendAttempt); ok {
				return a
			}
		}
		return &sendAttempt{out: SendResponse{CommitOutcome: "none"}}
	}
	respond := func(w http.ResponseWriter, a *sendAttempt, status int, code string) {
		a.out.Error = code
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(a.out)
	}
	reject := func(w http.ResponseWriter, r *http.Request, err error) {
		a := attemptFor(r)
		a.out.Accepted = false
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
			w.Header().Set("Retry-After", strconv.FormatInt(int64((min(failure.retry, time.Hour)+time.Second-1)/time.Second), 10))
		}
		respond(w, a, failure.status, failure.code)
	}
	pipeline, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[SendState]{MaximumDuration: c.MaximumDuration, Middleware: middleware, Reject: reject,
		Decode: func(r *http.Request) (SendState, error) {
			s := SendState{input: &sendInput{attempt: attemptFor(r)}}
			if r.URL.Path != "/v1/otp/send" || r.URL.EscapedPath() != r.URL.Path {
				return s, signinFailure{status: 404, code: "not_found"}
			}
			if r.Method != http.MethodPost {
				return s, signinFailure{status: 405, code: "method_not_allowed"}
			}
			if r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Trailer) != 0 {
				return s, identityhttp.ErrInvalidInput
			}
			key, present, err := decoder.IdempotencyKey(r, identityhttp.HeaderRequired)
			if err != nil || !present {
				return s, identityhttp.ErrInvalidInput
			}
			facts, err := network.Resolve(r)
			if err != nil || facts.Realm() != identityhttp.RealmTenant {
				return s, signinFailure{status: 421, code: "misdirected_request"}
			}
			if facts.Scheme() != "https" {
				return s, identityhttp.ErrInvalidInput
			}
			if _, err := origin.Check(r); err != nil {
				return s, signinFailure{status: 403, code: "origin_denied"}
			}
			bearer, found, err := decoder.CookieBearer(r, flowCookie.Name, identityhttp.HeaderRequired)
			if err != nil || !found {
				return s, identityhttp.ErrInvalidInput
			}
			deviceBearer, found, err := decoder.CookieBearer(r, "__Host-identity_device", identityhttp.HeaderRequired)
			if err != nil || !found {
				return s, identityhttp.ErrInvalidInput
			}
			device, err := devices.Resolve(r.Context(), c.Now(), facts.TenantID(), string(c.Origin), deviceBearer.Token())
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			input, err := identityhttp.DecodeJSON[map[string]json.RawMessage](decoder, r)
			if err != nil {
				if r.Context().Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return s, identityhttp.ErrUnavailable
				}
				return s, identityhttp.ErrInvalidInput
			}
			var flowID, address string
			if !recoveryFields(input, map[string]any{"flowID": &flowID, "email": &address}) {
				return s, identityhttp.ErrInvalidInput
			}
			id, err := identity.ParsePreAuthTransactionID(flowID)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			flow, err := otp.NewPreAuthSendFlow(id, bearer)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			parsed, err := addresses.Parse(email.AddressInput(address))
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			destination, err := otp.NewDestinationInput(parsed.Canonical().Record().Value)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.input.request = otp.SendRequest{TenantID: facts.TenantID(), Caller: caller(facts.TenantID()), Flow: flow, Channel: otp.ChannelEmail, Destination: destination, Purpose: otp.PurposeSignin, TargetID: c.TargetID, Network: facts.ClientIP().String(), Device: device.DeviceID(), IdempotencyKey: key}
			if s.input.request.Validate() != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.input.facts, s.input.device = facts, device
			return s, nil
		},
		Authenticate: func(_ *http.Request, s SendState) (SendState, error) { return s, nil },
		Admit: func(r *http.Request, s SendState) error {
			return signinRateError(c.Rate.Admit(r.Context(), s.input.facts, identityhttp.AuthRateRequest{OperationID: "identity.otp.send", Identifier: s.input.request.Destination.Value()}))
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s SendState) {
			a := s.input.attempt
			if !c.Now().Before(s.input.device.ExpiresAt()) {
				reject(w, r, identityhttp.ErrInvalidInput)
				return
			}
			a.attempted = true
			a.out.CommitOutcome = "unknown"
			result, err := c.Service.Send(r.Context(), s.input.request)
			if result.CommandID != "" {
				if _, e := identity.ParseCommandID(string(result.CommandID)); e != nil {
					reject(w, r, identityhttp.ErrUnavailable)
					return
				}
				a.out.CommandID = result.CommandID
			}
			if result.Outcome != 0 {
				a.out.CommitOutcome = outcome(result.Outcome)
			}
			// Retain every native outcome, but use the router's credential-free
			// cancellation failure profile even for conflict/in-progress receipts.
			if r.Context().Err() != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			if result.Outcome == identity.CommitOutcomeConflict {
				reject(w, r, signinFailure{status: 409, code: "conflict"})
				return
			}
			if result.Outcome == identity.CommitOutcomeInProgress {
				reject(w, r, signinFailure{status: 409, code: "in_progress", retry: result.RetryAfter})
				return
			}
			if err != nil || r.Context().Err() != nil || result.CommandID == "" || result.Outcome != identity.CommitOutcomeCommitted {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			a.out.Accepted = true
			respond(w, a, 202, "")
		},
	})
	if err != nil {
		return nil, err
	}
	return &sendPipeline{pipeline: pipeline}, nil
}

func sendTarget(s string) bool {
	if s == "" || len(s) > 256 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

// Send borrows the existing credential-response guard in its permanently
// unissued state. Only the actual consuming signin pipeline can set that guard's
// private issuance tuple; Send never gains cookie/CSRF output ownership.
type sendPipeline struct{ pipeline http.Handler }

func (p *sendPipeline) WithOperationMiddleware(m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if p == nil || p.pipeline == nil {
		return nil, identityhttp.ErrInvalidInput
	}
	bound, err := identityhttp.WithOperationMiddleware(p.pipeline, m)
	if err != nil {
		return nil, err
	}
	return &sendPipeline{pipeline: bound}, nil
}
func (p *sendPipeline) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r != nil {
		r = r.WithContext(context.WithValue(r.Context(), sendAttemptKey{}, &sendAttempt{out: SendResponse{CommitOutcome: "none"}}))
	}
	(&signinPipeline{pipeline: p.pipeline}).ServeHTTP(w, r)
}
