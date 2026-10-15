package mfahttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/session"
)

// OTPSendService borrows the native original-child sending owner. Its rate
// source authenticates the original canonical recipient without allocating a
// command, preparing output, generating a code or mutating a quota. Destination
// metadata is internal only, never sending authority or HTTP response data.
// Both methods are bounded, concurrent-safe and owned by the same service.
type OTPSendService interface {
	OtpSend(context.Context, mfa.OtpSendRequest) (mfa.OtpSendResult, error)
	OtpSendingRateSource(context.Context, mfa.OtpSendRequest) (string, error)
}

// OTPSendConfig explicitly selects secondary-OTP sending for password-origin
// partial login, not authenticated enrollment or ordinary OTP signin. Original
// network/browser/device/callback and actor policy must match native issuance.
// Service/Rate/Now remain borrowed and concurrent-safe; MaximumDuration is
// 1ms..30s, with earlier inbound deadlines winning. Construction performs no IO.
type OTPSendConfig struct {
	Network         identityhttp.NetworkConfig
	Service         OTPSendService
	Rate            *identityhttp.AuthRateLimiter
	Origin          identityhttp.Origin
	CallbackURL     string
	Device          session.BrowserDeviceConfig
	ActorID         identity.ActorID
	PolicyRevision  authorization.Revision
	Now             func() time.Time
	MaximumDuration time.Duration
}

// OTPSendResponse contains only no-store historical queue/outcome metadata.
// Accepted means the original queue commitment, never provider delivery, factor
// verification or login. No code, destination, proof, session or CSRF is exposed.
type OTPSendResponse struct {
	Accepted      bool               `json:"accepted"`
	CommandID     identity.CommandID `json:"commandID,omitempty"`
	CommitOutcome string             `json:"commitOutcome"`
	ChallengeID   string             `json:"challengeID,omitempty"`
	DeliveryState string             `json:"deliveryState,omitempty"`
	Error         string             `json:"error,omitempty"`
}

type otpSendAttemptKey struct{}
type otpSendAttempt struct {
	out   OTPSendResponse
	proof capability.Proof
}
type otpSendInput struct {
	facts             identityhttp.NetworkFacts
	request           mfa.OtpSendRequest
	device            session.BrowserDevice
	wire, destination string
}

func sendingAttempt(r *http.Request) *otpSendAttempt {
	return r.Context().Value(otpSendAttemptKey{}).(*otpSendAttempt)
}

// NewOTPSendHandler selects POST /v1/mfa/otp-send. Closed JSON contains original
// preAuthID/continuationID, enrolled factorID/channel, token and callbackURL.
// Exactly one original Idempotency-Key is required; the native owner assigns
// CommandID. Destination/user/generation/command/key alternatives are forbidden.
// Sending cannot consume the child, enroll a factor or issue credentials.
func NewOTPSendHandler(c OTPSendConfig) (http.Handler, error) {
	return NewOTPSendHandlerWithMiddleware(c, nil)
}

// NewOTPSendHandlerWithMiddleware binds actual decode, delivery-IP/source,
// canonical-destination quota and native send phases. Hooks cannot replace
// private intent, bypass the native owner or acquire credential output custody.
func NewOTPSendHandlerWithMiddleware(c OTPSendConfig, m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if enableNil(c.Service) || !c.Rate.Configured() || c.Now == nil || c.PolicyRevision == 0 || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second {
		return nil, identityhttp.ErrInvalidInput
	}
	u, err := url.Parse(c.CallbackURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || strings.Contains(c.CallbackURL, "#") || len(c.CallbackURL) > 2048 {
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
	caller := func(tenant identity.TenantID, child string) authorization.DecisionContext {
		return authorization.DecisionContext{PolicyRevision: c.PolicyRevision, Request: authorization.Request{Tenant: authorization.TenantID(tenant), Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: authorization.SubjectID(c.ActorID)}, Action: "identity.mfa.otp-send", Resource: authorization.Resource{Type: "identity.mfa-continuation", ID: authorization.ResourceID(child)}}}
	}
	if caller("configuration", "configuration").Validate() != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	reject := func(w http.ResponseWriter, r *http.Request, err error) {
		a := sendingAttempt(r)
		a.out.Accepted = false
		a.out.ChallengeID = ""
		a.out.DeliveryState = ""
		f := rejection{status: 503, code: "unavailable"}
		var specific rejection
		var denied identity.ForbiddenError
		var conflict identity.ConflictError
		var invalid identity.InvalidInputError
		switch {
		case errors.As(err, &specific):
			f = specific
		case errors.Is(err, identityhttp.ErrInvalidInput) || errors.As(err, &invalid):
			f = rejection{status: 400, code: "invalid_request"}
		case errors.As(err, &denied):
			f = rejection{status: 403, code: "denied"}
		case errors.As(err, &conflict):
			f = rejection{status: 409, code: "conflict"}
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
	pipeline, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[otpSendInput]{MaximumDuration: c.MaximumDuration, Middleware: m, Reject: reject,
		Decode: func(r *http.Request) (otpSendInput, error) {
			var s otpSendInput
			if r.URL.Path != "/v1/mfa/otp-send" || r.URL.EscapedPath() != r.URL.Path {
				return s, rejection{status: 404, code: "not_found"}
			}
			if r.Method != http.MethodPost {
				return s, rejection{status: 405, code: "method_not_allowed"}
			}
			if r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Trailer) != 0 {
				return s, identityhttp.ErrInvalidInput
			}
			for name := range r.Header {
				if strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "Proxy-Authorization") || strings.EqualFold(name, "X-CSRF-Token") || strings.EqualFold(name, "X-MFA-Variant") {
					return s, identityhttp.ErrInvalidInput
				}
			}
			key, present, err := decoder.IdempotencyKey(r, identityhttp.HeaderRequired)
			if err != nil || !present {
				return s, identityhttp.ErrInvalidInput
			}
			facts, err := network.Resolve(r)
			if err != nil || facts.Realm() != identityhttp.RealmTenant {
				return s, rejection{status: 421, code: "misdirected_request"}
			}
			if facts.Scheme() != "https" {
				return s, rejection{status: 403, code: "https_required"}
			}
			if _, err := origin.Check(r); err != nil {
				return s, rejection{status: 403, code: "origin_denied"}
			}
			browser, present, err := decoder.CookieBearer(r, "__Host-identity_flow", identityhttp.HeaderRequired)
			if err != nil || !present {
				return s, identityhttp.ErrInvalidInput
			}
			deviceCookie, present, err := decoder.CookieBearer(r, "__Host-identity_device", identityhttp.HeaderRequired)
			if err != nil || !present {
				return s, identityhttp.ErrInvalidInput
			}
			device, err := devices.Resolve(r.Context(), c.Now(), facts.TenantID(), facts.Origin(), deviceCookie.Token())
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			body, err := identityhttp.DecodeJSON[map[string]json.RawMessage](decoder, r)
			if err != nil || len(body) != 6 {
				return s, identityhttp.ErrInvalidInput
			}
			defer func() {
				for _, raw := range body {
					clear(raw)
				}
			}()
			var flow, child, factor, channel, wire, callback string
			for name, dst := range map[string]*string{"preAuthID": &flow, "continuationID": &child, "factorID": &factor, "channel": &channel, "token": &wire, "callbackURL": &callback} {
				raw, ok := body[name]
				if !ok || string(raw) == "null" || json.Unmarshal(raw, dst) != nil {
					return s, identityhttp.ErrInvalidInput
				}
			}
			preauth, err := identity.ParsePreAuthTransactionID(flow)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			if _, err := identity.ParseCommandID(child); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			if _, err := identity.ParseCommandID(factor); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			if callback != c.CallbackURL || len(wire) < 32 || len(wire) > 4096 {
				return s, identityhttp.ErrInvalidInput
			}
			var selected delivery.Channel
			switch channel {
			case "email":
				selected = delivery.ChannelEmail
			case "sms":
				selected = delivery.ChannelSMS
			default:
				return s, identityhttp.ErrInvalidInput
			}
			s.request = mfa.OtpSendRequest{TenantID: facts.TenantID(), ContinuationID: mfa.ContinuationID(child), FactorID: mfa.FactorID(factor), Channel: selected, IdempotencyKey: key, PreAuthID: preauth, Cookie: browser, Caller: caller(facts.TenantID(), child), Origin: string(c.Origin), Callback: callback, Network: facts.ClientIP().String(), Device: device.DeviceID()}
			s.facts, s.device, s.wire = facts, device, wire
			return s, nil
		},
		Authenticate: func(r *http.Request, s otpSendInput) (otpSendInput, error) {
			if err := rateError(c.Rate.AdmitDeliveryIP(r.Context(), s.facts, "identity.mfa.otp-send")); err != nil {
				return s, err
			}
			proof, err := capability.ParseProof(s.wire, capability.DefaultLimits())
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			sendingAttempt(r).proof = proof
			s.request.Proof = proof
			s.wire = ""
			if s.request.Validate() != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.destination, err = c.Service.OtpSendingRateSource(r.Context(), s.request)
			if err != nil {
				return s, err
			}
			if r.Context().Err() != nil {
				return s, identityhttp.ErrUnavailable
			}
			return s, nil
		},
		Admit: func(r *http.Request, s otpSendInput) error {
			return rateError(c.Rate.AdmitDeliveryIdentifier(r.Context(), s.facts, identityhttp.AuthRateRequest{OperationID: "identity.mfa.otp-send", Identifier: s.destination}))
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s otpSendInput) {
			a := sendingAttempt(r)
			if !c.Now().Before(s.device.ExpiresAt()) {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			a.out.CommitOutcome = "unknown"
			result, err := c.Service.OtpSend(r.Context(), s.request)
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
			if r.Context().Err() != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			if err != nil {
				reject(w, r, err)
				return
			}
			switch result.Outcome {
			case identity.CommitOutcomeConflict:
				reject(w, r, rejection{status: 409, code: "conflict"})
				return
			case identity.CommitOutcomeInProgress:
				reject(w, r, rejection{status: 409, code: "in_progress"})
				return
			case identity.CommitOutcomeNotCommitted:
				reject(w, r, rejection{status: 403, code: "denied"})
				return
			}
			if result.Outcome != identity.CommitOutcomeCommitted || result.CommandID == "" || result.ChallengeID != string(result.CommandID) || result.DeliveryState != delivery.StateQueued {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			a.out.Accepted = true
			a.out.ChallengeID = result.ChallengeID
			a.out.DeliveryState = "queued"
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(a.out)
		},
	})
	if err != nil {
		return nil, err
	}
	return &otpSendPipeline{pipeline: pipeline}, nil
}

type otpSendPipeline struct{ pipeline http.Handler }

func (p *otpSendPipeline) WithOperationMiddleware(m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if p == nil || p.pipeline == nil {
		return nil, identityhttp.ErrInvalidInput
	}
	h, err := identityhttp.WithOperationMiddleware(p.pipeline, m)
	if err != nil {
		return nil, err
	}
	return &otpSendPipeline{pipeline: h}, nil
}
func (p *otpSendPipeline) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a := &otpSendAttempt{out: OTPSendResponse{CommitOutcome: "none"}}
	r = r.WithContext(context.WithValue(r.Context(), otpSendAttemptKey{}, a))
	defer func() { _ = a.proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }) }()
	// This response guard has no issuance/disclosure tuple. Sending cannot
	// acquire cookie, CSRF, MFA proof, redirect or recovery-code output custody.
	(&enablePipeline{pipeline: p.pipeline}).ServeHTTP(w, r)
}

// Format redacts borrowed owners and original browser configuration.
func (OTPSendConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfahttp.OTPSendConfig(redacted)"))
}

// MarshalJSON rejects implicit configuration export.
func (OTPSendConfig) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText rejects implicit text/map-key export.
func (OTPSendConfig) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// LogValue emits a fixed redacted marker.
func (OTPSendConfig) LogValue() slog.Value {
	return slog.StringValue("mfahttp.OTPSendConfig(redacted)")
}
