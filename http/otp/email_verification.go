package otphttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/session"
)

// EmailVerificationConfig selects the authenticated self-user, known-empty-MFA,
// pending-nonprimary email OTP profile. It selects no signin, primary replacement
// or pre-auth branch. Owners are borrowed and must honor bounded contexts and
// support concurrent calls. Source authenticates original possession, not renewed
// current validity. Native workflow admission remains mandatory on every mutation
// and independently authorizes historical recovery. Cookie, Origin, CSRFKeys,
// Device, policy revision and prompt Now are trusted deployment configuration.
// Send requires DeliveryRate and the existing scoped device cookie; completion
// and recovery require VerificationRate. Construction performs no IO.
type EmailVerificationConfig struct {
	Network          identityhttp.NetworkConfig
	Service          otp.EmailVerificationService
	Source           otp.EmailVerificationRateSource
	DeliveryRate     *identityhttp.AuthRateLimiter
	VerificationRate *identityhttp.ChallengeVerificationRateLimiter
	Cookie           session.CookiePolicy
	Origin           identityhttp.Origin
	CSRFKeys         []session.CSRFKey
	Device           session.BrowserDeviceConfig
	PolicyRevision   authorization.Revision
	Now              func() time.Time
	MaximumDuration  time.Duration
}

// Format redacts deployment key and owner custody.
func (EmailVerificationConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otphttp.EmailVerificationConfig(redacted)"))
}

// MarshalJSON rejects implicit configuration export.
func (EmailVerificationConfig) MarshalJSON() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}

// MarshalText rejects implicit configuration export.
func (EmailVerificationConfig) MarshalText() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}

// EmailVerificationRecovery is the existing code-free consuming-correlation
// shape. Native email recovery authenticates its distinct purpose and scope;
// shared wire fields do not make signin and verification interchangeable.
type EmailVerificationRecovery SigninRecovery

// EmailVerificationResponse describes an original issuance, verification or
// historical observation, never authentication. Verified is true only for a
// new successful native verification. Recovery never returns an address or
// session. Unknown/committed durability survives later disclosure failures.
type EmailVerificationResponse struct {
	Accepted       bool                       `json:"accepted"`
	Verified       bool                       `json:"verified"`
	CommandID      identity.CommandID         `json:"commandID,omitempty"`
	CommitOutcome  string                     `json:"commitOutcome"`
	AddressID      identity.IdentifierID      `json:"addressID,omitempty"`
	AddressVersion uint64                     `json:"addressVersion,omitempty"`
	Recovery       *EmailVerificationRecovery `json:"recovery,omitempty"`
	Error          string                     `json:"error,omitempty"`
}

type emailVerificationResponseKey struct{}
type emailVerificationHTTPState struct {
	facts     identityhttp.NetworkFacts
	flow      otp.SendFlow
	csrf      session.CSRFToken
	device    session.BrowserDevice
	address   identity.IdentifierID
	version   uint64
	key       identity.IdempotencyKey
	send      identity.CommandID
	code      auth.OneTimeCode
	recovery  otp.EmailVerifyRecovery
	user      identity.UserID
	caller    authorization.DecisionContext
	out       *EmailVerificationResponse
	challenge otp.EmailVerificationChallenge
}

func (emailVerificationHTTPState) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otphttp.emailVerificationHTTPState(redacted)"))
}
func (emailVerificationHTTPState) MarshalJSON() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}
func (emailVerificationHTTPState) MarshalText() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}

// NewEmailVerificationSendHandler constructs cookie/CSRF-protected POST
// /v1/otp/send with closed flowID/addressID/addressVersion JSON and exactly one
// Idempotency-Key. Purpose/channel are fixed; no mailbox, user, actor, policy or
// factor override is accepted. Native original-key source precedes budgets.
func NewEmailVerificationSendHandler(c EmailVerificationConfig) (http.Handler, error) {
	return newEmailVerificationHandler(c, 0, nil)
}

// NewEmailVerifyHandler constructs POST /v1/otp/email-verify with exact original
// flowID/sendCommandID/code, cookie, Origin and stored synchronizer. It meters
// one new logical submission. Idempotency-Key and identity overrides deny.
func NewEmailVerifyHandler(c EmailVerificationConfig) (http.Handler, error) {
	return newEmailVerificationHandler(c, 1, nil)
}

// NewEmailVerifyRecoveryHandler constructs code-free POST
// /v1/otp/email-verify/recover. Original possession and CSRF are required even
// after the original session ceases to be executable. Only current authorized
// native metadata is returned; no mutation, comparison or credential delivery.
func NewEmailVerifyRecoveryHandler(c EmailVerificationConfig) (http.Handler, error) {
	return newEmailVerificationHandler(c, 2, nil)
}

func newEmailVerificationHandler(c EmailVerificationConfig, mode int, m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if mode < 0 || mode > 2 || nilOwner(c.Service) || nilOwner(c.Source) || c.PolicyRevision == 0 || c.Now == nil || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || len(c.CSRFKeys) < 1 || len(c.CSRFKeys) > 16 || mode == 0 && !c.DeliveryRate.Configured() || mode != 0 && !c.VerificationRate.Configured() {
		return nil, identityhttp.ErrInvalidInput
	}
	keys := make(map[uint32]session.CSRFKey, len(c.CSRFKeys))
	for _, key := range c.CSRFKeys {
		if key.Version() == 0 || keys[key.Version()].Version() != 0 {
			return nil, identityhttp.ErrInvalidInput
		}
		keys[key.Version()] = key
	}
	cookie, err := c.Cookie.DeletionAttributes()
	if err != nil {
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
	csrf, err := identityhttp.NewCSRFDecoder(identityhttp.CSRFDecoderConfig{Origins: origin, FormField: "csrf_token"})
	if err != nil {
		return nil, err
	}
	var devices *session.BrowserDeviceCodec
	if mode == 0 {
		devices, err = session.NewBrowserDeviceCodec(c.Device)
		if err != nil {
			return nil, identityhttp.ErrInvalidInput
		}
	}
	paths := [...]string{"/v1/otp/send", "/v1/otp/email-verify", "/v1/otp/email-verify/recover"}
	actions := [...]authorization.Action{"identity.otp.send", "identity.otp.email-verify", "identity.otp.email-verify.recover"}
	response := func(r *http.Request) *EmailVerificationResponse {
		if out, ok := r.Context().Value(emailVerificationResponseKey{}).(*EmailVerificationResponse); ok {
			return out
		}
		return &EmailVerificationResponse{CommitOutcome: "none"}
	}
	write := func(w http.ResponseWriter, r *http.Request, status int, code string) {
		out := response(r)
		out.Error = code
		if code != "" {
			out.Accepted, out.Verified, out.AddressID, out.AddressVersion = false, false, "", 0
		}
		data, err := json.Marshal(out)
		if err != nil || len(data) > 16384 {
			status, data = 503, []byte(`{"error":"unavailable"}`)
		}
		w.WriteHeader(status)
		_, _ = w.Write(append(data, '\n'))
	}
	failure := func(err error) signinFailure {
		var f signinFailure
		if errors.As(err, &f) {
			return f
		}
		var denied identity.ForbiddenError
		var conflict identity.ConflictError
		var invalid identity.InvalidInputError
		switch {
		case errors.As(err, &denied), errors.Is(err, session.ErrCSRFDenied):
			return signinFailure{status: 403, code: "denied"}
		case errors.As(err, &conflict):
			return signinFailure{status: 409, code: "conflict"}
		case errors.As(err, &invalid), errors.Is(err, identityhttp.ErrInvalidInput), errors.Is(err, otp.ErrInvalidAttempt):
			return signinFailure{status: 400, code: "invalid_request"}
		}
		return signinFailure{status: 503, code: "unavailable"}
	}
	reject := func(w http.ResponseWriter, r *http.Request, err error) {
		f := failure(err)
		if f.status == 405 {
			w.Header().Set("Allow", http.MethodPost)
		}
		if f.retry > 0 {
			w.Header().Set("Retry-After", strconv.FormatInt(int64((min(max(f.retry, time.Second), time.Hour)+time.Second-1)/time.Second), 10))
		}
		write(w, r, f.status, f.code)
	}
	asSend := func(s emailVerificationHTTPState) otp.EmailVerificationSendRequest {
		return otp.EmailVerificationSendRequest{TenantID: s.facts.TenantID(), UserID: s.user, AddressID: s.address, AddressVersion: s.version, Caller: s.caller, Flow: s.flow, Network: s.facts.ClientIP().String(), Device: s.device.DeviceID(), IdempotencyKey: s.key}
	}
	asVerify := func(s emailVerificationHTTPState) otp.EmailVerifyRequest {
		return otp.EmailVerifyRequest{TenantID: s.facts.TenantID(), UserID: s.user, Caller: s.caller, Flow: s.flow, SendCommandID: s.send, Code: s.code}
	}
	pipeline, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[emailVerificationHTTPState]{MaximumDuration: c.MaximumDuration, Middleware: m, Reject: reject,
		Decode: func(r *http.Request) (s emailVerificationHTTPState, err error) {
			s.out = response(r)
			if r.URL.Path != paths[mode] || r.URL.EscapedPath() != r.URL.Path {
				return s, signinFailure{status: 404, code: "not_found"}
			}
			if r.Method != http.MethodPost {
				return s, signinFailure{status: 405, code: "method_not_allowed"}
			}
			if r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Trailer) != 0 {
				return s, identityhttp.ErrInvalidInput
			}
			if _, _, err = decoder.Bearer(r, identityhttp.HeaderForbidden); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			policy := identityhttp.HeaderForbidden
			if mode == 0 {
				policy = identityhttp.HeaderRequired
			}
			s.key, _, err = decoder.IdempotencyKey(r, policy)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.facts, err = network.Resolve(r)
			if err != nil || s.facts.Realm() != identityhttp.RealmTenant {
				return s, signinFailure{status: 421, code: "misdirected_request"}
			}
			if s.facts.Scheme() != "https" {
				return s, identityhttp.ErrInvalidInput
			}
			s.csrf, _, err = identityhttp.DecodeCSRF(csrf, r, session.ParseCSRFToken)
			if err != nil {
				return s, signinFailure{status: 403, code: "origin_or_csrf_denied"}
			}
			bearer, present, err := decoder.CookieBearer(r, cookie.Name, identityhttp.HeaderRequired)
			if err != nil || !present {
				return s, signinFailure{status: 403, code: "denied"}
			}
			fields, err := identityhttp.DecodeJSON[map[string]json.RawMessage](decoder, r)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			var flowID string
			switch mode {
			case 0:
				if !recoveryFields(fields, map[string]any{"flowID": &flowID, "addressID": &s.address, "addressVersion": &s.version}) {
					return s, identityhttp.ErrInvalidInput
				}
				device, found, err := decoder.CookieBearer(r, "__Host-identity_device", identityhttp.HeaderRequired)
				if err != nil || !found {
					return s, identityhttp.ErrInvalidInput
				}
				s.device, err = devices.Resolve(r.Context(), c.Now(), s.facts.TenantID(), string(c.Origin), device.Token())
				if err != nil {
					return s, identityhttp.ErrInvalidInput
				}
			case 1:
				var code string
				if !recoveryFields(fields, map[string]any{"flowID": &flowID, "sendCommandID": &s.send, "code": &code}) {
					return s, identityhttp.ErrInvalidInput
				}
				s.code, err = auth.NewOneTimeCode(code)
				if err != nil {
					return s, identityhttp.ErrInvalidInput
				}
			case 2:
				var wire map[string]json.RawMessage
				if !recoveryFields(fields, map[string]any{"flowID": &flowID, "recovery": &wire}) {
					return s, identityhttp.ErrInvalidInput
				}
				b, err := decodeSigninRecovery(wire)
				if err != nil {
					return s, identityhttp.ErrInvalidInput
				}
				s.recovery, err = otp.NewEmailVerifyRecovery(otp.CheckRecoveryBindings(b))
				if err != nil {
					return s, identityhttp.ErrInvalidInput
				}
			}
			s.flow, err = otp.NewSessionSendFlow(flowID, bearer)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			return s, nil
		},
		Authenticate: func(r *http.Request, s emailVerificationHTTPState) (emailVerificationHTTPState, error) {
			if mode != 0 {
				if err := signinRateError(c.VerificationRate.AdmitIP(r.Context(), s.facts)); err != nil {
					return s, err
				}
			}
			original, err := c.Source.EmailVerificationSession(r.Context(), s.facts.TenantID(), s.flow)
			if err != nil {
				return s, err
			}
			b, err := original.Bindings()
			if err != nil || b.TenantID != s.facts.TenantID() || b.Authentication.Kind != session.AuthenticationVerified || b.UserID == "" {
				return s, identityhttp.ErrUnavailable
			}
			flowKind, flowID, _, _ := s.flow.Bindings()
			if flowKind != otp.FlowAuthorizationAuthenticatedSession || b.SessionID != flowID {
				return s, identityhttp.ErrUnavailable
			}
			state := original.CSRFState()
			binding, err := state.Bindings()
			if err != nil {
				return s, signinFailure{status: 403, code: "denied"}
			}
			if state.Check(session.CSRFBinding{TenantID: b.TenantID, SessionID: b.SessionID, SessionVersion: b.Version}, s.csrf, keys[binding.KeyVersion]) != nil {
				return s, signinFailure{status: 403, code: "denied"}
			}
			s.user = b.UserID
			s.caller = authorization.DecisionContext{PolicyRevision: c.PolicyRevision, Request: authorization.Request{Tenant: authorization.TenantID(b.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(b.UserID)}, Action: actions[mode], Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}}}
			if mode == 1 {
				request := asVerify(s)
				if request.Validate() != nil {
					return s, identityhttp.ErrInvalidInput
				}
				s.challenge, err = c.Source.EmailVerificationChallenge(r.Context(), request)
				if err != nil {
					return s, err
				}
				if s.challenge.UserID != s.user {
					return s, identityhttp.ErrUnavailable
				}
				if _, err := s.challenge.Target.Bindings(); err != nil {
					return s, identityhttp.ErrUnavailable
				}
			}
			return s, nil
		},
		Admit: func(r *http.Request, s emailVerificationHTTPState) error {
			if mode == 0 {
				request := asSend(s)
				if request.Validate() != nil {
					return identityhttp.ErrInvalidInput
				}
				destination, err := c.Source.EmailVerificationSendDestination(r.Context(), request)
				if err != nil {
					return err
				}
				return signinRateError(c.DeliveryRate.Admit(r.Context(), s.facts, identityhttp.AuthRateRequest{OperationID: "identity.otp.send", Identifier: destination.Value(), UserID: s.user}))
			}
			if mode == 2 {
				return (otp.EmailVerifyRecoveryRequest{TenantID: s.facts.TenantID(), UserID: s.user, Caller: s.caller, Flow: s.flow, Recovery: s.recovery}).Validate()
			}
			return signinRateError(c.VerificationRate.AdmitChallenge(r.Context(), s.facts, identityhttp.ChallengeVerificationRateRequest{OperationID: "identity.otp.email-verify", UserID: s.user, ChallengeID: string(s.send), ChallengeLifetime: s.challenge.Lifetime}))
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s emailVerificationHTTPState) {
			s.out.CommitOutcome = "unknown"
			if mode == 0 {
				result, err := c.Service.SendEmailVerification(r.Context(), asSend(s))
				s.out.CommandID, s.out.CommitOutcome = result.CommandID, outcome(result.Outcome)
				if err != nil {
					reject(w, r, err)
					return
				}
				if result.Outcome != identity.CommitOutcomeCommitted {
					reject(w, r, signinFailure{status: 409, code: "in_progress", retry: result.RetryAfter})
					return
				}
				s.out.Accepted = true
				write(w, r, 202, "")
				return
			}
			var result otp.EmailVerifyResult
			var err error
			if mode == 1 {
				result, err = c.Service.EmailVerify(r.Context(), asVerify(s))
			} else {
				result, err = c.Service.RecoverEmailVerify(r.Context(), otp.EmailVerifyRecoveryRequest{TenantID: s.facts.TenantID(), UserID: s.user, Caller: s.caller, Flow: s.flow, Recovery: s.recovery})
			}
			s.out.CommandID, s.out.CommitOutcome = result.CommandID, outcome(result.Outcome)
			if b, e := result.Recovery.Bindings(); e == nil {
				s.out.Recovery = emailVerificationRecovery(b)
			}
			if mode == 2 {
				original, _ := s.recovery.Bindings()
				observed, e := result.Recovery.Bindings()
				if e != nil || observed != original || result.CommandID != original.Attempt.CommandID || !result.Replayed || result.Address != (identity.IdentifierProjection{}) || err != nil {
					reject(w, r, identityhttp.ErrUnavailable)
					return
				}
				if result.Outcome != identity.CommitOutcomeCommitted && result.Outcome != identity.CommitOutcomeNotCommitted {
					reject(w, r, identityhttp.ErrUnavailable)
					return
				}
				write(w, r, 200, "")
				return
			}
			if err != nil {
				reject(w, r, err)
				return
			}
			view, e := result.Address.Bindings()
			target, targetErr := s.challenge.Target.Bindings()
			if e != nil || targetErr != nil || result.Outcome != identity.CommitOutcomeCommitted || result.Replayed || view.TenantID != s.facts.TenantID() || view.UserID != s.user || !view.Verified || view.Primary || view.IdentifierID != target.IdentifierID || view.IdentifierVersion != target.IdentifierVersion+1 || view.VerificationVersion != target.VerificationVersion+1 || s.out.Recovery == nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			s.out.Verified, s.out.AddressID, s.out.AddressVersion = true, view.IdentifierID, view.IdentifierVersion
			write(w, r, 200, "")
		},
	})
	if err != nil {
		return nil, err
	}
	return &emailVerificationPipeline{pipeline: pipeline}, nil
}

func emailVerificationRecovery(b otp.CheckRecoveryBindings) *EmailVerificationRecovery {
	return &EmailVerificationRecovery{SendCommandID: b.SendCommandID, Attempt: SigninAttempt{CommandID: b.Attempt.CommandID, TenantID: b.Attempt.TenantID, AttemptID: string(b.Attempt.AttemptID), Fingerprint: string(b.Attempt.Fingerprint), FingerprintKeyVersion: b.Attempt.FingerprintKeyVersion}, ExpectedVersion: b.ExpectedVersion, DigestKeyVersion: b.DigestKeyVersion, ScopeDigest: b.ScopeDigest}
}

type emailVerificationPipeline struct{ pipeline http.Handler }

func (p *emailVerificationPipeline) WithOperationMiddleware(m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if p == nil || p.pipeline == nil {
		return nil, identityhttp.ErrInvalidInput
	}
	h, err := identityhttp.WithOperationMiddleware(p.pipeline, m)
	if err != nil {
		return nil, err
	}
	return &emailVerificationPipeline{pipeline: h}, nil
}
func (p *emailVerificationPipeline) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r != nil {
		r = r.WithContext(context.WithValue(r.Context(), emailVerificationResponseKey{}, &EmailVerificationResponse{CommitOutcome: "none"}))
	}
	(&signinPipeline{pipeline: p.pipeline}).ServeHTTP(w, r)
}
