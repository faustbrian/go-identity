package phonehttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strconv"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/phone"
	"github.com/faustbrian/go-identity/session"
)

// VerificationSource authenticates retained native custody before transport
// budgets. Session authenticates original possession, not renewed active
// authority. Destination resolves exact original keyed input before send
// admission; Lifetime authenticates the original purpose/subject/challenge and
// returns its immutable issued interval, never remaining validity. Implementations
// perform no code comparison, consumption or delivery and honor bounded contexts.
// Current authority remains the workflow owner's transactional responsibility.
type VerificationSource interface {
	PhoneVerificationSession(context.Context, identity.TenantID, otp.SendFlow) (session.Session, error)
	PhoneEnrollmentDestination(context.Context, phone.EnrollmentRequest) (phone.Number, error)
	PhoneVerificationLifetime(context.Context, phone.VerificationRequest) (time.Duration, error)
}

// VerificationConfig explicitly selects existing-account cookie phone
// enrollment/verification/history. No public signup, signin, reset or bearer
// fallback is enabled. Owners are borrowed, bounded and concurrency-safe. Proofs
// reads original signed password records; only Service can admit/consume them.
// NumberPolicy and CSRF keys are copied; clocks and services remain borrowed.
// DeliveryRate and VerificationRate are shared strong owners, not per-request
// limiters. Device must be the deployment's existing signed browser-device
// profile for Send. Construction performs no IO or provider calls.
type VerificationConfig struct {
	Network          identityhttp.NetworkConfig
	Service          phone.VerificationService
	Source           VerificationSource
	Proofs           auth.ReauthenticationSource
	NumberPolicy     *phone.NumberPolicy
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

// Format redacts borrowed runtime owners and key custody.
func (VerificationConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("phonehttp.VerificationConfig(redacted)"))
}

// MarshalJSON rejects implicit configuration export.
func (VerificationConfig) MarshalJSON() ([]byte, error) { return nil, phone.ErrVerificationDisclosure }

// MarshalText rejects implicit text/map-key export.
func (VerificationConfig) MarshalText() ([]byte, error) { return nil, phone.ErrVerificationDisclosure }

// VerificationResponse is an explicit credential-free wire projection, not a
// secret-safe logging handle. Accepted describes queued original intent, not SMS
// delivery. Verified/identifier fields occur only on fresh known verification.
// Recovery is code-free original correlation, never permission to resubmit.
type VerificationResponse struct {
	Accepted          bool                  `json:"accepted"`
	Verified          bool                  `json:"verified"`
	CommandID         identity.CommandID    `json:"commandID,omitempty"`
	CommitOutcome     string                `json:"commitOutcome"`
	IdentifierID      identity.IdentifierID `json:"identifierID,omitempty"`
	IdentifierVersion uint64                `json:"identifierVersion,omitempty"`
	Recovery          *VerificationRecovery `json:"recovery,omitempty"`
	Error             string                `json:"error,omitempty"`
}

type verificationState struct {
	facts    identityhttp.NetworkFacts
	flow     otp.SendFlow
	csrf     session.CSRFToken
	bearer   auth.BearerCredential
	device   session.BrowserDevice
	key      identity.IdempotencyKey
	number   phone.Number
	proofID  auth.ProofID
	send     identity.CommandID
	code     auth.OneTimeCode
	recovery phone.VerificationRecovery
	user     identity.UserID
	caller   authorization.DecisionContext
	enroll   phone.EnrollmentRequest
	verify   phone.VerificationRequest
	history  phone.VerificationRecoveryRequest
	lifetime time.Duration
	out      *VerificationResponse
}
type responseKey struct{}
type failure struct {
	status int
	code   string
	retry  time.Duration
}

func (failure) Error() string { return "phonehttp: request denied" }

// NewSendHandler selects only POST /v1/phone/send-verification. Exact cookie,
// Origin, current CSRF, signed device, action-proof ID and one retry key are
// required. Closed JSON accepts flowID, number and proofID, never authority.
func NewSendHandler(c VerificationConfig) (http.Handler, error) { return newHandler(c, 0, nil) }

// NewVerifyHandler selects purpose-bound POST /v1/phone/verify. Every submission
// is a new counted native attempt; ambiguity uses original recovery, not retry.
func NewVerifyHandler(c VerificationConfig) (http.Handler, error) { return newHandler(c, 1, nil) }

// NewRecoveryHandler selects code-free POST /v1/phone/verify/recover. Original
// possession/current CSRF and current disclosure policy remain mandatory.
func NewRecoveryHandler(c VerificationConfig) (http.Handler, error) { return newHandler(c, 2, nil) }

func nilOwner(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return r.IsNil()
	}
	return false
}

func newHandler(c VerificationConfig, mode int, middleware []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if mode < 0 || mode > 2 || nilOwner(c.Service) || nilOwner(c.Source) || c.PolicyRevision == 0 || c.Now == nil || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || len(c.CSRFKeys) == 0 || len(c.CSRFKeys) > 16 || mode == 0 && (nilOwner(c.Proofs) || c.NumberPolicy == nil || c.NumberPolicy.Profile() != phone.CurrentNumberProfile() || !c.DeliveryRate.Configured()) || mode != 0 && !c.VerificationRate.Configured() {
		return nil, identityhttp.ErrInvalidInput
	}
	c.CSRFKeys = slices.Clone(c.CSRFKeys)
	keys := make(map[uint32]session.CSRFKey, len(c.CSRFKeys))
	for _, key := range c.CSRFKeys {
		if key.Version() == 0 || keys[key.Version()].Version() != 0 {
			return nil, identityhttp.ErrInvalidInput
		}
		keys[key.Version()] = key
	}
	if c.NumberPolicy != nil {
		snapshot := *c.NumberPolicy
		c.NumberPolicy = &snapshot
	}
	network, err := identityhttp.NewNetworkResolver(c.Network)
	if err != nil {
		return nil, err
	}
	decoder, err := identityhttp.NewRequestDecoder(c.Network.Limits)
	if err != nil {
		return nil, err
	}
	cookie, err := c.Cookie.DeletionAttributes()
	if err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	origins, err := identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{Network: network, TrustedOrigins: []identityhttp.Origin{c.Origin}, RefererFallback: identityhttp.RefererFallbackDeny})
	if err != nil {
		return nil, err
	}
	csrf, err := identityhttp.NewCSRFDecoder(identityhttp.CSRFDecoderConfig{Origins: origins, FormField: "csrf_token"})
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
	paths := [...]string{"/v1/phone/send-verification", "/v1/phone/verify", "/v1/phone/verify/recover"}
	actions := [...]authorization.Action{"identity.phone.send-verification", "identity.phone.verify", "identity.phone.verify.recover"}
	write := func(w http.ResponseWriter, r *http.Request, status int, code string) {
		out := responseFor(r)
		out.Error = code
		if code != "" {
			out.Accepted, out.Verified, out.IdentifierID, out.IdentifierVersion = false, false, "", 0
		}
		data, err := json.Marshal(out)
		if err != nil || len(data) > 16384 {
			status, data = 503, []byte(`{"error":"unavailable"}`)
		}
		w.WriteHeader(status)
		_, _ = w.Write(append(data, '\n'))
	}
	reject := func(w http.ResponseWriter, r *http.Request, err error) {
		f := failure{503, "unavailable", 0}
		var specific failure
		var denied identity.ForbiddenError
		var invalid identity.InvalidInputError
		var conflict identity.ConflictError
		switch {
		case errors.As(err, &specific):
			f = specific
		case errors.As(err, &denied), errors.Is(err, session.ErrCSRFDenied), errors.Is(err, auth.ErrInvalidProof):
			f = failure{403, "denied", 0}
		case errors.As(err, &conflict):
			f = failure{409, "conflict", 0}
		case errors.As(err, &invalid), errors.Is(err, identityhttp.ErrInvalidInput), errors.Is(err, phone.ErrInvalidVerification), errors.Is(err, phone.ErrNumberInvalid):
			f = failure{400, "invalid_request", 0}
		}
		if f.status == 405 {
			w.Header().Set("Allow", http.MethodPost)
		}
		if f.retry > 0 {
			w.Header().Set("Retry-After", strconv.FormatInt(int64((min(max(f.retry, time.Second), time.Hour)+time.Second-1)/time.Second), 10))
		}
		write(w, r, f.status, f.code)
	}
	pipeline, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[verificationState]{MaximumDuration: c.MaximumDuration, Middleware: middleware, Reject: reject,
		Decode: func(r *http.Request) (s verificationState, err error) {
			s.out = responseFor(r)
			if r.URL.Path != paths[mode] || r.URL.EscapedPath() != r.URL.Path {
				return s, failure{404, "not_found", 0}
			}
			if r.Method != http.MethodPost {
				return s, failure{405, "method_not_allowed", 0}
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
				return s, failure{421, "misdirected_request", 0}
			}
			if s.facts.Scheme() != "https" {
				return s, failure{403, "https_required", 0}
			}
			s.csrf, _, err = identityhttp.DecodeCSRF(csrf, r, session.ParseCSRFToken)
			if err != nil {
				return s, failure{403, "origin_or_csrf_denied", 0}
			}
			var present bool
			s.bearer, present, err = decoder.CookieBearer(r, cookie.Name, identityhttp.HeaderRequired)
			if err != nil || !present {
				return s, failure{403, "denied", 0}
			}
			if _, err = session.ParseToken(s.bearer.Token()); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			body, err := identityhttp.DecodeJSON[map[string]json.RawMessage](decoder, r)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			var flow string
			switch mode {
			case 0:
				var number, proof string
				if !closedFields(body, map[string]any{"flowID": &flow, "number": &number, "proofID": &proof}) {
					return s, identityhttp.ErrInvalidInput
				}
				if _, err = identity.ParseCommandID(proof); err != nil {
					return s, identityhttp.ErrInvalidInput
				}
				s.proofID = auth.ProofID(proof)
				s.number, err = c.NumberPolicy.Canonicalize(r.Context(), number)
				if err != nil {
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
				if !closedFields(body, map[string]any{"flowID": &flow, "sendCommandID": &s.send, "code": &code}) {
					return s, identityhttp.ErrInvalidInput
				}
				if _, err = identity.ParseCommandID(string(s.send)); err != nil {
					return s, identityhttp.ErrInvalidInput
				}
				s.code, err = auth.NewOneTimeCode(code)
				if err != nil {
					return s, identityhttp.ErrInvalidInput
				}
			case 2:
				var recovery map[string]json.RawMessage
				if !closedFields(body, map[string]any{"flowID": &flow, "recovery": &recovery}) {
					return s, identityhttp.ErrInvalidInput
				}
				s.recovery, err = decodeRecovery(recovery)
				if err != nil {
					return s, identityhttp.ErrInvalidInput
				}
			}
			s.flow, err = otp.NewSessionSendFlow(flow, s.bearer)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			return s, nil
		},
		Authenticate: func(r *http.Request, s verificationState) (verificationState, error) {
			if mode != 0 {
				if err := rateError(c.VerificationRate.AdmitIP(r.Context(), s.facts)); err != nil {
					return s, err
				}
			}
			original, err := c.Source.PhoneVerificationSession(r.Context(), s.facts.TenantID(), s.flow)
			if err != nil {
				return s, err
			}
			b, err := original.Bindings()
			_, flowID, _, _ := s.flow.Bindings()
			if err != nil || b.TenantID != s.facts.TenantID() || b.SessionID != flowID || b.UserID == "" || b.Authentication.Kind != session.AuthenticationVerified {
				return s, identityhttp.ErrUnavailable
			}
			csrfState := original.CSRFState()
			binding, err := csrfState.Bindings()
			if err != nil || csrfState.Check(session.CSRFBinding{TenantID: b.TenantID, SessionID: b.SessionID, SessionVersion: b.Version}, s.csrf, keys[binding.KeyVersion]) != nil {
				return s, failure{403, "denied", 0}
			}
			s.user = b.UserID
			s.caller = authorization.DecisionContext{PolicyRevision: c.PolicyRevision, Request: authorization.Request{Tenant: authorization.TenantID(b.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(b.UserID)}, Action: actions[mode], Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}}}
			switch mode {
			case 0:
				record, err := c.Proofs.Reauthentication(r.Context(), s.proofID)
				if err != nil {
					return s, err
				}
				if record.Proof.Proof.ID != s.proofID || record.Proof.Proof.Tenant != string(b.TenantID) || record.Proof.Proof.Subject != string(s.user) || record.Proof.Action != string(actions[0]) {
					return s, failure{403, "denied", 0}
				}
				s.enroll, err = phone.NewEnrollmentRequest(phone.EnrollmentRequestSpec{TenantID: b.TenantID, UserID: s.user, Number: s.number, Session: s.bearer, Proof: record.Proof, Caller: s.caller, CSRFToken: s.csrf, IdempotencyKey: s.key, Network: s.facts.ClientIP().String(), Device: s.device.DeviceID()})
				if err != nil {
					return s, err
				}
				destination, err := c.Source.PhoneEnrollmentDestination(r.Context(), s.enroll)
				if err != nil {
					return s, err
				}
				if !destination.Equal(s.number) {
					return s, identityhttp.ErrUnavailable
				}
			case 1:
				s.verify, err = phone.NewVerificationRequest(phone.VerificationRequestSpec{TenantID: b.TenantID, UserID: s.user, Caller: s.caller, Flow: s.flow, SendCommandID: s.send, Code: s.code, CSRFToken: s.csrf})
				if err != nil {
					return s, err
				}
				s.lifetime, err = c.Source.PhoneVerificationLifetime(r.Context(), s.verify)
				if err != nil {
					return s, err
				}
			case 2:
				s.history, err = phone.NewVerificationRecoveryRequest(phone.VerificationRecoveryRequestSpec{TenantID: b.TenantID, UserID: s.user, Caller: s.caller, Flow: s.flow, Recovery: s.recovery, CSRFToken: s.csrf})
				if err != nil {
					return s, err
				}
			}
			return s, nil
		},
		Admit: func(r *http.Request, s verificationState) error {
			if mode == 0 {
				number, err := s.number.Record()
				if err != nil {
					return err
				}
				return rateError(c.DeliveryRate.Admit(r.Context(), s.facts, identityhttp.AuthRateRequest{OperationID: string(actions[0]), Identifier: number.E164, UserID: s.user}))
			}
			if mode == 1 {
				return rateError(c.VerificationRate.AdmitChallenge(r.Context(), s.facts, identityhttp.ChallengeVerificationRateRequest{OperationID: string(actions[1]), UserID: s.user, ChallengeID: string(s.send), ChallengeLifetime: s.lifetime}))
			}
			return nil
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s verificationState) {
			s.out.CommitOutcome = "unknown"
			if mode == 0 {
				result, err := c.Service.SendVerification(r.Context(), s.enroll)
				if b, e := result.Bindings(); e == nil {
					if !sameSubject(b.Binding, s) || b.Binding.OperationID != string(actions[0]) {
						reject(w, r, identityhttp.ErrUnavailable)
						return
					}
					s.out.CommandID, s.out.CommitOutcome = b.Binding.CommandID, outcome(b.Outcome)
					if err == nil && b.Outcome != identity.CommitOutcomeCommitted {
						err = failure{409, "in_progress", b.RetryAfter}
					}
				} else if err == nil {
					err = identityhttp.ErrUnavailable
				}
				if err == nil && r.Context().Err() != nil {
					err = r.Context().Err()
				}
				if err != nil {
					reject(w, r, err)
					return
				}
				s.out.Accepted = true
				write(w, r, 202, "")
				return
			}
			var result phone.VerificationResult
			var err error
			if mode == 1 {
				result, err = c.Service.Verify(r.Context(), s.verify)
			} else {
				result, err = c.Service.RecoverVerification(r.Context(), s.history)
			}
			if b, e := result.Bindings(); e == nil {
				if !sameSubject(b.Binding, s) || b.Binding.OperationID != string(actions[1]) {
					reject(w, r, identityhttp.ErrUnavailable)
					return
				}
				if mode == 2 {
					original, _ := s.recovery.Bindings()
					if b.Binding.CommandID != original.Attempt.CommandID {
						reject(w, r, identityhttp.ErrUnavailable)
						return
					}
				}
				s.out.CommandID, s.out.CommitOutcome = b.Binding.CommandID, outcome(b.Outcome)
				if original, e := b.Recovery.Bindings(); e == nil {
					wire := recoveryWire(original)
					s.out.Recovery = &wire
				}
				if err == nil && mode == 1 && b.Outcome == identity.CommitOutcomeCommitted && !b.Replayed {
					projection, e := b.Identifier.Bindings()
					if e != nil || projection.TenantID != s.facts.TenantID() || projection.UserID != s.user || projection.Kind != identity.IdentifierPhone || !projection.Verified || string(projection.IdentifierID) != b.Binding.RecordID {
						err = identityhttp.ErrUnavailable
					} else {
						s.out.Verified, s.out.IdentifierID, s.out.IdentifierVersion = true, projection.IdentifierID, projection.IdentifierVersion
					}
				} else if err == nil && b.Outcome != identity.CommitOutcomeCommitted && !(mode == 2 && b.Outcome == identity.CommitOutcomeNotCommitted) {
					err = failure{409, "in_progress", b.RetryAfter}
				}
			} else if err == nil {
				err = identityhttp.ErrUnavailable
			}
			if err == nil && r.Context().Err() != nil {
				err = r.Context().Err()
			}
			if err != nil {
				reject(w, r, err)
				return
			}
			write(w, r, 200, "")
		},
	})
	if err != nil {
		return nil, err
	}
	return &verificationHandler{pipeline}, nil
}

func sameSubject(b identity.CommandBinding, s verificationState) bool {
	return b.TenantID == s.facts.TenantID() && b.UserID == s.user && b.ActorID == identity.ActorID(s.user) && b.ActorKind == authorization.SubjectUser
}
func rateError(r identityhttp.AuthRateResult, err error) error {
	if errors.Is(err, identityhttp.ErrRateLimited) {
		return failure{429, "rate_limited", r.RetryAfter}
	}
	if err != nil || !r.Allowed {
		return identityhttp.ErrUnavailable
	}
	return nil
}
func responseFor(r *http.Request) *VerificationResponse {
	if out, ok := r.Context().Value(responseKey{}).(*VerificationResponse); ok {
		return out
	}
	return &VerificationResponse{CommitOutcome: "none"}
}

type verificationHandler struct{ pipeline http.Handler }

func (h *verificationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	r = r.WithContext(context.WithValue(r.Context(), responseKey{}, &VerificationResponse{CommitOutcome: "none"}))
	h.pipeline.ServeHTTP(w, r)
}
func (h *verificationHandler) WithOperationMiddleware(m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if h == nil || h.pipeline == nil {
		return nil, identityhttp.ErrInvalidInput
	}
	p, err := identityhttp.WithOperationMiddleware(h.pipeline, m)
	if err != nil {
		return nil, err
	}
	return &verificationHandler{p}, nil
}
