package phonehttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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

// ChangeSource authenticates original native custody before transport budgets.
// These reads grant no live session, proof freshness or mutation authority and
// must neither compare a code nor create a request, challenge, debit or delivery.
// Lifetime is the immutable issued interval, not remaining or renewed validity.
// Implementations honor bounded contexts and concurrent independent calls.
type ChangeSource interface {
	PhoneChangeSession(context.Context, identity.TenantID, otp.SendFlow) (session.Session, error)
	PhoneChangeDestination(context.Context, phone.ChangeRequest) (phone.Number, error)
	PhoneUpdateLifetime(context.Context, phone.UpdateRequest) (time.Duration, error)
}

// ChangeConfig explicitly selects cookie-only existing-account replacement.
// Owners/clocks are borrowed and concurrent-safe; number/CSRF policies are copied.
// Source authenticates original possession; Service repeats all native current
// authority, proof, risk and atomic effects. Sending uses the deployment's signed
// browser device. No enrollment, reset, signup or bearer fallback is selected.
// MaximumDuration is 1ms..30s; construction performs no IO or provider work.
type ChangeConfig struct {
	Network         identityhttp.NetworkConfig
	Service         phone.ChangeService
	Source          ChangeSource
	Proofs          auth.ReauthenticationSource
	NumberPolicy    *phone.NumberPolicy
	DeliveryRate    *identityhttp.AuthRateLimiter
	UpdateRate      *identityhttp.KeyedSecretRateLimiter
	RecoveryRate    *identityhttp.ChallengeVerificationRateLimiter
	Cookie          session.CookiePolicy
	Origin          identityhttp.Origin
	CSRFKeys        []session.CSRFKey
	Device          session.BrowserDeviceConfig
	PolicyRevision  authorization.Revision
	Now             func() time.Time
	MaximumDuration time.Duration
}

// ChangeResponse exposes only original credential-free outcome metadata.
// Accepted means an original SMS intent was queued, not externally delivered.
// Updated describes a fresh known replacement, not fresh authentication; replay
// and history never set it. Pending cascade is not completed downstream cleanup.
// Recovery carries no code or proof and cannot authorize another submission.
type ChangeResponse struct {
	Accepted          bool                  `json:"accepted"`
	Updated           bool                  `json:"updated"`
	Replayed          bool                  `json:"replayed"`
	CommandID         identity.CommandID    `json:"commandID,omitempty"`
	CommitOutcome     string                `json:"commitOutcome"`
	CascadeID         identity.CascadeID    `json:"cascadeID,omitempty"`
	CascadeGeneration uint64                `json:"cascadeGeneration,omitempty"`
	CascadeStatus     string                `json:"cascadeStatus,omitempty"`
	Recovery          *VerificationRecovery `json:"recovery,omitempty"`
	Error             string                `json:"error,omitempty"`
}

type changeState struct {
	facts    identityhttp.NetworkFacts
	body     changeBody
	flow     otp.SendFlow
	csrf     session.CSRFToken
	key      identity.IdempotencyKey
	user     identity.UserID
	change   phone.ChangeRequest
	update   phone.UpdateRequest
	history  phone.UpdateRecoveryRequest
	lifetime time.Duration
}
type changeResponseKey struct{}

func changeResponse(r *http.Request) *ChangeResponse {
	if out, ok := r.Context().Value(changeResponseKey{}).(*ChangeResponse); ok {
		return out
	}
	return &ChangeResponse{CommitOutcome: "none"}
}

// NewChangeSendHandler selects only new-number POST /v1/phone/send-verification.
// Closed JSON requires the original flow, new/previous numbers, exact predecessor
// versions and sending-proof ID. Cookie, Origin, CSRF, signed device and exactly
// one header retry key are mandatory. It is not the enrollment send handler.
func NewChangeSendHandler(c ChangeConfig) (http.Handler, error) { return newChangeHandler(c, 0, nil) }

// NewUpdateHandler selects POST /v1/phone/update. Closed JSON requires flowID,
// sendCommandID, code, distinct update-proof ID and registered reason. The header
// retry key identifies one logical submission, including a wrong-code denial.
func NewUpdateHandler(c ChangeConfig) (http.Handler, error) { return newChangeHandler(c, 1, nil) }

// NewUpdateRecoveryHandler selects code-free POST /v1/phone/update/recover.
// Original cookie/flow/current synchronizer and current native disclosure policy
// remain mandatory. Codes, fresh proofs and Idempotency-Key headers are forbidden.
func NewUpdateRecoveryHandler(c ChangeConfig) (http.Handler, error) {
	return newChangeHandler(c, 2, nil)
}

func newChangeHandler(c ChangeConfig, mode int, middleware []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if mode < 0 || mode > 2 || nilOwner(c.Service) || nilOwner(c.Source) || c.NumberPolicy == nil || c.NumberPolicy.Profile() != phone.CurrentNumberProfile() || c.PolicyRevision == 0 || c.Now == nil || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || len(c.CSRFKeys) == 0 || len(c.CSRFKeys) > 16 || mode != 2 && nilOwner(c.Proofs) || mode == 0 && !c.DeliveryRate.Configured() || mode == 1 && !c.UpdateRate.Configured() || mode == 2 && !c.RecoveryRate.Configured() {
		return nil, identityhttp.ErrInvalidInput
	}
	policy := *c.NumberPolicy
	c.NumberPolicy = &policy
	c.CSRFKeys = slices.Clone(c.CSRFKeys)
	keys := make(map[uint32]session.CSRFKey, len(c.CSRFKeys))
	for _, key := range c.CSRFKeys {
		if key.Version() == 0 || keys[key.Version()].Version() != 0 {
			return nil, identityhttp.ErrInvalidInput
		}
		keys[key.Version()] = key
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
	paths := [...]string{"/v1/phone/send-verification", "/v1/phone/update", "/v1/phone/update/recover"}
	actions := [...]authorization.Action{"identity.phone.send-verification", "identity.phone.update", "identity.phone.update.recover"}
	write := func(w http.ResponseWriter, r *http.Request, status int, code string) {
		out := changeResponse(r)
		out.Error = code
		if code != "" {
			out.Accepted, out.Updated = false, false
		}
		wire, err := json.Marshal(out)
		if err != nil || len(wire) > 16384 {
			status, wire = 503, []byte(`{"error":"unavailable"}`)
		}
		w.WriteHeader(status)
		_, _ = w.Write(append(wire, '\n'))
	}
	reject := func(w http.ResponseWriter, r *http.Request, err error) {
		f := failure{503, "unavailable", 0}
		var specific failure
		var denied identity.ForbiddenError
		var last identity.FinalAccessError
		var invalid identity.InvalidInputError
		var conflict identity.ConflictError
		switch {
		case errors.As(err, &specific):
			f = specific
		case errors.As(err, &denied), errors.As(err, &last), errors.Is(err, auth.ErrInvalidProof), errors.Is(err, session.ErrCSRFDenied):
			f = failure{403, "denied", 0}
		case errors.As(err, &conflict):
			f = failure{409, "conflict", 0}
		case errors.As(err, &invalid), errors.Is(err, identityhttp.ErrInvalidInput), errors.Is(err, phone.ErrInvalidChange), errors.Is(err, phone.ErrInvalidVerification), errors.Is(err, phone.ErrNumberInvalid):
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
	pipeline, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[changeState]{MaximumDuration: c.MaximumDuration, Middleware: middleware, Reject: reject,
		Decode: func(r *http.Request) (s changeState, err error) {
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
			keyPolicy := identityhttp.HeaderRequired
			if mode == 2 {
				keyPolicy = identityhttp.HeaderForbidden
			}
			s.key, _, err = decoder.IdempotencyKey(r, keyPolicy)
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
			bearer, _, err := decoder.CookieBearer(r, cookie.Name, identityhttp.HeaderRequired)
			if err != nil {
				return s, failure{403, "denied", 0}
			}
			if _, err = session.ParseToken(bearer.Token()); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			body, err := identityhttp.DecodeJSON[map[string]json.RawMessage](decoder, r)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.body, err = decodeChangeBody(r.Context(), c.NumberPolicy, mode, body)
			if err != nil {
				return s, err
			}
			s.flow, err = otp.NewSessionSendFlow(s.body.flowID, bearer)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			if mode == 0 {
				device, _, err := decoder.CookieBearer(r, "__Host-identity_device", identityhttp.HeaderRequired)
				if err != nil {
					return s, identityhttp.ErrInvalidInput
				}
				resolved, err := devices.Resolve(r.Context(), c.Now(), s.facts.TenantID(), string(c.Origin), device.Token())
				if err != nil {
					return s, identityhttp.ErrInvalidInput
				}
				s.body.change.Enrollment.Device = resolved.DeviceID()
			}
			return s, nil
		},
		Authenticate: func(r *http.Request, s changeState) (changeState, error) {
			if mode == 2 {
				if err := rateError(c.RecoveryRate.AdmitIP(r.Context(), s.facts)); err != nil {
					return s, err
				}
			}
			original, err := c.Source.PhoneChangeSession(r.Context(), s.facts.TenantID(), s.flow)
			if err != nil {
				return s, err
			}
			b, err := original.Bindings()
			_, flowID, bearer, _ := s.flow.Bindings()
			if err != nil || b.TenantID != s.facts.TenantID() || b.SessionID != flowID || b.UserID == "" || b.Authentication.Kind != session.AuthenticationVerified {
				return s, identityhttp.ErrUnavailable
			}
			state := original.CSRFState()
			binding, err := state.Bindings()
			if err != nil || state.Check(session.CSRFBinding{TenantID: b.TenantID, SessionID: b.SessionID, SessionVersion: b.Version}, s.csrf, keys[binding.KeyVersion]) != nil {
				return s, failure{403, "denied", 0}
			}
			s.user = b.UserID
			caller := authorization.DecisionContext{PolicyRevision: c.PolicyRevision, Request: authorization.Request{Tenant: authorization.TenantID(b.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(b.UserID)}, Action: actions[mode], Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}}}
			if mode == 2 {
				s.history, err = phone.NewUpdateRecoveryRequest(phone.UpdateRecoveryRequestSpec{TenantID: b.TenantID, UserID: b.UserID, Caller: caller, Flow: s.flow, Recovery: s.body.recovery, CSRFToken: s.csrf})
				return s, err
			}
			record, err := c.Proofs.Reauthentication(r.Context(), s.body.proofID)
			if err != nil {
				return s, err
			}
			p := record.Proof
			if p.Proof.ID != s.body.proofID || p.Proof.Tenant != string(b.TenantID) || p.Proof.Subject != string(b.UserID) || p.SessionID != b.SessionID || p.Action != string(actions[mode]) {
				return s, failure{403, "denied", 0}
			}
			if mode == 0 {
				spec := s.body.change
				spec.Enrollment.TenantID, spec.Enrollment.UserID, spec.Enrollment.Caller = b.TenantID, b.UserID, caller
				spec.Enrollment.Session, spec.Enrollment.Proof, spec.Enrollment.CSRFToken = bearer, p, s.csrf
				spec.Enrollment.IdempotencyKey, spec.Enrollment.Network = s.key, s.facts.ClientIP().String()
				s.change, err = phone.NewChangeRequest(spec)
				if err != nil {
					return s, err
				}
				destination, err := c.Source.PhoneChangeDestination(r.Context(), s.change)
				if err != nil {
					return s, err
				}
				if !destination.Equal(spec.Enrollment.Number) {
					return s, identityhttp.ErrUnavailable
				}
			} else {
				spec := s.body.update
				spec.TenantID, spec.UserID, spec.Caller = b.TenantID, b.UserID, caller
				spec.Flow, spec.Proof, spec.CSRFToken, spec.IdempotencyKey = s.flow, p, s.csrf, s.key
				s.update, err = phone.NewUpdateRequest(spec)
				if err != nil {
					return s, err
				}
				s.lifetime, err = c.Source.PhoneUpdateLifetime(r.Context(), s.update)
			}
			return s, err
		},
		Admit: func(r *http.Request, s changeState) error {
			if mode == 0 {
				number, err := s.body.change.Enrollment.Number.Record()
				if err != nil {
					return err
				}
				return rateError(c.DeliveryRate.Admit(r.Context(), s.facts, identityhttp.AuthRateRequest{OperationID: string(actions[0]), Identifier: number.E164, UserID: s.user}))
			}
			if mode == 1 {
				return rateError(c.UpdateRate.Admit(r.Context(), s.facts, identityhttp.KeyedSecretRateRequest{OperationID: string(actions[1]), UserID: s.user, IdempotencyKey: s.key, ChallengeID: string(s.body.update.SendCommandID), ChallengeLifetime: s.lifetime}))
			}
			return nil
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s changeState) {
			out := changeResponse(r)
			out.CommitOutcome = "unknown"
			if mode == 0 {
				result, err := c.Service.SendChange(r.Context(), s.change)
				if result.Outcome != identity.CommitOutcomeInvalid {
					b := result.Binding
					if result.Validate() != nil || b.TenantID != s.facts.TenantID() || b.UserID != s.user || b.ActorKind != authorization.SubjectUser || b.ActorID != identity.ActorID(s.user) || b.OperationID != string(actions[0]) || b.SchemaID != "identity.phone.send-verification.change.native-v1" || b.SchemaVersion != 1 || b.RecordID != string(b.CommandID) {
						reject(w, r, identityhttp.ErrUnavailable)
						return
					}
					out.CommandID, out.CommitOutcome = b.CommandID, outcome(result.Outcome)
				}
				if err == nil && r.Context().Err() != nil {
					err = r.Context().Err()
				}
				if err == nil && result.Outcome != identity.CommitOutcomeCommitted {
					err = changePending(result)
				}
				if err != nil {
					reject(w, r, err)
					return
				}
				out.Accepted = true
				write(w, r, 202, "")
				return
			}
			var result phone.UpdateResult
			var err error
			if mode == 1 {
				result, err = c.Service.Update(r.Context(), s.update)
			} else {
				result, err = c.Service.RecoverUpdate(r.Context(), s.history)
			}
			if result.Result.Outcome != identity.CommitOutcomeInvalid {
				b := result.Result.Binding
				correlation, recoveryError := result.Recovery.Bindings()
				if result.Validate() != nil || recoveryError != nil || b.TenantID != s.facts.TenantID() || b.UserID != s.user || b.ActorKind != authorization.SubjectUser || b.ActorID != identity.ActorID(s.user) || b.OperationID != string(actions[1]) || b.SchemaID != "identity.phone.update.native-v1" || b.SchemaVersion != 1 || mode == 1 && correlation.SendCommandID != s.body.update.SendCommandID {
					reject(w, r, identityhttp.ErrUnavailable)
					return
				}
				if mode == 2 {
					requested, _ := s.body.recovery.Bindings()
					if correlation != requested || !result.Replayed {
						reject(w, r, identityhttp.ErrUnavailable)
						return
					}
				}
				out.CommandID, out.CommitOutcome, out.Replayed = b.CommandID, outcome(result.Result.Outcome), result.Replayed
				recovery := recoveryWire(correlation)
				out.Recovery = &recovery
				if cascade := result.Result.Cascade; cascade != nil {
					out.CascadeID, out.CascadeGeneration, out.CascadeStatus = cascade.CascadeID, cascade.Generation, "pending"
				}
			}
			if err == nil && r.Context().Err() != nil {
				err = r.Context().Err()
			}
			if err == nil && result.Result.Outcome != identity.CommitOutcomeCommitted && !(result.Replayed && result.Result.Outcome == identity.CommitOutcomeNotCommitted) {
				err = changePending(result.Result)
			}
			if err != nil {
				reject(w, r, err)
				return
			}
			out.Updated = mode == 1 && result.Result.Outcome == identity.CommitOutcomeCommitted && !result.Replayed
			write(w, r, 200, "")
		},
	})
	if err != nil {
		return nil, err
	}
	return &changeHandler{pipeline: pipeline}, nil
}

func changePending(result identity.CommandResult) error {
	switch result.Outcome {
	case identity.CommitOutcomeInProgress:
		return failure{409, "in_progress", result.RetryAfter}
	case identity.CommitOutcomeConflict:
		return failure{409, "conflict", 0}
	default:
		return identityhttp.ErrUnavailable
	}
}

type changeHandler struct{ pipeline http.Handler }

func (h *changeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	r = r.WithContext(context.WithValue(r.Context(), changeResponseKey{}, &ChangeResponse{CommitOutcome: "none"}))
	h.pipeline.ServeHTTP(w, r)
}
func (h *changeHandler) WithOperationMiddleware(m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if h == nil || h.pipeline == nil {
		return nil, identityhttp.ErrInvalidInput
	}
	p, err := identityhttp.WithOperationMiddleware(h.pipeline, m)
	if err != nil {
		return nil, err
	}
	return &changeHandler{pipeline: p}, nil
}

// Format redacts all borrowed owners, configuration and synchronizer custody.
func (ChangeConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("phonehttp.ChangeConfig(redacted)"))
}

// MarshalJSON denies implicit configuration/credential export.
func (ChangeConfig) MarshalJSON() ([]byte, error) { return nil, phone.ErrVerificationDisclosure }

// MarshalText denies implicit configuration and map-key export.
func (ChangeConfig) MarshalText() ([]byte, error) { return nil, phone.ErrVerificationDisclosure }
func (changeState) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("phonehttp.changeState(redacted)"))
}
func (changeState) MarshalJSON() ([]byte, error) { return nil, phone.ErrVerificationDisclosure }
func (changeState) MarshalText() ([]byte, error) { return nil, phone.ErrVerificationDisclosure }
func (changeBody) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("phonehttp.changeBody(redacted)"))
}
func (changeBody) MarshalJSON() ([]byte, error) { return nil, phone.ErrVerificationDisclosure }
func (changeBody) MarshalText() ([]byte, error) { return nil, phone.ErrVerificationDisclosure }
