package emailhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	email "github.com/faustbrian/go-identity/email"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
)

// ConfirmationService is the consumer-owned original-signup confirmation port.
// The native owner authenticates original issuance/current policy for rate
// selection, then independently checks and atomically consumes the proof with
// the protected mutation. Source metadata is neither a validity lease nor
// permission to consume. Implementations must honor bounded contexts, support
// concurrent independent requests and never expose raw diagnostics/secrets.
// password/postgres.SignupService implements this port without HTTP imports.
type ConfirmationService interface {
	RegistrationVerificationRateSource(context.Context, capability.Proof, string, authorization.DecisionContext) (identity.UserID, string, time.Duration, error)
	VerificationConfirm(context.Context, email.VerificationConfirmRequest) (email.VerificationConfirmResult, error)
}

// ConfirmationConfig explicitly selects original-signup confirmation without
// session issuance. Network and Origin are frozen by their owning constructors.
// Service, Rate and prompt concurrency-safe Now remain borrowed. ActorID and
// positive PolicyRevision are trusted deployment query-policy identity, never
// browser claims or the original signup actor. MaximumDuration is 1ms..30s;
// earlier deadlines win. Construction registers nothing and performs no IO.
type ConfirmationConfig struct {
	Network         identityhttp.NetworkConfig
	Service         ConfirmationService
	Rate            *identityhttp.ChallengeVerificationRateLimiter
	Origin          identityhttp.Origin
	ActorID         identity.ActorID
	PolicyRevision  authorization.Revision
	Now             func() time.Time
	MaximumDuration time.Duration
}

// Format redacts deployment composition.
func (ConfirmationConfig) Format(f fmt.State, _ rune) {
	io.WriteString(f, "emailhttp.ConfirmationConfig(redacted)")
}

// LogValue emits a constant marker.
func (ConfirmationConfig) LogValue() slog.Value {
	return slog.StringValue("emailhttp.ConfirmationConfig(redacted)")
}

// MarshalJSON denies implicit configuration export.
func (ConfirmationConfig) MarshalJSON() ([]byte, error) { return nil, email.ErrSensitiveSerialization }

// MarshalText denies implicit configuration export.
func (ConfirmationConfig) MarshalText() ([]byte, error) { return nil, email.ErrSensitiveSerialization }

// ConfirmedAddress is an explicitly disclosed fresh committed email snapshot,
// not current authority. Personal data belongs only in the authorized no-store
// response. Versions are independent; replay and failure omit the whole value.
type ConfirmedAddress struct {
	IdentifierID        identity.IdentifierID `json:"identifierID"`
	UserID              identity.UserID       `json:"userID"`
	Email               string                `json:"email,omitempty"`
	Primary             bool                  `json:"primary"`
	IdentifierVersion   uint64                `json:"identifierVersion"`
	VerificationVersion uint64                `json:"verificationVersion"`
}

// ConfirmationResponse conserves the original attempt outcome without claiming
// rollback on failure. Confirmed means that original command committed, not
// fresh account eligibility; Replayed receipts contain no address/session.
// Recovery is sensitive original correlation, not bearer or retry authority.
type ConfirmationResponse struct {
	Confirmed     bool                  `json:"confirmed"`
	CommandID     identity.CommandID    `json:"commandID,omitempty"`
	CommitOutcome string                `json:"commitOutcome"`
	Replayed      bool                  `json:"replayed"`
	Address       *ConfirmedAddress     `json:"address,omitempty"`
	Recovery      *ConfirmationRecovery `json:"recovery,omitempty"`
	Error         string                `json:"error,omitempty"`
	// Signin is present only for the explicitly selected registration-signin
	// profile. Its outcome is independent of the verification command above.
	Signin *VerificationSigninResponse `json:"signin,omitempty"`
}

// ConfirmationRecovery is detached original receipt correlation. It grants no
// authority and never selects a new execution. No recovery endpoint is selected
// by this initial confirmation feature; the native typed recovery remains usable.
type ConfirmationRecovery struct {
	TenantID  identity.TenantID         `json:"tenantID"`
	UserID    identity.UserID           `json:"userID"`
	RecordID  string                    `json:"recordID"`
	ActorID   identity.ActorID          `json:"actorID"`
	ActorKind authorization.SubjectKind `json:"actorKind"`
}

type confirmationAttempt struct {
	out          ConfirmationResponse
	entered      bool
	cookie, csrf string
}
type attemptKey struct{}
type confirmationInput struct {
	facts        identityhttp.NetworkFacts
	request      email.VerificationConfirmRequest
	token        string
	rate         identityhttp.ChallengeVerificationRateRequest
	attempt      *confirmationAttempt
	browser      auth.BearerCredential
	device       string
	deviceExpiry time.Time
}

// ConfirmationState retains private immutable request custody for synchronous
// middleware. It is not a principal or clearance and must not outlive the call.
type ConfirmationState struct{ input *confirmationInput }

// Attempt returns detached metadata; entered means a call began, not commitment.
func (s ConfirmationState) Attempt() (ConfirmationResponse, bool) {
	if s.input == nil || s.input.attempt == nil {
		return ConfirmationResponse{CommitOutcome: "none"}, false
	}
	a := s.input.attempt
	out := a.out
	if out.Address != nil {
		copy := *out.Address
		out.Address = &copy
	}
	if out.Recovery != nil {
		copy := *out.Recovery
		out.Recovery = &copy
	}
	if out.Signin != nil {
		copy := *out.Signin
		out.Signin = &copy
	}
	return out, a.entered
}

// Format prevents private bearer and personal metadata traversal.
func (ConfirmationState) Format(f fmt.State, _ rune) {
	io.WriteString(f, "emailhttp.ConfirmationState(redacted)")
}

// LogValue emits a constant marker.
func (ConfirmationState) LogValue() slog.Value {
	return slog.StringValue("emailhttp.ConfirmationState(redacted)")
}

// MarshalJSON denies implicit state export.
func (ConfirmationState) MarshalJSON() ([]byte, error) { return nil, email.ErrSensitiveSerialization }

// MarshalText denies implicit state export.
func (ConfirmationState) MarshalText() ([]byte, error) { return nil, email.ErrSensitiveSerialization }

type failure struct {
	status int
	code   string
	retry  time.Duration
}

func (f failure) Error() string { return "identity.http.email." + f.code }
func attemptFor(r *http.Request) *confirmationAttempt {
	if r != nil {
		if a, ok := r.Context().Value(attemptKey{}).(*confirmationAttempt); ok {
			return a
		}
	}
	return &confirmationAttempt{out: ConfirmationResponse{CommitOutcome: "none"}}
}

// NewConfirmationHandler selects POST /v1/email/verification-confirm only.
// Closed JSON requires token (32..4096 bytes), exact HTTPS callback (<=2048)
// and stable commandID. Reject Authorization, Idempotency-Key, query/trailer
// alternatives and body identity overrides; ambient cookies grant no authority.
// Exact mapped HTTPS tenant and Origin are required. Trusted-IP rate admission
// precedes proof parsing/source authentication; subject/original-grant budgets
// follow without recounting IP. One native call owns confirmation and replay.
// Responses are no-store/nosniff JSON and issue no cookies, tokens or redirects.
// Fresh successful commit alone may disclose an address. Unknown and known
// committed disclosure failures remain distinct, with no automatic retry.
func NewConfirmationHandler(c ConfirmationConfig) (http.Handler, error) {
	return NewConfirmationHandlerWithMiddleware(c, nil)
}

// NewConfirmationHandlerWithMiddleware binds hooks to real Decode,
// Authenticate, Admit and Handle phases without replacing original custody.
func NewConfirmationHandlerWithMiddleware(c ConfirmationConfig, m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if nilService(c.Service) {
		return nil, identityhttp.ErrInvalidInput
	}
	return newConfirmationHandler(c, m, c.Service, c.Service.RegistrationVerificationRateSource)
}

type confirmationExecutor interface {
	VerificationConfirm(context.Context, email.VerificationConfirmRequest) (email.VerificationConfirmResult, error)
}

type confirmationRateSource func(context.Context, capability.Proof, string, authorization.DecisionContext) (identity.UserID, string, time.Duration, error)

// This transport-only projection conserves the typed native result's original
// recovery action. It never constructs a verification recovery for a change,
// substitutes authority or turns a malformed committed result into rollback.
type confirmationExecutionResult struct {
	Outcome    identity.CommitOutcome
	Address    identity.IdentifierProjection
	Recovery   identity.RecoveryQuery
	Replayed   bool
	RetryAfter time.Duration
	valid      bool
	signin     *email.VerificationSigninResult
}

type confirmationExecution func(context.Context, *confirmationInput) (confirmationExecutionResult, error)

// The wire, origin, rate ordering and response custody are shared transport
// policy. Selection still freezes each native owner's distinct provenance read.
func newConfirmationHandler(c ConfirmationConfig, m []identityhttp.MiddlewareDescriptor, service confirmationExecutor, source confirmationRateSource) (http.Handler, error) {
	if nilService(service) {
		return nil, identityhttp.ErrInvalidInput
	}
	execute := func(ctx context.Context, input *confirmationInput) (confirmationExecutionResult, error) {
		out, err := service.VerificationConfirm(ctx, input.request)
		q, bindingErr := out.Recovery.Bindings()
		return confirmationExecutionResult{Outcome: out.Outcome, Address: out.Address, Recovery: q, Replayed: out.Replayed, RetryAfter: out.RetryAfter, valid: out.Validate() == nil && bindingErr == nil}, err
	}
	return newConfirmationOperation(c, m, execute, source, "identity.email.verification-confirm", nil)
}

func newConfirmationOperation(c ConfirmationConfig, m []identityhttp.MiddlewareDescriptor, execute confirmationExecution, source confirmationRateSource, action string, signin *VerificationSigninConfig) (http.Handler, error) {
	path := "/v1/email/verification-confirm"
	if action == "identity.email.change-confirm" {
		path = "/v1/email/change-confirm"
	} else if action != "identity.email.verification-confirm" {
		return nil, identityhttp.ErrInvalidInput
	}
	if execute == nil || source == nil || !c.Rate.Configured() || c.Now == nil || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second {
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
	caller := func(tenant identity.TenantID, now time.Time) authorization.DecisionContext {
		return authorization.DecisionContext{PolicyRevision: c.PolicyRevision, Request: authorization.Request{Tenant: authorization.TenantID(tenant), Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: authorization.SubjectID(c.ActorID)}, Action: authorization.Action(action), Resource: authorization.Resource{Type: "identity.user"}, Environment: authorization.Environment{Time: now.UTC()}}}
	}
	if caller("configuration", time.Time{}).Validate() != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	reject := func(w http.ResponseWriter, r *http.Request, err error) {
		a := attemptFor(r)
		// Selected signin is a separate transaction: rejecting its delivery
		// cannot undo an already validated parent verification commitment.
		a.out.Confirmed = signin != nil && a.out.Confirmed
		a.out.Address = nil
		a.cookie, a.csrf = "", ""
		if a.out.Signin != nil {
			a.out.Signin.SignedIn, a.out.Signin.SessionID = false, ""
		}
		f := failure{503, "unavailable", 0}
		if errors.Is(err, identityhttp.ErrInvalidInput) || errors.Is(err, email.ErrInvalidVerification) {
			f = failure{400, "invalid_request", 0}
		}
		var specific failure
		if errors.As(err, &specific) {
			f = specific
		}
		if f.status == 405 {
			w.Header().Set("Allow", http.MethodPost)
		}
		if f.retry > 0 {
			w.Header().Set("Retry-After", strconv.FormatInt(int64((min(f.retry, time.Hour)+time.Second-1)/time.Second), 10))
		}
		a.out.Error = f.code
		w.WriteHeader(f.status)
		json.NewEncoder(w).Encode(a.out)
	}
	pipeline, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[ConfirmationState]{MaximumDuration: c.MaximumDuration, Middleware: m, Reject: reject,
		Decode: func(r *http.Request) (ConfirmationState, error) {
			s := ConfirmationState{input: &confirmationInput{attempt: attemptFor(r)}}
			if r.URL.Path != path || r.URL.EscapedPath() != r.URL.Path {
				return s, failure{404, "not_found", 0}
			}
			if r.Method != http.MethodPost {
				return s, failure{405, "method_not_allowed", 0}
			}
			if r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Trailer) != 0 {
				return s, identityhttp.ErrInvalidInput
			}
			if _, _, err := decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			if _, _, err := decoder.Bearer(r, identityhttp.HeaderForbidden); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			facts, err := network.Resolve(r)
			if err != nil || facts.Realm() != identityhttp.RealmTenant {
				return s, failure{421, "misdirected_request", 0}
			}
			if facts.Scheme() != "https" {
				return s, failure{403, "https_required", 0}
			}
			if _, err := origin.Check(r); err != nil {
				return s, failure{403, "origin_denied", 0}
			}
			fields, err := identityhttp.DecodeJSON[map[string]json.RawMessage](decoder, r)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			var token, callback, command string
			if len(fields) != 3 || !readString(fields, "token", &token) || !readString(fields, "callback", &callback) || !readString(fields, "commandID", &command) || len(token) < 32 || len(token) > 4096 || len(callback) > 2048 {
				return s, identityhttp.ErrInvalidInput
			}
			id, err := identity.ParseCommandID(command)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			u, err := url.Parse(callback)
			if err != nil || u == nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" || u.Fragment != "" || u.RawFragment != "" || u.Host == "" || u.String() != callback {
				return s, identityhttp.ErrInvalidInput
			}
			now := c.Now()
			if now.IsZero() {
				return s, identityhttp.ErrUnavailable
			}
			correlation, err := identity.NewCommandID()
			if err != nil {
				return s, identityhttp.ErrUnavailable
			}
			s.input.facts = facts
			s.input.token = token
			s.input.request = email.VerificationConfirmRequest{TenantID: facts.TenantID(), CommandID: id, Callback: *u, Caller: caller(facts.TenantID(), now), Network: facts.ClientIP().String()}
			// Native audit binding requires correlation, but client headers must
			// neither select it nor replace the original durable workflow command.
			s.input.request.Caller.CorrelationID = string(correlation)
			if signin != nil {
				browser, device, err := signin.browserInput(r, decoder, facts, now)
				if err != nil {
					return s, err
				}
				s.input.browser, s.input.device, s.input.deviceExpiry = browser, device.DeviceID(), device.ExpiresAt()
			}
			return s, nil
		},
		Authenticate: func(r *http.Request, s ConfirmationState) (ConfirmationState, error) {
			if err := rateFailure(c.Rate.AdmitIP(r.Context(), s.input.facts)); err != nil {
				return s, err
			}
			limits := capability.DefaultLimits()
			limits.MaxTokenBytes = 4096
			proof, err := capability.ParseProof(s.input.token, limits)
			s.input.token = ""
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.input.request.Token = proof
			valid := s.input.request.Validate() == nil
			if action == "identity.email.change-confirm" {
				valid = email.ChangeConfirmRequest(s.input.request).Validate() == nil
			}
			if !valid {
				return s, identityhttp.ErrInvalidInput
			}
			user, grant, lifetime, err := source(r.Context(), proof, s.input.request.Callback.String(), s.input.request.Caller)
			if err != nil {
				return s, ownerFailure(err)
			}
			s.input.rate = identityhttp.ChallengeVerificationRateRequest{OperationID: action, UserID: user, ChallengeID: grant, ChallengeLifetime: lifetime}
			return s, nil
		},
		Admit: func(r *http.Request, s ConfirmationState) error {
			return rateFailure(c.Rate.AdmitChallenge(r.Context(), s.input.facts, s.input.rate))
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s ConfirmationState) {
			a := s.input.attempt
			a.entered = true
			a.out.CommandID = s.input.request.CommandID
			a.out.CommitOutcome = "unknown"
			result, err := execute(r.Context(), s.input)
			a.out.CommitOutcome = outcome(result.Outcome)
			if !result.valid {
				// A native owner can deny before creating an execution receipt.
				// That is a refusal, not an outage or evidence of rollback. Do
				// not accept partial/claimed receipts through this exception.
				var denied identity.ForbiddenError
				if errors.As(err, &denied) && result.Outcome == identity.CommitOutcomeInvalid && result.Address == (identity.IdentifierProjection{}) && result.Recovery == (identity.RecoveryQuery{}) && !result.Replayed && result.RetryAfter == 0 {
					reject(w, r, ownerFailure(err))
					return
				}
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			q := result.Recovery
			if q.TenantID != s.input.request.TenantID || q.UserID != s.input.rate.UserID || q.CommandID != s.input.request.CommandID || q.ActorID != c.ActorID || q.ActorKind != authorization.SubjectServiceAccount || q.OperationID != action {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			a.out.Recovery = &ConfirmationRecovery{TenantID: q.TenantID, UserID: q.UserID, RecordID: q.RecordID, ActorID: q.ActorID, ActorKind: q.ActorKind}
			a.out.Replayed = result.Replayed
			if signin != nil {
				a.out.Confirmed = result.Outcome == identity.CommitOutcomeCommitted
			}
			if signin != nil && result.signin != nil && result.signin.Issuance.CommandID != "" {
				issued := result.signin.Issuance
				child := result.signin.Recovery
				a.out.Signin = &VerificationSigninResponse{CommandID: issued.CommandID, CommitOutcome: outcome(issued.CommitOutcome), Replayed: issued.Replayed, Recovery: ConfirmationRecovery{TenantID: child.TenantID, UserID: child.UserID, RecordID: child.RecordID, ActorID: child.ActorID, ActorKind: child.ActorKind}}
			}
			if r.Context().Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				reject(w, r, ownerFailure(err))
				return
			}
			// The native owner pairs classified receipts with typed errors. Only
			// their matching classifications may override generic unavailability;
			// cancellation and untrusted receipts never reach this boundary.
			var conflict identity.ConflictError
			var unavailable identity.UnavailableError
			if result.Outcome == identity.CommitOutcomeConflict && (err == nil || errors.As(err, &conflict) && (conflict.CommandID == "" || conflict.CommandID == s.input.request.CommandID)) {
				reject(w, r, failure{409, "conflict", 0})
				return
			}
			if result.Outcome == identity.CommitOutcomeInProgress && (err == nil || errors.As(err, &unavailable)) {
				reject(w, r, failure{409, "in_progress", result.RetryAfter})
				return
			}
			if err != nil {
				reject(w, r, ownerFailure(err))
				return
			}
			if result.Outcome == identity.CommitOutcomeUnknown {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			if result.Outcome != identity.CommitOutcomeCommitted {
				reject(w, r, failure{403, "invalid_verification", 0})
				return
			}
			if !result.Replayed {
				b, e := result.Address.Bindings()
				if e != nil {
					reject(w, r, identityhttp.ErrUnavailable)
					return
				}
				value, _, included := result.Address.Values()
				a.out.Address = &ConfirmedAddress{IdentifierID: b.IdentifierID, UserID: b.UserID, Primary: b.Primary, IdentifierVersion: b.IdentifierVersion, VerificationVersion: b.VerificationVersion}
				if included {
					a.out.Address.Email = value
				}
			}
			a.out.Confirmed = true
			if signin != nil && result.signin != nil && result.signin.Issuance.Token != (session.Token{}) {
				if !c.Now().Before(s.input.deviceExpiry) {
					reject(w, r, identityhttp.ErrUnavailable)
					return
				}
				cookie, csrf, err := signin.delivery(s.input.request, *result.signin, c.Now())
				if err != nil || a.out.Signin == nil {
					reject(w, r, identityhttp.ErrUnavailable)
					return
				}
				a.cookie, a.csrf = cookie, csrf
				a.out.Signin.SignedIn = true
				spec, _ := result.signin.Issuance.Session.Bindings()
				a.out.Signin.SessionID = spec.SessionID
			}
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(a.out)
		},
	})
	if err != nil {
		return nil, err
	}
	return &confirmationPipeline{pipeline: pipeline}, nil
}

func readString(fields map[string]json.RawMessage, key string, out *string) bool {
	raw, ok := fields[key]
	return ok && string(raw) != "null" && json.Unmarshal(raw, out) == nil && *out != ""
}
func nilService(s any) bool {
	if s == nil {
		return true
	}
	v := reflect.ValueOf(s)
	switch v.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Func, reflect.Chan, reflect.Slice, reflect.Interface:
		return v.IsNil()
	}
	return false
}
func rateFailure(out identityhttp.AuthRateResult, err error) error {
	if errors.Is(err, identityhttp.ErrRateLimited) {
		return failure{429, "rate_limited", out.RetryAfter}
	}
	if err != nil || !out.Allowed {
		return identityhttp.ErrUnavailable
	}
	return nil
}
func ownerFailure(err error) error {
	var forbidden identity.ForbiddenError
	if errors.As(err, &forbidden) {
		return failure{403, "invalid_verification", 0}
	}
	return identityhttp.ErrUnavailable
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
