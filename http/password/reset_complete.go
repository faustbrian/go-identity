package passwordhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
	primitive "github.com/faustbrian/go-password"
)

// ResetCompleteService borrows the native workflow and purpose-bound durable
// original-source reader. Source metadata grants no capability use; completion
// repeats authoritative admission and owns atomic credential/session effects.
type ResetCompleteService interface {
	password.ResetService
	ResetCompletionRateSource(context.Context, capability.Proof, authorization.DecisionContext) (identity.UserID, identity.CredentialID, string, time.Duration, error)
}

// ResetCompleteConfig selects explicit-confirmation reset, never link-scanner
// consumption or automatic signin. Borrowed owners and Now are concurrent-safe
// and must outlive handlers. The signed Device cookie is abuse correlation,
// not account authority. MaximumDuration is 1ms..30s; earlier deadlines win.
type ResetCompleteConfig struct {
	Network         identityhttp.NetworkConfig
	Service         ResetCompleteService
	Rate            *identityhttp.ChallengeVerificationRateLimiter
	Origin          identityhttp.Origin
	Device          session.BrowserDeviceConfig
	ActorID         identity.ActorID
	PolicyRevision  authorization.Revision
	Now             func() time.Time
	MaximumDuration time.Duration
}

// Format redacts borrowed runtime configuration.
func (ResetCompleteConfig) Format(s fmt.State, _ rune) {
	io.WriteString(s, "passwordhttp.ResetCompleteConfig(redacted)")
}

// MarshalJSON denies runtime export.
func (ResetCompleteConfig) MarshalJSON() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// MarshalText denies runtime export.
func (ResetCompleteConfig) MarshalText() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// LogValue returns a fixed marker.
func (ResetCompleteConfig) LogValue() slog.Value {
	return slog.StringValue("passwordhttp.ResetCompleteConfig(redacted)")
}

// ResetCompleteRecovery is proof/password-free native recovery scope, not
// authorization. Current trusted query policy must separately permit its read.
type ResetCompleteRecovery struct {
	TenantID     identity.TenantID         `json:"tenantID"`
	UserID       identity.UserID           `json:"userID"`
	CredentialID identity.CredentialID     `json:"credentialID"`
	ActorID      identity.ActorID          `json:"actorID"`
	ActorKind    authorization.SubjectKind `json:"actorKind"`
}

// ResetCompleteResponse exposes credential/version and session-revocation
// success only after error-free known commitment. It emits no credentials.
type ResetCompleteResponse struct {
	Completed         bool                   `json:"completed"`
	CommitOutcome     string                 `json:"commitOutcome"`
	CommandID         identity.CommandID     `json:"commandID,omitempty"`
	CredentialVersion uint64                 `json:"credentialVersion,omitempty"`
	SessionsRevoked   bool                   `json:"sessionsRevoked"`
	Recovery          *ResetCompleteRecovery `json:"recovery,omitempty"`
	Error             string                 `json:"error,omitempty"`
}
type resetCompleteAttempt struct {
	out     ResetCompleteResponse
	entered bool
	secret  primitive.Secret
	proof   capability.Proof
}
type resetCompleteAttemptKey struct{}

// ResetCompleteState holds private frozen custody for synchronous hooks. Hooks
// cannot select subject, replace proof/password, or retain state after return.
type ResetCompleteState struct {
	facts      identityhttp.NetworkFacts
	request    password.ResetCompleteRequest
	device     session.BrowserDevice
	token      string
	rate       identityhttp.ChallengeVerificationRateRequest
	credential identity.CredentialID
	attempt    *resetCompleteAttempt
}

// Attempt returns detached metadata; entered does not imply commitment.
func (s ResetCompleteState) Attempt() (ResetCompleteResponse, bool) {
	if s.attempt == nil {
		return ResetCompleteResponse{CommitOutcome: "none"}, false
	}
	out := s.attempt.out
	if out.Recovery != nil {
		copy := *out.Recovery
		out.Recovery = &copy
	}
	return out, s.attempt.entered
}

// Format redacts original custody.
func (ResetCompleteState) Format(s fmt.State, _ rune) {
	io.WriteString(s, "passwordhttp.ResetCompleteState(redacted)")
}

// MarshalJSON denies state export.
func (ResetCompleteState) MarshalJSON() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// MarshalText denies state export.
func (ResetCompleteState) MarshalText() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// LogValue returns a fixed marker.
func (ResetCompleteState) LogValue() slog.Value {
	return slog.StringValue("passwordhttp.ResetCompleteState(redacted)")
}
func resetCompleteAttemptFor(r *http.Request) *resetCompleteAttempt {
	if a, ok := r.Context().Value(resetCompleteAttemptKey{}).(*resetCompleteAttempt); ok {
		return a
	}
	return &resetCompleteAttempt{out: ResetCompleteResponse{CommitOutcome: "none"}}
}

// NewResetCompleteHandler constructs POST /v1/password/reset-complete. Closed
// JSON requires original commandID, token and newPassword. No retry key,
// Authorization, query token, identity override or GET consumption is accepted.
// Owned Secret/proof custody is destroyed on every exit; native durable one-use
// remains atomic with mutation, not this local cleanup.
func NewResetCompleteHandler(c ResetCompleteConfig) (http.Handler, error) {
	return NewResetCompleteHandlerWithMiddleware(c, nil)
}

// NewResetCompleteHandlerWithMiddleware binds existing typed operation phases.
func NewResetCompleteHandlerWithMiddleware(c ResetCompleteConfig, m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if c.Service == nil || c.Rate == nil || !c.Rate.Configured() || c.Now == nil || c.PolicyRevision == 0 || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second {
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
	devices, err := session.NewBrowserDeviceCodec(c.Device)
	if err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	caller := func(tenant identity.TenantID, correlation string) authorization.DecisionContext {
		return authorization.DecisionContext{PolicyRevision: c.PolicyRevision, CorrelationID: correlation, Request: authorization.Request{Tenant: authorization.TenantID(tenant), Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: authorization.SubjectID(c.ActorID)}, Action: "identity.password.reset-complete", Resource: authorization.Resource{Type: "identity.user"}}}
	}
	if caller("configuration", "").Validate() != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	reject := func(w http.ResponseWriter, r *http.Request, err error) {
		a := resetCompleteAttemptFor(r)
		a.out.Completed = false
		a.out.SessionsRevoked = false
		a.out.CredentialVersion = 0
		f := failure{status: 503, code: "unavailable"}
		if errors.Is(err, identityhttp.ErrInvalidInput) {
			f = failure{status: 400, code: "invalid_request"}
		}
		var denied identity.ForbiddenError
		if errors.As(err, &denied) || errors.Is(err, password.ErrInvalidReset) {
			f = failure{status: 403, code: "denied"}
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
		json.NewEncoder(w).Encode(a.out)
	}
	p, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[ResetCompleteState]{MaximumDuration: c.MaximumDuration, Middleware: m, Reject: reject,
		Decode: func(r *http.Request) (ResetCompleteState, error) {
			s := ResetCompleteState{attempt: resetCompleteAttemptFor(r)}
			if r.URL.Path != "/v1/password/reset-complete" || r.URL.EscapedPath() != r.URL.Path {
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
			now := c.Now()
			if now.IsZero() {
				return s, identityhttp.ErrUnavailable
			}
			device, present, err := decoder.CookieBearer(r, "__Host-identity_device", identityhttp.HeaderRequired)
			if err != nil || !present {
				return s, identityhttp.ErrInvalidInput
			}
			s.device, err = devices.Resolve(r.Context(), now, facts.TenantID(), facts.Origin(), device.Token())
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			body, err := identityhttp.DecodeJSON[map[string]json.RawMessage](decoder, r)
			if err != nil || len(body) != 3 {
				return s, identityhttp.ErrInvalidInput
			}
			var command, token, value string
			for name, dst := range map[string]*string{"commandID": &command, "token": &token, "newPassword": &value} {
				raw, ok := body[name]
				if !ok || string(raw) == "null" || json.Unmarshal(raw, dst) != nil {
					return s, identityhttp.ErrInvalidInput
				}
			}
			id, err := identity.ParseCommandID(command)
			if err != nil || len(token) < 32 || len(token) > 4096 || len(value) == 0 || len(value) > 1<<20 {
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
			s.facts = facts
			s.token = token
			s.request = password.ResetCompleteRequest{TenantID: facts.TenantID(), CommandID: id, NewPassword: secret, Caller: caller(facts.TenantID(), string(correlation)), Origin: string(c.Origin), Network: facts.ClientIP().String(), Device: s.device.DeviceID()}
			return s, nil
		},
		Authenticate: func(r *http.Request, s ResetCompleteState) (ResetCompleteState, error) {
			if err := signinRateError(c.Rate.AdmitIP(r.Context(), s.facts)); err != nil {
				return s, err
			}
			limits := capability.DefaultLimits()
			limits.MaxTokenBytes = 4096
			proof, err := capability.ParseProof(s.token, limits)
			s.token = ""
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.attempt.proof = proof
			s.request.Token = proof
			if s.request.Validate() != nil {
				return s, identityhttp.ErrInvalidInput
			}
			user, credential, challenge, lifetime, err := c.Service.ResetCompletionRateSource(r.Context(), proof, s.request.Caller)
			if err != nil {
				return s, err
			}
			if credential == "" || len(credential) > 256 {
				return s, identityhttp.ErrUnavailable
			}
			s.credential = credential
			s.rate = identityhttp.ChallengeVerificationRateRequest{OperationID: "identity.password.reset-complete", UserID: user, ChallengeID: challenge, ChallengeLifetime: lifetime}
			return s, nil
		},
		Admit: func(r *http.Request, s ResetCompleteState) error {
			if !s.device.ExpiresAt().After(c.Now()) {
				return identityhttp.ErrUnavailable
			}
			return signinRateError(c.Rate.AdmitChallenge(r.Context(), s.facts, s.rate))
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s ResetCompleteState) {
			if !s.device.ExpiresAt().After(c.Now()) {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			a := s.attempt
			a.entered = true
			a.out.CommandID = s.request.CommandID
			a.out.CommitOutcome = "unknown"
			a.out.Recovery = &ResetCompleteRecovery{TenantID: s.request.TenantID, UserID: s.rate.UserID, CredentialID: s.credential, ActorID: c.ActorID, ActorKind: authorization.SubjectServiceAccount}
			result, err := c.Service.ResetComplete(r.Context(), s.request)
			// Current authority can deny before the native owner returns a
			// command receipt (for example, a consumed proof under a new
			// command). Preserve that denial without inventing NotCommitted
			// for historical work. Original recovery stays unknown; successor
			// and session success remain absent.
			if result == (password.ResetCompleteResult{}) && r.Context().Err() == nil {
				var denied identity.ForbiddenError
				if errors.As(err, &denied) || errors.Is(err, password.ErrInvalidReset) {
					reject(w, r, err)
					return
				}
			}
			if result.Validate() != nil || result.CommandID != s.request.CommandID {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			a.out.CommitOutcome = signinOutcome(result.Outcome)
			if r.Context().Err() != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			var conflict identity.ConflictError
			var unavailable identity.UnavailableError
			if result.Outcome == identity.CommitOutcomeConflict && (err == nil || errors.As(err, &conflict) && (conflict.CommandID == "" || conflict.CommandID == s.request.CommandID)) {
				reject(w, r, failure{status: 409, code: "conflict"})
				return
			}
			if result.Outcome == identity.CommitOutcomeInProgress && (err == nil || errors.As(err, &unavailable)) {
				reject(w, r, failure{status: 409, code: "in_progress", retry: time.Second})
				return
			}
			if err != nil {
				reject(w, r, err)
				return
			}
			if result.Outcome != identity.CommitOutcomeCommitted {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			a.out.Completed = true
			a.out.SessionsRevoked = result.SessionsRevoked
			a.out.CredentialVersion = result.CredentialVersion
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(a.out)
		},
	})
	if err != nil {
		return nil, err
	}
	return &resetCompletePipeline{pipeline: p}, nil
}

type resetCompletePipeline struct{ pipeline http.Handler }

func (p *resetCompletePipeline) WithOperationMiddleware(m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if p == nil || p.pipeline == nil {
		return nil, identityhttp.ErrInvalidInput
	}
	h, err := identityhttp.WithOperationMiddleware(p.pipeline, m)
	if err != nil {
		return nil, err
	}
	return &resetCompletePipeline{pipeline: h}, nil
}
func (p *resetCompletePipeline) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a := &resetCompleteAttempt{out: ResetCompleteResponse{CommitOutcome: "none"}}
	defer func() { a.secret.Destroy() }()
	defer func() { _ = a.proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }) }()
	r = r.WithContext(context.WithValue(r.Context(), resetCompleteAttemptKey{}, a))
	servePasswordPipeline(w, r, p.pipeline)
}
