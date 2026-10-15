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

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/password"
)

// ResetInspectService combines read-only UI inspection with the native
// original-source reader used only for shared subject/challenge admission.
// Historical metadata is not usable authority or a client-selected identity.
type ResetInspectService interface {
	password.ResetInspectionService
	ResetInspectionRateSource(context.Context, capability.Proof, authorization.DecisionContext) (identity.UserID, identity.CredentialID, string, time.Duration, error)
}

// ResetInspectConfig explicitly selects no-store, origin-bound inspection.
// Owners remain borrowed/concurrent-safe and must outlive handlers. Rate uses
// canonical rate.secret, not completion's rate.verify or an emergency fallback.
// MaximumDuration is 1ms..30s; earlier deadlines win. Construction performs no IO.
type ResetInspectConfig struct {
	Network         identityhttp.NetworkConfig
	Service         ResetInspectService
	Rate            *identityhttp.KeyedSecretRateLimiter
	Origin          identityhttp.Origin
	ActorID         identity.ActorID
	PolicyRevision  authorization.Revision
	MaximumDuration time.Duration
}

// Format redacts runtime dependencies and deployment inputs.
func (ResetInspectConfig) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "passwordhttp.ResetInspectConfig(redacted)")
}

// MarshalJSON denies incidental runtime export.
func (ResetInspectConfig) MarshalJSON() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// MarshalText denies incidental textual runtime export.
func (ResetInspectConfig) MarshalText() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// LogValue redacts dependencies and deployment inputs from structured logs.
func (ResetInspectConfig) LogValue() slog.Value {
	return slog.StringValue("passwordhttp.ResetInspectConfig(redacted)")
}

// ResetInspectResponse is advisory UI state without subject, expiry or an
// execution ticket. Error is a fixed transport category; no bearer is echoed.
type ResetInspectResponse struct {
	Valid bool   `json:"valid"`
	Error string `json:"error,omitempty"`
}

type resetInspectCustody struct{ proof capability.Proof }
type resetInspectCustodyKey struct{}

// ResetInspectState retains private synchronous pipeline custody. Hooks cannot
// replace the token, choose a subject or retain proof custody after returning.
type ResetInspectState struct {
	facts   identityhttp.NetworkFacts
	request password.ResetInspectRequest
	source  identityhttp.ChallengeVerificationRateRequest
	invalid bool
}

// Format redacts private proof and source metadata.
func (ResetInspectState) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "passwordhttp.ResetInspectState(redacted)")
}

// MarshalJSON denies state/proof export.
func (ResetInspectState) MarshalJSON() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// MarshalText denies textual state/proof export.
func (ResetInspectState) MarshalText() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// LogValue redacts proof custody and original-source metadata.
func (ResetInspectState) LogValue() slog.Value {
	return slog.StringValue("passwordhttp.ResetInspectState(redacted)")
}

// NewResetInspectHandler constructs only POST /v1/password/reset/inspect.
// A bounded closed JSON body carries exactly token. Query tokens, credentials,
// idempotency keys, GET consumption, redirects and subject overrides deny.
// Inspection never calls ResetComplete; local proof custody is destroyed on exit.
func NewResetInspectHandler(c ResetInspectConfig) (http.Handler, error) {
	return NewResetInspectHandlerWithMiddleware(c, nil)
}

// NewResetInspectHandlerWithMiddleware selects typed read-only owner phases.
func NewResetInspectHandlerWithMiddleware(c ResetInspectConfig, middleware []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if c.Service == nil || c.Rate == nil || !c.Rate.Configured() || c.ActorID == "" || c.PolicyRevision == 0 || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second {
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
	caller := func(tenant identity.TenantID, correlation string) authorization.DecisionContext {
		return authorization.DecisionContext{PolicyRevision: c.PolicyRevision, CorrelationID: correlation, Request: authorization.Request{Tenant: authorization.TenantID(tenant), Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: authorization.SubjectID(c.ActorID)}, Action: "identity.password.reset-inspect", Resource: authorization.Resource{Type: "identity.user"}}}
	}
	if caller("configuration", "").Validate() != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	reject := func(w http.ResponseWriter, _ *http.Request, err error) {
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
		w.WriteHeader(f.status)
		_ = json.NewEncoder(w).Encode(ResetInspectResponse{Error: f.code})
	}
	pipeline, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[ResetInspectState]{MaximumDuration: c.MaximumDuration, Middleware: middleware, Reject: reject,
		Decode: func(r *http.Request) (ResetInspectState, error) {
			var state ResetInspectState
			if r.URL.Path != "/v1/password/reset/inspect" || r.URL.EscapedPath() != r.URL.Path {
				return state, failure{status: 404, code: "not_found"}
			}
			if r.Method != http.MethodPost {
				return state, failure{status: 405, code: "method_not_allowed"}
			}
			if r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Trailer) != 0 {
				return state, identityhttp.ErrInvalidInput
			}
			if _, _, err := decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil {
				return state, identityhttp.ErrInvalidInput
			}
			for name := range r.Header {
				if strings.EqualFold(name, "Authorization") {
					return state, identityhttp.ErrInvalidInput
				}
			}
			facts, err := network.Resolve(r)
			if err != nil {
				return state, identityhttp.ErrInvalidInput
			}
			if facts.Realm() != identityhttp.RealmTenant {
				return state, failure{status: 421, code: "misdirected_request"}
			}
			if facts.Scheme() != "https" {
				return state, failure{status: 403, code: "https_required"}
			}
			if _, err := origin.Check(r); err != nil {
				return state, failure{status: 403, code: "origin_denied"}
			}
			body, err := identityhttp.DecodeJSON[map[string]json.RawMessage](decoder, r)
			var token string
			if err != nil || len(body) != 1 || json.Unmarshal(body["token"], &token) != nil || len(token) < 32 || len(token) > 4096 {
				return state, identityhttp.ErrInvalidInput
			}
			limits := capability.DefaultLimits()
			limits.MaxTokenBytes = 4096
			proof, err := capability.ParseProof(token, limits)
			if err != nil {
				return state, identityhttp.ErrInvalidInput
			}
			holder, ok := r.Context().Value(resetInspectCustodyKey{}).(*resetInspectCustody)
			if !ok {
				_ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
				return state, identityhttp.ErrUnavailable
			}
			holder.proof = proof
			correlation, err := identity.NewCommandID()
			if err != nil {
				return state, identityhttp.ErrUnavailable
			}
			state.facts = facts
			state.request = password.ResetInspectRequest{TenantID: facts.TenantID(), Token: proof, Caller: caller(facts.TenantID(), string(correlation)), Origin: string(c.Origin)}
			if state.request.Validate() != nil {
				return state, identityhttp.ErrInvalidInput
			}
			return state, nil
		},
		Authenticate: func(r *http.Request, state ResetInspectState) (ResetInspectState, error) {
			if err := signinRateError(c.Rate.AdmitInspectionIP(r.Context(), state.facts, "identity.password.reset-inspect")); err != nil {
				return state, err
			}
			user, _, challenge, lifetime, err := c.Service.ResetInspectionRateSource(r.Context(), state.request.Token, state.request.Caller)
			var denied identity.ForbiddenError
			if errors.As(err, &denied) || errors.Is(err, password.ErrInvalidReset) {
				state.invalid = true
				return state, nil
			}
			if err != nil || r.Context().Err() != nil {
				return state, identityhttp.ErrUnavailable
			}
			state.source = identityhttp.ChallengeVerificationRateRequest{OperationID: "identity.password.reset-inspect", UserID: user, ChallengeID: challenge, ChallengeLifetime: lifetime}
			return state, nil
		},
		Admit: func(r *http.Request, state ResetInspectState) error {
			if state.invalid {
				return nil
			}
			return signinRateError(c.Rate.AdmitInspectionSubject(r.Context(), state.facts, state.source))
		},
		Handle: func(w http.ResponseWriter, r *http.Request, state ResetInspectState) {
			var result password.ResetInspectResult
			if !state.invalid {
				var err error
				result, err = c.Service.ResetInspect(r.Context(), state.request)
				if err != nil || r.Context().Err() != nil {
					reject(w, r, identityhttp.ErrUnavailable)
					return
				}
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(ResetInspectResponse{Valid: result.Valid})
		},
	})
	if err != nil {
		return nil, err
	}
	return &resetInspectPipeline{pipeline: pipeline}, nil
}

type resetInspectPipeline struct{ pipeline http.Handler }

func (p *resetInspectPipeline) WithOperationMiddleware(m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if p == nil || p.pipeline == nil {
		return nil, identityhttp.ErrInvalidInput
	}
	handler, err := identityhttp.WithOperationMiddleware(p.pipeline, m)
	if err != nil {
		return nil, err
	}
	return &resetInspectPipeline{pipeline: handler}, nil
}

func (p *resetInspectPipeline) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	holder := &resetInspectCustody{}
	defer func() {
		_ = holder.proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
	}()
	r = r.WithContext(context.WithValue(r.Context(), resetInspectCustodyKey{}, holder))
	servePasswordPipeline(w, r, p.pipeline)
}
