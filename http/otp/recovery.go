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

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/session"
)

// SigninRecoveryService is the borrowed historical recovery owner. It must
// authenticate original possession and current disclosure policy even after
// successful consumption or expiry. It never compares codes, charges attempts,
// issues credentials or requires an executable pre-auth transaction.
type SigninRecoveryService interface {
	RecoverSignin(context.Context, otp.SigninRecoveryRequest) (otp.SigninResult, error)
}

// SigninRecoveryConfig selects original browser custody and a bounded native
// recovery owner. Network, Origin, ActorID and positive PolicyRevision are
// trusted deployment policy. FlowCookie must be __Host-identity_flow. Rate is
// the retained shared strict owner; recovery shares signin IP admission but
// does not debit a challenge or canonical identifier comparison budget.
// Service must be concurrency-safe and honor contexts. Construction transfers
// no resources. MaximumDuration is 1ms..30s and cannot extend caller deadlines.
type SigninRecoveryConfig struct {
	Network         identityhttp.NetworkConfig
	Service         SigninRecoveryService
	Rate            *identityhttp.AuthRateLimiter
	Origin          identityhttp.Origin
	FlowCookie      session.CookiePolicy
	ActorID         identity.ActorID
	PolicyRevision  authorization.Revision
	MaximumDuration time.Duration
}

// Format redacts runtime composition and borrowed owner state.
func (SigninRecoveryConfig) Format(s fmt.State, _ rune) {
	io.WriteString(s, "otphttp.SigninRecoveryConfig(redacted)")
}

// MarshalJSON denies implicit runtime configuration export.
func (SigninRecoveryConfig) MarshalJSON() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

// MarshalText denies implicit runtime configuration export.
func (SigninRecoveryConfig) MarshalText() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

// LogValue redacts runtime configuration diagnostics.
func (SigninRecoveryConfig) LogValue() slog.Value {
	return slog.StringValue("otphttp.SigninRecoveryConfig(redacted)")
}

// SigninRecoveryState owns request-local historical custody, never live
// authentication. Hooks may observe detached attempt metadata, not replace the
// original scope or authorize credential delivery. Do not retain this state.
type SigninRecoveryState struct {
	facts   identityhttp.NetworkFacts
	request otp.SigninRecoveryRequest
	attempt *signinAttempt
}

// Attempt returns detached code-free history. True means recovery was entered,
// not committed or signed in. SignedIn is always false, including committed
// history; the session identity describes an original effect, not live authority.
func (s SigninRecoveryState) Attempt() (SigninResponse, bool) {
	return (SigninState{attempt: s.attempt}).Attempt()
}

// Format prevents traversal of original bearer custody.
func (SigninRecoveryState) Format(s fmt.State, _ rune) {
	io.WriteString(s, "otphttp.SigninRecoveryState(redacted)")
}

// MarshalJSON denies implicit request-state export.
func (SigninRecoveryState) MarshalJSON() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

// MarshalText denies implicit request-state export.
func (SigninRecoveryState) MarshalText() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

// LogValue redacts request-state diagnostics.
func (SigninRecoveryState) LogValue() slog.Value {
	return slog.StringValue("otphttp.SigninRecoveryState(redacted)")
}

// NewSigninRecoveryHandler explicitly constructs POST /v1/otp/signin/recover.
// Closed JSON accepts flowID and the exact previously returned recovery object,
// never code, replacement subject, remember policy or a new attempt. Exact
// tenant HTTPS host, configured Origin and original flow cookie are required.
// Query, trailers, Authorization and Idempotency-Key are forbidden. Recovery
// calls its native owner once without executable-source discovery or fallback.
// No result can deliver bearer/CSRF credentials or assert a current login.
// Responses use SigninResponse: 200 resolved history, 400 invalid input, 403
// origin, 404 path, 405 method, 421 host, 429 IP admission, 503 unresolved or
// unavailable history. Construction registers no route or feature metadata.
func NewSigninRecoveryHandler(c SigninRecoveryConfig) (http.Handler, error) {
	return NewSigninRecoveryHandlerWithMiddleware(c, nil)
}

// NewSigninRecoveryHandlerWithMiddleware exposes real typed recovery phases
// under the same response guard as signin. Decode freezes original input,
// Authenticate applies trusted IP admission, and Handle recovers once. Hooks
// cannot forge cookie/CSRF delivery, even by short-circuiting or trailers.
func NewSigninRecoveryHandlerWithMiddleware(c SigninRecoveryConfig, middleware []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if nilOwner(c.Service) || !c.Rate.Configured() || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second {
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
	cookie, err := c.FlowCookie.DeletionAttributes()
	if err != nil || cookie.Name != "__Host-identity_flow" {
		return nil, identityhttp.ErrInvalidInput
	}
	caller := func(tenant identity.TenantID) authorization.DecisionContext {
		return authorization.DecisionContext{PolicyRevision: c.PolicyRevision, Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: authorization.SubjectID(c.ActorID)}, Tenant: authorization.TenantID(tenant), Action: "identity.otp.signin", Resource: authorization.Resource{Type: "identity.request-admission", ID: "identity.otp.signin"}}}
	}
	if caller("configuration").Validate() != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	reject := func(w http.ResponseWriter, r *http.Request, err error) {
		a := signinAttemptFor(r)
		a.out.SignedIn = false
		a.cookie, a.csrf = "", ""
		f := signinFailure{status: 503, code: "unavailable"}
		if errors.Is(err, identityhttp.ErrInvalidInput) {
			f = signinFailure{status: 400, code: "invalid_request"}
		}
		var specific signinFailure
		if errors.As(err, &specific) {
			f = specific
		}
		if f.status == 405 {
			w.Header().Set("Allow", http.MethodPost)
		}
		if f.retry > 0 {
			w.Header().Set("Retry-After", strconv.FormatInt(int64((min(max(f.retry, time.Second), time.Hour)+time.Second-1)/time.Second), 10))
		}
		signinResponse(w, a, f.status, f.code)
	}
	pipeline, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[SigninRecoveryState]{MaximumDuration: c.MaximumDuration, Middleware: middleware, Reject: reject,
		Decode: func(r *http.Request) (SigninRecoveryState, error) {
			s := SigninRecoveryState{attempt: signinAttemptFor(r)}
			fail := func(status int, code string) (SigninRecoveryState, error) {
				return s, signinFailure{status: status, code: code}
			}
			if r.URL.Path != "/v1/otp/signin/recover" || r.URL.EscapedPath() != r.URL.Path {
				return fail(404, "not_found")
			}
			if r.Method != http.MethodPost {
				return fail(405, "method_not_allowed")
			}
			if r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Trailer) != 0 {
				return fail(400, "invalid_request")
			}
			if _, _, err := decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil {
				return fail(400, "invalid_request")
			}
			facts, err := network.Resolve(r)
			if err != nil || facts.Realm() != identityhttp.RealmTenant {
				return fail(421, "misdirected_request")
			}
			if facts.Scheme() != "https" {
				return fail(400, "invalid_request")
			}
			if _, err := origin.Check(r); err != nil {
				return fail(403, "origin_denied")
			}
			bearer, present, err := decoder.CookieBearer(r, cookie.Name, identityhttp.HeaderRequired)
			if err != nil || !present {
				return fail(400, "invalid_request")
			}
			input, err := identityhttp.DecodeJSON[map[string]json.RawMessage](decoder, r)
			if err != nil {
				if r.Context().Err() != nil {
					return s, identityhttp.ErrUnavailable
				}
				return fail(400, "invalid_request")
			}
			var flowID string
			var recovery map[string]json.RawMessage
			if !recoveryFields(input, map[string]any{"flowID": &flowID, "recovery": &recovery}) {
				return fail(400, "invalid_request")
			}
			id, err := identity.ParsePreAuthTransactionID(flowID)
			if err != nil {
				return fail(400, "invalid_request")
			}
			flow, err := otp.NewPreAuthSendFlow(id, bearer)
			if err != nil {
				return fail(400, "invalid_request")
			}
			b, err := decodeSigninRecovery(recovery)
			if err != nil {
				return fail(400, "invalid_request")
			}
			opaque, err := otp.NewSigninRecovery(b)
			if err != nil {
				return fail(400, "invalid_request")
			}
			s.request = otp.SigninRecoveryRequest{TenantID: facts.TenantID(), Caller: caller(facts.TenantID()), Flow: flow, Recovery: opaque}
			if s.request.Validate() != nil {
				return fail(400, "invalid_request")
			}
			s.facts = facts
			return s, nil
		},
		Authenticate: func(r *http.Request, s SigninRecoveryState) (SigninRecoveryState, error) {
			return s, signinRateError(c.Rate.AdmitSigninIP(r.Context(), s.facts, "identity.otp.signin"))
		},
		Admit: func(*http.Request, SigninRecoveryState) error { return nil },
		Handle: func(w http.ResponseWriter, r *http.Request, s SigninRecoveryState) {
			a := s.attempt
			a.attempted = true
			a.ctx = r.Context()
			a.out.CommitOutcome = "unknown"
			result, err := c.Service.RecoverSignin(r.Context(), s.request)
			original, _ := s.request.Recovery.Bindings()
			observed, e := result.Recovery.Bindings()
			if e != nil || observed != original || result.Issuance.CommandID != original.Attempt.CommandID || !result.Issuance.Replayed {
				signinResponse(w, a, 503, "unavailable")
				return
			}
			a.out.CommandID = result.Issuance.CommandID
			a.out.CommitOutcome = outcome(result.Issuance.CommitOutcome)
			a.out.Recovery = &SigninRecovery{SendCommandID: original.SendCommandID, Attempt: SigninAttempt{CommandID: original.Attempt.CommandID, TenantID: original.Attempt.TenantID, AttemptID: string(original.Attempt.AttemptID), Fingerprint: string(original.Attempt.Fingerprint), FingerprintKeyVersion: original.Attempt.FingerprintKeyVersion}, ExpectedVersion: original.ExpectedVersion, DigestKeyVersion: original.DigestKeyVersion, ScopeDigest: original.ScopeDigest}
			if err != nil || r.Context().Err() != nil || result.Issuance.CommitOutcome != identity.CommitOutcomeCommitted && result.Issuance.CommitOutcome != identity.CommitOutcomeNotCommitted {
				signinResponse(w, a, 503, "unavailable")
				return
			}
			if result.Issuance.CommitOutcome == identity.CommitOutcomeCommitted {
				if !historicalSessionID(result.SessionID) {
					signinResponse(w, a, 503, "unavailable")
					return
				}
				a.out.SessionID = result.SessionID
			}
			signinResponse(w, a, 200, "")
		},
	})
	if err != nil {
		return nil, err
	}
	return &signinPipeline{pipeline: pipeline}, nil
}

// Recovery may have no live session payload to validate. Retain the session
// owner's exact visible-ASCII, 128-byte identity boundary for historical output.
func historicalSessionID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for i := range len(id) {
		if id[i] < 33 || id[i] > 126 {
			return false
		}
	}
	return true
}

func recoveryFields(input map[string]json.RawMessage, fields map[string]any) bool {
	if len(input) != len(fields) {
		return false
	}
	for key, dst := range fields {
		raw, ok := input[key]
		if !ok || string(raw) == "null" || json.Unmarshal(raw, dst) != nil {
			return false
		}
	}
	return true
}

func decodeSigninRecovery(input map[string]json.RawMessage) (otp.SigninRecoveryBindings, error) {
	var b otp.SigninRecoveryBindings
	var attempt map[string]json.RawMessage
	var digest []json.RawMessage
	if !recoveryFields(input, map[string]any{"sendCommandID": &b.SendCommandID, "attempt": &attempt, "expectedVersion": &b.ExpectedVersion, "digestKeyVersion": &b.DigestKeyVersion, "scopeDigest": &digest}) || len(digest) != 32 {
		return b, identityhttp.ErrInvalidInput
	}
	if !recoveryFields(attempt, map[string]any{"commandID": &b.Attempt.CommandID, "tenantID": &b.Attempt.TenantID, "attemptID": &b.Attempt.AttemptID, "fingerprint": &b.Attempt.Fingerprint, "fingerprintKeyVersion": &b.Attempt.FingerprintKeyVersion}) {
		return b, identityhttp.ErrInvalidInput
	}
	for i, raw := range digest {
		if string(raw) == "null" || json.Unmarshal(raw, &b.ScopeDigest[i]) != nil {
			return b, identityhttp.ErrInvalidInput
		}
	}
	clear(digest)
	return b, nil
}
