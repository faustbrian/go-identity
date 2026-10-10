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

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
	primitive "github.com/faustbrian/go-password"
)

// BearerVerificationConfig selects only strict bearer password verification.
// Sessions and Verification must share the real native primary authority;
// never select a consumer-written store or proof builder. The generic handler
// supplies no device correlation; its owner's policy must permit that profile.
// For password/postgres.VerificationWorkflow, use this configuration inside
// BrowserDeviceBearerVerificationConfig to satisfy native Authentication risk.
// Rate is a shared native atomic profile, never per-request.
// All borrowed owners and prompt concurrency-safe Now must outlive calls.
// PolicyRevision is trusted positive startup policy. MaximumDuration is
// 1ms..30s and never extends an inbound deadline. No cookie fallback exists.
type BearerVerificationConfig struct {
	Network         identityhttp.NetworkConfig
	Sessions        *session.SessionService
	Verification    password.VerificationService
	Rate            *identityhttp.PasswordVerificationRateLimiter
	PolicyRevision  authorization.Revision
	Now             func() time.Time
	MaximumDuration time.Duration
}

// Format redacts borrowed configuration for every verb.
func (BearerVerificationConfig) Format(s fmt.State, _ rune) {
	io.WriteString(s, "passwordhttp.BearerVerificationConfig(redacted)")
}

// MarshalJSON denies implicit runtime export.
func (BearerVerificationConfig) MarshalJSON() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// MarshalText denies implicit text/map-key export.
func (BearerVerificationConfig) MarshalText() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// LogValue redacts runtime composition.
func (BearerVerificationConfig) LogValue() slog.Value {
	return slog.StringValue("passwordhttp.BearerVerificationConfig(redacted)")
}

// VerificationProof is an explicit projection of the original committed proof,
// not a session, signing record or consumer authority. Protected operations look
// up and validate the original signed record using ProofID. No identity/session
// lookup keys or credentials are delivered. Times are never renewed by transport.
type VerificationProof struct {
	ProofID   string    `json:"proofID"`
	Purpose   string    `json:"purpose"`
	Action    string    `json:"action"`
	Audience  string    `json:"audience"`
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// VerificationResponse retains original command observations on errors. Proof
// and Verified require error-free fresh known commit and original primary
// session bindings. Outcome none is not rollback; CommandID is correlation,
// not recovery permission. Scoped native Recover never redelivers a proof.
type VerificationResponse struct {
	Verified      bool               `json:"verified"`
	Proof         *VerificationProof `json:"proof,omitempty"`
	CommandID     identity.CommandID `json:"commandID,omitempty"`
	CommitOutcome string             `json:"commitOutcome"`
	Error         string             `json:"error,omitempty"`
}

type verificationAttempt struct {
	secret    primitive.Secret
	out       VerificationResponse
	attempted bool
}
type verificationKey struct{}

// VerificationState is immutable request-local custody for synchronous trusted
// hooks. It grants no reusable authority; do not retain it after the request.
type VerificationState struct {
	facts      identityhttp.NetworkFacts
	bearer     auth.BearerCredential
	credential session.Credential
	target     password.VerificationTarget
	read       session.GetResult
	user       identity.UserID
	device     session.BrowserDevice
	attempt    *verificationAttempt
}

// Principal returns detached preliminary owner metadata, not issuance authority.
func (s VerificationState) Principal() (identity.TenantID, identity.UserID, bool) {
	return s.facts.TenantID(), s.user, s.user != ""
}

// Attempt returns a detached original observation; true means native invocation,
// not commit or delivery. Hooks cannot modify the retained proof projection.
func (s VerificationState) Attempt() (VerificationResponse, bool) {
	if s.attempt == nil {
		return VerificationResponse{CommitOutcome: "none"}, false
	}
	out := s.attempt.out
	if out.Proof != nil {
		copy := *out.Proof
		out.Proof = &copy
	}
	return out, s.attempt.attempted
}

// Format redacts password and credential custody.
func (VerificationState) Format(s fmt.State, _ rune) {
	io.WriteString(s, "passwordhttp.VerificationState(redacted)")
}

// MarshalJSON denies implicit request-state export.
func (VerificationState) MarshalJSON() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// MarshalText denies implicit request-state text/map-key export.
func (VerificationState) MarshalText() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// LogValue redacts original request custody.
func (VerificationState) LogValue() slog.Value {
	return slog.StringValue("passwordhttp.VerificationState(redacted)")
}

// NewBearerVerificationHandler constructs exact POST /v1/password/verify only.
// Closed JSON requires password, purpose, action and audience. The native owner
// separately checks the exact startup target allowlist. No proof/identity,
// lifetime/assurance or key override is accepted. Idempotency-Key is forbidden.
// Bearer comes only from one strict Authorization header; ambient cookies are
// ignored and CSRF alternatives rejected. No session or cookie is issued.
// This constructor exposes no route/metadata or cookie profile by itself.
func NewBearerVerificationHandler(c BearerVerificationConfig) (http.Handler, error) {
	return NewBearerVerificationHandlerWithMiddleware(c, nil)
}

// NewBearerVerificationHandlerWithMiddleware binds bounded decoding, one owner
// session read, atomic rate admission and one native verification invocation.
// Original session validity is never refreshed through rate/hooks/native work.
// Native custody owns current primary/password/policy/risk/signing and atomic
// effects. All paths destroy the handler-owned password; hooks cannot replace
// original input, emit cookies/CSRF/trailers or turn observations into authority.
func NewBearerVerificationHandlerWithMiddleware(c BearerVerificationConfig, middleware []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	return newBearerVerificationHandler(c, middleware, nil)
}

func newBearerVerificationHandler(c BearerVerificationConfig, middleware []identityhttp.MiddlewareDescriptor, devices *session.BrowserDeviceCodec) (http.Handler, error) {
	if !c.Sessions.Configured() || nilOwner(c.Verification) || !c.Rate.Configured() || c.PolicyRevision == 0 || c.Now == nil || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second {
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
	reject := func(w http.ResponseWriter, r *http.Request, err error) {
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
		a := verificationAttemptFor(r)
		a.out.Verified, a.out.Proof, a.out.Error = false, nil, f.code
		writeVerificationResponse(w, f.status, a.out)
	}
	pipeline, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[VerificationState]{MaximumDuration: c.MaximumDuration, Middleware: middleware, Reject: reject,
		Decode: func(r *http.Request) (VerificationState, error) {
			s := VerificationState{attempt: verificationAttemptFor(r)}
			if r.URL.Path != "/v1/password/verify" || r.URL.EscapedPath() != r.URL.Path {
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
				if strings.EqualFold(name, "X-CSRF-Token") {
					return s, identityhttp.ErrInvalidInput
				}
			}
			var present bool
			var err error
			s.bearer, present, err = decoder.Bearer(r, identityhttp.HeaderRequired)
			if err != nil || !present {
				return s, identityhttp.ErrInvalidInput
			}
			token, err := session.ParseToken(s.bearer.Token())
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.credential, err = session.NewCredential(session.CredentialBearer, token)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			// The credential decoder validates framing before host resolution,
			// so malformed/duplicate headers are invalid input, not a host error.
			facts, err := network.Resolve(r)
			if err != nil || facts.Realm() != identityhttp.RealmTenant {
				return s, failure{status: 421, code: "misdirected_request"}
			}
			if facts.Scheme() != "https" {
				return s, identityhttp.ErrInvalidInput
			}
			s.facts = facts
			if devices != nil {
				device, found, err := decoder.AuxiliaryCookieBearer(r, "__Host-identity_device", identityhttp.HeaderRequired)
				if err != nil || !found {
					return s, identityhttp.ErrInvalidInput
				}
				s.device, err = devices.Resolve(r.Context(), c.Now(), facts.TenantID(), facts.Origin(), device.Token())
				if err != nil {
					return s, identityhttp.ErrInvalidInput
				}
			}
			body, err := identityhttp.DecodeJSON[map[string]json.RawMessage](decoder, r)
			if err != nil || len(body) != 4 {
				return s, identityhttp.ErrInvalidInput
			}
			var value, purpose, action, audience string
			for name, dst := range map[string]*string{"password": &value, "purpose": &purpose, "action": &action, "audience": &audience} {
				raw, ok := body[name]
				if !ok || string(raw) == "null" || json.Unmarshal(raw, dst) != nil {
					return s, identityhttp.ErrInvalidInput
				}
			}
			s.target = password.VerificationTarget{Purpose: auth.Purpose(purpose), Action: action, Audience: audience}
			if len(value) == 0 || len(value) > 1<<20 || s.target.Validate() != nil {
				return s, identityhttp.ErrInvalidInput
			}
			raw := []byte(value)
			secret, err := primitive.NewSecret(raw)
			clear(raw)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.attempt.secret = secret
			return s, nil
		},
		Authenticate: func(r *http.Request, s VerificationState) (VerificationState, error) {
			read, err := c.Sessions.Get(r.Context(), session.GetRequest{TenantID: s.facts.TenantID(), Credential: s.credential})
			if err != nil {
				return s, identityhttp.ErrUnavailable
			}
			if !read.Authenticated {
				return s, failure{status: 401, code: "denied"}
			}
			if read.ValidateAt(c.Now()) != nil {
				return s, identityhttp.ErrUnavailable
			}
			b, err := read.Session.Bindings()
			if err != nil || b.TenantID != s.facts.TenantID() {
				return s, identityhttp.ErrUnavailable
			}
			s.read, s.user = read, b.UserID
			return s, nil
		},
		Admit: func(r *http.Request, s VerificationState) error {
			out, err := c.Rate.Admit(r.Context(), s.facts, identityhttp.PasswordVerificationRateRequest{UserID: s.user})
			if errors.Is(err, identityhttp.ErrRateLimited) {
				return failure{status: 429, code: "rate_limited", retry: out.RetryAfter}
			}
			if err != nil || !out.Allowed || s.read.ValidateAt(c.Now()) != nil || (devices != nil && !s.device.ExpiresAt().After(c.Now())) {
				return identityhttp.ErrUnavailable
			}
			return nil
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s VerificationState) {
			if s.read.ValidateAt(c.Now()) != nil || (devices != nil && !s.device.ExpiresAt().After(c.Now())) {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			caller := authorization.DecisionContext{PolicyRevision: c.PolicyRevision, Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(s.user)}, Tenant: authorization.TenantID(s.facts.TenantID()), Action: "identity.password.verify", Resource: authorization.Resource{Type: "identity.request-admission", ID: "identity.password.verify"}}}
			s.attempt.attempted = true
			result, err := c.Verification.Verify(r.Context(), password.VerificationRequest{TenantID: s.facts.TenantID(), Session: s.bearer, Password: s.attempt.secret, Target: s.target, Caller: caller, Network: s.facts.ClientIP().String(), Device: s.device.DeviceID()})
			if !verificationObservation(s, result) {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			if err != nil || r.Context().Err() != nil {
				f := failure{status: 503, code: "unavailable"}
				var denied identity.ForbiddenError
				if r.Context().Err() == nil && errors.As(err, &denied) {
					f = failure{status: 403, code: "denied"}
				}
				reject(w, r, f)
				return
			}
			if result.Proof == (auth.ReauthenticationProof{}) && result.Outcome == identity.CommitOutcomeInvalid {
				reject(w, r, failure{status: 403, code: "denied"})
				return
			}
			now := c.Now()
			b, bindingErr := s.read.Session.Bindings()
			use := auth.ReauthenticationUse{ProofUse: auth.ProofUse{Tenant: string(s.facts.TenantID()), Subject: string(s.user), Purpose: s.target.Purpose, Audience: s.target.Audience, Now: now}, SessionID: b.SessionID, SessionVersion: b.Version, Action: s.target.Action, MaximumAge: 15 * time.Minute}
			if bindingErr != nil || s.read.ValidateAt(now) != nil || (devices != nil && !s.device.ExpiresAt().After(now)) || result.Outcome != identity.CommitOutcomeCommitted || result.Proof.Validate(use) != nil || result.Proof.Proof.Method != "password" || result.Proof.Proof.Assurance != auth.AssuranceSingleFactor || result.Proof.Proof.ExpiresAt.Sub(result.Proof.Proof.IssuedAt) > 15*time.Minute || string(result.Proof.Proof.ID) != string(result.CommandID) {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			p := result.Proof.Proof
			s.attempt.out.Verified = true
			s.attempt.out.Proof = &VerificationProof{ProofID: string(p.ID), Purpose: string(p.Purpose), Action: result.Proof.Action, Audience: p.Audience, IssuedAt: p.IssuedAt, ExpiresAt: p.ExpiresAt}
			writeVerificationResponse(w, 200, s.attempt.out)
		},
	})
	if err != nil {
		return nil, err
	}
	return &verificationPipeline{pipeline: pipeline}, nil
}

func verificationObservation(s VerificationState, r password.VerificationResult) bool {
	name := "none"
	switch r.Outcome {
	case identity.CommitOutcomeInvalid:
	case identity.CommitOutcomeNotCommitted:
		name = "not_committed"
	case identity.CommitOutcomeCommitted:
		name = "committed"
	case identity.CommitOutcomeUnknown:
		name = "unknown"
	case identity.CommitOutcomeConflict:
		name = "conflict"
	case identity.CommitOutcomeInProgress:
		name = "in_progress"
	default:
		return false
	}
	if r.CommandID != "" {
		if _, err := identity.ParseCommandID(string(r.CommandID)); err != nil {
			return false
		}
	} else if r.Outcome != identity.CommitOutcomeInvalid {
		return false
	}
	s.attempt.out.CommandID, s.attempt.out.CommitOutcome = r.CommandID, name
	return true
}
func verificationAttemptFor(r *http.Request) *verificationAttempt {
	if r != nil {
		if a, ok := r.Context().Value(verificationKey{}).(*verificationAttempt); ok {
			return a
		}
	}
	return &verificationAttempt{out: VerificationResponse{CommitOutcome: "none"}}
}
func writeVerificationResponse(w http.ResponseWriter, status int, out VerificationResponse) {
	data, err := json.Marshal(out)
	if err != nil {
		w.WriteHeader(503)
		return
	}
	w.WriteHeader(status)
	w.Write(append(data, '\n'))
}

type verificationPipeline struct{ pipeline http.Handler }

func (p *verificationPipeline) WithOperationMiddleware(m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if p == nil || p.pipeline == nil {
		return nil, identityhttp.ErrInvalidInput
	}
	h, err := identityhttp.WithOperationMiddleware(p.pipeline, m)
	if err != nil {
		return nil, err
	}
	return &verificationPipeline{pipeline: h}, nil
}
func (p *verificationPipeline) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a := &verificationAttempt{out: VerificationResponse{CommitOutcome: "none"}}
	defer func() { a.secret.Destroy() }()
	r = r.WithContext(context.WithValue(r.Context(), verificationKey{}, a))
	servePasswordPipeline(w, r, p.pipeline)
}
