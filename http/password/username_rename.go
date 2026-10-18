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
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
	"github.com/faustbrian/go-identity/username"
)

// UsernameRenameService combines the existing native mutation/recovery owner
// and original-custody source used before transport subject-rate admission.
type UsernameRenameService interface {
	username.RenameService
	username.RenameRateSource
}

// UsernameRenameConfig explicitly selects cookie/password-proof self rename.
// Proofs reads the original committed signed verification; Service independently
// verifies its signature and original request custody before rate admission and
// current authority/MFA/CSRF atomically with mutation. No current session read
// precedes original-key resolution: rename invalidates identifier-bound sessions
// while exact historical retries must remain recoverable without renewal.
// Owners are borrowed/concurrent-safe. Rate is shared, PolicyRevision trusted,
// MaximumDuration 1ms..30s; earlier deadlines win. Construction performs no IO.
type UsernameRenameConfig struct {
	Network         identityhttp.NetworkConfig
	Service         UsernameRenameService
	Proofs          auth.ReauthenticationSource
	Rate            *identityhttp.KeyedSecretRateLimiter
	Cookie          session.CookiePolicy
	TrustedOrigins  []identityhttp.Origin
	PolicyRevision  authorization.Revision
	MaximumDuration time.Duration
}

// UsernameRenameResponse is credential-free original command metadata. Recovery
// is only a lookup scope, not authority. Error/unknown outcomes never assert a
// successful mutation or authorize automatic retry with replacement input.
type UsernameRenameResponse struct {
	Changed           bool                    `json:"changed"`
	CommandID         identity.CommandID      `json:"commandID,omitempty"`
	CommitOutcome     string                  `json:"commitOutcome"`
	IdentifierVersion uint64                  `json:"identifierVersion,omitempty"`
	Recovery          *identity.RecoveryQuery `json:"recovery,omitempty"`
	Error             string                  `json:"error,omitempty"`
}

// MarshalJSON uses the existing closed self-command recovery wire projection.
func (r UsernameRenameResponse) MarshalJSON() ([]byte, error) {
	base, err := json.Marshal(ChangeResponse{Changed: r.Changed, CommandID: r.CommandID, CommitOutcome: r.CommitOutcome, Recovery: r.Recovery, Error: r.Error})
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(base, &fields); err != nil {
		return nil, err
	}
	if r.IdentifierVersion != 0 {
		fields["identifierVersion"], err = json.Marshal(r.IdentifierVersion)
	}
	if err != nil {
		return nil, err
	}
	return json.Marshal(fields)
}

type usernameRenameAttempt struct {
	out       UsernameRenameResponse
	attempted bool
}
type usernameRenameKey struct{}

type usernameRenameInput struct {
	ProofID                     string                `json:"proofID"`
	IdentifierID                identity.IdentifierID `json:"identifierID"`
	ExpectedIdentifierVersion   uint64                `json:"expectedIdentifierVersion"`
	ExpectedVerificationVersion uint64                `json:"expectedVerificationVersion"`
	Username                    string                `json:"username"`
}

// UsernameRenameState retains private synchronous request custody, not reusable
// authority. Middleware must not retain it beyond the bounded request.
type UsernameRenameState struct {
	facts   identityhttp.NetworkFacts
	request username.RenameRequest
	proofID auth.ProofID
	attempt *usernameRenameAttempt
}

// NewUsernameRenameHandler selects only POST /v1/username/update. Closed JSON
// carries proofID, identifierID, expectedIdentifierVersion,
// expectedVerificationVersion and username. Exact original key/cookie/CSRF and
// trusted HTTPS Origin are required; no caller-selected user, tenant or proof.
func NewUsernameRenameHandler(c UsernameRenameConfig) (http.Handler, error) {
	return NewUsernameRenameHandlerWithMiddleware(c, nil)
}

// NewUsernameRenameHandlerWithMiddleware preserves original signed custody
// before shared rate admission and native mutation, without another proof engine.
func NewUsernameRenameHandlerWithMiddleware(c UsernameRenameConfig, m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if nilOwner(c.Service) || nilOwner(c.Proofs) || !c.Rate.Configured() || c.PolicyRevision == 0 || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second {
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
	cookie, err := c.Cookie.DeletionAttributes()
	if err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	origin, err := identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{Network: network, TrustedOrigins: c.TrustedOrigins, RefererFallback: identityhttp.RefererFallbackDeny})
	if err != nil {
		return nil, err
	}
	csrf, err := identityhttp.NewCSRFDecoder(identityhttp.CSRFDecoderConfig{Origins: origin, FormField: "csrf_token"})
	if err != nil {
		return nil, err
	}
	reject := func(w http.ResponseWriter, r *http.Request, err error) {
		f := failure{status: 503, code: "unavailable"}
		var specific failure
		var denied identity.ForbiddenError
		var conflict identity.ConflictError
		var busy identity.InProgressError
		switch {
		case errors.As(err, &specific):
			f = specific
		case errors.As(err, &denied), errors.Is(err, auth.ErrInvalidProof), errors.Is(err, username.ErrDenied):
			f = failure{status: 403, code: "denied"}
		case errors.Is(err, identityhttp.ErrInvalidInput), errors.Is(err, username.ErrInvalid):
			f = failure{status: 400, code: "invalid_request"}
		case errors.As(err, &conflict):
			f = failure{status: 409, code: "conflict"}
		case errors.As(err, &busy):
			f = failure{status: 409, code: "in_progress"}
		}
		if f.status == 405 {
			w.Header().Set("Allow", http.MethodPost)
		}
		if f.retry > 0 {
			w.Header().Set("Retry-After", strconv.FormatInt(int64((min(max(f.retry, time.Second), time.Minute)+time.Second-1)/time.Second), 10))
		}
		out := usernameRenameAttemptFor(r).out
		out.Changed = false
		out.IdentifierVersion = 0
		out.Error = f.code
		w.WriteHeader(f.status)
		_ = json.NewEncoder(w).Encode(out)
	}
	pipeline, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[UsernameRenameState]{MaximumDuration: c.MaximumDuration, Middleware: m, Reject: reject,
		Decode: func(r *http.Request) (UsernameRenameState, error) {
			s := UsernameRenameState{attempt: usernameRenameAttemptFor(r)}
			if r.URL.Path != "/v1/username/update" || r.URL.EscapedPath() != r.URL.Path {
				return s, failure{status: 404, code: "not_found"}
			}
			if r.Method != http.MethodPost {
				return s, failure{status: 405, code: "method_not_allowed"}
			}
			if r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Trailer) != 0 {
				return s, identityhttp.ErrInvalidInput
			}
			facts, err := network.Resolve(r)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			if facts.Realm() != identityhttp.RealmTenant {
				return s, failure{status: 421, code: "misdirected_request"}
			}
			if facts.Scheme() != "https" {
				return s, failure{status: 403, code: "https_required"}
			}
			s.facts = facts
			key, present, err := decoder.IdempotencyKey(r, identityhttp.HeaderRequired)
			if err != nil || !present {
				return s, identityhttp.ErrInvalidInput
			}
			if _, _, err = decoder.Bearer(r, identityhttp.HeaderForbidden); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			bearer, present, err := decoder.CookieBearer(r, cookie.Name, identityhttp.HeaderRequired)
			if err != nil || !present {
				return s, identityhttp.ErrInvalidInput
			}
			if _, err = session.ParseToken(bearer.Token()); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			csrfToken, _, err := identityhttp.DecodeCSRF(csrf, r, session.ParseCSRFToken)
			if err != nil {
				return s, failure{status: 403, code: "origin_or_csrf_denied"}
			}
			body, err := identityhttp.DecodeJSON[usernameRenameInput](decoder, r)
			if err != nil || !visible(body.ProofID, 22, 128) || len(body.Username) == 0 || len(body.Username) > username.MaximumBytes || body.ExpectedIdentifierVersion == 0 || body.ExpectedIdentifierVersion == ^uint64(0) || body.ExpectedVerificationVersion == 0 || body.ExpectedVerificationVersion == ^uint64(0) {
				return s, identityhttp.ErrInvalidInput
			}
			if _, err := identity.ParseIdentifierID(string(body.IdentifierID)); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.proofID = auth.ProofID(body.ProofID)
			s.request = username.RenameRequest{TenantID: facts.TenantID(), IdentifierID: body.IdentifierID, ExpectedIdentifierVersion: body.ExpectedIdentifierVersion, ExpectedVerificationVersion: body.ExpectedVerificationVersion, Username: body.Username, IdempotencyKey: key, Session: bearer, CSRFToken: csrfToken, Network: facts.ClientIP().String()}
			return s, nil
		},
		Authenticate: func(r *http.Request, s UsernameRenameState) (UsernameRenameState, error) {
			record, err := c.Proofs.Reauthentication(r.Context(), s.proofID)
			if err != nil {
				return s, err
			}
			p := record.Proof
			if p.Proof.ID != s.proofID || p.Proof.Tenant != string(s.facts.TenantID()) {
				return s, failure{status: 403, code: "denied"}
			}
			user := identity.UserID(p.Proof.Subject)
			s.request.Proof = p
			s.request.Caller = authorization.DecisionContext{PolicyRevision: c.PolicyRevision, Request: authorization.Request{Tenant: authorization.TenantID(s.facts.TenantID()), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(user)}, Action: "identity.username.update", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(user)}}}
			if s.request.Validate() != nil {
				return s, failure{status: 403, code: "denied"}
			}
			validated, err := c.Service.RenameRateSource(r.Context(), s.request)
			if err != nil {
				return s, err
			}
			if validated != user {
				return s, identityhttp.ErrUnavailable
			}
			return s, nil
		},
		Admit: func(r *http.Request, s UsernameRenameState) error {
			out, err := c.Rate.Admit(r.Context(), s.facts, identityhttp.KeyedSecretRateRequest{OperationID: "identity.username.update", UserID: identity.UserID(s.request.Caller.Request.Subject.ID), IdempotencyKey: s.request.IdempotencyKey})
			if errors.Is(err, identityhttp.ErrRateLimited) {
				return failure{status: 429, code: "rate_limited", retry: out.RetryAfter}
			}
			if err != nil || !out.Allowed {
				return identityhttp.ErrUnavailable
			}
			return nil
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s UsernameRenameState) {
			s.attempt.attempted = true
			result, err := c.Service.Rename(r.Context(), s.request)
			if result.Outcome != identity.CommitOutcomeInvalid || result.Binding.CommandID != "" || result.Feature != nil {
				if !projectUsernameRename(s, result) {
					reject(w, r, identityhttp.ErrUnavailable)
					return
				}
			}
			if r.Context().Err() != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			if err != nil {
				reject(w, r, err)
				return
			}
			if result.Outcome != identity.CommitOutcomeCommitted || result.Feature == nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			s.attempt.out.Changed = true
			s.attempt.out.IdentifierVersion = result.Feature.AfterVersion
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(s.attempt.out)
		},
	})
	if err != nil {
		return nil, err
	}
	return &usernameRenamePipeline{pipeline: pipeline}, nil
}

func projectUsernameRename(s UsernameRenameState, r identity.CommandResult) bool {
	b := r.Binding
	q := s.request
	op := identity.FeatureOperation{Owner: "identity/username", OperationID: "identity.username.update", SchemaID: "identity.username.update.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	if r.Validate() != nil || r.Feature == nil || r.Feature.Operation != op || b.OperationID != op.OperationID || b.TenantID != q.TenantID || b.UserID != identity.UserID(q.Caller.Request.Subject.ID) || b.ActorID != identity.ActorID(b.UserID) || b.ActorKind != authorization.SubjectUser || b.RecordID != string(q.IdentifierID) || r.Outcome == identity.CommitOutcomeCommitted && r.Feature.BeforeVersion != q.ExpectedIdentifierVersion {
		return false
	}
	name := ""
	switch r.Outcome {
	case identity.CommitOutcomeCommitted:
		name = "committed"
	case identity.CommitOutcomeNotCommitted:
		name = "not_committed"
	case identity.CommitOutcomeUnknown:
		name = "unknown"
	case identity.CommitOutcomeConflict:
		name = "conflict"
	case identity.CommitOutcomeInProgress:
		name = "in_progress"
	default:
		return false
	}
	s.attempt.out.CommandID = b.CommandID
	s.attempt.out.CommitOutcome = name
	s.attempt.out.Recovery = &identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
	return true
}

func usernameRenameAttemptFor(r *http.Request) *usernameRenameAttempt {
	if r != nil {
		if a, ok := r.Context().Value(usernameRenameKey{}).(*usernameRenameAttempt); ok {
			return a
		}
	}
	return &usernameRenameAttempt{out: UsernameRenameResponse{CommitOutcome: "none"}}
}

type usernameRenamePipeline struct{ pipeline http.Handler }

func (p *usernameRenamePipeline) WithOperationMiddleware(m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if p == nil || p.pipeline == nil {
		return nil, identityhttp.ErrInvalidInput
	}
	h, err := identityhttp.WithOperationMiddleware(p.pipeline, m)
	if err != nil {
		return nil, err
	}
	return &usernameRenamePipeline{h}, nil
}
func (p *usernameRenamePipeline) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a := &usernameRenameAttempt{out: UsernameRenameResponse{CommitOutcome: "none"}}
	r = r.WithContext(context.WithValue(r.Context(), usernameRenameKey{}, a))
	servePasswordPipeline(w, r, p.pipeline)
}

// Format redacts borrowed configuration and original request custody.
func (UsernameRenameConfig) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "passwordhttp.UsernameRenameConfig(redacted)")
}

// LogValue redacts borrowed configuration.
func (UsernameRenameConfig) LogValue() slog.Value {
	return slog.StringValue("passwordhttp.UsernameRenameConfig(redacted)")
}

// MarshalJSON refuses implicit configuration export.
func (UsernameRenameConfig) MarshalJSON() ([]byte, error) { return nil, username.ErrDisclosure }

// MarshalText refuses implicit configuration export.
func (UsernameRenameConfig) MarshalText() ([]byte, error) { return nil, username.ErrDisclosure }

// Format redacts original request custody.
func (UsernameRenameState) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "passwordhttp.UsernameRenameState(redacted)")
}

// LogValue redacts original request custody.
func (UsernameRenameState) LogValue() slog.Value {
	return slog.StringValue("passwordhttp.UsernameRenameState(redacted)")
}

// MarshalJSON refuses implicit state export.
func (UsernameRenameState) MarshalJSON() ([]byte, error) { return nil, username.ErrDisclosure }

// MarshalText refuses implicit state export.
func (UsernameRenameState) MarshalText() ([]byte, error) { return nil, username.ErrDisclosure }
