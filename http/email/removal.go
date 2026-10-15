package emailhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
)

// RemovalService authenticates original request possession for shared secret
// admission, then independently fences current authority and all atomic native
// effects. Rate-source metadata is neither a freshness lease nor permission.
type RemovalService interface {
	email.AddressRemovalService
	email.AddressRemovalRateSource
}

// RemovalConfig selects cookie-only human self-removal. Original signed proof
// records must remain available through request retention. Native Service owns
// signature, cookie/CSRF, current factor/recovery authority and mutation. All
// owners are borrowed, concurrent-safe and bounded; no session lookup/issuance
// fallback is allowed. MaximumDuration is 1ms..30s. Construction performs no IO.
type RemovalConfig struct {
	Network         identityhttp.NetworkConfig
	Proofs          auth.ReauthenticationSource
	Service         RemovalService
	Rate            *identityhttp.KeyedSecretRateLimiter
	Cookie          session.CookiePolicy
	Origin          identityhttp.Origin
	PolicyRevision  authorization.Revision
	MaximumDuration time.Duration
}

// RemovalResponse exposes original outcome and pending cascade correlation only.
// Removed means committed local removal, not acknowledged asynchronous cleanup.
// Unknown is not rollback. No credential, mailbox, actor or replacement command
// is disclosed; retry the exact original key/input or use native scoped recovery.
type RemovalResponse struct {
	Removed           bool               `json:"removed"`
	CommandID         identity.CommandID `json:"commandID,omitempty"`
	CommitOutcome     string             `json:"commitOutcome"`
	CascadeID         identity.CascadeID `json:"cascadeID,omitempty"`
	CascadeGeneration uint64             `json:"cascadeGeneration,omitempty"`
	CascadeStatus     string             `json:"cascadeStatus,omitempty"`
	Error             string             `json:"error,omitempty"`
}

type removalState struct {
	facts   identityhttp.NetworkFacts
	proofID auth.ProofID
	request email.AddressRemoveRequest
}
type removalAttemptKey struct{}

func removalAttempt(r *http.Request) *RemovalResponse {
	if out, ok := r.Context().Value(removalAttemptKey{}).(*RemovalResponse); ok && out != nil {
		return out
	}
	return &RemovalResponse{CommitOutcome: "none"}
}

// NewAddressRemoveHandler selects POST /v1/email/address-remove with exactly one
// original proofID, target, canonical decimal version strings, registered reason
// and explicit supported primary/recovery disposition. Cookie, exact Origin,
// stored X-CSRF-Token and Idempotency-Key are mandatory. Body authority overrides,
// duplicate/unknown fields, query/trailers and bearer fallback deny. This handler
// neither issues authentication nor exposes a recovery endpoint.
func NewAddressRemoveHandler(c RemovalConfig) (http.Handler, error) {
	return newAddressRemoveHandler(c, nil)
}

func newAddressRemoveHandler(c RemovalConfig, m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if nilService(c.Proofs) || nilService(c.Service) || !c.Rate.Configured() || c.PolicyRevision == 0 || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second {
		return nil, identityhttp.ErrInvalidInput
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
	origins, err := identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{Network: network, TrustedOrigins: []identityhttp.Origin{c.Origin}, RefererFallback: identityhttp.RefererFallbackDeny})
	if err != nil {
		return nil, err
	}
	csrf, err := identityhttp.NewCSRFDecoder(identityhttp.CSRFDecoderConfig{Origins: origins, FormField: "csrf_token"})
	if err != nil {
		return nil, err
	}
	const action = "identity.email.address-remove"
	reject := func(w http.ResponseWriter, r *http.Request, err error) {
		out := removalAttempt(r)
		out.Removed = false
		f := failure{503, "unavailable", 0}
		if errors.Is(err, identityhttp.ErrInvalidInput) || errors.Is(err, email.ErrInvalidRemoval) {
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
		out.Error = f.code
		w.WriteHeader(f.status)
		_ = json.NewEncoder(w).Encode(out)
	}
	pipeline, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[removalState]{MaximumDuration: c.MaximumDuration, Middleware: m, Reject: reject,
		Decode: func(r *http.Request) (s removalState, err error) {
			if r.URL.Path != "/v1/email/address-remove" || r.URL.EscapedPath() != r.URL.Path {
				return s, failure{404, "not_found", 0}
			}
			if r.Method != http.MethodPost {
				return s, failure{405, "method_not_allowed", 0}
			}
			if r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Trailer) != 0 {
				return s, identityhttp.ErrInvalidInput
			}
			s.facts, err = network.Resolve(r)
			if err != nil || s.facts.Realm() != identityhttp.RealmTenant {
				return s, failure{421, "misdirected_request", 0}
			}
			if s.facts.Scheme() != "https" {
				return s, failure{403, "https_required", 0}
			}
			if _, _, err := decoder.Bearer(r, identityhttp.HeaderForbidden); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.request.Primary.Session, _, err = decoder.CookieBearer(r, cookie.Name, identityhttp.HeaderRequired)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			if _, err := session.ParseToken(s.request.Primary.Session.Token()); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.request.IdempotencyKey, _, err = decoder.IdempotencyKey(r, identityhttp.HeaderRequired)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.request.Primary.CSRFToken, _, err = identityhttp.DecodeCSRF(csrf, r, session.ParseCSRFToken)
			if err != nil {
				return s, failure{403, "origin_or_csrf_denied", 0}
			}
			fields, err := identityhttp.DecodeJSON[map[string]json.RawMessage](decoder, r)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.proofID, err = decodeRemovalFields(fields, &s.request)
			if err != nil {
				return s, err
			}
			s.request.TenantID, s.request.Network = s.facts.TenantID(), s.facts.ClientIP().String()
			return s, nil
		},
		Authenticate: func(r *http.Request, s removalState) (removalState, error) {
			record, err := c.Proofs.Reauthentication(r.Context(), s.proofID)
			if r.Context().Err() != nil || err != nil && !errors.Is(err, auth.ErrInvalidProof) {
				return s, identityhttp.ErrUnavailable
			}
			if err != nil || record.Proof.Proof.ID != s.proofID || record.Proof.Proof.Tenant != string(s.request.TenantID) {
				return s, failure{403, "denied", 0}
			}
			s.request.Primary.Proof = record.Proof
			user := identity.UserID(record.Proof.Proof.Subject)
			s.request.Caller = authorization.DecisionContext{PolicyRevision: c.PolicyRevision, Request: authorization.Request{Tenant: authorization.TenantID(s.request.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(user)}, Action: action, Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(user)}}}
			if s.request.Validate() != nil {
				return s, failure{403, "denied", 0}
			}
			actual, err := c.Service.AddressRemoveRateSource(r.Context(), s.request)
			if err != nil {
				return s, requestOwnerFailure(err)
			}
			if actual != user || user == "" {
				return s, identityhttp.ErrUnavailable
			}
			return s, nil
		},
		Admit: func(r *http.Request, s removalState) error {
			out, err := c.Rate.Admit(r.Context(), s.facts, identityhttp.KeyedSecretRateRequest{OperationID: action, UserID: identity.UserID(s.request.Caller.Request.Subject.ID), IdempotencyKey: s.request.IdempotencyKey})
			return rateFailure(out, err)
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s removalState) {
			out := removalAttempt(r)
			out.CommitOutcome = "unknown"
			result, err := c.Service.AddressRemove(r.Context(), s.request)
			b := result.Binding
			if result.Outcome != identity.CommitOutcomeInvalid {
				if result.Validate() != nil || b.OperationID != action || b.SchemaID != action+".native-v1" || b.SchemaVersion != 1 || b.TenantID != s.request.TenantID || b.UserID != identity.UserID(s.request.Caller.Request.Subject.ID) || b.ActorID != identity.ActorID(b.UserID) || b.ActorKind != authorization.SubjectUser || b.RecordID != string(s.request.AddressID) {
					reject(w, r, identityhttp.ErrUnavailable)
					return
				}
				out.CommandID = b.CommandID
				out.CommitOutcome = outcome(result.Outcome)
			}
			if r.Context().Err() != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			if result.Outcome == identity.CommitOutcomeInProgress {
				reject(w, r, failure{409, "in_progress", result.RetryAfter})
				return
			}
			if result.Outcome == identity.CommitOutcomeConflict {
				reject(w, r, failure{409, "conflict", 0})
				return
			}
			if err != nil {
				reject(w, r, requestOwnerFailure(err))
				return
			}
			if result.Outcome != identity.CommitOutcomeCommitted || result.Cascade == nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			out.Removed, out.CascadeID, out.CascadeGeneration, out.CascadeStatus = true, result.Cascade.CascadeID, result.Cascade.Generation, "pending"
			w.WriteHeader(200)
			_ = json.NewEncoder(w).Encode(out)
		},
	})
	if err != nil {
		return nil, err
	}
	return &confirmationPipeline{pipeline: &removalPipeline{pipeline: pipeline}}, nil
}

func decodeRemovalFields(fields map[string]json.RawMessage, r *email.AddressRemoveRequest) (auth.ProofID, error) {
	invalid := identityhttp.ErrInvalidInput
	if len(fields) != 7 {
		return "", invalid
	}
	values := map[string]*string{}
	var proof, id, version, verification, reason, primary, recovery string
	values["proofID"], values["addressID"], values["expectedIdentifierVersion"], values["expectedVerificationVersion"], values["reason"], values["primaryDisposition"], values["recoveryDisposition"] = &proof, &id, &version, &verification, &reason, &primary, &recovery
	for name, out := range values {
		if !readString(fields, name, out) {
			return "", invalid
		}
	}
	if _, err := identity.ParseCommandID(proof); err != nil {
		return "", invalid
	}
	target, err := identity.ParseIdentifierID(id)
	if err != nil {
		return "", invalid
	}
	parse := func(v string) (uint64, error) {
		n, e := strconv.ParseUint(v, 10, 64)
		if e != nil || n == 0 || n == ^uint64(0) || strconv.FormatUint(n, 10) != v {
			return 0, invalid
		}
		return n, nil
	}
	r.AddressID = target
	r.Reason = identity.PolicyReason(reason)
	r.ExpectedIdentifierVersion, err = parse(version)
	if err != nil {
		return "", err
	}
	r.ExpectedVerificationVersion, err = parse(verification)
	if err != nil {
		return "", err
	}
	switch primary {
	case "preserve-primary":
		r.PrimaryDisposition = email.PreserveRemainingPrimary
	case "leave-unassigned":
		r.PrimaryDisposition = email.LeavePrimaryUnassigned
	default:
		return "", invalid
	}
	if recovery != "preserve-verified-email" {
		return "", invalid
	}
	r.RecoveryDisposition = email.PreserveVerifiedEmailRecovery
	if len(reason) > 64 {
		return "", invalid
	}
	return auth.ProofID(proof), nil
}

type removalPipeline struct{ pipeline http.Handler }

func (p *removalPipeline) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r = r.WithContext(context.WithValue(r.Context(), removalAttemptKey{}, &RemovalResponse{CommitOutcome: "none"}))
	p.pipeline.ServeHTTP(w, r)
}
func (p *removalPipeline) WithOperationMiddleware(m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if p == nil || p.pipeline == nil {
		return nil, identityhttp.ErrInvalidInput
	}
	h, e := identityhttp.WithOperationMiddleware(p.pipeline, m)
	if e != nil {
		return nil, e
	}
	return &removalPipeline{pipeline: h}, nil
}

// Format redacts runtime proof, policy and key custody.
func (RemovalConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("emailhttp.RemovalConfig(redacted)"))
}

// MarshalJSON refuses implicit configuration export.
func (RemovalConfig) MarshalJSON() ([]byte, error) { return nil, email.ErrSensitiveSerialization }

// MarshalText refuses implicit configuration export.
func (RemovalConfig) MarshalText() ([]byte, error) { return nil, email.ErrSensitiveSerialization }

// LogValue exposes only a constant marker.
func (RemovalConfig) LogValue() slog.Value {
	return slog.StringValue("emailhttp.RemovalConfig(redacted)")
}

func (removalState) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("emailhttp.removalState(redacted)"))
}
func (removalState) MarshalJSON() ([]byte, error) { return nil, email.ErrSensitiveSerialization }
func (removalState) MarshalText() ([]byte, error) { return nil, email.ErrSensitiveSerialization }
func (removalState) LogValue() slog.Value {
	return slog.StringValue("emailhttp.removalState(redacted)")
}
