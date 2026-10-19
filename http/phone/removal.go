package phonehttp

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
	"github.com/faustbrian/go-identity/phone"
	"github.com/faustbrian/go-identity/session"
)

// RemovalService supplies original keyed possession for transport admission and
// the actual protected native mutation. Rate-source output grants no freshness
// or authority; Remove must repeat its current checks in the owning transaction.
type RemovalService interface {
	phone.RemovalService
	phone.RemovalRateSource
}

// RemovalConfig independently selects cookie-only phone self-removal. Owners
// remain borrowed, bounded and concurrent-safe. Proofs retains the original
// signed action/session record; Service authenticates signature, original
// bearer/CSRF, recovery policy and current authority. No transport session
// lookup, OTP, bearer-header fallback or administrative target is selected.
// MaximumDuration is explicit, 1ms..30s. Construction performs no IO.
type RemovalConfig struct {
	Network         identityhttp.NetworkConfig
	Proofs          auth.ReauthenticationSource
	Service         RemovalService
	Rate            *identityhttp.KeyedSecretRateLimiter
	NumberPolicy    *phone.NumberPolicy
	Cookie          session.CookiePolicy
	Origin          identityhttp.Origin
	PolicyRevision  authorization.Revision
	MaximumDuration time.Duration
}

// RemovalResponse is an explicit credential-free outcome projection. Removed
// means committed local removal, not completed downstream cleanup or SMS sending.
// Unknown is not rollback: preserve exact key/input or recover natively.
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
	spec    phone.RemoveRequestSpec
	request phone.RemoveRequest
}
type removalResponseKey struct{}

func removalResponse(r *http.Request) *RemovalResponse {
	if out, ok := r.Context().Value(removalResponseKey{}).(*RemovalResponse); ok && out != nil {
		return out
	}
	return &RemovalResponse{CommitOutcome: "none"}
}

// NewRemovalHandler selects POST /v1/phone/remove only. Exact cookie/Origin,
// X-CSRF-Token and one Idempotency-Key header are required. Closed JSON contains
// number, identifierID, expectedIdentifierVersion, expectedVerificationVersion,
// proofID and reason. Versions are canonical positive decimal strings, never
// lossy JSON numbers. User/tenant, OTP, request-key and command overrides deny.
func NewRemovalHandler(c RemovalConfig) (http.Handler, error) { return newRemovalHandler(c, nil) }

func newRemovalHandler(c RemovalConfig, m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if nilOwner(c.Proofs) || nilOwner(c.Service) || !c.Rate.Configured() || c.NumberPolicy == nil || c.NumberPolicy.Profile() != phone.CurrentNumberProfile() || c.PolicyRevision == 0 || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second {
		return nil, identityhttp.ErrInvalidInput
	}
	policy := *c.NumberPolicy
	c.NumberPolicy = &policy
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
	const action = "identity.phone.remove"
	reject := func(w http.ResponseWriter, r *http.Request, err error) {
		out := removalResponse(r)
		out.Removed = false
		f := failure{503, "unavailable", 0}
		if errors.Is(err, identityhttp.ErrInvalidInput) || errors.Is(err, phone.ErrInvalidRemoval) {
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
			if r.URL.Path != "/v1/phone/remove" || r.URL.EscapedPath() != r.URL.Path {
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
			s.spec.Session, _, err = decoder.CookieBearer(r, cookie.Name, identityhttp.HeaderRequired)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			if _, err := session.ParseToken(s.spec.Session.Token()); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.spec.IdempotencyKey, _, err = decoder.IdempotencyKey(r, identityhttp.HeaderRequired)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.spec.CSRFToken, _, err = identityhttp.DecodeCSRF(csrf, r, session.ParseCSRFToken)
			if err != nil {
				return s, failure{403, "origin_or_csrf_denied", 0}
			}
			fields, err := identityhttp.DecodeJSON[map[string]json.RawMessage](decoder, r)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			proof, spec, err := decodeRemovalBody(r.Context(), c.NumberPolicy, fields)
			if err != nil {
				return s, err
			}
			s.proofID = proof
			s.spec.Number, s.spec.IdentifierID, s.spec.Reason = spec.Number, spec.IdentifierID, spec.Reason
			s.spec.ExpectedIdentifierVersion, s.spec.ExpectedVerificationVersion = spec.ExpectedIdentifierVersion, spec.ExpectedVerificationVersion
			s.spec.TenantID, s.spec.Network = s.facts.TenantID(), s.facts.ClientIP().String()
			return s, nil
		},
		Authenticate: func(r *http.Request, s removalState) (removalState, error) {
			record, err := c.Proofs.Reauthentication(r.Context(), s.proofID)
			if r.Context().Err() != nil || err != nil && !errors.Is(err, auth.ErrInvalidProof) {
				return s, identityhttp.ErrUnavailable
			}
			if err != nil || record.Proof.Proof.ID != s.proofID || record.Proof.Proof.Tenant != string(s.spec.TenantID) {
				return s, failure{403, "denied", 0}
			}
			s.spec.Proof, s.spec.UserID = record.Proof, identity.UserID(record.Proof.Proof.Subject)
			s.spec.Caller = authorization.DecisionContext{PolicyRevision: c.PolicyRevision, Request: authorization.Request{Tenant: authorization.TenantID(s.spec.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(s.spec.UserID)}, Action: action, Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(s.spec.UserID)}}}
			s.request, err = phone.NewRemoveRequest(s.spec)
			if err != nil {
				return s, failure{403, "denied", 0}
			}
			actual, err := c.Service.RemovalRateSource(r.Context(), s.request)
			if err != nil {
				return s, removalOwnerError(err)
			}
			if actual == "" || actual != s.spec.UserID {
				return s, identityhttp.ErrUnavailable
			}
			return s, nil
		},
		Admit: func(r *http.Request, s removalState) error {
			out, err := c.Rate.Admit(r.Context(), s.facts, identityhttp.KeyedSecretRateRequest{OperationID: action, UserID: s.spec.UserID, IdempotencyKey: s.spec.IdempotencyKey})
			return rateError(out, err)
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s removalState) {
			out := removalResponse(r)
			out.CommitOutcome = "unknown"
			result, err := c.Service.Remove(r.Context(), s.request)
			b := result.Binding
			if result.Outcome != identity.CommitOutcomeInvalid {
				if result.Validate() != nil || b.OperationID != action || b.SchemaID != action+".native-v1" || b.SchemaVersion != 1 || b.TenantID != s.spec.TenantID || b.UserID != s.spec.UserID || b.ActorID != identity.ActorID(s.spec.UserID) || b.ActorKind != authorization.SubjectUser || b.RecordID != string(s.spec.IdentifierID) {
					reject(w, r, identityhttp.ErrUnavailable)
					return
				}
				out.CommandID = b.CommandID
				switch result.Outcome {
				case identity.CommitOutcomeCommitted:
					out.CommitOutcome = "committed"
				case identity.CommitOutcomeNotCommitted:
					out.CommitOutcome = "not_committed"
				case identity.CommitOutcomeConflict:
					out.CommitOutcome = "conflict"
				case identity.CommitOutcomeInProgress:
					out.CommitOutcome = "in_progress"
				default:
					out.CommitOutcome = "unknown"
				}
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
				reject(w, r, removalOwnerError(err))
				return
			}
			if result.Outcome != identity.CommitOutcomeCommitted || result.Cascade == nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			out.Removed, out.CascadeID, out.CascadeGeneration, out.CascadeStatus = true, result.Cascade.CascadeID, result.Cascade.Generation, "pending"
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(out)
		},
	})
	if err != nil {
		return nil, err
	}
	return &removalHandler{pipeline: pipeline}, nil
}

func decodeRemovalBody(ctx context.Context, p *phone.NumberPolicy, fields map[string]json.RawMessage) (auth.ProofID, phone.RemoveRequestSpec, error) {
	invalid := identityhttp.ErrInvalidInput
	var out phone.RemoveRequestSpec
	if ctx == nil || p == nil || len(fields) != 6 {
		return "", out, invalid
	}
	values := make(map[string]string, 6)
	for _, name := range []string{"number", "identifierID", "expectedIdentifierVersion", "expectedVerificationVersion", "proofID", "reason"} {
		var value string
		if json.Unmarshal(fields[name], &value) != nil || value == "" || len(value) > 128 {
			return "", out, invalid
		}
		values[name] = value
	}
	if _, err := identity.ParseCommandID(values["proofID"]); err != nil {
		return "", out, invalid
	}
	id, err := identity.ParseIdentifierID(values["identifierID"])
	if err != nil {
		return "", out, invalid
	}
	out.IdentifierID = id
	parse := func(value string) (uint64, error) {
		n, err := strconv.ParseUint(value, 10, 64)
		if err != nil || n == 0 || n == ^uint64(0) || strconv.FormatUint(n, 10) != value {
			return 0, invalid
		}
		return n, nil
	}
	out.ExpectedIdentifierVersion, err = parse(values["expectedIdentifierVersion"])
	if err != nil {
		return "", out, err
	}
	out.ExpectedVerificationVersion, err = parse(values["expectedVerificationVersion"])
	if err != nil {
		return "", out, err
	}
	out.Number, err = p.Canonicalize(ctx, values["number"])
	if err != nil {
		return "", out, invalid
	}
	out.Reason = identity.PolicyReason(values["reason"])
	return auth.ProofID(values["proofID"]), out, nil
}

func removalOwnerError(err error) error {
	var conflict identity.ConflictError
	var forbidden identity.ForbiddenError
	var last identity.FinalAccessError
	var invalid identity.InvalidInputError
	switch {
	case errors.As(err, &conflict):
		return failure{409, "conflict", 0}
	case errors.As(err, &forbidden), errors.As(err, &last):
		return failure{403, "denied", 0}
	case errors.As(err, &invalid), errors.Is(err, phone.ErrInvalidRemoval):
		return identityhttp.ErrInvalidInput
	default:
		return identityhttp.ErrUnavailable
	}
}

type removalHandler struct{ pipeline http.Handler }

func (h *removalHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	r = r.WithContext(context.WithValue(r.Context(), removalResponseKey{}, &RemovalResponse{CommitOutcome: "none"}))
	h.pipeline.ServeHTTP(w, r)
}
func (h *removalHandler) WithOperationMiddleware(m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if h == nil || h.pipeline == nil {
		return nil, identityhttp.ErrInvalidInput
	}
	p, err := identityhttp.WithOperationMiddleware(h.pipeline, m)
	if err != nil {
		return nil, err
	}
	return &removalHandler{pipeline: p}, nil
}

// Format redacts borrowed proof/service/rate owners and deployment configuration.
func (RemovalConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("phonehttp.RemovalConfig(redacted)"))
}

// MarshalJSON denies implicit runtime configuration export.
func (RemovalConfig) MarshalJSON() ([]byte, error) { return nil, phone.ErrVerificationDisclosure }

// MarshalText denies implicit runtime configuration export.
func (RemovalConfig) MarshalText() ([]byte, error) { return nil, phone.ErrVerificationDisclosure }
func (removalState) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("phonehttp.removalState(redacted)"))
}
func (removalState) MarshalJSON() ([]byte, error) { return nil, phone.ErrVerificationDisclosure }
func (removalState) MarshalText() ([]byte, error) { return nil, phone.ErrVerificationDisclosure }
