package mfahttp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/session"
)

// RecoveryRegenerateConfig selects native whole-set replacement without route
// registration. Borrowed sessions/proof source/service/rate owners must share
// actual authority, honor bounded contexts and support concurrent use. Proofs
// returns original signed evidence, never renewed projections; Service must
// independently authenticate that evidence and atomically consume it with all
// replacement/session effects. Count must match native policy and is 1..64;
// maximum age is positive and at most five minutes. Trusted
// origins, cookie, revision and prompt Now are immutable startup policy.
type RecoveryRegenerateConfig struct {
	Network         identityhttp.NetworkConfig
	Sessions        *session.SessionService
	Proofs          auth.ReauthenticationSource
	Service         mfa.RecoveryRegenerationService
	Rate            *identityhttp.KeyedSecretRateLimiter
	Cookie          session.CookiePolicy
	TrustedOrigins  []identityhttp.Origin
	PolicyRevision  authorization.Revision
	Now             func() time.Time
	MaximumDuration time.Duration
	MaximumAge      time.Duration
	CodeCount       uint32
}

// Format redacts borrowed authority and configuration.
func (RecoveryRegenerateConfig) Format(s fmt.State, _ rune) {
	io.WriteString(s, "mfahttp.RecoveryRegenerateConfig(redacted)")
}

// MarshalJSON rejects implicit configuration export.
func (RecoveryRegenerateConfig) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText rejects implicit configuration export.
func (RecoveryRegenerateConfig) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// LogValue returns only a fixed marker.
func (RecoveryRegenerateConfig) LogValue() slog.Value {
	return slog.StringValue("mfahttp.RecoveryRegenerateConfig(redacted)")
}

type regenerationState struct {
	enableState
	command  identity.CommandID
	origin   identityhttp.Origin
	request  mfa.RecoveryRegenerateRequest
	lifetime time.Duration
	until    time.Time
}

func (regenerationState) Format(s fmt.State, _ rune) {
	io.WriteString(s, "mfahttp.regenerationState(redacted)")
}
func (regenerationState) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }
func (regenerationState) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }
func (regenerationState) LogValue() slog.Value {
	return slog.StringValue("mfahttp.regenerationState(redacted)")
}

// NewRecoveryRegenerateHandler owns POST /v1/mfa/recovery-regenerate without
// registering it. Closed JSON accepts only commandID/proofID; actual cookie,
// exact HTTPS Origin and native CSRF synchronizer are mandatory. No user/set/
// count/purpose selection, Authorization, Idempotency-Key, query or trailers
// are accepted. Only a fresh error-free known commit reveals codes. Replayed,
// uncertain and cancelled results never redeliver; native recovery is code-free.
func NewRecoveryRegenerateHandler(c RecoveryRegenerateConfig) (http.Handler, error) {
	return NewRecoveryRegenerateHandlerWithMiddleware(c, nil)
}

// NewRecoveryRegenerateHandlerWithMiddleware binds hooks to real cookie/proof
// reads, stable original-command quota admission and protected replacement.
// Mutation intentionally revokes the source session: delivery retains its
// original observation deadline, not a new read or a requirement to revive it.
func NewRecoveryRegenerateHandlerWithMiddleware(c RecoveryRegenerateConfig, m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if !c.Sessions.Configured() || enableNil(c.Proofs) || enableNil(c.Service) || !c.Rate.Configured() || c.Now == nil || c.PolicyRevision == 0 || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || c.MaximumAge <= 0 || c.MaximumAge > 5*time.Minute || c.CodeCount < 1 || c.CodeCount > 64 {
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
	origins, err := identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{Network: network, TrustedOrigins: c.TrustedOrigins, RefererFallback: identityhttp.RefererFallbackDeny})
	if err != nil {
		return nil, err
	}
	csrf, err := identityhttp.NewCSRFDecoder(identityhttp.CSRFDecoderConfig{Origins: origins, FormField: "csrf_token"})
	if err != nil {
		return nil, err
	}
	classify := func(err error) enableFailure {
		var specific enableFailure
		var denied identity.ForbiddenError
		var conflict identity.ConflictError
		var busy identity.InProgressError
		switch {
		case errors.As(err, &specific):
			return specific
		case errors.Is(err, identityhttp.ErrInvalidInput):
			return enableFailure{status: 400, code: "invalid_request"}
		case errors.As(err, &denied), errors.Is(err, auth.ErrInvalidProof):
			return enableFailure{status: 403, code: "denied"}
		case errors.As(err, &conflict):
			return enableFailure{status: 409, code: "conflict"}
		case errors.As(err, &busy):
			return enableFailure{status: 409, code: "in_progress", retry: busy.RetryAfter}
		default:
			return enableFailure{status: 503, code: "unavailable"}
		}
	}
	writeFailure := func(w http.ResponseWriter, f enableFailure, observation map[string]any) {
		if observation == nil {
			observation = map[string]any{"commitOutcome": "none"}
		}
		observation["regenerated"], observation["error"] = false, f.code
		if f.status == 405 {
			w.Header().Set("Allow", http.MethodPost)
		}
		if f.retry > 0 {
			w.Header().Set("Retry-After", strconv.FormatInt(int64((min(max(f.retry, time.Second), time.Hour)+time.Second-1)/time.Second), 10))
		}
		w.WriteHeader(f.status)
		_ = json.NewEncoder(w).Encode(observation)
	}
	reject := func(w http.ResponseWriter, _ *http.Request, err error) { writeFailure(w, classify(err), nil) }
	pipeline, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[regenerationState]{MaximumDuration: c.MaximumDuration, Middleware: m, Reject: reject,
		Decode: func(r *http.Request) (regenerationState, error) {
			s := regenerationState{}
			if r.URL.Path != "/v1/mfa/recovery-regenerate" || r.URL.EscapedPath() != r.URL.Path {
				return s, enableFailure{status: 404, code: "not_found"}
			}
			if r.Method != http.MethodPost {
				return s, enableFailure{status: 405, code: "method_not_allowed"}
			}
			if r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Trailer) != 0 {
				return s, identityhttp.ErrInvalidInput
			}
			facts, err := network.Resolve(r)
			if err != nil || facts.Realm() != identityhttp.RealmTenant {
				return s, enableFailure{status: 421, code: "misdirected_request"}
			}
			if facts.Scheme() != "https" {
				return s, identityhttp.ErrInvalidInput
			}
			s.facts = facts
			if _, _, err := decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			if _, _, err := decoder.Bearer(r, identityhttp.HeaderForbidden); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			var present bool
			s.bearer, present, err = decoder.CookieBearer(r, cookie.Name, identityhttp.HeaderRequired)
			if err != nil || !present {
				return s, identityhttp.ErrInvalidInput
			}
			s.csrf, _, err = identityhttp.DecodeCSRF(csrf, r, session.ParseCSRFToken)
			if err != nil {
				return s, enableFailure{status: 403, code: "origin_or_csrf_denied"}
			}
			s.origin, err = origins.Check(r)
			if err != nil {
				return s, enableFailure{status: 403, code: "origin_or_csrf_denied"}
			}
			token, err := session.ParseToken(s.bearer.Token())
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.credential, err = session.NewCredential(session.CredentialCookie, token)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			body, err := identityhttp.DecodeJSON[map[string]json.RawMessage](decoder, r)
			if err != nil || len(body) != 2 {
				return s, identityhttp.ErrInvalidInput
			}
			var command, proof string
			for name, dst := range map[string]*string{"commandID": &command, "proofID": &proof} {
				if raw, ok := body[name]; !ok || json.Unmarshal(raw, dst) != nil {
					return s, identityhttp.ErrInvalidInput
				}
			}
			s.command, err = identity.ParseCommandID(command)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			id, err := identity.ParseCommandID(proof)
			if err != nil || id == s.command {
				return s, identityhttp.ErrInvalidInput
			}
			s.proofID = auth.ProofID(id)
			return s, nil
		},
		Authenticate: func(r *http.Request, s regenerationState) (regenerationState, error) {
			read, err := c.Sessions.Get(r.Context(), session.GetRequest{TenantID: s.facts.TenantID(), Credential: s.credential})
			if err != nil {
				return s, identityhttp.ErrUnavailable
			}
			if !read.Authenticated {
				return s, enableFailure{status: 401, code: "denied"}
			}
			b, err := read.Session.Bindings()
			if err != nil || b.TenantID != s.facts.TenantID() || read.ValidateAt(c.Now()) != nil {
				return s, identityhttp.ErrUnavailable
			}
			s.read, s.user = read, b.UserID
			record, err := c.Proofs.Reauthentication(r.Context(), s.proofID)
			if err != nil {
				return s, err
			}
			p := record.Proof
			now := c.Now()
			use := auth.ReauthenticationUse{ProofUse: auth.ProofUse{Tenant: string(b.TenantID), Subject: string(b.UserID), Purpose: "identity.mfa.recovery-regenerate", Audience: p.Proof.Audience, Now: now}, SessionID: b.SessionID, SessionVersion: b.Version, Action: "identity.mfa.recovery-regenerate", MaximumAge: c.MaximumAge}
			if p.Proof.ID != s.proofID || p.Validate(use) != nil || s.read.ValidateAt(now) != nil {
				return s, identity.ForbiddenError{}
			}
			caller := authorization.DecisionContext{PolicyRevision: c.PolicyRevision, Request: authorization.Request{Tenant: authorization.TenantID(b.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(b.UserID)}, Action: "identity.mfa.recovery-regenerate", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}}}
			s.request = mfa.RecoveryRegenerateRequest{TenantID: b.TenantID, CommandID: s.command, FactorProof: p.Proof, Session: s.bearer, CSRFToken: s.csrf, Caller: caller, Origin: string(s.origin), Network: s.facts.ClientIP().String()}
			if s.request.Validate() != nil {
				return s, identity.ForbiddenError{}
			}
			s.lifetime = p.Proof.ExpiresAt.Sub(p.Proof.IssuedAt)
			s.until = p.Proof.ExpiresAt
			if freshUntil := p.Proof.IssuedAt.Add(c.MaximumAge); freshUntil.Before(s.until) {
				s.until = freshUntil
			}
			if read.ValidUntil().Before(s.until) {
				s.until = read.ValidUntil()
			}
			if s.lifetime <= 0 || !now.Before(s.until) {
				return s, identity.ForbiddenError{}
			}
			return s, nil
		},
		Admit: func(r *http.Request, s regenerationState) error {
			out, err := c.Rate.AdmitOriginalCommand(r.Context(), s.facts, identityhttp.OriginalCommandSecretRateRequest{OperationID: "identity.mfa.recovery-regenerate", UserID: s.user, CommandID: s.command, ChallengeID: string(s.proofID), ChallengeLifetime: s.lifetime})
			if errors.Is(err, identityhttp.ErrRateLimited) {
				return enableFailure{status: 429, code: "rate_limited", retry: out.RetryAfter}
			}
			if err != nil || !out.Allowed || s.read.ValidateAt(c.Now()) != nil || !c.Now().Before(s.until) {
				return identityhttp.ErrUnavailable
			}
			return nil
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s regenerationState) {
			if s.read.ValidateAt(c.Now()) != nil || !c.Now().Before(s.until) {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			result, err := c.Service.RecoveryRegenerate(r.Context(), s.request)
			defer func() {
				for _, code := range result.RecoveryCodes.Codes {
					code.Destroy()
				}
			}()
			observation := enableObservation(mfa.EnableResult{CommandID: s.command, Outcome: result.Outcome})
			if err != nil || r.Context().Err() != nil {
				writeFailure(w, classify(err), observation)
				return
			}
			if result.Outcome == identity.CommitOutcomeCommitted && result.CommandID == s.command && len(result.RecoveryCodes.Codes) == 0 {
				writeFailure(w, enableFailure{status: 409, code: "replay"}, observation)
				return
			}
			if result.Outcome != identity.CommitOutcomeCommitted || result.CommandID != s.command || len(result.RecoveryCodes.Codes) != int(c.CodeCount) || s.read.ValidateAt(c.Now()) != nil || !c.Now().Before(s.until) {
				writeFailure(w, enableFailure{status: 503, code: "unavailable"}, observation)
				return
			}
			metadata, err := json.Marshal(map[string]any{"regenerated": true, "commitOutcome": "committed", "commandID": s.command})
			if err != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			data := make([]byte, len(metadata)-1, len(metadata)+int(c.CodeCount)*25+32)
			copy(data, metadata[:len(metadata)-1])
			clear(metadata)
			defer func() { clear(data[:cap(data)]) }()
			data = append(data, `,"recoveryCodes":[`...)
			for i, code := range result.RecoveryCodes.Codes {
				if i > 0 {
					data = append(data, ',')
				}
				if code.Len() != 22 || code.Use(func(raw []byte) error {
					var decoded [16]byte
					var canonical [22]byte
					defer clear(decoded[:])
					defer clear(canonical[:])
					n, err := base64.RawURLEncoding.Decode(decoded[:], raw)
					if err != nil || n != len(decoded) {
						return identityhttp.ErrInvalidInput
					}
					base64.RawURLEncoding.Encode(canonical[:], decoded[:])
					if !bytes.Equal(canonical[:], raw) {
						return identityhttp.ErrInvalidInput
					}
					data = append(data, '"')
					data = append(data, raw...)
					data = append(data, '"')
					return nil
				}) != nil {
					writeFailure(w, enableFailure{status: 503, code: "unavailable"}, observation)
					return
				}
			}
			data = append(data, ']', '}', '\n')
			start := c.Now()
			observation["regenerated"] = false
			writeSecretJSON(w, r, data, observation, func() bool {
				at := c.Now()
				return !at.Before(start) && at.Before(s.until) && s.read.ValidateAt(at) == nil
			})
		},
	})
	if err != nil {
		return nil, err
	}
	return &enablePipeline{pipeline: pipeline}, nil
}
