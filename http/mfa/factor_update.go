package mfahttp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
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

// FactorUpdateConfig selects cookie-only native TOTP rename without registering
// a route. Sessions, original proof source, mutation and shared keyed quota
// owners are borrowed, bounded and concurrency-safe. Exact origins and policy
// revision are trusted startup inputs. MaximumAge is positive and at most five
// minutes; MaximumDuration is 1ms..30s. Neither can renew original validity.
type FactorUpdateConfig struct {
	Network                     identityhttp.NetworkConfig
	Sessions                    *session.SessionService
	Proofs                      auth.ReauthenticationSource
	Service                     mfa.FactorManagementService
	Rate                        *identityhttp.KeyedSecretRateLimiter
	Cookie                      session.CookiePolicy
	TrustedOrigins              []identityhttp.Origin
	PolicyRevision              authorization.Revision
	Now                         func() time.Time
	MaximumDuration, MaximumAge time.Duration
}

type factorUpdateHTTPState struct {
	base    enableState
	origin  identityhttp.Origin
	factor  mfa.FactorID
	name    string
	version uint64
}

// NewFactorUpdateHandler owns POST /v1/mfa/factor-update without registration.
// Closed JSON requires factorID, proofID, action:"rename", name and expectedVersion.
// One Idempotency-Key, actual cookie, exact Origin and synchronizer are required.
// Subject, tenant, command, method and proof projections cannot be overridden.
// Fresh known commit returns safe metadata, never a session or factor secret.
func NewFactorUpdateHandler(c FactorUpdateConfig) (http.Handler, error) {
	return NewFactorUpdateHandlerWithMiddleware(c, nil)
}

// NewFactorUpdateHandlerWithMiddleware preserves owned session/proof deadlines
// through actual decode, authentication, shared quota and native mutation phases.
func NewFactorUpdateHandlerWithMiddleware(c FactorUpdateConfig, m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if !c.Sessions.Configured() || enableNil(c.Proofs) || enableNil(c.Service) || !c.Rate.Configured() || c.Now == nil || c.PolicyRevision == 0 || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || c.MaximumAge <= 0 || c.MaximumAge > 5*time.Minute {
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
		f := enableFailure{status: 503, code: "unavailable"}
		var specific enableFailure
		var denied identity.ForbiddenError
		var conflict identity.ConflictError
		var busy identity.InProgressError
		switch {
		case errors.As(err, &specific):
			return specific
		case errors.Is(err, identityhttp.ErrInvalidInput):
			f = enableFailure{status: 400, code: "invalid_request"}
		case errors.As(err, &denied):
			f = enableFailure{status: 403, code: "denied"}
		case errors.As(err, &conflict):
			f = enableFailure{status: 409, code: "conflict"}
		case errors.As(err, &busy):
			f = enableFailure{status: 409, code: "in_progress", retry: busy.RetryAfter}
		}
		return f
	}
	fail := func(w http.ResponseWriter, f enableFailure, observation map[string]any) {
		if observation == nil {
			observation = map[string]any{"commitOutcome": "none"}
		}
		observation["error"] = f.code
		if f.status == 405 {
			w.Header().Set("Allow", http.MethodPost)
		}
		if f.retry > 0 {
			w.Header().Set("Retry-After", strconv.FormatInt(int64((min(max(f.retry, time.Second), time.Hour)+time.Second-1)/time.Second), 10))
		}
		w.WriteHeader(f.status)
		_ = json.NewEncoder(w).Encode(observation)
	}
	reject := func(w http.ResponseWriter, _ *http.Request, err error) { fail(w, classify(err), nil) }
	h, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[factorUpdateHTTPState]{MaximumDuration: c.MaximumDuration, Middleware: m, Reject: reject,
		Decode: func(r *http.Request) (factorUpdateHTTPState, error) {
			s := factorUpdateHTTPState{}
			if r.URL.Path != "/v1/mfa/factor-update" || r.URL.EscapedPath() != r.URL.Path {
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
			s.base.facts = facts
			key, present, err := decoder.IdempotencyKey(r, identityhttp.HeaderRequired)
			if err != nil || !present {
				return s, identityhttp.ErrInvalidInput
			}
			s.base.key = key
			if _, _, err := decoder.Bearer(r, identityhttp.HeaderForbidden); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.base.bearer, present, err = decoder.CookieBearer(r, cookie.Name, identityhttp.HeaderRequired)
			if err != nil || !present {
				return s, identityhttp.ErrInvalidInput
			}
			s.base.csrf, _, err = identityhttp.DecodeCSRF(csrf, r, session.ParseCSRFToken)
			if err != nil {
				return s, enableFailure{status: 403, code: "origin_or_csrf_denied"}
			}
			s.origin, err = origins.Check(r)
			if err != nil {
				return s, enableFailure{status: 403, code: "origin_or_csrf_denied"}
			}
			token, err := session.ParseToken(s.base.bearer.Token())
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.base.credential, err = session.NewCredential(session.CredentialCookie, token)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			body, err := identityhttp.DecodeJSON[map[string]json.RawMessage](decoder, r)
			if err != nil || len(body) != 5 {
				return s, identityhttp.ErrInvalidInput
			}
			var factor, proof, action string
			for name, dst := range map[string]*string{"factorID": &factor, "proofID": &proof, "action": &action, "name": &s.name} {
				raw, ok := body[name]
				if !ok || len(raw) < 2 || raw[0] != '"' || json.Unmarshal(raw, dst) != nil {
					return s, identityhttp.ErrInvalidInput
				}
			}
			if action != "rename" {
				return s, identityhttp.ErrInvalidInput
			}
			id, err := identity.ParseCommandID(factor)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.factor = mfa.FactorID(id)
			id, err = identity.ParseCommandID(proof)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.base.proofID = auth.ProofID(id)
			if raw, ok := body["expectedVersion"]; !ok || json.Unmarshal(raw, &s.version) != nil || s.version == 0 || s.version == ^uint64(0) {
				return s, identityhttp.ErrInvalidInput
			}
			// The public request owns the same bounded presentation policy. Use
			// display validation here without fabricating factor authority.
			projection := mfa.FactorProjection{ID: s.factor, Method: "totp", Label: s.name, State: mfa.FactorActive, Version: s.version, CreatedAt: c.Now()}
			if (mfa.ListResult{Factors: []mfa.FactorProjection{projection}}).ValidateAt(c.Now()) != nil {
				return s, identityhttp.ErrInvalidInput
			}
			return s, nil
		},
		Authenticate: func(r *http.Request, s factorUpdateHTTPState) (factorUpdateHTTPState, error) {
			read, err := c.Sessions.Get(r.Context(), session.GetRequest{TenantID: s.base.facts.TenantID(), Credential: s.base.credential})
			if err != nil {
				return s, identityhttp.ErrUnavailable
			}
			if !read.Authenticated {
				return s, enableFailure{status: 401, code: "denied"}
			}
			b, err := read.Session.Bindings()
			if err != nil || b.TenantID != s.base.facts.TenantID() || read.ValidateAt(c.Now()) != nil {
				return s, identityhttp.ErrUnavailable
			}
			s.base.read, s.base.user = read, b.UserID
			return s, nil
		},
		Admit: func(r *http.Request, s factorUpdateHTTPState) error {
			out, err := c.Rate.Admit(r.Context(), s.base.facts, identityhttp.KeyedSecretRateRequest{OperationID: "identity.mfa.factor-update", UserID: s.base.user, IdempotencyKey: s.base.key})
			if errors.Is(err, identityhttp.ErrRateLimited) {
				return enableFailure{status: 429, code: "rate_limited", retry: out.RetryAfter}
			}
			if err != nil || !out.Allowed || s.base.read.ValidateAt(c.Now()) != nil {
				return identityhttp.ErrUnavailable
			}
			return nil
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s factorUpdateHTTPState) {
			if s.base.read.ValidateAt(c.Now()) != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			record, err := c.Proofs.Reauthentication(r.Context(), s.base.proofID)
			if r.Context().Err() != nil || err != nil && !errors.Is(err, auth.ErrInvalidProof) {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			b, bindErr := s.base.read.Session.Bindings()
			p := record.Proof
			use := auth.ReauthenticationUse{ProofUse: auth.ProofUse{Tenant: string(s.base.facts.TenantID()), Subject: string(s.base.user), Purpose: "identity.mfa.factor-update", Audience: p.Proof.Audience, Now: c.Now()}, SessionID: b.SessionID, SessionVersion: b.Version, Action: "identity.mfa.factor-update", MaximumAge: c.MaximumAge}
			if err != nil || bindErr != nil || p.Proof.ID != s.base.proofID || p.Proof.Method != "totp" || p.Proof.Assurance != auth.AssuranceMultiFactor || p.Validate(use) != nil {
				reject(w, r, identity.ForbiddenError{})
				return
			}
			if s.base.read.ValidateAt(c.Now()) != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			caller := authorization.DecisionContext{PolicyRevision: c.PolicyRevision, Request: authorization.Request{Tenant: authorization.TenantID(b.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(b.UserID)}, Action: "identity.mfa.factor-update", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}}}
			request := mfa.FactorUpdateRequest{TenantID: b.TenantID, FactorID: s.factor, Action: mfa.Rename, Name: s.name, ExpectedVersion: s.version, FactorProof: p.Proof, Session: s.base.bearer, CSRFToken: s.base.csrf, Caller: caller, Origin: string(s.origin), Network: s.base.facts.ClientIP().String(), IdempotencyKey: s.base.key}
			if request.Validate() != nil {
				reject(w, r, identityhttp.ErrInvalidInput)
				return
			}
			out, err := c.Service.FactorUpdate(r.Context(), request)
			safeObservation := mfa.EnableResult{Outcome: out.Outcome}
			if _, parseErr := identity.ParseCommandID(string(out.CommandID)); parseErr == nil {
				safeObservation.CommandID = out.CommandID
			}
			observation := enableObservation(safeObservation)
			if err != nil || r.Context().Err() != nil {
				fail(w, classify(err), observation)
				return
			}
			freshUse := use
			freshUse.ProofUse.Now = c.Now()
			if _, err := identity.ParseCommandID(string(out.CommandID)); err != nil || out.Outcome != identity.CommitOutcomeCommitted || out.Factor.ID != s.factor || out.Factor.Method != "totp" || out.Factor.State != mfa.FactorActive || out.Factor.Label != s.name || out.Factor.Version != s.version+1 || (mfa.ListResult{Factors: []mfa.FactorProjection{out.Factor}}).ValidateAt(c.Now()) != nil || s.base.read.ValidateAt(c.Now()) != nil || p.Validate(freshUse) != nil {
				fail(w, enableFailure{status: 503, code: "unavailable"}, observation)
				return
			}
			data, err := factorUpdateBody(out)
			if err != nil {
				fail(w, classify(err), observation)
				return
			}
			defer clear(data)
			start := c.Now()
			writeSecretJSON(w, r, data, observation, func() bool {
				at := c.Now()
				freshUse := use
				freshUse.ProofUse.Now = at
				return !at.Before(start) && s.base.read.ValidateAt(at) == nil && p.Validate(freshUse) == nil
			})
		},
	})
	if err != nil {
		return nil, err
	}
	return &enablePipeline{pipeline: h}, nil
}

func factorUpdateBody(out mfa.FactorUpdateResult) ([]byte, error) {
	type factor struct {
		ID         mfa.FactorID    `json:"id"`
		Method     string          `json:"method"`
		Label      string          `json:"label"`
		State      mfa.FactorState `json:"state"`
		CreatedAt  time.Time       `json:"createdAt"`
		LastUsedAt *time.Time      `json:"lastUsedAt,omitempty"`
		Version    uint64          `json:"version"`
	}
	f := factor{ID: out.Factor.ID, Method: out.Factor.Method, Label: out.Factor.Label, State: out.Factor.State, CreatedAt: out.Factor.CreatedAt.UTC(), Version: out.Factor.Version}
	if !out.Factor.LastUsedAt.IsZero() {
		v := out.Factor.LastUsedAt.UTC()
		f.LastUsedAt = &v
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(struct {
		Outcome   string             `json:"commitOutcome"`
		CommandID identity.CommandID `json:"commandID"`
		Factor    factor             `json:"factor"`
	}{"committed", out.CommandID, f}) != nil || buffer.Len() > 4096 {
		return nil, identityhttp.ErrUnavailable
	}
	return buffer.Bytes(), nil
}

// Format redacts borrowed configuration and rate custody.
func (FactorUpdateConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfahttp.FactorUpdateConfig(redacted)"))
}

// MarshalJSON rejects implicit configuration export.
func (FactorUpdateConfig) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText rejects implicit configuration export.
func (FactorUpdateConfig) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// LogValue emits only a fixed redaction marker.
func (FactorUpdateConfig) LogValue() slog.Value {
	return slog.StringValue("mfahttp.FactorUpdateConfig(redacted)")
}
