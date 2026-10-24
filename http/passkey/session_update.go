package passkeyhttp

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
)

// SessionUpdateService borrows the same native current-session action owner for
// both phases. It must bind genuine UV options to the exact intent and consume
// the assertion atomically with the mutation. Contexts are bounded; concurrent
// calls and original-key recovery remain native-owned, not HTTP-owned.
type SessionUpdateService interface {
	UpdateOptions(context.Context, passkey.SessionUpdateOptionsRequest) (passkey.KeyedAssertionOptionsResult, error)
	Update(context.Context, passkey.SessionUpdateCompletion) (passkey.UpdateResult, error)
}

// SessionUpdateConfig explicitly selects the password-free cookie profile of
// POST /v1/passkey/update. It is mutually exclusive with UpdateConfig. Sessions,
// CSRFKeys and Service must share actual native custody. Rate is the shared
// rate.secret owner. Both phases require distinct original header-only keys.
// Dependencies/clock are borrowed, prompt, concurrency-safe and must outlive
// requests. MaximumDuration is 1ms..30s; earlier deadlines and authority expiry
// are never extended. No password, device cookie or session issuance is added.
type SessionUpdateConfig struct {
	Network         identityhttp.NetworkConfig
	Sessions        *session.SessionService
	Service         SessionUpdateService
	Rate            *identityhttp.KeyedSecretRateLimiter
	Origin          identityhttp.Origin
	SessionCookie   session.CookiePolicy
	CSRFKeys        []session.CSRFKey
	PolicyRevision  authorization.Revision
	Audience        string
	Now             func() time.Time
	MaximumDuration time.Duration
}

func (SessionUpdateConfig) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("passkeyhttp.SessionUpdateConfig(redacted)"))
}

// MarshalJSON rejects implicit owner/key export.
func (SessionUpdateConfig) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText rejects implicit owner/key export.
func (SessionUpdateConfig) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// SessionUpdateState is immutable original request custody. Hooks may observe
// detached principal metadata, never replace credentials or the native intent.
type SessionUpdateState struct{ *sessionUpdateState }
type sessionUpdateState struct {
	facts      identityhttp.NetworkFacts
	body       requestBody
	key        identity.IdempotencyKey
	credential session.Credential
	csrf       session.CSRFToken
	read       session.GetResult
	request    passkey.SessionUpdateRequest
}

// Principal returns credential-free self-user metadata, not reusable authority.
func (s SessionUpdateState) Principal() (identity.TenantID, identity.UserID, bool) {
	if s.sessionUpdateState == nil || !s.read.Authenticated {
		return "", "", false
	}
	r, err := s.read.Session.Bindings()
	return r.TenantID, r.UserID, err == nil
}
func (SessionUpdateState) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("passkeyhttp.SessionUpdateState(redacted)"))
}

// MarshalJSON rejects implicit request/session export.
func (SessionUpdateState) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText rejects implicit request/session export.
func (SessionUpdateState) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// NewSessionUpdateHandler selects the closed phase=options|complete profile of
// POST /v1/passkey/update. Both phases require current cookie/CSRF/Origin and a
// header-only key. Completion accepts the original ceremony and assertion, not
// a password proof or caller-allocated command. Retries disclose metadata only.
func NewSessionUpdateHandler(c SessionUpdateConfig) (http.Handler, error) {
	return NewSessionUpdateHandlerWithMiddleware(c, nil)
}

// NewSessionUpdateHandlerWithMiddleware retains real session/rate/native phases
// and original validity through synchronous hooks and bounded final delivery.
func NewSessionUpdateHandlerWithMiddleware(c SessionUpdateConfig, m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if !c.Sessions.Configured() || absent(c.Service) || !c.Rate.Configured() || c.Now == nil || c.PolicyRevision == 0 || !visible(c.Audience, 256) || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || len(c.CSRFKeys) == 0 || len(c.CSRFKeys) > 16 {
		return nil, identityhttp.ErrInvalidInput
	}
	c.CSRFKeys = slices.Clone(c.CSRFKeys)
	for i, key := range c.CSRFKeys {
		if key.Version() == 0 {
			return nil, identityhttp.ErrInvalidInput
		}
		for _, prior := range c.CSRFKeys[:i] {
			if key.Version() == prior.Version() {
				return nil, identityhttp.ErrInvalidInput
			}
		}
	}
	i, err := newIngress(c.Network, c.Origin)
	if err != nil {
		return nil, err
	}
	decoder, err := identityhttp.NewCSRFDecoder(identityhttp.CSRFDecoderConfig{Origins: i.origin, FormField: "csrf_token"})
	if err != nil {
		return nil, err
	}
	cookie, err := c.SessionCookie.DeletionAttributes()
	if err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	fresh := func(s SessionUpdateState) bool {
		return s.sessionUpdateState != nil && s.read.ValidateAt(c.Now()) == nil
	}
	h, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[SessionUpdateState]{MaximumDuration: c.MaximumDuration, Middleware: m, Reject: reject,
		Decode: func(r *http.Request) (SessionUpdateState, error) {
			s := SessionUpdateState{&sessionUpdateState{}}
			facts, body, key, err := i.decode(r, "session-update", true)
			if err != nil {
				return s, err
			}
			s.facts, s.body, s.key = facts, body, key
			bearer, _, err := i.decoder.CookieBearer(r, cookie.Name, identityhttp.HeaderRequired)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.csrf, _, err = identityhttp.DecodeCSRF(decoder, r, session.ParseCSRFToken)
			if err != nil {
				return s, failure{status: 403, code: "origin_or_csrf_denied"}
			}
			token, err := session.ParseToken(bearer.Token())
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.credential, err = session.NewCredential(session.CredentialCookie, token)
			return s, err
		},
		Authenticate: func(r *http.Request, s SessionUpdateState) (SessionUpdateState, error) {
			var err error
			s.read, err = c.Sessions.Get(r.Context(), session.GetRequest{TenantID: s.facts.TenantID(), Credential: s.credential})
			if err != nil {
				return s, identityhttp.ErrUnavailable
			}
			if !s.read.Authenticated {
				return s, failure{status: 401, code: "unauthenticated"}
			}
			if !fresh(s) {
				return s, identityhttp.ErrUnavailable
			}
			record, err := s.read.Session.Bindings()
			if err != nil || record.TenantID != s.facts.TenantID() || record.Audience != c.Audience {
				return s, identityhttp.ErrUnavailable
			}
			binding := session.CSRFBinding{TenantID: record.TenantID, SessionID: record.SessionID, SessionVersion: record.Version}
			matched := false
			for _, key := range c.CSRFKeys {
				if s.read.Session.CSRFState().Check(binding, s.csrf, key) == nil {
					matched = true
					break
				}
			}
			if !matched {
				return s, failure{status: 403, code: "origin_or_csrf_denied"}
			}
			correlation, err := identity.NewCommandID()
			if err != nil {
				return s, identityhttp.ErrUnavailable
			}
			caller := authorization.DecisionContext{PolicyRevision: c.PolicyRevision, CorrelationID: string(correlation), Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(record.UserID)}, Tenant: authorization.TenantID(record.TenantID), Action: "identity.passkey.update", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(record.UserID)}}}
			s.request = passkey.SessionUpdateRequest{Credential: s.credential, CSRFToken: s.csrf, Caller: caller, ReferenceID: identity.CredentialID(s.body.referenceID), ExpectedVersion: s.body.expectedVersion, Name: s.body.name, Origin: string(c.Origin), Network: s.facts.ClientIP().String()}
			requestDelivery(r).valid = func() bool { return fresh(s) }
			return s, nil
		},
		Admit: func(r *http.Request, s SessionUpdateState) error {
			if !fresh(s) {
				return identityhttp.ErrUnavailable
			}
			_, user, _ := s.Principal()
			return rateFailure(c.Rate.Admit(r.Context(), s.facts, identityhttp.KeyedSecretRateRequest{OperationID: "identity.passkey.update", UserID: user, IdempotencyKey: s.key}))
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s SessionUpdateState) {
			if !fresh(s) {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			if s.body.sessionOptions {
				sessionUpdateOptions(c, w, r, s, fresh)
				return
			}
			out, err := c.Service.Update(r.Context(), passkey.SessionUpdateCompletion{SessionUpdateRequest: s.request, IdempotencyKey: s.key, CeremonyID: s.body.ceremonyID, Response: s.body.response})
			valid := validSessionUpdateReceipt(out.Receipt, out.CommandID, s.request, false)
			if valid && out.Outcome == out.Receipt.Outcome {
				observeSessionUpdate(r, out.Receipt)
			} else {
				valid = false
			}
			if err != nil {
				if valid {
					reject(w, r, domainFailure(err))
				} else {
					rejectNative(w, r, err)
				}
				return
			}
			if !valid || out.Outcome != identity.CommitOutcomeCommitted || out.Replayed && out.Credential != nil || !out.Replayed && out.Credential == nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			response := UpdateResponse{CommandID: out.CommandID, CommitOutcome: "committed", Replayed: out.Replayed}
			if !out.Replayed {
				item := out.Credential
				if item.ReferenceID != string(s.request.ReferenceID) || item.Version != s.request.ExpectedVersion+1 || item.State != "active" || item.Label != s.request.Name || item.CreatedAt.IsZero() {
					reject(w, r, identityhttp.ErrUnavailable)
					return
				}
				response.Credential = &CredentialMetadata{item.ReferenceID, item.Version, item.State, item.Label, item.AAGUID, item.BackupEligible, item.BackupState, item.CreatedAt, item.LastUsedAt}
			}
			requestDelivery(r).render(w, r, response, func() bool { return fresh(s) })
		},
	})
	if err != nil {
		return nil, err
	}
	return &protectedPipeline{pipeline: h, maximum: c.MaximumDuration}, nil
}

func validSessionUpdateReceipt(out identity.CommandResult, id identity.CommandID, r passkey.SessionUpdateRequest, options bool) bool {
	b := out.Binding
	schema, record := "identity.passkey.update.assertion-v1", string(r.ReferenceID)
	before, after := r.ExpectedVersion, r.ExpectedVersion+1
	if options {
		schema, record = "identity.passkey.update.options-v1", string(id)
		before, after = 0, 1
	}
	return id != "" && out.Validate() == nil && id == b.CommandID && b.TenantID == identity.TenantID(r.Caller.Request.Tenant) && b.UserID == identity.UserID(r.Caller.Request.Subject.ID) && b.ActorKind == authorization.SubjectUser && b.ActorID == identity.ActorID(b.UserID) && b.OperationID == "identity.passkey.update" && b.RecordID == record && b.SchemaID == schema && b.SchemaVersion == 1 && b.PolicyVersion == uint64(r.Caller.PolicyRevision) && (out.Outcome != identity.CommitOutcomeCommitted || out.Feature != nil && out.Feature.BeforeVersion == before && out.Feature.AfterVersion == after)
}
func observeSessionUpdate(r *http.Request, out identity.CommandResult) {
	d := requestDelivery(r)
	switch out.Outcome {
	case identity.CommitOutcomeCommitted:
		d.observeCommitted(out.Binding.CommandID)
	case identity.CommitOutcomeUnknown:
		d.observed = &failure{status: 503, code: "unknown", commandID: out.Binding.CommandID, outcome: "unknown"}
	case identity.CommitOutcomeNotCommitted:
		d.observed = &failure{status: 503, code: "not_committed", commandID: out.Binding.CommandID, outcome: "not_committed"}
	case identity.CommitOutcomeConflict:
		d.observed = &failure{status: 409, code: "conflict", commandID: out.Binding.CommandID, outcome: "conflict"}
	case identity.CommitOutcomeInProgress:
		d.observed = &failure{status: 409, code: "in_progress", commandID: out.Binding.CommandID, outcome: "in_progress", retry: out.RetryAfter}
	}
}
func sessionUpdateOptions(c SessionUpdateConfig, w http.ResponseWriter, r *http.Request, s SessionUpdateState, fresh func(SessionUpdateState) bool) {
	out, err := c.Service.UpdateOptions(r.Context(), passkey.SessionUpdateOptionsRequest{SessionUpdateRequest: s.request, IdempotencyKey: s.key})
	valid := validSessionUpdateReceipt(out.Receipt, out.CommandID, s.request, true)
	if valid {
		observeSessionUpdate(r, out.Receipt)
	}
	if err != nil {
		if valid {
			reject(w, r, domainFailure(err))
		} else {
			rejectNative(w, r, err)
		}
		return
	}
	if !valid || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
		reject(w, r, identityhttp.ErrUnavailable)
		return
	}
	response := optionsResponse{CommandID: out.CommandID, CommitOutcome: "committed", Replayed: out.Replayed}
	deliver := func() bool { return fresh(s) }
	ceremony, has := out.Options.Ceremony()
	if out.Replayed {
		if has {
			reject(w, r, identityhttp.ErrUnavailable)
			return
		}
	} else {
		if !has || ceremony.ID != string(out.CommandID) || ceremony.Intent.Context.TenantID != identity.TenantID(s.request.Caller.Request.Tenant) || ceremony.Intent.Context.UserID != identity.UserID(s.request.Caller.Request.Subject.ID) || ceremony.Intent.Context.CommandID != out.CommandID || ceremony.Intent.Origin != string(c.Origin) {
			reject(w, r, identityhttp.ErrUnavailable)
			return
		}
		deliver = func() bool { return fresh(s) && c.Now().Before(ceremony.ExpiresAt) }
		if err := out.Options.TransferJSON(r.Context(), func(_ context.Context, wire []byte) error {
			if len(wire) == 0 || len(wire) > 262144 {
				return identityhttp.ErrUnavailable
			}
			response.Options = append([]byte(nil), wire...)
			return nil
		}); err != nil {
			reject(w, r, identityhttp.ErrUnavailable)
			return
		}
	}
	requestDelivery(r).render(w, r, response, deliver)
}
