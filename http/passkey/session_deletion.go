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

// SessionDeletionService borrows the native current-session genuine-UV removal
// owner. It alone verifies and atomically consumes the assertion with current
// recovery policy, exact removal and required session effects. RecoverDelete
// reads original metadata under current self-user authority, without repeating
// removal or allocating/rebinding a command. Calls must honor bounded contexts
// and concurrent callers. No concrete store or fallback belongs to this port.
type SessionDeletionService interface {
	DeleteOptions(context.Context, passkey.SessionDeleteOptionsRequest) (passkey.KeyedAssertionOptionsResult, error)
	Delete(context.Context, passkey.SessionDeleteCompletion) (passkey.SessionDeleteResult, error)
	RecoverDelete(context.Context, passkey.SessionDeleteRequest, identity.RecoveryQuery) (passkey.SessionDeleteResult, error)
}

// SessionDeletionConfig selects password-free POST /v1/passkey/delete, mutually
// exclusive with DeleteConfig. Sessions, CSRFKeys and Service must share actual
// native custody. Rate is the shared keyed rate.secret owner; every phase needs
// a header-only key. Options and completion retain distinct original keys;
// recovery uses its key only for rate admission. Dependencies and prompt clock
// are borrowed, concurrency-safe and must outlive requests. MaximumDuration is
// 1ms..30s; earlier deadlines and original validity are never extended. No
// password proof, device cookie, recovery store or session issuance is added.
type SessionDeletionConfig struct {
	Network         identityhttp.NetworkConfig
	Sessions        *session.SessionService
	Service         SessionDeletionService
	Rate            *identityhttp.KeyedSecretRateLimiter
	Origin          identityhttp.Origin
	SessionCookie   session.CookiePolicy
	CSRFKeys        []session.CSRFKey
	PolicyRevision  authorization.Revision
	Audience        string
	Now             func() time.Time
	MaximumDuration time.Duration
}

func (SessionDeletionConfig) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("passkeyhttp.SessionDeletionConfig(redacted)"))
}

// MarshalJSON rejects implicit owner/key export.
func (SessionDeletionConfig) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText rejects implicit owner/key export.
func (SessionDeletionConfig) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// SessionDeletionState retains immutable original request custody. Hooks can
// observe detached principal metadata, not replace credentials or native intent.
// Closure custody also prevents enclosing diagnostic values traversing secrets.
type SessionDeletionState struct{ value func() *sessionDeletionState }
type sessionDeletionState struct {
	facts      identityhttp.NetworkFacts
	body       requestBody
	key        identity.IdempotencyKey
	credential session.Credential
	csrf       session.CSRFToken
	read       session.GetResult
	request    passkey.SessionDeleteRequest
}

func (s SessionDeletionState) state() *sessionDeletionState {
	if s.value == nil {
		return nil
	}
	return s.value()
}

// Principal returns credential-free self-user metadata, never reusable authority.
func (s SessionDeletionState) Principal() (identity.TenantID, identity.UserID, bool) {
	p := s.state()
	if p == nil || !p.read.Authenticated {
		return "", "", false
	}
	r, err := p.read.Session.Bindings()
	return r.TenantID, r.UserID, err == nil
}

func (SessionDeletionState) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("passkeyhttp.SessionDeletionState(redacted)"))
}

// MarshalJSON rejects implicit request/session export.
func (SessionDeletionState) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText rejects implicit request/session export.
func (SessionDeletionState) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// NewSessionDeletionHandler selects closed phase=options|complete|recover on
// the existing delete route. Every call authenticates current cookie/CSRF/self
// scope. Completion can acknowledge its own session invalidation within only
// the original positive-read/context ceiling. Later calls need current authority;
// after removal, recover using a new genuine surviving-key session and the
// original command/target. Recovery returns metadata only, not options history.
func NewSessionDeletionHandler(c SessionDeletionConfig) (http.Handler, error) {
	return NewSessionDeletionHandlerWithMiddleware(c, nil)
}

// NewSessionDeletionHandlerWithMiddleware retains original session/rate/native
// phases and validity through synchronous hooks and bounded buffered delivery.
func NewSessionDeletionHandlerWithMiddleware(c SessionDeletionConfig, m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if !c.Sessions.Configured() || absent(c.Service) || !c.Rate.Configured() || c.Now == nil || c.PolicyRevision == 0 || !visible(c.Audience, 256) || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || len(c.CSRFKeys) == 0 || len(c.CSRFKeys) > 16 {
		return nil, identityhttp.ErrInvalidInput
	}
	c.CSRFKeys = slices.Clone(c.CSRFKeys)
	for index, key := range c.CSRFKeys {
		if key.Version() == 0 {
			return nil, identityhttp.ErrInvalidInput
		}
		for _, prior := range c.CSRFKeys[:index] {
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
	fresh := func(s SessionDeletionState) bool {
		p := s.state()
		return p != nil && p.read.ValidateAt(c.Now()) == nil
	}
	h, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[SessionDeletionState]{MaximumDuration: c.MaximumDuration, Middleware: m, Reject: reject,
		Decode: func(r *http.Request) (SessionDeletionState, error) {
			p := &sessionDeletionState{}
			s := SessionDeletionState{value: func() *sessionDeletionState { return p }}
			facts, body, key, err := i.decode(r, "session-delete", true)
			if err != nil {
				return s, err
			}
			p.facts, p.body, p.key = facts, body, key
			bearer, _, err := i.decoder.CookieBearer(r, cookie.Name, identityhttp.HeaderRequired)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			p.csrf, _, err = identityhttp.DecodeCSRF(decoder, r, session.ParseCSRFToken)
			if err != nil {
				return s, failure{status: 403, code: "origin_or_csrf_denied"}
			}
			token, err := session.ParseToken(bearer.Token())
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			p.credential, err = session.NewCredential(session.CredentialCookie, token)
			return s, err
		},
		Authenticate: func(r *http.Request, s SessionDeletionState) (SessionDeletionState, error) {
			p := s.state()
			var err error
			p.read, err = c.Sessions.Get(r.Context(), session.GetRequest{TenantID: p.facts.TenantID(), Credential: p.credential})
			if err != nil {
				return s, identityhttp.ErrUnavailable
			}
			if !p.read.Authenticated {
				return s, failure{status: 401, code: "unauthenticated"}
			}
			if !fresh(s) {
				return s, identityhttp.ErrUnavailable
			}
			record, err := p.read.Session.Bindings()
			if err != nil || record.TenantID != p.facts.TenantID() || record.Audience != c.Audience {
				return s, identityhttp.ErrUnavailable
			}
			binding := session.CSRFBinding{TenantID: record.TenantID, SessionID: record.SessionID, SessionVersion: record.Version}
			matched := false
			for _, key := range c.CSRFKeys {
				if p.read.Session.CSRFState().Check(binding, p.csrf, key) == nil {
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
			caller := authorization.DecisionContext{PolicyRevision: c.PolicyRevision, CorrelationID: string(correlation), Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(record.UserID)}, Tenant: authorization.TenantID(record.TenantID), Action: "identity.passkey.delete", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(record.UserID)}}}
			p.request = passkey.NewSessionDeleteRequest(passkey.SessionDeleteRequestSpec{Credential: p.credential, CSRFToken: p.csrf, Caller: caller, ReferenceID: identity.CredentialID(p.body.referenceID), ExpectedVersion: p.body.expectedVersion, Origin: string(c.Origin), Network: p.facts.ClientIP().String()})
			requestDelivery(r).valid = func() bool { return fresh(s) }
			return s, nil
		},
		Admit: func(r *http.Request, s SessionDeletionState) error {
			if !fresh(s) {
				return identityhttp.ErrUnavailable
			}
			p := s.state()
			_, user, _ := s.Principal()
			return rateFailure(c.Rate.Admit(r.Context(), p.facts, identityhttp.KeyedSecretRateRequest{OperationID: "identity.passkey.delete", UserID: user, IdempotencyKey: p.key}))
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s SessionDeletionState) {
			if !fresh(s) {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			p := s.state()
			if p.body.sessionOptions {
				sessionDeletionOptions(c, w, r, s, fresh)
				return
			}
			var result passkey.SessionDeleteResult
			var err error
			if p.body.sessionRecovery {
				tenant, user, _ := s.Principal()
				query := identity.RecoveryQuery{CommandID: identity.CommandID(p.body.commandID), TenantID: tenant, UserID: user, ActorID: identity.ActorID(user), ActorKind: authorization.SubjectUser, OperationID: "identity.passkey.delete", RecordID: p.body.referenceID}
				result, err = c.Service.RecoverDelete(r.Context(), p.request, query)
			} else {
				result, err = c.Service.Delete(r.Context(), passkey.NewSessionDeleteCompletion(passkey.SessionDeleteCompletionSpec{SessionDeleteRequest: p.request, IdempotencyKey: p.key, CeremonyID: p.body.ceremonyID, Response: p.body.response}))
			}
			out, projectionErr := result.Bindings()
			valid := projectionErr == nil && validSessionDeletionReceipt(out.Receipt, out.CommandID, p.request, false) && out.Outcome == out.Receipt.Outcome && (!p.body.sessionRecovery || out.Replayed && out.CommandID == identity.CommandID(p.body.commandID))
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
			if !valid || out.Outcome != identity.CommitOutcomeCommitted {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			requestDelivery(r).render(w, r, DeleteResponse{CommandID: out.CommandID, CommitOutcome: "committed", Replayed: out.Replayed}, func() bool { return fresh(s) })
		},
	})
	if err != nil {
		return nil, err
	}
	return &protectedPipeline{pipeline: h, maximum: c.MaximumDuration}, nil
}

func validSessionDeletionReceipt(out identity.CommandResult, id identity.CommandID, custody passkey.SessionDeleteRequest, options bool) bool {
	r, err := custody.Bindings()
	if err != nil || id == "" || out.Validate() != nil || out.Feature == nil {
		return false
	}
	b := out.Binding
	schema, record := "identity.passkey.delete.assertion-v1", string(r.ReferenceID)
	if options {
		schema, record = "identity.passkey.delete.options-v1", string(id)
	}
	op := identity.FeatureOperation{Owner: "passkey", OperationID: "identity.passkey.delete", SchemaID: schema, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	if b.CommandID != id || b.TenantID != identity.TenantID(r.Caller.Request.Tenant) || b.UserID != identity.UserID(r.Caller.Request.Subject.ID) || b.ActorKind != authorization.SubjectUser || b.ActorID != identity.ActorID(b.UserID) || b.OperationID != op.OperationID || b.RecordID != record || b.SchemaID != schema || b.SchemaVersion != 1 || b.PolicyVersion != uint64(r.Caller.PolicyRevision) || out.Feature.Operation != op {
		return false
	}
	if out.Outcome != identity.CommitOutcomeCommitted {
		return true
	}
	f := out.Feature
	if options {
		return f.BeforeVersion == 0 && f.AfterVersion == 1
	}
	// passkey.SessionDeleteRequestSpec defines ExpectedVersion as inventory
	// metadata, independent of the kernel reference lifecycle advanced here.
	return f.BeforeVersion > 0 && f.BeforeVersion < ^uint64(0) && f.AfterVersion == f.BeforeVersion+1
}

func sessionDeletionOptions(c SessionDeletionConfig, w http.ResponseWriter, r *http.Request, s SessionDeletionState, fresh func(SessionDeletionState) bool) {
	p := s.state()
	out, err := c.Service.DeleteOptions(r.Context(), passkey.SessionDeleteOptionsRequest{SessionDeleteRequest: p.request, IdempotencyKey: p.key})
	valid := validSessionDeletionReceipt(out.Receipt, out.CommandID, p.request, true)
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
		tenant, user, _ := s.Principal()
		if !has || ceremony.ID != string(out.CommandID) || ceremony.Intent.Kind != "get" || len(ceremony.Intent.UserHandle) != 32 || len(ceremony.Intent.AllowedCredentials) != 1 || ceremony.Intent.Context.TenantID != tenant || ceremony.Intent.Context.UserID != user || ceremony.Intent.Context.ActorID != identity.ActorID(user) || ceremony.Intent.Context.AnonymousFlowID != "" || ceremony.Intent.Context.CommandID != out.CommandID || ceremony.Intent.Origin != string(c.Origin) || !c.Now().Before(ceremony.ExpiresAt) {
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
