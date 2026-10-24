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
	webauthn "github.com/faustbrian/go-webauthn"
)

// SessionEnrollmentService borrows one native current-session enrollment owner.
// A creates action-bound UV options; B consumes that assertion and returns
// registration options plus A's original absolute delivery ceiling; C consumes
// the registration. Source authenticates original user/challenge rate metadata,
// never a validity lease. All calls must be bounded and concurrency-safe.
type SessionEnrollmentService interface {
	EnrollmentAssertionOptions(context.Context, passkey.SessionEnrollmentOptionsRequest) (passkey.KeyedAssertionOptionsResult, error)
	RegistrationOptionsForDelivery(context.Context, passkey.SessionEnrollmentAuthorization) (passkey.KeyedRegistrationOptionsResult, time.Time, error)
	SessionRegistrationRateSource(context.Context, passkey.SessionEnrollmentRequest, string) (passkey.CeremonyRateSource, error)
	Register(context.Context, passkey.SessionEnrollmentCompletion) (passkey.SessionEnrollmentResult, error)
}

// SessionEnrollmentConfig selects password-free additional-key enrollment on
// the existing registration route pair. Sessions/CSRF/Service must share native
// cookie authority. Shared canonical options and verification rate owners are
// required. Dependencies and prompt Now are borrowed, concurrency-safe and must
// outlive requests. MaximumDuration is 1ms..30s and cannot extend a deadline.
// This profile needs neither password proofs nor a device cookie and never
// issues a session. RegistrationConfig is mutually exclusive; Signup may share
// the pair only with identical ingress, Origin, session cookie and rate owners.
type SessionEnrollmentConfig struct {
	Network          identityhttp.NetworkConfig
	Sessions         *session.SessionService
	Service          SessionEnrollmentService
	OptionsRate      *identityhttp.AuthRateLimiter
	VerificationRate *identityhttp.ChallengeVerificationRateLimiter
	Origin           identityhttp.Origin
	SessionCookie    session.CookiePolicy
	CSRFKeys         []session.CSRFKey
	PolicyRevision   authorization.Revision
	Audience         string
	Now              func() time.Time
	MaximumDuration  time.Duration
}

func (SessionEnrollmentConfig) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("passkeyhttp.SessionEnrollmentConfig(redacted)"))
}

// MarshalJSON rejects implicit runtime-owner and key export.
func (SessionEnrollmentConfig) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText rejects implicit runtime-owner and key export.
func (SessionEnrollmentConfig) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// SessionEnrollmentState retains original session/intent custody privately.
// Principal exposes detached metadata only; hooks cannot replace native input.
// Closure storage also excludes custody from enclosing unexported fmt fields.
type SessionEnrollmentState struct {
	value func() *sessionEnrollmentState
}
type sessionEnrollmentState struct {
	facts      identityhttp.NetworkFacts
	body       requestBody
	key        identity.IdempotencyKey
	credential session.Credential
	csrf       session.CSRFToken
	read       session.GetResult
	request    passkey.SessionEnrollmentRequest
	source     passkey.CeremonyRateSource
}

// Principal returns self-user metadata, not a reusable authorization lease.
func (s SessionEnrollmentState) Principal() (identity.TenantID, identity.UserID, bool) {
	if s.value == nil || !s.value().read.Authenticated {
		return "", "", false
	}
	r, err := s.value().read.Session.Bindings()
	return r.TenantID, r.UserID, err == nil
}
func (SessionEnrollmentState) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("passkeyhttp.SessionEnrollmentState(redacted)"))
}

// MarshalJSON rejects implicit original-session/intent export.
func (SessionEnrollmentState) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText rejects implicit original-session/intent export.
func (SessionEnrollmentState) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// NewSessionEnrollmentOptionsHandler selects mode=session and closed
// phase=assertion|registration at POST /v1/passkey/register-options. Each phase
// requires its distinct original header-only key and current cookie/CSRF/Origin.
func NewSessionEnrollmentOptionsHandler(c SessionEnrollmentConfig) (http.Handler, error) {
	return NewSessionEnrollmentOptionsHandlerWithMiddleware(c, nil)
}

// NewSessionEnrollmentOptionsHandlerWithMiddleware preserves native custody and
// original A/B expiry through synchronous hooks and bounded final delivery.
func NewSessionEnrollmentOptionsHandlerWithMiddleware(c SessionEnrollmentConfig, m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	return newSessionEnrollmentHandler(c, m, false)
}

// NewSessionEnrollmentVerifyHandler selects non-keyed mode=session registration
// completion at POST /v1/passkey/register-verify. Original command/ceremony and
// genuine registration response remain native-owned; no session is issued.
func NewSessionEnrollmentVerifyHandler(c SessionEnrollmentConfig) (http.Handler, error) {
	return NewSessionEnrollmentVerifyHandlerWithMiddleware(c, nil)
}

// NewSessionEnrollmentVerifyHandlerWithMiddleware binds hooks to actual
// current-session, rate-source, admission and native completion phases.
func NewSessionEnrollmentVerifyHandlerWithMiddleware(c SessionEnrollmentConfig, m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	return newSessionEnrollmentHandler(c, m, true)
}

func newSessionEnrollmentHandler(c SessionEnrollmentConfig, m []identityhttp.MiddlewareDescriptor, complete bool) (http.Handler, error) {
	if !c.Sessions.Configured() || absent(c.Service) || !c.OptionsRate.Configured() || !c.VerificationRate.Configured() || c.Now == nil || c.PolicyRevision == 0 || !visible(c.Audience, 256) || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || len(c.CSRFKeys) == 0 || len(c.CSRFKeys) > 16 {
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
	operation := "register-options"
	if complete {
		operation = "register-verify"
	}
	action := "identity.passkey." + operation
	fresh := func(s *sessionEnrollmentState) bool { return s != nil && s.read.ValidateAt(c.Now()) == nil }
	h, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[SessionEnrollmentState]{MaximumDuration: c.MaximumDuration, Middleware: m, Reject: reject,
		Decode: func(r *http.Request) (SessionEnrollmentState, error) {
			s := &sessionEnrollmentState{}
			state := SessionEnrollmentState{value: func() *sessionEnrollmentState { return s }}
			facts, body, key, err := i.decode(r, operation, true)
			if err != nil {
				return state, err
			}
			if !body.sessionEnrollment {
				return state, identityhttp.ErrInvalidInput
			}
			s.facts, s.body, s.key = facts, body, key
			bearer, _, err := i.decoder.CookieBearer(r, cookie.Name, identityhttp.HeaderRequired)
			if err != nil {
				return state, identityhttp.ErrInvalidInput
			}
			s.csrf, _, err = identityhttp.DecodeCSRF(decoder, r, session.ParseCSRFToken)
			if err != nil {
				return state, failure{status: 403, code: "origin_or_csrf_denied"}
			}
			token, err := session.ParseToken(bearer.Token())
			if err != nil {
				return state, identityhttp.ErrInvalidInput
			}
			s.credential, err = session.NewCredential(session.CredentialCookie, token)
			return state, err
		},
		Authenticate: func(r *http.Request, state SessionEnrollmentState) (SessionEnrollmentState, error) {
			s := state.value()
			var admission identityhttp.AuthRateResult
			var err error
			if complete {
				admission, err = c.VerificationRate.AdmitIP(r.Context(), s.facts)
			} else {
				admission, err = c.OptionsRate.AdmitPasskeyOptionsIP(r.Context(), s.facts, action)
			}
			if err := rateFailure(admission, err); err != nil {
				return state, err
			}
			s.read, err = c.Sessions.Get(r.Context(), session.GetRequest{TenantID: s.facts.TenantID(), Credential: s.credential})
			if err != nil {
				return state, identityhttp.ErrUnavailable
			}
			if !s.read.Authenticated {
				return state, failure{status: 401, code: "unauthenticated"}
			}
			if !fresh(s) {
				return state, identityhttp.ErrUnavailable
			}
			record, err := s.read.Session.Bindings()
			if err != nil || record.TenantID != s.facts.TenantID() || record.Audience != c.Audience {
				return state, identityhttp.ErrUnavailable
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
				return state, failure{status: 403, code: "origin_or_csrf_denied"}
			}
			correlation, err := identity.NewCommandID()
			if err != nil {
				return state, identityhttp.ErrUnavailable
			}
			caller := authorization.DecisionContext{PolicyRevision: c.PolicyRevision, CorrelationID: string(correlation), Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(record.UserID)}, Tenant: authorization.TenantID(record.TenantID), Action: authorization.Action(action), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(record.UserID)}}}
			s.request = passkey.NewSessionEnrollmentRequest(passkey.SessionEnrollmentRequestSpec{Credential: s.credential, CSRFToken: s.csrf, Caller: caller, Label: s.body.label, Origin: string(c.Origin), Network: s.facts.ClientIP().String()})
			if complete {
				s.source, err = c.Service.SessionRegistrationRateSource(r.Context(), s.request, s.body.ceremonyID)
				if err != nil {
					return state, domainFailure(err)
				}
				if s.source.Kind != passkey.RateSourceUser || s.source.UserID != record.UserID || s.source.CeremonyID != s.body.ceremonyID || s.source.Identifier != "" || s.source.AnonymousFlowID != "" || s.source.Lifetime != 5*time.Minute {
					return state, identityhttp.ErrUnavailable
				}
			}
			requestDelivery(r).valid = func() bool { return fresh(s) }
			return state, nil
		},
		Admit: func(r *http.Request, state SessionEnrollmentState) error {
			s := state.value()
			if !fresh(s) {
				return identityhttp.ErrUnavailable
			}
			if !complete {
				return nil
			}
			return rateFailure(c.VerificationRate.AdmitChallenge(r.Context(), s.facts, identityhttp.ChallengeVerificationRateRequest{OperationID: action, UserID: s.source.UserID, ChallengeID: s.source.CeremonyID, ChallengeLifetime: s.source.Lifetime}))
		},
		Handle: func(w http.ResponseWriter, r *http.Request, state SessionEnrollmentState) {
			s := state.value()
			if !fresh(s) {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			if !complete {
				sessionEnrollmentOptions(c, w, r, s, fresh)
				return
			}
			out, nativeErr := c.Service.Register(r.Context(), passkey.NewSessionEnrollmentCompletion(passkey.SessionEnrollmentCompletionSpec{SessionEnrollmentRequest: s.request, CommandID: identity.CommandID(s.body.commandID), CeremonyID: s.body.ceremonyID, Response: s.body.response}))
			result, bindingErr := out.Bindings()
			valid := bindingErr == nil && result.CommandID == identity.CommandID(s.body.commandID) && validSessionEnrollmentReceipt(result.Receipt, result.CommandID, s.request, 2) && result.Outcome == result.Receipt.Outcome
			if valid {
				observeSessionUpdate(r, result.Receipt)
			}
			if nativeErr != nil {
				if valid {
					reject(w, r, domainFailure(nativeErr))
				} else {
					rejectNative(w, r, nativeErr)
				}
				return
			}
			if !valid || result.Outcome != identity.CommitOutcomeCommitted || result.Replayed && result.Credential != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			response := SessionEnrollmentResponse{Registered: true, CommandID: result.CommandID, CommitOutcome: "committed", Replayed: result.Replayed}
			if item := result.Credential; item != nil {
				if item.ReferenceID != string(result.CommandID) || item.Version != 1 || item.State != "active" || item.Label != s.body.label || item.CreatedAt.IsZero() {
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

// SessionEnrollmentResponse exposes acknowledged durability and optional fresh
// safe metadata only, never a challenge, bearer, raw key or session issuance.
type SessionEnrollmentResponse struct {
	Registered    bool                `json:"registered"`
	CommandID     identity.CommandID  `json:"commandID"`
	CommitOutcome string              `json:"commitOutcome"`
	Replayed      bool                `json:"replayed"`
	Credential    *CredentialMetadata `json:"credential,omitempty"`
}

func validSessionEnrollmentReceipt(out identity.CommandResult, id identity.CommandID, custody passkey.SessionEnrollmentRequest, stage int) bool {
	r, err := custody.Bindings()
	if err != nil {
		return false
	}
	op, schema := "identity.passkey.register-options", "identity.passkey.register-options.session-assertion-options-v1"
	if stage == 1 {
		schema = "identity.passkey.register-options.session-registration-options-v1"
	}
	if stage == 2 {
		op, schema = "identity.passkey.register-verify", "identity.passkey.register-verify.session-registration-v1"
	}
	b := out.Binding
	descriptor := identity.FeatureOperation{Owner: "passkey", OperationID: op, SchemaID: schema, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	return id != "" && out.Validate() == nil && out.Feature != nil && out.Feature.Operation == descriptor && b.CommandID == id && b.TenantID == identity.TenantID(r.Caller.Request.Tenant) && b.UserID == identity.UserID(r.Caller.Request.Subject.ID) && b.ActorKind == authorization.SubjectUser && b.ActorID == identity.ActorID(b.UserID) && b.OperationID == op && b.RecordID == string(id) && b.SchemaID == schema && b.SchemaVersion == 1 && b.PolicyVersion == uint64(r.Caller.PolicyRevision) && (out.Outcome != identity.CommitOutcomeCommitted || out.Feature.BeforeVersion == 0 && out.Feature.AfterVersion == 1)
}

func sessionEnrollmentOptions(c SessionEnrollmentConfig, w http.ResponseWriter, r *http.Request, s *sessionEnrollmentState, fresh func(*sessionEnrollmentState) bool) {
	var receipt identity.CommandResult
	var id identity.CommandID
	var replay bool
	var ceremony webauthn.CeremonyRecord
	var has bool
	var transfer func(context.Context, func(context.Context, []byte) error) error
	var ceiling time.Time
	var err error
	stage := 0
	if s.body.enrollmentRegistration {
		stage = 1
		var out passkey.KeyedRegistrationOptionsResult
		out, ceiling, err = c.Service.RegistrationOptionsForDelivery(r.Context(), passkey.NewSessionEnrollmentAuthorization(passkey.SessionEnrollmentAuthorizationSpec{SessionEnrollmentRequest: s.request, IdempotencyKey: s.key, CeremonyID: s.body.ceremonyID, Response: s.body.response}))
		receipt, id, replay = out.Receipt, out.CommandID, out.Replayed
		ceremony, has = out.Options.Ceremony()
		transfer = out.Options.TransferJSON
	} else {
		out, e := c.Service.EnrollmentAssertionOptions(r.Context(), passkey.SessionEnrollmentOptionsRequest{SessionEnrollmentRequest: s.request, IdempotencyKey: s.key})
		err = e
		receipt, id, replay = out.Receipt, out.CommandID, out.Replayed
		ceremony, has = out.Options.Ceremony()
		transfer = out.Options.TransferJSON
	}
	valid := validSessionEnrollmentReceipt(receipt, id, s.request, stage)
	if valid {
		observeSessionUpdate(r, receipt)
	}
	if err != nil {
		if valid {
			reject(w, r, domainFailure(err))
		} else {
			rejectNative(w, r, err)
		}
		return
	}
	if !valid || receipt.Outcome != identity.CommitOutcomeCommitted {
		reject(w, r, identityhttp.ErrUnavailable)
		return
	}
	response := optionsResponse{CommandID: id, CommitOutcome: "committed", Replayed: replay}
	defer func() { clear(response.Options) }()
	deliver := func() bool { return fresh(s) }
	if replay {
		if has || !ceiling.IsZero() {
			reject(w, r, identityhttp.ErrUnavailable)
			return
		}
	} else {
		intent := ceremony.Intent
		if !has || ceremony.ID != string(id) || ceremony.ExpiresAt.IsZero() || intent.Context.CommandID != id || intent.Context.TenantID != receipt.Binding.TenantID || intent.Context.UserID != receipt.Binding.UserID || intent.Context.ActorID != receipt.Binding.ActorID || intent.Context.AnonymousFlowID != "" || intent.Origin != string(c.Origin) || stage == 0 && (intent.Kind != "get" || len(intent.AllowedCredentials) != 1) || stage == 1 && (intent.Kind != "create" || !intent.ResidentKeyRequired || ceiling.IsZero()) {
			reject(w, r, identityhttp.ErrUnavailable)
			return
		}
		// The native B delivery API returns A's genuine absolute ceiling. B's
		// later protocol TTL and the rate source's fixed duration cannot renew it.
		deliver = func() bool {
			now := c.Now()
			return fresh(s) && now.Before(ceremony.ExpiresAt) && (stage == 0 || now.Before(ceiling))
		}
		if !deliver() {
			reject(w, r, identityhttp.ErrUnavailable)
			return
		}
		if err := transfer(r.Context(), func(_ context.Context, wire []byte) error {
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
