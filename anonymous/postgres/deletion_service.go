package anonymouspostgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// DeletionConfig selects authenticated self-disposal of an existing native
// anonymous user. No signin/password implementation is required at construction.
// Install kernel/anonymous/session disposal and request-key preparation histories,
// the actual protected risk-counter history, authorization, audit and outbox.
// Retention is a bounded pure policy callback evaluated outside SQL; this profile
// accepts explicit Allow only, and denies legal holds or deferred erasure rather
// than ignoring them. Cleanup comes from the stored subject, never the request.
// ConfigurationID must change when callback semantics change. Borrow all owner
// pools/keys/clocks until calls finish; no background work is created.
type DeletionConfig struct {
	Repository                Config
	Sessions                  sessionpg.Config
	Profile                   sessionpg.AnonymousAdmissionConfig
	Validation                session.ServiceConfig
	CSRFKeys                  []session.CSRFKey
	Origins, Reasons          []string
	ConfigurationID, PolicyID string
	Retention                 *identity.PolicyEvaluator
	RetentionPolicyVersion    uint64
	RequestKeys               kernel.RequestKeyConfig
	Coordinator               kernel.CoordinatorConfig
	Risk                      riskpg.Config
	IntentKey                 [32]byte
	ActiveEnvelopeKeyID       string
}

// DeletionService composes real primary owners under the existing coordinator.
// It owns neither a transaction/replay ledger nor session/token authority.
// Immutable composition is concurrency-safe, with one private phase per call.
type DeletionService struct {
	pool       *database.Pool
	repository *Repository
	directory  *kernel.Repository
	domain     *kernel.AnonymousDisposalDomain
	sessions   *sessionpg.Repository
	reader     *session.AnonymousSessionService
	effect     *sessionpg.AnonymousDisposalEffect
	risk       *riskpg.Repository
	crypto     *envelope.Service
	config     func() DeletionConfig
	profile    [32]byte
}

var _ anonymous.Deleter = (*DeletionService)(nil)

// NewDeletionService freezes explicit trusted native composition without IO,
// migration, policy callbacks, entropy or session generation. It accepts no
// application-provided store, transaction engine or identity assertion.
func NewDeletionService(pool *database.Pool, c DeletionConfig, keys *keyring.Provider) (*DeletionService, error) {
	if keys == nil || c.Retention == nil || c.RetentionPolicyVersion == 0 || !signinText(c.ConfigurationID, 128) || !signinText(c.PolicyID, 128) || !signinText(c.ActiveEnvelopeKeyID, 256) || c.IntentKey == ([32]byte{}) || !signinURLs(c.Origins, true) || len(c.Reasons) == 0 || len(c.Reasons) > 32 || len(c.CSRFKeys) == 0 || len(c.CSRFKeys) > 4 || c.Coordinator.QueryPolicy == nil || c.Coordinator.AdmissionPolicy == nil || c.Coordinator.AdmissionPolicy.PolicyVersion != c.RequestKeys.Policy.PolicyVersion || c.Risk.PolicyVersion != c.RequestKeys.Policy.PolicyVersion || c.Risk.CommandCounters == nil {
		return nil, anonymous.ErrInvalidInput
	}
	for n, k := range c.CSRFKeys {
		if k.Version() == 0 {
			return nil, anonymous.ErrInvalidInput
		}
		for _, old := range c.CSRFKeys[:n] {
			if k.Version() == old.Version() {
				return nil, anonymous.ErrInvalidInput
			}
		}
	}
	for n, reason := range c.Reasons {
		if !signinText(reason, 64) || slices.Contains(c.Reasons[:n], reason) {
			return nil, anonymous.ErrInvalidInput
		}
	}
	r, err := NewRepository(pool, c.Repository)
	if err != nil {
		return nil, err
	}
	d, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: c.Repository.MaximumDuration})
	if err != nil {
		return nil, anonymous.ErrInvalidInput
	}
	domain, err := kernel.NewAnonymousDisposalDomain(d)
	if err != nil {
		return nil, err
	}
	sessions, err := sessionpg.NewRepository(pool, c.Sessions)
	if err != nil {
		return nil, anonymous.ErrInvalidInput
	}
	reader, err := NewSessionService(pool, SessionServiceConfig{Repository: c.Repository, Sessions: c.Sessions, Profile: c.Profile, Validation: c.Validation})
	if err != nil {
		return nil, err
	}
	effect, err := sessionpg.NewAnonymousDisposalEffect(c.Sessions)
	if err != nil {
		return nil, err
	}
	protected, err := riskpg.NewRepository(c.Risk)
	if err != nil {
		return nil, anonymous.ErrInvalidInput
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		return nil, anonymous.ErrInvalidInput
	}
	c.CSRFKeys = slices.Clone(c.CSRFKeys)
	c.Origins = slices.Clone(c.Origins)
	c.Reasons = slices.Clone(c.Reasons)
	c.Validation.LookupKeys = slices.Clone(c.Validation.LookupKeys)
	c.Coordinator.RetainedFingerprintKeys = maps.Clone(c.Coordinator.RetainedFingerprintKeys)
	q, a := *c.Coordinator.QueryPolicy, *c.Coordinator.AdmissionPolicy
	c.Coordinator.QueryPolicy, c.Coordinator.AdmissionPolicy = &q, &a
	frame, err := json.Marshal(struct {
		Configuration, Policy, Namespace, Schema, SessionSchema string
		Profile                                                 sessionpg.AnonymousAdmissionConfig
		PolicyVersion, RetentionVersion                         uint64
		Origins, Reasons                                        []string
	}{c.ConfigurationID, c.PolicyID, c.RequestKeys.Namespace, c.Repository.Schema, c.Sessions.Schema, c.Profile, a.PolicyVersion, c.RetentionPolicyVersion, c.Origins, c.Reasons})
	if err != nil {
		return nil, anonymous.ErrInvalidInput
	}
	profile := sha256.Sum256(frame)
	clear(frame)
	s := &DeletionService{pool: pool, repository: r, directory: d, domain: domain, sessions: sessions, reader: reader, effect: effect, risk: protected, crypto: crypto, config: func() DeletionConfig { return c }, profile: profile}
	if _, _, err := s.coordinator(&deletionPhase{service: s}); err != nil {
		return nil, anonymous.ErrInvalidInput
	}
	return s, nil
}

func (s *DeletionService) coordinator(p *deletionPhase) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	a, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, err
	}
	l, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, nil, err
	}
	r, err := kernel.NewContributorRegistry([]kernel.Contributor{s.directory, s.risk, a, l, p})
	if err != nil {
		return nil, nil, err
	}
	c, err := kernel.NewCoordinatorWithRequestKeys(s.pool, r, s.config().Coordinator, s.config().RequestKeys)
	return c, r, err
}

func (s *DeletionService) caller(tenant identity.TenantID, user identity.UserID, action, kind, id string) authorization.DecisionContext {
	return authorization.DecisionContext{PolicyRevision: authorization.Revision(s.config().RequestKeys.Policy.PolicyVersion), Request: authorization.Request{Tenant: authorization.TenantID(tenant), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(user)}, Action: authorization.Action(action), Resource: authorization.Resource{Type: authorization.ResourceType(kind), ID: authorization.ResourceID(id)}}}
}

func (s *DeletionService) possesses(tenant identity.TenantID, credential session.Credential, csrf session.CSRFToken, source session.Session) bool {
	spec, err := source.Bindings()
	if err != nil || spec.TenantID != tenant || spec.Authentication.Kind != session.AuthenticationAnonymous {
		return false
	}
	matched := false
	for _, key := range s.config().Validation.LookupKeys {
		d, e := credential.Digest(key, string(tenant))
		if e == nil && d.KeyVersion == spec.Lookup.KeyVersion && subtle.ConstantTimeCompare(d.Sum[:], spec.Lookup.Sum[:]) == 1 {
			matched = true
		}
	}
	if !matched {
		return false
	}
	state := source.CSRFState()
	for _, key := range s.config().CSRFKeys {
		if state.Check(session.CSRFBinding{TenantID: tenant, SessionID: spec.SessionID, SessionVersion: spec.Version}, csrf, key) == nil {
			return true
		}
	}
	return false
}

// retainedSource is possession lookup only, including revoked rows. It may
// select the original keyed metadata scope, never authorize a fresh deletion.
// Fresh preparation independently invokes the complete anonymous session reader.
func (s *DeletionService) retainedSource(ctx context.Context, r anonymous.DeletionRequest) (session.Session, error) {
	var result session.Session
	for _, key := range s.config().Validation.LookupKeys {
		d, err := r.Credential.Digest(key, string(r.TenantID))
		if err != nil {
			return session.Session{}, anonymous.ErrInvalidInput
		}
		row, err := s.sessions.Lookup(ctx, r.TenantID, d)
		if errors.Is(err, sessionpg.ErrRecordAbsent) {
			continue
		}
		if err != nil {
			return session.Session{}, err
		}
		if result != (session.Session{}) {
			return session.Session{}, identity.ForbiddenError{}
		}
		result = row.Session
	}
	if result == (session.Session{}) || !s.possesses(r.TenantID, r.Credential, r.CSRFToken, result) {
		return session.Session{}, identity.ForbiddenError{}
	}
	return result, nil
}

func (s *DeletionService) intent(r anonymous.DeletionRequest, source session.Session) (identity.RequestIntent, error) {
	spec, err := source.Bindings()
	if err != nil {
		return identity.RequestIntent{}, anonymous.ErrInvalidInput
	}
	csrf, err := source.CSRFState().Bindings()
	if err != nil {
		return identity.RequestIntent{}, anonymous.ErrInvalidInput
	}
	frame, err := json.Marshal(struct {
		Tenant                          identity.TenantID
		Session                         string
		Version                         uint64
		Lookup                          session.TokenDigest
		CSRF                            session.CSRFStateSpec
		Origin, Network, Device, Reason string
		Expected                        uint64
	}{r.TenantID, spec.SessionID, spec.Version, spec.Lookup, csrf, r.Origin, r.Network, r.Device, r.Reason, r.ExpectedVersion})
	if err != nil {
		return identity.RequestIntent{}, anonymous.ErrInvalidInput
	}
	defer clear(frame)
	key := s.config().IntentKey
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte("identity-anonymous-delete-intent-v1\x00"))
	mac.Write(frame)
	return identity.NewRequestIntent([]identity.FeatureField{{Name: "profile", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: s.profile[:]}}, {Name: "input", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: mac.Sum(nil)}}})
}

// Delete binds the actual anonymous bearer/CSRF and original retry intent.
// Only a new command can enter live admission. Exact terminal retries return
// metadata, never reactivate a user, reevaluate retention or revoke twice.
func (s *DeletionService) Delete(ctx context.Context, r anonymous.DeletionRequest) (out anonymous.DeletionResult, err error) {
	if ctx == nil || s == nil || s.config == nil || r.Validate() != nil {
		return out, anonymous.ErrInvalidInput
	}
	ctx, stop := context.WithTimeout(ctx, s.config().Repository.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if err != nil || ctx.Err() != nil {
			err = signinPublicError(ctx, err)
			if ctx.Err() == nil && out.Outcome == identity.CommitOutcomeUnknown && out.Recovery.CommandID != "" {
				err = identity.UnknownCommitError{CommandID: out.Recovery.CommandID}
			}
		}
	}()
	if !slices.Contains(s.config().Origins, r.Origin) || !slices.Contains(s.config().Reasons, r.Reason) {
		return out, identity.ForbiddenError{}
	}
	source, err := s.retainedSource(ctx, r)
	if err != nil {
		return out, err
	}
	spec, _ := source.Bindings()
	intent, err := s.intent(r, source)
	if err != nil {
		return out, err
	}
	p := &deletionPhase{service: s, request: r}
	p.coordinator, p.registry, err = s.coordinator(p)
	if err != nil {
		return out, err
	}
	scope := kernel.RequestKeyScope{TenantID: r.TenantID, ActorID: identity.ActorID(spec.UserID), ActorKind: authorization.SubjectUser, Method: "POST", RouteID: deletionOperation().OperationID}
	caller := s.caller(r.TenantID, spec.UserID, deletionOperation().OperationID, "identity.request-admission", deletionOperation().OperationID)
	k, wire, err := p.coordinator.ResolvePreparedRequestKey(ctx, scope, r.IdempotencyKey, intent, caller, p.registration(), p)
	if err != nil {
		return out, err
	}
	defer clear(wire)
	if err = p.restore(ctx, k, wire, intent); err != nil {
		return out, err
	}
	if !s.possesses(r.TenantID, r.Credential, r.CSRFToken, p.source) {
		return out, identity.ForbiddenError{}
	}
	b := p.input.Command.Binding
	out.Recovery = deletionQuery(b)
	out.Outcome = identity.CommitOutcomeUnknown
	plan, err := p.plan()
	if err != nil {
		return out, err
	}
	reservation, receipt, err := p.coordinator.ReserveCommand(ctx, b, p.command, plan)
	if receipt.Outcome != identity.CommitOutcomeInvalid {
		out.Outcome = receipt.Outcome
	}
	out.RetryAfter = receipt.RetryAfter
	if err != nil || reservation == (kernel.Reservation{}) {
		out.Replayed = err == nil && receipt.Outcome == identity.CommitOutcomeCommitted
		return out, err
	}
	w, err := p.coordinator.Begin(ctx, reservation)
	if err != nil {
		return out, err
	}
	defer p.coordinator.Abort(w, identity.UnavailableError{})
	provisional, err := p.coordinator.ApplyFeature(ctx, w, p.command)
	if err != nil {
		receipt, err = p.coordinator.Abort(w, err)
	} else {
		receipt, err = p.coordinator.Commit(w, provisional)
	}
	if receipt.Outcome != identity.CommitOutcomeInvalid {
		out.Outcome = receipt.Outcome
	}
	out.RetryAfter = receipt.RetryAfter
	return out, err
}

// RecoverDeletion authenticates original encrypted input plus original bearer/
// CSRF possession, even after self-revocation or session payload cleanup. It
// only asks the existing coordinator to reconcile retained owner evidence.
// No live permission, retention reevaluation, issuance or reexecution occurs.
func (s *DeletionService) RecoverDeletion(ctx context.Context, r anonymous.DeletionRecoveryRequest) (out anonymous.DeletionResult, err error) {
	if ctx == nil || s == nil || s.config == nil || r.Validate() != nil {
		return out, anonymous.ErrInvalidInput
	}
	ctx, stop := context.WithTimeout(ctx, s.config().Repository.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if err != nil || ctx.Err() != nil {
			err = signinPublicError(ctx, err)
		}
	}()
	p := &deletionPhase{service: s}
	p.coordinator, p.registry, err = s.coordinator(p)
	if err != nil {
		return out, err
	}
	q := r.Recovery
	caller := s.caller(q.TenantID, q.UserID, q.OperationID, "identity.user", string(q.UserID))
	k, wire, err := p.coordinator.QueryRequestPreparation(ctx, q, caller, p.registration(), p)
	if err != nil {
		return out, err
	}
	defer clear(wire)
	if err = p.restore(ctx, k, wire, identity.RequestIntent{}); err != nil || deletionQuery(p.input.Command.Binding) != q {
		return out, identity.ForbiddenError{}
	}
	if r.Origin != p.input.Origin || r.Network != p.input.Network || r.Device != p.input.Device || !s.possesses(q.TenantID, r.Credential, r.CSRFToken, p.source) {
		return out, identity.ForbiddenError{}
	}
	out.Recovery, out.Outcome, out.Replayed = q, identity.CommitOutcomeUnknown, true
	receipt, err := p.coordinator.RecoverFeatureCommand(ctx, q, caller)
	if receipt.Outcome != identity.CommitOutcomeInvalid {
		out.Outcome = receipt.Outcome
	}
	out.RetryAfter = receipt.RetryAfter
	return out, err
}

func deletionQuery(b identity.CommandBinding) identity.RecoveryQuery {
	return identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
}

type deletionStoredKernel struct {
	User                                        identity.User
	Placeholder                                 identity.Identifier
	UserEpoch, IdentifierEpoch, CredentialEpoch uint64
	Hold                                        bool
	HoldVersion                                 uint64
	Action                                      kernel.AnonymousDisposalAction
	RetentionVersion                            uint64
}

func storeDeletionKernel(i kernel.AnonymousDisposalIntent) deletionStoredKernel {
	a := i.Snapshot.Authority
	return deletionStoredKernel{a.User, a.Placeholder, a.UserAuthorityVersion, a.IdentifierAuthorityVersion, a.CredentialAuthorityVersion, i.Snapshot.LegalHold, i.Snapshot.LegalHoldVersion, i.Action, i.RetentionPolicyVersion}
}
func (i deletionStoredKernel) intent() kernel.AnonymousDisposalIntent {
	return kernel.AnonymousDisposalIntent{Snapshot: kernel.AnonymousDisposalSnapshot{Authority: kernel.AnonymousAuthorityRecord{User: i.User, Placeholder: i.Placeholder, UserAuthorityVersion: i.UserEpoch, IdentifierAuthorityVersion: i.IdentifierEpoch, CredentialAuthorityVersion: i.CredentialEpoch}, LegalHold: i.Hold, LegalHoldVersion: i.HoldVersion}, Action: i.Action, RetentionPolicyVersion: i.RetentionVersion}
}

type deletionInput struct {
	Schema                  uint8
	Command                 identity.FeatureCommandSpec
	Kernel                  deletionStoredKernel
	Counters                deletionStoredCounters
	Intent                  []identity.FeatureField
	Until, PreparedAt       time.Time
	Origin, Network, Device string
}

// Explicit private envelope projection: the public plan deliberately rejects
// generic serialization, including when nested inside another struct.
type deletionStoredCounters kernel.CommandCounterPlan

type deletionPhase struct {
	service     *DeletionService
	request     anonymous.DeletionRequest
	coordinator *kernel.Coordinator
	registry    *kernel.ContributorRegistry
	input       deletionInput
	command     identity.Command
	source      session.Session
}

func (*deletionPhase) Descriptor() kernel.ContributorDescriptor { return creationOwner() }
func (*deletionPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{deletionOperation()}
}
func (p *deletionPhase) registration() kernel.FeatureRegistration {
	return kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: deletionOperation()}
}

func (p *deletionPhase) aad(k kernel.RequestKeyPreparationBinding) (envelope.Context, error) {
	c := p.service.config()
	if k.Feature != p.registration() || k.Scope.Method != "POST" || k.Scope.RouteID != deletionOperation().OperationID || k.Scope.ActorKind != authorization.SubjectUser || k.Namespace != c.RequestKeys.Namespace || k.PolicyVersion != c.RequestKeys.Policy.PolicyVersion || k.IntentDigest == ([32]byte{}) || k.Admission.FingerprintKeyVersion == 0 {
		return envelope.Context{}, anonymous.ErrInvalidInput
	}
	if _, err := identity.ParseCommandID(string(k.Admission.CommandID)); err != nil {
		return envelope.Context{}, err
	}
	frame, err := json.Marshal(struct {
		Binding signinStoredKey
		Profile [32]byte
	}{signinStoredKey(k), p.service.profile})
	if err != nil {
		return envelope.Context{}, err
	}
	defer clear(frame)
	sum := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"profile": "identity-anonymous-delete-input-v1", "binding": base64.RawURLEncoding.EncodeToString(sum[:])})
}

func (p *deletionPhase) PrepareRequestKey(ctx context.Context, k kernel.RequestKeyPreparationBinding, intent identity.RequestIntent) ([]byte, error) {
	s, c, r := p.service, p.service.config(), p.request
	aad, err := p.aad(k)
	if err != nil || r.Validate() != nil {
		return nil, anonymous.ErrInvalidInput
	}
	guest, err := s.reader.Get(ctx, session.GetRequest{TenantID: r.TenantID, Credential: r.Credential})
	if err != nil {
		return nil, err
	}
	if !guest.Recognized || guest.ValidateAt(c.Validation.Clock.Now()) != nil {
		return nil, identity.ForbiddenError{}
	}
	source, err := guest.Session.Bindings()
	if err != nil || source.TenantID != k.Scope.TenantID || string(source.UserID) != string(k.Scope.ActorID) || !s.possesses(r.TenantID, r.Credential, r.CSRFToken, guest.Session) {
		return nil, identity.ForbiddenError{}
	}
	snapshot, err := s.directory.GetAnonymousDisposal(ctx, identity.UserStatusQuery{TenantID: r.TenantID, UserID: source.UserID})
	if err != nil {
		return nil, err
	}
	subject, err := s.repository.Read(ctx, anonymous.SubjectQuery{TenantID: r.TenantID, UserID: source.UserID})
	if err != nil {
		return nil, err
	}
	record, _ := subject.Record()
	if record.Version != r.ExpectedVersion || record.State != anonymous.StateActive || record.Version != 1 || subject.RequireActive(r.TenantID, c.Validation.Clock.Now()) != nil {
		return nil, identity.ForbiddenError{}
	}
	until := guest.ValidUntil()
	now := c.Validation.Clock.Now()
	if guest.ValidateAt(now) != nil {
		return nil, identity.ForbiddenError{}
	}
	b := identity.CommandBinding{CommandID: k.Admission.CommandID, TenantID: r.TenantID, UserID: source.UserID, ActorID: identity.ActorID(source.UserID), ActorKind: authorization.SubjectUser, OperationID: deletionOperation().OperationID, SchemaID: deletionOperation().SchemaID, SchemaVersion: 1, PolicyID: c.PolicyID, PolicyVersion: k.PolicyVersion, CorrelationID: string(k.Admission.CommandID), RecordID: string(source.UserID)}
	decision, err := c.Coordinator.AdmissionPolicy.Authorization.Decide(ctx, s.caller(b.TenantID, b.UserID, b.OperationID, "identity.anonymous", string(b.UserID)))
	if err != nil || decision.Outcome != authorization.Allow || decision.Revision != authorization.Revision(b.PolicyVersion) {
		return nil, identity.ForbiddenError{}
	}
	action := identity.RetentionDelete
	disposal := kernel.AnonymousDisposeDelete
	if record.Cleanup == anonymous.CleanupAnonymize {
		action, disposal = identity.RetentionAnonymize, kernel.AnonymousDisposeAnonymize
	}
	if record.Cleanup == anonymous.CleanupRetain {
		disposal = kernel.AnonymousDisposeRetain
	}
	retention, err := c.Retention.DecideRetention(ctx, identity.RetentionPolicyInput{TenantID: b.TenantID, ActorID: b.ActorID, SubjectID: b.UserID, OperationID: b.OperationID, PolicyVersion: c.RetentionPolicyVersion, Deadline: until, Resource: identity.RetentionResource{Kind: "anonymous", ID: string(b.UserID)}, Action: action, LegalHold: snapshot.LegalHold, RequestedAt: now})
	if err != nil || retention.Disposition != identity.RetentionAllow {
		return nil, identity.ForbiddenError{}
	}
	i := kernel.AnonymousDisposalIntent{Snapshot: snapshot, Action: disposal, RetentionPolicyVersion: c.RetentionPolicyVersion}
	owned, err := kernel.AnonymousDisposalFields(i)
	if err != nil {
		return nil, identity.ForbiddenError{}
	}
	fields, err := DeletionFields(subject)
	if err != nil {
		return nil, err
	}
	fields = append(fields, owned...)
	owned, err = sessionpg.AnonymousSourceSessionFields(guest.Session)
	if err != nil {
		return nil, err
	}
	fields = append(fields, owned...)
	originalIntent, ok := intent.Fields()
	if !ok {
		return nil, anonymous.ErrInvalidInput
	}
	for _, f := range originalIntent {
		f.Name = "anonymous.request." + f.Name
		fields = append(fields, f)
	}
	fields = append(fields, identity.FeatureField{Name: "anonymous.valid-until", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: until}})
	command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: deletionOperation(), Fields: fields})
	if err != nil {
		return nil, err
	}
	var at time.Time
	if err := s.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		return nil, identity.UnavailableError{}
	}
	if !at.Before(until) || guest.ValidateAt(c.Validation.Clock.Now()) != nil {
		return nil, identity.ForbiddenError{}
	}
	command, counters, err := s.risk.PrepareCommandCounters(command, risk.Subject{User: string(source.UserID), Session: source.SessionID, Network: r.Network}, at.UTC())
	if err != nil {
		return nil, identity.ForbiddenError{}
	}
	feature, _ := command.Feature()
	input := deletionInput{Schema: 1, Command: feature, Kernel: storeDeletionKernel(i), Counters: deletionStoredCounters(counters), Intent: originalIntent, Until: until, PreparedAt: at.UTC(), Origin: r.Origin, Network: r.Network, Device: r.Device}
	return sealAnonymousInput(ctx, s.crypto, c.ActiveEnvelopeKeyID, aad, input)
}

func (p *deletionPhase) restore(ctx context.Context, k kernel.RequestKeyPreparationBinding, wire []byte, intent identity.RequestIntent) error {
	aad, err := p.aad(k)
	if err != nil {
		return err
	}
	var input deletionInput
	if err := openAnonymousInput(ctx, p.service.crypto, aad, wire, &input); err != nil {
		return err
	}
	b := input.Command.Binding
	if input.Schema != 1 || b.CommandID != k.Admission.CommandID || b.TenantID != k.Scope.TenantID || b.ActorID != k.Scope.ActorID || b.ActorKind != k.Scope.ActorKind || b.UserID != identity.UserID(k.Scope.ActorID) || b.RecordID != string(b.UserID) || b.PolicyID != p.service.config().PolicyID || b.PolicyVersion != k.PolicyVersion || input.Command.Operation != deletionOperation() || !readInstant(input.PreparedAt) || !input.Until.After(input.PreparedAt) || input.Until.Sub(input.PreparedAt) > 20*time.Second {
		return anonymous.ErrInvalidInput
	}
	if f, ok := intent.Fields(); ok && !reflect.DeepEqual(f, input.Intent) {
		return identity.ConflictError{}
	}
	command, err := identity.NewFeatureCommand(input.Command)
	if err != nil {
		return err
	}
	if err := p.service.risk.ValidateCommandCounters(command, kernel.CommandCounterPlan(input.Counters)); err != nil {
		return err
	}
	fields := make([]identity.FeatureField, 0, 100)
	for _, field := range input.Command.Fields {
		if strings.HasPrefix(field.Name, "anonymous.source-session.") {
			fields = append(fields, field)
		}
	}
	source, err := sessionpg.AnonymousSourceSessionFromFields(b.TenantID, b.UserID, fields)
	if err != nil {
		return err
	}
	if _, err := deletionSubject(command); err != nil {
		return err
	}
	if _, err := kernel.AnonymousDisposalFields(input.Kernel.intent()); err != nil {
		return err
	}
	p.input, p.command, p.source = input, command, source
	return nil
}

func (DeletionConfig) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("anonymouspostgres.DeletionConfig(redacted)"))
}
func (DeletionConfig) MarshalJSON() ([]byte, error) { return nil, anonymous.ErrDisclosure }
func (DeletionConfig) MarshalText() ([]byte, error) { return nil, anonymous.ErrDisclosure }
func (*DeletionService) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("anonymouspostgres.DeletionService(redacted)"))
}
func (*DeletionService) MarshalJSON() ([]byte, error) { return nil, anonymous.ErrDisclosure }
