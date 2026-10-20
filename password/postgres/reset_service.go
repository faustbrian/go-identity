package passwordpostgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	primitive "github.com/faustbrian/go-password/v2"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// ResetConfig is immutable native reset composition, not transport
// input. Issuer owns durable provenance; its exact Crypto config also creates
// the verifier used before hashing. Screening owns HIBP and password policy;
// Risk owns counted Authentication admission. QueryPolicy and AdmissionPolicy
// must be selected. GlobalAuthorityID and AuthorizationNamespace select actual
// primary authority, never default epochs. ConfigurationID pins borrowed
// callback semantics; change it when those semantics change. IdentifierKey is
// a separate private risk-attribution key. Retain original issuer, profile and
// command keys while historical workflow custody remains supported.
type ResetConfig struct {
	Repository                Config
	ConfigurationID, PolicyID string
	Profile                   password.ResetProfileConfig
	Issuer                    issuerpg.IssuerConfig
	Screening                 password.HashPreparationConfig
	// CollectReset selects attributed screening instead of Screening.Collect.
	// Exactly one collector is required. Native generation supplies original
	// command metadata and the authenticated issuer challenge before password
	// work; callers must not reconstruct these from transport correlation.
	CollectReset                              ResetScreeningCollector
	Risk                                      risk.AuthenticationAdmissionCustodyConfig
	Coordinator                               kernel.CoordinatorConfig
	Session                                   sessionpg.Config
	GlobalAuthorityID, AuthorizationNamespace string
	Origins                                   []string
	ActiveEnvelopeKeyID                       string
	IdentifierKey                             [32]byte
	// Request selects public request issuance/delivery. Nil preserves completion-
	// only composition; ResetRequest and its recovery then deny explicitly.
	Request *ResetRequestConfig
}

// ResetScreeningCollector synchronously borrows an exact candidate after native
// issuer provenance, original scope, proof and counted admission validation.
// Binding is the immutable original command, not today's transport attempt;
// challengeID is the verified grant ID matched to durable consumption custody.
// The collector owns provider/audit composition, honors ctx, retains no secret,
// and returns exactly one HIBP signal or an error. Unknown required audit delivery
// must deny and retain records through the existing audit reconciliation owner.
// Dependencies must be concurrency-safe. Recovery never invokes this callback.
type ResetScreeningCollector = func(context.Context, identity.CommandBinding, string, risk.Context, primitive.Secret) ([]risk.Signal, error)

// Format hides key material and runtime dependencies from diagnostics.
func (ResetConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passwordpostgres.ResetConfig(redacted)"))
}

// MarshalJSON denies serialization of native secret-bearing composition.
func (ResetConfig) MarshalJSON() ([]byte, error) { return nil, password.ErrSensitiveSerialization }

// MarshalText denies implicit textual export of native composition.
func (ResetConfig) MarshalText() ([]byte, error) { return nil, password.ErrSensitiveSerialization }

// LogValue hides secret-bearing composition from structured logging.
func (ResetConfig) LogValue() slog.Value {
	return slog.StringValue("passwordpostgres.ResetConfig(redacted)")
}

// ResetService owns native public request/completion and proof-free recovery through
// real issuance, primary factor/credential authority, one-use, password material,
// session revocation, audit and lifecycle owners. It borrows the primary pool
// and local keyring and owns no goroutines, automatic retries or extra journal.
// Optional Request composition enables enumeration-safe request issuance and
// encrypted delivery. A nil Request remains completion-only and denies request
// methods. HTTP/reference exposure must be selected and composed separately.
type ResetService struct {
	pool          *database.Pool
	repository    *Repository
	directory     *kernel.Repository
	authority     *authoritypg.AuthorityStore
	issuer        *issuerpg.Issuer
	verifier      capability.Service
	crypto        *envelope.Service
	profile       password.ResetProfile
	configuration [32]byte
	config        func() ResetConfig
	request       *resetRequestRuntime
}

// NewResetService freezes configuration without IO, password work, migration
// or callbacks. Install native reset/preparation/admission, factor authority,
// password replacement, session-reset, issuance provenance, audit and outbox
// histories before use. Local keyring custody excludes network decryption under
// restoration locks. Every dependency must be concurrent-safe and bounded.
func NewResetService(pool *database.Pool, c ResetConfig, keys *keyring.Provider) (*ResetService, error) {
	if keys == nil || !reauthenticationText(c.ConfigurationID, 128) || !reauthenticationText(c.PolicyID, 128) || !reauthenticationText(c.GlobalAuthorityID, 128) || !reauthenticationText(c.AuthorizationNamespace, 128) || !reauthenticationText(c.ActiveEnvelopeKeyID, 256) || c.IdentifierKey == ([32]byte{}) || !signinURLs(c.Origins, true) || c.Coordinator.AdmissionPolicy == nil || c.Coordinator.QueryPolicy == nil || c.Profile.Audience != c.Issuer.Audience {
		return nil, password.ErrPasswordWork
	}
	screening := c.Screening
	if c.CollectReset != nil {
		if screening.Collect != nil {
			return nil, password.ErrPasswordWork
		}
		// Validate the shared profile without invoking a provider. Generation
		// replaces this fail-closed callback only after authenticated custody.
		screening.Collect = func(context.Context, risk.Context, primitive.Secret) ([]risk.Signal, error) {
			return nil, password.ErrPasswordWork
		}
	}
	if _, err := password.NewHashPreparer(screening); err != nil || !signinCurrentHash(c.Screening.DummyHash, c.Repository.HashPolicy) {
		return nil, password.ErrPasswordWork
	}
	repository, err := NewRepository(pool, c.Repository)
	if err != nil {
		return nil, err
	}
	directory, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: c.Repository.MaximumDuration})
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	authority, err := authoritypg.NewAuthorityStore(pool.Raw(), c.Repository.MaximumDuration)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	issuer, err := issuerpg.NewIssuer(c.Issuer)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	verifier, err := capability.NewService(c.Issuer.Crypto)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	profile, err := password.NewResetProfile(c.Profile)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	if _, err := risk.NewAuthenticationAdmissionCustody(c.Risk); err != nil {
		return nil, password.ErrPasswordWork
	}
	if _, err := sessionpg.NewPasswordResetEffect(c.Session); err != nil {
		return nil, password.ErrPasswordWork
	}
	c.Origins = slices.Clone(c.Origins)
	c.Profile.Callbacks = slices.Clone(c.Profile.Callbacks)
	c.Profile.RetainedBindingKeys = maps.Clone(c.Profile.RetainedBindingKeys)
	c.Issuer.RetainedReplayKeys = maps.Clone(c.Issuer.RetainedReplayKeys)
	c.Risk.Keys = slices.Clone(c.Risk.Keys)
	c.Coordinator.RetainedFingerprintKeys = maps.Clone(c.Coordinator.RetainedFingerprintKeys)
	query, admission := *c.Coordinator.QueryPolicy, *c.Coordinator.AdmissionPolicy
	c.Coordinator.QueryPolicy, c.Coordinator.AdmissionPolicy = &query, &admission
	p := c.Screening.Primitive.Policy()
	frame, err := json.Marshal(struct {
		Domain, Configuration, Policy, Risk, Global, Namespace, Issuer, Audience, Algorithm string
		PolicyVersion, QueryVersion                                                         uint64
		Minimum, Maximum                                                                    uint32
		Lifetime, Timeout                                                                   time.Duration
		Parameters, Limits                                                                  any
		Dummy                                                                               [32]byte
		Origins, Callbacks                                                                  []string
		AttributedScreening                                                                 bool `json:",omitempty"`
	}{"identity-password-reset-native-v1", c.ConfigurationID, c.PolicyID, c.Risk.ConfigurationID, c.GlobalAuthorityID, c.AuthorizationNamespace, c.Profile.Issuer, c.Profile.Audience, string(p.Algorithm()), admission.PolicyVersion, query.PolicyVersion, uint32(c.Screening.MinimumBytes), uint32(c.Screening.MaximumBytes), c.Profile.MaximumLifetime, c.Screening.Timeout, p.Argon2idParameters(), p.Limits(), sha256.Sum256([]byte(c.Screening.DummyHash.String())), c.Origins, c.Profile.Callbacks, c.CollectReset != nil})
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	digest := sha256.Sum256(frame)
	clear(frame)
	s := &ResetService{pool: pool, repository: repository, directory: directory, authority: authority, issuer: issuer, verifier: verifier, crypto: crypto, profile: profile, configuration: digest, config: func() ResetConfig { return c }}
	if c.Request != nil {
		request := *c.Request
		request.Delivery.Locales = slices.Clone(request.Delivery.Locales)
		c.Request = &request
		s.request, err = s.newRequestRuntime(request)
		if err != nil {
			return nil, password.ErrPasswordWork
		}
	}
	if _, _, err := s.completionCoordinator(&resetCompletionPhase{repository: repository}); err != nil {
		return nil, password.ErrPasswordWork
	}
	return s, nil
}

func (s *ResetService) completionCoordinator(p *resetCompletionPhase) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	audits, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, err
	}
	outbox, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, nil, err
	}
	effect, err := sessionpg.NewPasswordResetEffect(s.config().Session)
	if err != nil {
		return nil, nil, err
	}
	p.repository, p.sessions = s.repository, effect
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{s.directory, audits, outbox, p, issuerpg.NewParticipant()})
	if err != nil {
		return nil, nil, err
	}
	coordinator, err := kernel.NewCoordinator(s.pool, registry, s.config().Coordinator)
	p.coordinator = coordinator
	return coordinator, registry, err
}

// ResetComplete verifies the actual original issued proof, derives its target
// without caller overrides and executes original-password preparation once.
// Current primary account, identifier, factor, authorization and password
// predecessors are fenced before hashing and again at atomic completion. Reset
// consumes one use with replacement, all-session revocation, audit and lifecycle.
// Matching retries restore original CAS and return the original receipt without
// providers or hashing; changed raw password/proof bytes conflict. No session,
// token, address or hash is returned. Borrowed input custody is never destroyed.
// Earlier deadlines win; uncertainty preserves CommandID and Unknown. Separate
// proof-free recovery does not regenerate or require a still-valid bearer.
func (s *ResetService) ResetComplete(ctx context.Context, r password.ResetCompleteRequest) (out password.ResetCompleteResult, err error) {
	if ctx == nil || s == nil || s.config == nil || r.Validate() != nil {
		return out, password.ErrPasswordWork
	}
	c := s.config()
	ctx, stop := context.WithTimeout(ctx, c.Repository.MaximumDuration)
	defer stop()
	started := false
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
			if started {
				out = password.ResetCompleteResult{CommandID: r.CommandID, Outcome: identity.CommitOutcomeUnknown}
				err = identity.UnknownCommitError{CommandID: r.CommandID}
			}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
	}()
	if !slices.Contains(c.Origins, r.Origin) {
		return out, identity.ForbiddenError{}
	}
	grant, originID, replayVersion, err := s.issuer.ReadIssuanceOrigin(ctx, s.pool, r.Token, "identity.password.reset-complete")
	if err != nil {
		return out, err
	}
	origin, err := s.profile.ResolveOriginal(grant, time.Now().UTC())
	if err != nil || origin.TenantID != r.TenantID || origin.OriginCommandID != originID || origin.FactorVersion == 0 || r.CommandID == originID {
		return out, identity.ForbiddenError{}
	}
	caller := r.Caller.Clone()
	if caller.Request.Resource.Type != "identity.user" || caller.Request.Resource.ID != "" && caller.Request.Resource.ID != authorization.ResourceID(origin.UserID) {
		return out, identity.ForbiddenError{}
	}
	caller.Request.Resource.ID = authorization.ResourceID(origin.UserID)
	p := &resetCompletionPhase{profile: s.profile, origin: origin, grant: grant, screening: c.Screening, collectReset: c.CollectReset, verifier: s.verifier, crypto: s.crypto, envelopeKey: c.ActiveEnvelopeKeyID, configuration: s.configuration, riskConfig: c.Risk, subject: risk.Subject{Network: r.Network, Device: r.Device}}
	coordinator, registry, err := s.completionCoordinator(p)
	if err != nil {
		return out, password.ErrPasswordWork
	}
	q := identity.RecoveryQuery{CommandID: r.CommandID, TenantID: r.TenantID, UserID: origin.UserID, ActorID: identity.ActorID(caller.Request.Subject.ID), ActorKind: caller.Request.Subject.Kind, OperationID: resetOperation().OperationID, RecordID: string(origin.CredentialID)}
	observation, observeErr := coordinator.ObserveCommandAdmission(ctx, q, caller)
	if observation.Validate() != nil {
		var unavailable identity.UnavailableError
		if !errors.As(observeErr, &unavailable) {
			return out, observeErr
		}
	}
	var spec identity.FeatureCommandSpec
	if observation.Absent {
		// Original command correlation is stable across independently correlated
		// transport attempts; it grants no permission and selects no subject.
		b := identity.CommandBinding{CommandID: r.CommandID, TenantID: r.TenantID, UserID: origin.UserID, ActorID: q.ActorID, ActorKind: q.ActorKind, OperationID: q.OperationID, SchemaID: resetOperation().SchemaID, SchemaVersion: 1, RecordID: q.RecordID, PolicyID: c.PolicyID, PolicyVersion: c.Coordinator.AdmissionPolicy.PolicyVersion, CorrelationID: string(r.CommandID)}
		if err := s.selectResetCompletion(ctx, p, caller); err != nil {
			return out, err
		}
		material, err := s.repository.ReadPasswordCredential(ctx, password.CredentialKey{TenantID: r.TenantID, SubjectID: origin.UserID})
		if err != nil {
			return out, err
		}
		a := material.Authority()
		p.intent = kernel.CredentialResetIntent{Replacement: kernel.CredentialReplacementIntent{Credential: a.Credential, ExpectedUserVersion: a.User.Version, ExpectedAuthorityVersion: a.AuthorityVersion}, ExpectedEnabled: a.Enabled}
		fields, err := kernel.CredentialResetFields(p.intent)
		if err != nil {
			return out, err
		}
		spec = identity.FeatureCommandSpec{Binding: b, Operation: resetOperation(), Fields: fields}
	} else {
		wire, generation, e := coordinator.QueryFeaturePreparation(ctx, q, caller, kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: resetOperation()}, p)
		defer clear(wire)
		if e != nil {
			return password.ResetCompleteResult{CommandID: r.CommandID, Outcome: identity.CommitOutcomeUnknown}, e
		}
		// Historical binding contains the original policy and correlation too.
		// Read the authorized metadata, not today's aggregate or a fabricated CAS.
		binding := observation.Record.Binding
		if observation.Validate() != nil {
			// Before final-plan attachment, generic receipt lookup deliberately
			// has no outcome. QueryFeaturePreparation has already authenticated
			// exact immutable scope; configuration and this stable caller binding
			// must also authenticate the original envelope before reconstruction.
			binding = identity.CommandBinding{CommandID: r.CommandID, TenantID: r.TenantID, UserID: origin.UserID, ActorID: q.ActorID, ActorKind: q.ActorKind, OperationID: q.OperationID, SchemaID: resetOperation().SchemaID, SchemaVersion: 1, RecordID: q.RecordID, PolicyID: c.PolicyID, PolicyVersion: c.Coordinator.AdmissionPolicy.PolicyVersion, CorrelationID: string(r.CommandID)}
		}
		spec, err = s.repository.readResetOutputIntent(ctx, s.crypto, binding, generation, s.configuration, wire)
		if err != nil {
			return out, err
		}
		p.intent, err = passwordResetIntent(spec)
		if err != nil {
			return out, err
		}
		// The authenticated original binding retains its audit correlation. The
		// current query policy and complete proof/password fingerprint, not a
		// diagnostic per-request correlation, authorize original command replay.
		if observation.Validate() != nil || observation.Record.Outcome == identity.CommitOutcomeInProgress {
			if err := s.selectResetCompletion(ctx, p, caller); err != nil {
				return out, err
			}
		}
	}
	p.original, err = identity.NewFeaturePasswordResetInputCommand(spec, r.NewPassword, r.Token)
	if err != nil {
		return out, err
	}
	p.consumption, err = s.issuer.PreparePasswordResetConsumption(ctx, p.original, replayVersion)
	if err != nil {
		return out, err
	}
	p.declaration, err = resetServiceAuditDeclaration(spec.Binding, resetOperation(), registry.Descriptors(), "credential", p.intent.Replacement.Credential.Version, p.intent.Replacement.Credential.Version+1, origin.IssuedAt)
	if err != nil {
		return out, err
	}
	p.declaration.Capability = &p.consumption
	p.declaration.Lifecycle.EventType = "password.reset.v1"
	plan, err := coordinator.PrepareFeaturePreparationPlan(p.original, p.declaration)
	if err != nil {
		return out, err
	}
	started = true
	result, err := coordinator.ExecutePreparedFeature(ctx, p.original, plan)
	return resetCompleteReceipt(r.CommandID, result, err)
}

func (s *ResetService) selectResetCompletion(ctx context.Context, p *resetCompletionPhase, caller authorization.DecisionContext) error {
	c := s.config()
	o := p.origin
	state, err := s.directory.GetIdentifierState(ctx, identity.IdentifierQuery{TenantID: o.TenantID, UserID: o.UserID, MaximumIdentifiers: 128})
	if err != nil {
		return err
	}
	var canonical string
	for _, i := range state.Identifiers {
		if i.ID == o.IdentifierID && i.Kind == identity.IdentifierEmail && i.Version == o.IdentifierVersion && i.Verified {
			canonical = i.CanonicalValue
		}
	}
	if canonical == "" {
		return identity.ForbiddenError{}
	}
	p.recipient, err = s.directory.ResolveRecipient(ctx, kernel.RecipientQuery{TenantID: o.TenantID, UserID: o.UserID, Kind: identity.IdentifierEmail, CanonicalValue: canonical, Eligibility: kernel.RecipientVerified})
	if err != nil {
		return err
	}
	if p.recipient.Suppressed || p.recipient.UserAuthorityVersion != o.UserAuthorityVersion || p.recipient.CredentialAuthorityVersion != o.CredentialAuthorityVersion {
		return identity.ForbiddenError{}
	}
	directory, err := s.directory.GetDirectoryAuthority(ctx, kernel.DirectoryAuthorityQuery{GlobalAuthorityID: c.GlobalAuthorityID, TenantID: o.TenantID})
	if err != nil {
		return err
	}
	if !directory.Enabled {
		return identity.ForbiddenError{}
	}
	p.directory = kernel.DirectoryAuthorityAdmission{Query: directory.Query, GlobalVersion: directory.GlobalVersion, TenantVersion: directory.TenantVersion}
	authority, err := s.authority.Get(ctx, authoritypg.AuthorityScope{TenantID: authorization.TenantID(o.TenantID), SubjectID: authorization.SubjectID(o.UserID), PolicyNamespace: c.AuthorizationNamespace})
	if err != nil {
		return readerFailure(ctx)
	}
	p.userAuthorization = kernel.UserAuthorizationAdmission{Scope: authority.Scope, Version: authority.Version}
	caller.Request.Environment.Time = time.Now().UTC()
	decision, err := c.Coordinator.AdmissionPolicy.Authorization.Decide(ctx, caller)
	if err != nil {
		return readerFailure(ctx)
	}
	if caller.PolicyRevision != authorization.Revision(c.Coordinator.AdmissionPolicy.PolicyVersion) || decision.Outcome != authorization.Allow || decision.Revision != caller.PolicyRevision {
		return identity.ForbiddenError{}
	}
	h := hmac.New(sha256.New, c.IdentifierKey[:])
	_, _ = h.Write([]byte("identity-reset-risk-identifier-v1\x00"))
	_, _ = h.Write([]byte(o.TenantID))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(o.IdentifierID))
	p.subject.IdentifierDigest = hex.EncodeToString(h.Sum(nil))
	return nil
}

// RecoverResetComplete authorizes and reconciles only original command history.
// It accepts no proof/password, performs no provider work or generation and
// returns metadata only. Foreign/missing scope denies; ambiguous outcomes stay
// unknown. Current query policy is required even for committed history.
func (s *ResetService) RecoverResetComplete(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (out password.ResetCompleteResult, err error) {
	if ctx == nil || s == nil || s.config == nil || q.OperationID != resetOperation().OperationID || q.UserID == "" || q.RecordID == "" {
		return out, password.ErrPasswordWork
	}
	ctx, stop := context.WithTimeout(ctx, s.config().Repository.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			out = password.ResetCompleteResult{}
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
	}()
	coordinator, _, err := s.completionCoordinator(&resetCompletionPhase{})
	if err != nil {
		return out, err
	}
	result, err := coordinator.RecoverFeatureCommand(ctx, q, caller)
	return resetCompleteReceipt(q.CommandID, result, err)
}

func resetCompleteReceipt(id identity.CommandID, r identity.CommandResult, err error) (password.ResetCompleteResult, error) {
	return resetCompleteReceiptForOperation(id, r, err, resetOperation())
}

func phoneResetCompleteReceipt(id identity.CommandID, r identity.CommandResult, err error) (password.ResetCompleteResult, error) {
	return resetCompleteReceiptForOperation(id, r, err, phonePasswordResetOperation())
}

// Preserve each caller's exact operation when projecting kernel history. Phone
// and email use the same result shape, not interchangeable recovery authority.
func resetCompleteReceiptForOperation(id identity.CommandID, r identity.CommandResult, err error, operation identity.FeatureOperation) (password.ResetCompleteResult, error) {
	out := password.ResetCompleteResult{CommandID: id, Outcome: r.Outcome}
	var collision identity.ConflictError
	if errors.As(err, &collision) {
		out.Outcome = identity.CommitOutcomeConflict
	}
	if r.Outcome == identity.CommitOutcomeCommitted {
		if r.Feature == nil || r.Feature.Operation != operation {
			return password.ResetCompleteResult{}, password.ErrPasswordWork
		}
		out.CredentialVersion, out.SessionsRevoked = r.Feature.AfterVersion, true
	}
	if out.Validate() != nil {
		return password.ResetCompleteResult{}, err
	}
	return out, err
}

func resetServiceAuditDeclaration(b identity.CommandBinding, op identity.FeatureOperation, contributors []kernel.ContributorDescriptor, subject string, before, after uint64, at time.Time) (kernel.CommandPlan, error) {
	kind := audit.ActorService
	if b.ActorKind == authorization.SubjectUser {
		kind = audit.ActorHuman
	}
	target := b.RecordID
	if target == "" {
		target = b.AnonymousFlowID
	}
	action := b.OperationID
	retention := "protected"
	// SECURITY_EVENTS.md gives self-service identifier events standard
	// retention. Select only these new native replacement schemas; older
	// enrollment/removal records keep their original declaration and digest.
	if op == phoneChangeSendingOperation() {
		action, retention = "identity.identifier.request_verification", "standard"
	}
	if op == actionPrimaryOperation("identity.phone.update") {
		retention = "standard"
	}
	if action == "identity.phone.remove" {
		// The security-event taxonomy names the identifier transition; the
		// feature command retains its distinct phone workflow identity.
		action = "identity.identifier.remove"
	}
	if action == "identity.phone.update" {
		action = "identity.identifier.change"
	}
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.CommandPlan{}, password.ErrPasswordWork
	}
	seed, err := builder.Build(audit.RecordInput{OccurredAt: at.UTC().Truncate(time.Microsecond), Action: action, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: kind, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: subject, ID: target}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": subject, "aggregate.id": target, "aggregate.before_version": strconv.FormatUint(before, 10), "aggregate.after_version": strconv.FormatUint(after, 10), "retention.class": retention}})
	if err != nil {
		return kernel.CommandPlan{}, password.ErrPasswordWork
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, op, subject, seed)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	return kernel.CommandPlan{Contributors: contributors, Feature: &kernel.FeatureRegistration{Contributor: kernel.ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}, Operation: op}, SubjectType: subject, Lifecycle: &kernel.LifecyclePlan{EventType: "password.reset.v1", BeforeVersion: before, AfterVersion: after}, Audits: []kernel.AuditPlan{{EventType: action, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: retention, BindingDigest: digest}}}, nil
}
