package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// Exactly one invocation owns these transient fields. The registry binds this
// exact pointer through all kernel phases; concurrent calls use another pointer.
type creationPhase struct {
	service       *Service
	request       apikey.CreateRequest
	observed      session.GetResult
	readStartedAt time.Time
	intent        identity.RequestIntent
	input         creationInput
	command       identity.Command
	counter       kernel.CommandCounterPlan
	coordinator   *kernel.Coordinator
	registry      *kernel.ContributorRegistry
	failure       error
	secret        apikey.Secret
	digest        apikey.Digest
	generation    uint64
	outputHash    [32]byte
	admission     risk.ProtectedProviderAdmission
	mutation      *apikey.Rotation
	imported      *apikey.ImportRequest
	revocation    bool
	applied       bool
}

func (p *creationPhase) operation() identity.FeatureOperation {
	if p.imported != nil {
		return importOperation()
	}
	if p.revocation {
		return revokeOperation()
	}
	if p.mutation != nil {
		return rotateOperation()
	}
	return createOperation()
}
func (p *creationPhase) action() string {
	if p.imported != nil {
		return "identity.api_key.import"
	}
	if p.revocation {
		return "identity.api_key.revoke"
	}
	if p.mutation != nil {
		return "identity.api_key.rotate"
	}
	return "identity.api_key.create"
}
func (p *creationPhase) lifecycle() kernel.LifecyclePlan {
	if p.imported != nil {
		return kernel.LifecyclePlan{EventType: "api_key.imported.v1", AfterVersion: p.input.Record.Version}
	}
	if p.revocation {
		return kernel.LifecyclePlan{EventType: "api_key.revoked.v1", BeforeVersion: p.input.Record.Version - 1, AfterVersion: p.input.Record.Version}
	}
	if p.mutation != nil {
		return kernel.LifecyclePlan{EventType: "api_key.rotated.v1", AfterVersion: 1}
	}
	return kernel.LifecyclePlan{EventType: "api_key.created.v1", AfterVersion: 1}
}

var _ kernel.FeatureAdmissionPreparationContributor = (*creationPhase)(nil)
var _ kernel.RequestKeyRecoveryContributor = (*creationPhase)(nil)
var _ kernel.FeatureCommitContributor = (*creationPhase)(nil)

func (*creationPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/apikey/postgres", ContractID: "identity.apikey", Version: 1}
}
func (p *creationPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{p.operation()}
}

func (p *creationPhase) PrepareRequestKey(ctx context.Context, b kernel.RequestKeyPreparationBinding, intent identity.RequestIntent) ([]byte, error) {
	expected, _ := p.intent.Fields()
	actual, ok := intent.Fields()
	if p.service == nil || !ok || !reflect.DeepEqual(expected, actual) || b.Feature != (kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: p.operation()}) || b.Scope.RouteID != p.operation().OperationID {
		return nil, apikey.ErrInvalid
	}
	if err := p.prepare(ctx, b); err != nil {
		p.failure = err
		return nil, err
	}
	plain, err := json.Marshal(storedBinding(p.input.Binding))
	if err != nil {
		return nil, apikey.ErrInvalid
	}
	aad, err := p.mappingContext(b)
	if err != nil {
		return nil, err
	}
	return p.service.seal(ctx, aad, plain)
}

func (p *creationPhase) prepare(ctx context.Context, b kernel.RequestKeyPreparationBinding) error {
	s := p.service
	c := s.config()
	if p.observed.ValidateAt(c.Clock.Now()) != nil {
		return apikey.ErrDenied
	}
	sessionSpec, err := p.observed.Session.Bindings()
	if err != nil {
		return apikey.ErrDenied
	}
	if b.Scope.TenantID != sessionSpec.TenantID || b.Scope.ActorID != identity.ActorID(sessionSpec.UserID) || b.Admission.CommandID == "" {
		return apikey.ErrDenied
	}
	status, err := s.directory.GetStatus(ctx, identity.UserStatusQuery{TenantID: sessionSpec.TenantID, UserID: sessionSpec.UserID})
	if err != nil {
		return nativeError(ctx, err)
	}
	if status.User.Status != identity.StatusActive {
		return apikey.ErrDenied
	}
	authority, err := s.configurationAuthority(ctx, sessionSpec.TenantID)
	if err != nil {
		return err
	}
	var keyID apikey.KeyID
	if p.imported != nil {
		keyID = p.imported.Record.ID
	} else {
		keyID, err = apikey.NewKeyID()
		if err != nil {
			return nativeError(ctx, err)
		}
	}
	owner, err := apikey.NewOwner(apikey.OwnerSpec{TenantID: sessionSpec.TenantID, Kind: apikey.OwnerUser, UserID: sessionSpec.UserID, Version: status.AuthorityVersion})
	if err != nil {
		return err
	}
	correlation := p.request.CorrelationID
	if correlation == "" {
		correlation = string(b.Admission.CommandID)
	}
	op := p.operation()
	binding := identity.CommandBinding{CommandID: b.Admission.CommandID, TenantID: sessionSpec.TenantID, UserID: sessionSpec.UserID, ActorID: identity.ActorID(sessionSpec.UserID), ActorKind: b.Scope.ActorKind, OperationID: op.OperationID, RecordID: string(keyID), SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, PolicyID: c.PolicyID, PolicyVersion: c.PolicyVersion, CorrelationID: correlation}
	verified, err := s.primaryTime(ctx)
	if err != nil {
		return err
	}
	if p.observed.ValidateAt(verified) != nil {
		return apikey.ErrDenied
	}
	until := minTime(p.observed.ValidUntil(), p.readStartedAt.Add(20*time.Second))
	// Every protected admission and final check already enforces this immutable
	// deadline, including a request that crosses the primary freshness boundary.
	until = minTime(until, managementProofDeadline(sessionSpec))
	config := c.Configuration.Spec()
	record := apikey.Record{ID: keyID, Owner: owner, Version: 1, AuthorityVersion: 1, ConfigurationID: config.ID, ConfigurationRevision: config.Revision, Name: p.request.Name, Status: apikey.KeyActive, Grant: slices.Clone(p.request.Permissions), CreatedAt: verified, ExpiresAt: p.request.ExpiresAt.UTC(), RootID: keyID, RootVersion: 1, Issuer: config.Issuer, Environment: config.Environment, Audience: config.Audience}
	var previous *apikey.Record
	var previousConfiguration *apikey.Configuration
	var previousAuthority *apikey.ConfigurationAuthorityBinding
	var imported *legacyImportBinding
	if p.imported != nil {
		record = p.imported.Record
		record.Grant = slices.Clone(record.Grant)
		if record.Owner.Spec().UserID != sessionSpec.UserID || record.Owner.Version() > status.AuthorityVersion {
			return apikey.ErrDenied
		}
		imported = &legacyImportBinding{p.imported.SourceID, p.imported.SourceVersion, p.imported.Digest.Sum()}
	}
	if p.mutation != nil {
		prior, priorConfiguration, err := s.managementRecord(ctx, sessionSpec.TenantID, p.mutation.KeyID)
		if err != nil {
			return err
		}
		if prior.Owner.Spec().UserID != sessionSpec.UserID || prior.Status != apikey.KeyActive || prior.Version == ^uint64(0) || prior.AuthorityVersion == ^uint64(0) {
			return apikey.ErrDenied
		}
		if prior.Version != p.mutation.ExpectedVersion {
			return identity.ConflictError{}
		}
		previous = &prior
		record = prior
		record.Owner = owner
		if p.revocation {
			record.Version++
			record.AuthorityVersion++
			record.RootVersion++
			record.Status, record.Grant = apikey.KeyRevoked, []string{}
			binding.RecordID = string(prior.ID)
		} else {
			if priorConfiguration.Spec().ID != c.Configuration.Spec().ID {
				if err := s.withConfiguration(priorConfiguration).allow(ctx, s.decision(sessionSpec.TenantID, sessionSpec.UserID, p.operation().OperationID, "api-key", priorConfiguration.Spec().ID, p.request.CorrelationID)); err != nil {
					return err
				}
				authority, err := s.withConfiguration(priorConfiguration).configurationAuthority(ctx, sessionSpec.TenantID)
				if err != nil {
					return err
				}
				previousConfiguration, previousAuthority = &priorConfiguration, &authority
			}
			if err := s.authorizePermissions(ctx, sessionSpec.TenantID, sessionSpec.UserID, prior.Grant, p.request.CorrelationID); err != nil {
				return err
			}
			record.ID, record.RootID, record.PreviousID = keyID, keyID, prior.ID
			record.Version, record.AuthorityVersion, record.RootVersion = 1, 1, 1
			record.CreatedAt = verified
			record.ConfigurationID, record.ConfigurationRevision, record.Issuer, record.Environment, record.Audience = config.ID, config.Revision, config.Issuer, config.Environment, config.Audience
			// SI-07 migration keeps the imported absolute deadline as a ceiling;
			// a modern successor must also honor current modern issuance policy.
			// Ordinary modern rotations retain their exact original deadline.
			if priorConfiguration.Spec().Algorithm == apikey.AlgorithmLegacySHA256V1 {
				record.ExpiresAt = minTime(prior.ExpiresAt, verified.Add(config.MaximumLifetime).Truncate(time.Microsecond))
			}
		}
	}
	p.input = creationInput{Configuration: c.Configuration, Record: record, Binding: binding, Session: p.observed.Session, Bearer: p.request.Authentication.Bearer, OwnerStatus: status, ConfigurationAuthority: authority, ReadStartedAt: p.readStartedAt, VerifiedAt: verified, ValidUntil: until, Network: p.request.Network}
	p.input.PreviousRecord = previous
	p.input.PreviousConfiguration, p.input.PreviousConfigurationAuthority, p.input.Import = previousConfiguration, previousAuthority, imported
	command, err := mapCreation(p.input)
	if err != nil {
		return err
	}
	p.command, p.counter, err = c.Counters.PrepareCommandCounters(command, risk.Subject{User: string(binding.UserID), Session: sessionSpec.SessionID, Network: p.request.Network}, verified)
	return nativeError(ctx, err)
}

type storedBinding identity.CommandBinding

func (p *creationPhase) mappingContext(b kernel.RequestKeyPreparationBinding) (envelope.Context, error) {
	if p == nil || p.service == nil || b.Namespace != p.service.config().RequestKeys.Namespace || b.Scope.Method != "POST" || b.Scope.RouteID != p.operation().OperationID || b.Feature != (kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: p.operation()}) || b.PolicyVersion != p.service.config().PolicyVersion || b.Admission.CommandID == "" || b.Admission.FingerprintKeyVersion == 0 || b.IntentDigest == ([32]byte{}) {
		return envelope.Context{}, apikey.ErrInvalid
	}
	frame, err := json.Marshal(struct {
		Namespace     string
		Scope         kernel.RequestKeyScope
		Admission     kernel.RequestKeyAdmission
		Feature       kernel.FeatureRegistration
		Policy        uint64
		Intent        [32]byte
		Configuration apikey.ConfigurationSpec
	}{b.Namespace, b.Scope, b.Admission, b.Feature, b.PolicyVersion, b.IntentDigest, p.service.config().Configuration.Spec()})
	if err != nil {
		return envelope.Context{}, apikey.ErrInvalid
	}
	digest := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"profile": "api-key-human-original-input-v1", "scope": hex.EncodeToString(digest[:])})
}

func (p *creationPhase) RestoreRequestKey(ctx context.Context, b kernel.RequestKeyPreparationBinding, wire []byte) (identity.CommandBinding, error) {
	aad, err := p.mappingContext(b)
	if err != nil {
		return identity.CommandBinding{}, err
	}
	plain, err := p.service.open(ctx, aad, wire, 4096)
	defer clear(plain)
	if err != nil {
		return identity.CommandBinding{}, err
	}
	var original storedBinding
	if decodeCanonical(plain, &original) != nil {
		return identity.CommandBinding{}, identity.UnavailableError{}
	}
	bound := identity.CommandBinding(original)
	if bound.ValidateFor(p.operation()) != nil || bound.CommandID != b.Admission.CommandID || bound.TenantID != b.Scope.TenantID || bound.UserID != identity.UserID(b.Scope.ActorID) || bound.ActorID != b.Scope.ActorID || bound.ActorKind != b.Scope.ActorKind || bound.OperationID != b.Scope.RouteID || bound.PolicyID != p.service.config().PolicyID || bound.PolicyVersion != b.PolicyVersion {
		return identity.CommandBinding{}, identity.UnavailableError{}
	}
	return bound, nil
}

func (p *creationPhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.service == nil || c != p.command || p.input.validate() != nil {
		return apikey.ErrInvalid
	}
	spec, ok := c.Feature()
	if !ok || spec.Binding != p.input.Binding || spec.Operation != p.operation() || plan.Feature == nil || *plan.Feature != (kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: p.operation()}) || plan.SubjectType != "api_key" || plan.CommandCounters == nil || *plan.CommandCounters != p.counter || plan.Lifecycle == nil || *plan.Lifecycle != p.lifecycle() || len(plan.Audits) != 1 || plan.Audits[0].EventType != p.action() || !plan.Audits[0].Required || plan.Audits[0].RequiredRecordCount != 1 || plan.Audits[0].RetentionClass != "protected" || plan.Capability != nil || plan.CapabilityIssuance != nil || plan.OTP != nil || plan.Delivery != nil {
		return apikey.ErrInvalid
	}
	digest, err := p.input.commitment()
	if err != nil {
		return err
	}
	for _, f := range spec.Fields {
		if f.Name == intentField(p.operation()) && f.Value.Kind == identity.FeatureBytes && bytes.Equal(f.Value.Bytes, digest[:]) {
			return nil
		}
	}
	return apikey.ErrInvalid
}

func (p *creationPhase) ValidateFeaturePreparation(c identity.Command, plan kernel.CommandPlan) error {
	return p.ValidateFeatureCommand(c, plan)
}

func (p *creationPhase) plan(final bool) (kernel.CommandPlan, error) {
	b := p.input.Binding
	life := p.lifecycle()
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.CommandPlan{}, identity.UnavailableError{}
	}
	seed, err := builder.Build(audit.RecordInput{OccurredAt: p.input.VerifiedAt, Action: p.action(), Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "api_key", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "api_key", "aggregate.id": b.RecordID, "aggregate.before_version": strconv.FormatUint(life.BeforeVersion, 10), "aggregate.after_version": strconv.FormatUint(life.AfterVersion, 10), "retention.class": "protected"}})
	if err != nil {
		return kernel.CommandPlan{}, apikey.ErrInvalid
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, p.operation(), "api_key", seed)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	plan := kernel.CommandPlan{Contributors: p.registry.Descriptors(), Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: p.operation()}, SubjectType: "api_key", Lifecycle: &life, CommandCounters: &p.counter, Audits: []kernel.AuditPlan{{EventType: p.action(), SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}}
	if !final {
		return p.coordinator.PrepareFeaturePreparationPlan(p.command, plan)
	}
	return p.coordinator.PrepareCommandPlan(b, p.command, plan)
}

func (p *creationPhase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, c identity.Command) error {
	return p.admit(ctx, w, c)
}

func (p *creationPhase) admit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.command {
		return identity.ForbiddenError{}
	}
	if _, _, _, err := w.FeatureScope(p); err != nil {
		return err
	}
	config := p.service.config()
	s, err := p.input.Session.Bindings()
	if err != nil {
		return identity.ForbiddenError{}
	}
	bearer, ok := c.SessionToken()
	if !ok {
		return identity.ForbiddenError{}
	}
	token, err := session.ParseToken(bearer.Token())
	if err != nil {
		return identity.ForbiddenError{}
	}
	key, ok := config.LookupKeys[s.Lookup.KeyVersion]
	if !ok {
		return identity.ForbiddenError{}
	}
	digest, err := token.Digest(key, string(s.TenantID))
	if err != nil || digest.KeyVersion != s.Lookup.KeyVersion || subtle.ConstantTimeCompare(digest.Sum[:], s.Lookup.Sum[:]) != 1 {
		return identity.ForbiddenError{}
	}
	directory, credential, policy, err := sessionpg.OriginalSessionAdmission(config.Profile, p.input.Session, p.input.Binding)
	if err != nil {
		return identity.ForbiddenError{}
	}
	if err := w.RequireActiveDirectoryAuthority(ctx, p, directory); err != nil {
		return err
	}
	if _, err := w.RequireActiveActorCredential(ctx, p, credential); err != nil {
		return err
	}
	if err := w.RequireActiveUserStatus(ctx, p, p.input.OwnerStatus); err != nil {
		return err
	}
	if err := w.RequireActiveActorAuthorization(ctx, p, policy); err != nil {
		return err
	}
	if err := sessionpg.RequireSession(ctx, w, config.Session, p.input.Session); err != nil {
		return err
	}
	// Acquire the configuration's UPDATE lock directly on every mutation path.
	// Never retain SHARE and upgrade it during rotate/narrow/revoke; all keys
	// in this configuration share this lifecycle epoch, not their credential root.
	if err := p.requireConfiguration(ctx, w); err != nil {
		return err
	}
	if err := p.requirePrevious(ctx, w); err != nil {
		return err
	}
	if err := p.requireImportTarget(ctx, w); err != nil {
		return err
	}
	at, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if p.observed.ValidateAt(at) != nil || at.Before(p.input.VerifiedAt) || !at.Before(p.input.ValidUntil) || !p.revocation && p.imported == nil && !at.Before(p.input.Record.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *creationPhase) requireConfiguration(ctx context.Context, w kernel.Work) error {
	configurations := []configurationFence{{p.input.Configuration, p.input.ConfigurationAuthority.Version}}
	if p.input.PreviousConfiguration != nil {
		configurations = append(configurations, configurationFence{*p.input.PreviousConfiguration, p.input.PreviousConfigurationAuthority.Version})
	}
	slices.SortFunc(configurations, func(a, b configurationFence) int {
		return strings.Compare(a.configuration.Spec().ID, b.configuration.Spec().ID)
	})
	for _, fence := range configurations {
		if err := p.requireConfigurationFence(ctx, w, fence); err != nil {
			return err
		}
	}
	return nil
}

type configurationFence struct {
	configuration apikey.Configuration
	version       uint64
}

func (p *creationPhase) requireConfigurationFence(ctx context.Context, w kernel.Work, fence configurationFence) error {
	rows, err := w.Query(ctx, `SELECT authority_version::text,configuration_digest,enabled FROM identity_api_keys.configurations WHERE tenant_id=$1 AND configuration_id=$2 FOR UPDATE`, string(p.input.Binding.TenantID), fence.configuration.Spec().ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	var version string
	var fingerprint []byte
	var enabled bool
	if !rows.Next() {
		return identity.ForbiddenError{}
	}
	if err := rows.Scan(&version, &fingerprint, &enabled); err != nil {
		return err
	}
	if rows.Next() || rows.Err() != nil {
		return identity.UnavailableError{}
	}
	want, _ := configurationDigest(fence.configuration)
	expected := fence.version
	if p.applied && p.mutation != nil {
		expected++
	}
	if !enabled || version != strconv.FormatUint(expected, 10) || !bytes.Equal(fingerprint, want[:]) {
		return identity.ForbiddenError{}
	}
	return nil
}

type creationAdmission struct {
	phase     *creationPhase
	admission risk.ProtectedProviderAdmission
}

func (a *creationAdmission) Check(ctx context.Context) error {
	if a == nil || a.phase == nil || ctx == nil {
		return apikey.ErrInvalid
	}
	now := a.phase.service.config().Clock.Now()
	if a.phase.observed.ValidateAt(now) != nil || now.Before(a.phase.input.VerifiedAt) || !now.Before(a.phase.input.ValidUntil) {
		return apikey.ErrDenied
	}
	return a.admission.Check(ctx)
}
func (a *creationAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	return a.phase.generate(ctx, generation, a.admission)
}
func (p *creationPhase) riskScope() risk.Context {
	return risk.Context{Tenant: string(p.input.Binding.TenantID), Operation: risk.Action(p.operation().OperationID), Attempt: string(p.input.Binding.CommandID)}
}
func (p *creationPhase) PrepareFeatureAdmission(ctx context.Context, c identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if c != p.command {
		return nil, apikey.ErrInvalid
	}
	result, err := p.service.config().Risk.Evaluation.EvaluateProtectedProviders(ctx, risk.EvaluateRequest{Context: p.riskScope(), Phase: risk.NonIssuing})
	if err != nil {
		return nil, err
	}
	admission, err := p.service.custody.Prepare(ctx, result, p.riskScope())
	if err != nil {
		return nil, err
	}
	p.admission = admission
	return &creationAdmission{phase: p, admission: admission}, nil
}
func (p *creationPhase) RestoreFeatureAdmission(ctx context.Context, c identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if c != p.command {
		return nil, apikey.ErrInvalid
	}
	if err := p.restoreOutput(ctx, generation, wire); err != nil {
		return nil, err
	}
	return &creationAdmission{phase: p, admission: p.admission}, nil
}

type storedProviderAdmission risk.PreparedProtectedProviderAdmission
type creationOutput struct {
	Schema        uint16
	Generation    uint64
	Commitment    [32]byte
	PepperVersion uint32
	Digest        [32]byte
	Risk          storedProviderAdmission
}

func (p *creationPhase) outputContext(generation uint64) (envelope.Context, error) {
	if generation == 0 {
		return envelope.Context{}, apikey.ErrInvalid
	}
	digest, err := p.input.commitment()
	if err != nil {
		return envelope.Context{}, err
	}
	frame, err := json.Marshal(struct {
		Binding    storedBinding
		Generation uint64
		Commitment [32]byte
	}{storedBinding(p.input.Binding), generation, digest})
	if err != nil {
		return envelope.Context{}, apikey.ErrInvalid
	}
	h := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"profile": "api-key-human-digest-preparation-v1", "scope": hex.EncodeToString(h[:])})
}
func (p *creationPhase) generate(ctx context.Context, generation uint64, admission risk.ProtectedProviderAdmission) ([]byte, error) {
	if p.generation != 0 || generation == 0 {
		return nil, apikey.ErrDenied
	}
	aad, err := p.outputContext(generation)
	if err != nil {
		return nil, err
	}
	secret, digest := apikey.Secret{}, apikey.Digest{}
	if p.imported != nil {
		digest = apikey.Digest{Sum: p.imported.Digest.Sum()}
	} else if !p.revocation {
		secret, err = apikey.GenerateSecret()
		if err != nil {
			return nil, err
		}
		digest, err = secret.Digest(p.service.config().Pepper, string(p.input.Binding.TenantID), p.input.Configuration)
		if err != nil {
			return nil, err
		}
	}
	commitment, _ := p.input.commitment()
	plain, err := json.Marshal(creationOutput{Schema: 1, Generation: generation, Commitment: commitment, PepperVersion: digest.PepperVersion, Digest: digest.Sum, Risk: storedProviderAdmission(admission.Prepared())})
	defer clear(plain)
	if err != nil {
		return nil, apikey.ErrInvalid
	}
	wire, err := p.service.seal(ctx, aad, plain)
	if err != nil {
		return nil, err
	}
	p.secret, p.digest, p.generation, p.admission = secret, digest, generation, admission
	return wire, nil
}
func (p *creationPhase) GenerateFeaturePreparation(ctx context.Context, c identity.Command, generation uint64) ([]byte, error) {
	if c != p.command {
		return nil, apikey.ErrInvalid
	}
	return p.generate(ctx, generation, p.admission)
}
func (p *creationPhase) restoreOutput(ctx context.Context, generation uint64, wire []byte) error {
	aad, err := p.outputContext(generation)
	if err != nil {
		return err
	}
	plain, err := p.service.open(ctx, aad, wire, 64<<10)
	defer clear(plain)
	if err != nil {
		return err
	}
	var output creationOutput
	commitment, _ := p.input.commitment()
	if decodeCanonical(plain, &output) != nil || output.Schema != 1 || output.Generation != generation || output.Commitment != commitment {
		return identity.UnavailableError{}
	}
	validDigest := p.revocation && output.PepperVersion == 0 && output.Digest == ([32]byte{}) || p.imported != nil && output.PepperVersion == 0 && output.Digest == p.imported.Digest.Sum() || p.imported == nil && !p.revocation && output.PepperVersion != 0 && output.Digest != ([32]byte{})
	if !validDigest {
		return identity.UnavailableError{}
	}
	admission, err := p.service.custody.Restore(ctx, risk.PreparedProtectedProviderAdmission(output.Risk), p.riskScope())
	if err != nil {
		return err
	}
	digest := apikey.Digest{PepperVersion: output.PepperVersion, Sum: output.Digest}
	if p.generation != generation || !p.digest.Equal(digest) {
		p.secret = apikey.Secret{}
	}
	p.digest, p.generation, p.admission, p.outputHash = digest, generation, admission, sha256.Sum256(wire)
	return nil
}
func (p *creationPhase) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	if c != p.command {
		return identity.Command{}, kernel.CommandPlan{}, apikey.ErrInvalid
	}
	if err := p.restoreOutput(ctx, generation, wire); err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	plan, err := p.plan(true)
	return p.command, plan, err
}

func (p *creationPhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if err := w.RequireFeatureCommand(ctx, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.admit(ctx, w, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	wire, generation, err := w.FeaturePreparationOutput(p)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	defer clear(wire)
	// RestoreFeaturePreparation already authenticated this exact ciphertext
	// outside SQL. Rebind it here without decrypting or invoking the risk owner's
	// configured clock under locks; only its trusted-primary CheckAt runs below.
	if generation != p.generation || p.outputHash == ([32]byte{}) || sha256.Sum256(wire) != p.outputHash {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	at, err := w.DatabaseTime(ctx)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.admission.CheckAt(ctx, at); err != nil {
		return identity.FeatureReceipt{}, err
	}
	record, err := encodeRecord(p.input.Record, p.input.Configuration)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	b, fingerprint, executionGeneration, err := w.FeatureCommandIdentity(p)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	var n int64
	if !p.revocation {
		n, err = w.Exec(ctx, `INSERT INTO identity_api_keys.keys(tenant_id,configuration_id,key_id,user_id,pepper_version,lookup_digest,record) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`, string(b.TenantID), p.input.Record.ConfigurationID, b.RecordID, string(b.UserID), int64(p.digest.PepperVersion), p.digest.Sum[:], record)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		if n != 1 {
			return identity.FeatureReceipt{}, identity.ConflictError{}
		}
	}
	if p.mutation != nil {
		tombstone := p.tombstone()
		previousConfiguration := p.input.Configuration
		if p.input.PreviousConfiguration != nil {
			previousConfiguration = *p.input.PreviousConfiguration
		}
		wire, err := encodeRecord(tombstone, previousConfiguration)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		n, err = w.Exec(ctx, `UPDATE identity_api_keys.keys SET record=$4 WHERE tenant_id=$1 AND configuration_id=$2 AND key_id=$3`, string(b.TenantID), tombstone.ConfigurationID, string(tombstone.ID), wire)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		if n != 1 {
			return identity.FeatureReceipt{}, identity.ConflictError{}
		}
		n, err = w.Exec(ctx, `UPDATE identity_api_keys.configurations SET authority_version=authority_version+1 WHERE tenant_id=$1 AND configuration_id=$2 AND authority_version=$3::numeric`, string(b.TenantID), p.input.Record.ConfigurationID, strconv.FormatUint(p.input.ConfigurationAuthority.Version, 10))
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		if n != 1 {
			return identity.FeatureReceipt{}, identity.ConflictError{}
		}
		if p.input.PreviousConfiguration != nil {
			n, err = w.Exec(ctx, `UPDATE identity_api_keys.configurations SET authority_version=authority_version+1 WHERE tenant_id=$1 AND configuration_id=$2 AND authority_version=$3::numeric`, string(b.TenantID), previousConfiguration.Spec().ID, strconv.FormatUint(p.input.PreviousConfigurationAuthority.Version, 10))
			if err != nil {
				return identity.FeatureReceipt{}, err
			}
			if n != 1 {
				return identity.FeatureReceipt{}, identity.ConflictError{}
			}
		}
	}
	if err := p.persistImport(ctx, w); err != nil {
		return identity.FeatureReceipt{}, err
	}
	bound, err := json.Marshal(storedBinding(b))
	if err != nil {
		return identity.FeatureReceipt{}, apikey.ErrInvalid
	}
	n, err = w.Exec(ctx, `INSERT INTO identity_api_keys.command_effects(command_id,tenant_id,key_id,binding,fingerprint,generation,record) VALUES($1,$2,$3,$4,$5,$6::numeric,$7)`, string(b.CommandID), string(b.TenantID), b.RecordID, bound, fingerprint[:], strconv.FormatUint(executionGeneration, 10), record)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	p.applied = true
	life := p.lifecycle()
	return identity.FeatureReceipt{Operation: p.operation(), BeforeVersion: life.BeforeVersion, AfterVersion: life.AfterVersion}, nil
}
func (p *creationPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if err := p.admit(ctx, w, c); err != nil {
		return err
	}
	at, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	return p.admission.CheckAt(ctx, at)
}

func (p *creationPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, feature, life, err := w.FeatureScope(p)
	if err != nil || feature != (kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: p.operation()}) {
		return kernel.RecoveryUnknown, apikey.ErrInvalid
	}
	rows, err := w.Query(ctx, `SELECT binding,record FROM identity_api_keys.command_effects WHERE command_id=$1 AND tenant_id=$2`, string(b.CommandID), string(b.TenantID))
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return kernel.RecoveryUnknown, err
		}
		return kernel.RecoveryNotCommitted, nil
	}
	var binding, record []byte
	if err := rows.Scan(&binding, &record); err != nil {
		return kernel.RecoveryUnknown, err
	}
	if rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	want, _ := json.Marshal(storedBinding(b))
	restored, err := decodeRecord(record, p.service.config().Configuration)
	if err != nil || !bytes.Equal(binding, want) || restored.ID != apikey.KeyID(b.RecordID) || restored.Owner.Spec().UserID != b.UserID || restored.Owner.Spec().TenantID != b.TenantID || restored.Version != life.AfterVersion || p.operation().ValidateRecordVersions(life.BeforeVersion, life.AfterVersion) != nil || p.revocation && (life.EventType != "api_key.revoked.v1" || restored.Status != apikey.KeyRevoked || len(restored.Grant) != 0) || p.imported != nil && life.EventType != "api_key.imported.v1" || !p.revocation && p.imported == nil && (restored.Version != 1 || restored.Status != apikey.KeyActive || p.mutation != nil && (life.EventType != "api_key.rotated.v1" || restored.PreviousID == "") || p.mutation == nil && life.EventType != "api_key.created.v1") {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	if p.imported != nil {
		if err := p.recoverImport(ctx, w, b, restored); err != nil {
			return kernel.RecoveryUnknown, err
		}
	}
	return kernel.RecoveryCommitted, nil
}

func (s *Service) seal(ctx context.Context, aad envelope.Context, plain []byte) ([]byte, error) {
	sealed, err := s.crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, KeyReference: s.config().ActiveEnvelopeKeyID, Context: aad})
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return sealed.MarshalBinary()
}
func (s *Service) open(ctx context.Context, aad envelope.Context, wire []byte, maximum int) ([]byte, error) {
	if len(wire) == 0 || len(wire) > maximum+4096 {
		return nil, identity.UnavailableError{}
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	plain, err := s.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	if err != nil || len(plain) > maximum {
		clear(plain)
		return nil, identity.UnavailableError{}
	}
	return plain, nil
}
func decodeCanonical(wire []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil {
		return apikey.ErrInvalid
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return apikey.ErrInvalid
	}
	canonical, err := json.Marshal(out)
	if err != nil || !bytes.Equal(canonical, wire) {
		return apikey.ErrInvalid
	}
	return nil
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
