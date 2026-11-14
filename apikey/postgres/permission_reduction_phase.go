package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strconv"

	"github.com/faustbrian/go-audit"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	kernel "github.com/faustbrian/go-identity/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// Reduction retains three decision grants plus the source permission ceiling
// and a base64-encoded record. Four 64x128-byte, sixfold-escaped grants, an
// encoded 64KiB record and bounded binding/epoch metadata fit within 384KiB.
// The smaller verification-only limit does not cover this original intent;
// this remains below the existing kernel's 1MiB preparation-ciphertext cap.
const maximumReductionSnapshotBytes = 384 << 10

func permissionReductionOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/apikey", OperationID: "identity.apikey.update", SchemaID: "apikey-permission-reduction-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectUser}
}

// The existing native preparation owns these original nonsecret facts. Scalar
// wire projections deliberately avoid the public owners' redacted encoders.
type reductionDecisionWire struct {
	CommandID                                                   identity.CommandID
	KeyID                                                       apikey.KeyID
	Owner                                                       apikey.OwnerSpec
	ExpectedKeyVersion, ExpectedAuthorityVersion, PolicyVersion uint64
	PriorGrant, EffectiveCurrentGrant, Grant                    []string
	Disposition                                                 apikey.PermissionReductionDisposition
	ConfigurationTenant                                         identity.TenantID
	ConfigurationID                                             string
	ConfigurationVersion                                        uint64
}

func reductionWire(d apikey.PermissionReductionDecision) reductionDecisionWire {
	return reductionDecisionWire{CommandID: d.CommandID, KeyID: d.KeyID, Owner: d.Owner.Spec(), ExpectedKeyVersion: d.ExpectedKeyVersion, ExpectedAuthorityVersion: d.ExpectedAuthorityVersion, PolicyVersion: d.PolicyVersion, PriorGrant: slices.Clone(d.PriorGrant), EffectiveCurrentGrant: slices.Clone(d.EffectiveCurrentGrant), Grant: slices.Clone(d.Grant), Disposition: d.Disposition, ConfigurationTenant: d.ConfigurationAuthority.TenantID, ConfigurationID: d.ConfigurationAuthority.ConfigurationID, ConfigurationVersion: d.ConfigurationAuthority.Version}
}

func (x reductionDecisionWire) decision() (apikey.PermissionReductionDecision, error) {
	owner, err := apikey.NewOwner(x.Owner)
	if err != nil {
		return apikey.PermissionReductionDecision{}, apikey.ErrInvalid
	}
	d := apikey.PermissionReductionDecision{CommandID: x.CommandID, KeyID: x.KeyID, Owner: owner, ExpectedKeyVersion: x.ExpectedKeyVersion, ExpectedAuthorityVersion: x.ExpectedAuthorityVersion, PolicyVersion: x.PolicyVersion, PriorGrant: slices.Clone(x.PriorGrant), EffectiveCurrentGrant: slices.Clone(x.EffectiveCurrentGrant), Grant: slices.Clone(x.Grant), Disposition: x.Disposition, ConfigurationAuthority: apikey.ConfigurationAuthorityBinding{TenantID: x.ConfigurationTenant, ConfigurationID: x.ConfigurationID, Version: x.ConfigurationVersion}}
	return d, d.Validate()
}

func sameReductionDecision(a, b apikey.PermissionReductionDecision) bool {
	x, _ := json.Marshal(reductionWire(a))
	y, _ := json.Marshal(reductionWire(b))
	return bytes.Equal(x, y)
}

type reductionSnapshot struct {
	Schema       uint16
	Generation   uint64
	Binding      storedBinding
	Decision     reductionDecisionWire
	Source       verificationSnapshot
	ActorVersion uint64
}

type reductionPhase struct {
	store               *PermissionReductionStore
	decision            apikey.PermissionReductionDecision
	binding             identity.CommandBinding
	original, generated identity.Command
	coordinator         *kernel.Coordinator
	registry            *kernel.ContributorRegistry
	snapshot            reductionSnapshot
	applied             bool
	result              *apikey.Record
	actorVersion        uint64
}

var _ kernel.FeaturePreparationContributor = (*reductionPhase)(nil)

func (*reductionPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/apikey/postgres", ContractID: "identity.apikey", Version: 1}
}
func (p *reductionPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{p.store.operation()}
}

func (p *reductionPhase) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.store == nil || command != p.original && command != p.generated || plan.Feature == nil || plan.Feature.Contributor != p.Descriptor() || plan.Feature.Operation != p.store.operation() || plan.SubjectType != "api_key" || plan.Lifecycle == nil {
		return apikey.ErrInvalid
	}
	spec, ok := command.Feature()
	if !ok || spec.Binding != p.binding || spec.Operation != p.store.operation() || plan.Lifecycle.EventType != "api_key.permissions_changed.v1" || plan.Lifecycle.BeforeVersion != p.decision.ExpectedKeyVersion || plan.Lifecycle.AfterVersion != p.decision.ExpectedKeyVersion+1 {
		return apikey.ErrInvalid
	}
	return p.store.validateDecision(p.decision)
}
func (p *reductionPhase) ValidateFeaturePreparation(command identity.Command, plan kernel.CommandPlan) error {
	return p.ValidateFeatureCommand(command, plan)
}

func (p *reductionPhase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, command identity.Command) error {
	binding, feature, _, err := w.FeatureScope(p)
	if err != nil || command != p.original || binding != p.binding || feature.Operation != p.store.operation() || p.actorVersion == 0 {
		return apikey.ErrDenied
	}
	return authority.RequireAuthority(ctx, w, p.store.actorScope(), p.actorVersion, p.store.primary.config().MaximumDuration)
}

func (p *reductionPhase) plan() (kernel.CommandPlan, error) {
	b := p.binding
	life := kernel.LifecyclePlan{EventType: "api_key.permissions_changed.v1", BeforeVersion: p.decision.ExpectedKeyVersion, AfterVersion: p.decision.ExpectedKeyVersion + 1}
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	seed, err := builder.Build(audit.RecordInput{OccurredAt: p.store.primary.config().Clock.Now().UTC(), Action: "identity.api_key.update", Outcome: audit.OutcomeDenied, ReasonCode: "not_authorized", Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "api_key", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID, CausationID: string(b.CommandID)}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{NoChange: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "api_key", "aggregate.id": b.RecordID, "aggregate.before_version": strconv.FormatUint(life.BeforeVersion, 10), "aggregate.after_version": strconv.FormatUint(life.AfterVersion, 10), "retention.class": "protected"}})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, p.store.operation(), "api_key", seed)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	plan := kernel.CommandPlan{Contributors: p.registry.Descriptors(), Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: p.store.operation()}, SubjectType: "api_key", Lifecycle: &life, Audits: []kernel.AuditPlan{{EventType: "identity.api_key.update", SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}}
	return p.coordinator.PrepareFeaturePreparationPlan(p.original, plan)
}

func (p *reductionPhase) snapshotContext(generation uint64) (envelope.Context, error) {
	if generation == 0 {
		return envelope.Context{}, apikey.ErrInvalid
	}
	wire, err := json.Marshal(struct {
		Binding        storedBinding
		Generation     uint64
		Configuration  apikey.ConfigurationSpec
		ActorNamespace string
	}{storedBinding(p.binding), generation, p.store.primary.config().Configuration.Spec(), p.store.config.ActorPolicyNamespace})
	if err != nil {
		return envelope.Context{}, apikey.ErrInvalid
	}
	digest := sha256.Sum256(wire)
	return envelope.NewContext(map[string]string{"profile": "api-key-original-permission-reduction-v1", "scope": hex.EncodeToString(digest[:])})
}

func sourceBindingForRecord(record apikey.Record, configuration apikey.ConfigurationAuthorityBinding) apikey.SourceAuthorityBinding {
	return apikey.SourceAuthorityBinding{ConfigurationAuthority: configuration, ConfigurationRevision: record.ConfigurationRevision, KeyID: record.ID, Owner: record.Owner, AuthorityVersion: record.AuthorityVersion, RootID: record.RootID, RootVersion: record.RootVersion, Issuer: record.Issuer, Environment: record.Environment, Audience: record.Audience, Grant: slices.Clone(record.Grant), ExpiresAt: record.ExpiresAt}
}

func (p *reductionPhase) GenerateFeaturePreparation(ctx context.Context, command identity.Command, generation uint64) ([]byte, error) {
	if command != p.original || generation == 0 {
		return nil, apikey.ErrInvalid
	}
	primary := p.store.primary
	actorVersion, err := p.store.authorizeActor(ctx)
	if err != nil {
		return nil, err
	}
	record, err := primary.currentRecord(ctx, p.binding.TenantID, p.decision.KeyID)
	if err != nil || !p.store.owns(record.Owner) || record.Version != p.decision.ExpectedKeyVersion || record.AuthorityVersion != p.decision.ExpectedAuthorityVersion || !slices.Equal(record.Grant, p.decision.PriorGrant) {
		return nil, identity.ConflictError{}
	}
	var source verificationSnapshot
	if p.store.organizationID != "" {
		source, err = p.generateOrganization(ctx, generation, record)
	} else {
		source, err = p.generateUser(ctx, generation, record)
	}
	if err != nil {
		return nil, err
	}
	x := reductionSnapshot{Schema: 1, Generation: generation, Binding: storedBinding(p.binding), Decision: reductionWire(p.decision), ActorVersion: actorVersion, Source: source}
	aad, err := p.snapshotContext(generation)
	if err != nil {
		return nil, err
	}
	plain, err := json.Marshal(x)
	defer clear(plain)
	if err != nil || len(plain) > maximumReductionSnapshotBytes {
		return nil, apikey.ErrInvalid
	}
	return primary.seal(ctx, aad, plain)
}

func (p *reductionPhase) generateUser(ctx context.Context, generation uint64, record apikey.Record) (verificationSnapshot, error) {
	primary := p.store.primary
	observed, err := primary.ObserveSourceAuthority(ctx, sourceBindingForRecord(record, p.decision.ConfigurationAuthority))
	if err != nil {
		return verificationSnapshot{}, err
	}
	actual, err := (apikey.ScopePolicy{}).DecidePermissionReduction(p.binding.CommandID, record, currentReductionAuthority(observed), primary.config().Configuration, observed.VerifiedAt)
	if err != nil || !sameReductionDecision(actual, p.decision) {
		return verificationSnapshot{}, apikey.ErrDenied
	}
	recordWire, err := encodeRecord(record, primary.config().Configuration)
	if err != nil {
		return verificationSnapshot{}, err
	}
	return verificationSnapshot{Schema: 1, Generation: generation, Binding: storedBinding(p.binding), Record: recordWire, GlobalVersion: observed.GlobalVersion, TenantVersion: observed.TenantVersion, UserVersion: observed.UserVersion, UserSecurity: observed.UserAuthorityVersion, UserStatus: identity.StatusActive, AuthorizationVersion: observed.AuthorizationVersion, PolicyVersion: observed.PolicyVersion, ConfigurationVersion: observed.ConfigurationAuthority.Version, Permissions: slices.Clone(observed.Grant), Started: observed.ReadStartedAt, Verified: observed.VerifiedAt, Until: observed.ValidUntil}, nil
}

func currentReductionAuthority(o apikey.SourceAuthorityObservation) apikey.CurrentAuthority {
	return apikey.CurrentAuthority{Owner: o.Owner, OwnerActive: true, TenantActive: true, Permissions: slices.Clone(o.Grant), PolicyVersion: o.PolicyVersion, ConfigurationAuthority: o.ConfigurationAuthority, ReadStartedAt: o.ReadStartedAt, VerifiedAt: o.VerifiedAt, ValidUntil: o.ValidUntil}
}

func (p *reductionPhase) observation() (apikey.SourceAuthorityObservation, error) {
	x := p.snapshot.Source
	primary := p.store.primary
	record, err := decodeRecord(x.Record, primary.config().Configuration)
	if err != nil || x.Schema != 1 || x.Generation != p.snapshot.Generation || x.Binding != storedBinding(p.binding) || x.Organization != nil || x.UserStatus != identity.StatusActive || !exactTime(x.Started) || !exactTime(x.Verified) || !exactTime(x.Until) {
		return apikey.SourceAuthorityObservation{}, identity.UnavailableError{}
	}
	ownerSpec := record.Owner.Spec()
	ownerSpec.Version = x.UserSecurity
	owner, err := apikey.NewOwner(ownerSpec)
	if err != nil {
		return apikey.SourceAuthorityObservation{}, identity.UnavailableError{}
	}
	configuration := apikey.ConfigurationAuthorityBinding{TenantID: p.binding.TenantID, ConfigurationID: record.ConfigurationID, Version: x.ConfigurationVersion}
	out := apikey.SourceAuthorityObservation{Binding: sourceBindingForRecord(record, configuration), Record: record, Owner: owner, Grant: slices.Clone(x.Permissions), PolicyVersion: x.PolicyVersion, ConfigurationAuthority: configuration, GlobalVersion: x.GlobalVersion, TenantVersion: x.TenantVersion, UserVersion: x.UserVersion, UserAuthorityVersion: x.UserSecurity, AuthorizationVersion: x.AuthorizationVersion, ReadStartedAt: x.Started, VerifiedAt: x.Verified, ValidUntil: x.Until}
	if out.Validate(out.Binding, primary.config().Configuration, x.Verified) != nil || out.PolicyVersion != primary.config().PolicyVersion || record.Owner.Spec().Kind != apikey.OwnerUser || record.Owner.Spec().UserID != p.binding.UserID || record.Owner.Spec().TenantID != p.binding.TenantID || record.ID != p.decision.KeyID {
		return apikey.SourceAuthorityObservation{}, identity.UnavailableError{}
	}
	actual, err := (apikey.ScopePolicy{}).DecidePermissionReduction(p.binding.CommandID, record, currentReductionAuthority(out), primary.config().Configuration, x.Verified)
	if err != nil || !sameReductionDecision(actual, p.decision) {
		return apikey.SourceAuthorityObservation{}, identity.UnavailableError{}
	}
	return out, nil
}

func (p *reductionPhase) restore(ctx context.Context, generation uint64, wire []byte) error {
	aad, err := p.snapshotContext(generation)
	if err != nil {
		return err
	}
	plain, err := p.store.primary.open(ctx, aad, wire, maximumReductionSnapshotBytes)
	defer clear(plain)
	if err != nil {
		return err
	}
	var x reductionSnapshot
	if decodeCanonical(plain, &x) != nil || x.Schema != 1 || x.Generation != generation || x.Binding != storedBinding(p.binding) || x.ActorVersion == 0 {
		return identity.UnavailableError{}
	}
	decision, err := x.Decision.decision()
	if err != nil || !sameReductionDecision(decision, p.decision) {
		return identity.ConflictError{}
	}
	p.snapshot = x
	if p.store.organizationID != "" {
		_, err = p.organizationObservation()
		return err
	}
	_, err = p.observation()
	return err
}

func (p *reductionPhase) RestoreFeaturePreparation(ctx context.Context, original identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	if original != p.original {
		return identity.Command{}, kernel.CommandPlan{}, apikey.ErrInvalid
	}
	if err := p.restore(ctx, generation, wire); err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	spec, _ := p.original.Feature()
	digest := sha256.Sum256(wire)
	spec.Fields = append(spec.Fields, identity.FeatureField{Name: "apikey.reduction.authority", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}})
	generated, err := identity.NewFeatureCommand(spec)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	p.generated = generated
	plan, err := p.plan()
	return generated, plan, err
}

func (p *reductionPhase) check(ctx context.Context, w kernel.Work) error {
	binding, feature, _, err := w.FeatureScope(p)
	if err != nil || binding != p.binding || feature.Operation != p.store.operation() {
		return apikey.ErrDenied
	}
	if p.store.organizationID != "" {
		return p.checkOrganization(ctx, w)
	}
	observed, err := p.observation()
	if err != nil {
		return err
	}
	if p.applied {
		if p.result == nil {
			return identity.UnavailableError{}
		}
		observed.Record = *p.result
		observed.ConfigurationAuthority.Version++
		observed.Binding = sourceBindingForRecord(observed.Record, observed.ConfigurationAuthority)
		observed.Grant = slices.Clone(p.result.Grant)
	}
	primary := p.store.primary
	if err := primary.requireSourceOwner(ctx, w, p, observed); err != nil {
		return err
	}
	if err := p.requireActor(ctx, w); err != nil {
		return err
	}
	return primary.requireSourceRecord(ctx, w, observed)
}

func (p *reductionPhase) requireActor(ctx context.Context, w kernel.Work) error {
	return authority.RequireAuthority(ctx, w, p.store.actorScope(), p.snapshot.ActorVersion, p.store.primary.config().MaximumDuration)
}

func (p *reductionPhase) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	if command != p.generated || w.RequireFeatureCommand(ctx, p, command) != nil {
		return identity.FeatureReceipt{}, apikey.ErrInvalid
	}
	wire, generation, err := w.FeaturePreparationOutput(p)
	defer clear(wire)
	if err != nil || p.restore(ctx, generation, wire) != nil {
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	if err := p.check(ctx, w); err != nil {
		return identity.FeatureReceipt{}, err
	}
	var record apikey.Record
	if p.store.organizationID != "" {
		observed, err := p.organizationObservation()
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		record = observed.Record
		record.Owner = observed.Owner
	} else {
		observed, err := p.observation()
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		record = observed.Record
		record.Owner = observed.Owner
	}
	record.Grant = slices.Clone(p.decision.Grant)
	record.Version++
	record.AuthorityVersion++
	record.RootVersion++
	if err := p.store.primary.persistReducedRecord(ctx, w, p.binding.TenantID, p.snapshot.Source.ConfigurationVersion, record); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.persistEffect(ctx, w, record); err != nil {
		return identity.FeatureReceipt{}, err
	}
	p.applied, p.result = true, &record
	return identity.FeatureReceipt{Operation: p.store.operation(), BeforeVersion: p.decision.ExpectedKeyVersion, AfterVersion: record.Version}, nil
}

func (p *reductionPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, command identity.Command) error {
	if command != p.generated || !p.applied {
		return apikey.ErrInvalid
	}
	return p.check(ctx, w)
}
