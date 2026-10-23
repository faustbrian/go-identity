package anonymouspostgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
	kernel "github.com/faustbrian/go-identity/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// This is original encrypted input inside the existing request-key owner, not
// another batch/command journal. Explicit private projections avoid serializing
// public opaque domain objects. Restoring never refreshes admission or policy.
type cleanupInput struct {
	Schema                            uint8
	Command                           identity.FeatureCommandSpec
	Kernel                            deletionStoredKernel
	Intent                            []identity.FeatureField
	RunID                             identity.CommandID
	GlobalVersion, TenantVersion      uint64
	ObservedAt, LocalStartedAt, Until time.Time
}

type cleanupPhase struct {
	service     *CleanupService
	request     CleanupSubjectRequest
	coordinator *kernel.Coordinator
	registry    *kernel.ContributorRegistry
	input       cleanupInput
	command     identity.Command
	deferred    bool
}

func (*cleanupPhase) Descriptor() kernel.ContributorDescriptor { return creationOwner() }
func (*cleanupPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{expiryOperation()}
}
func (p *cleanupPhase) registration() kernel.FeatureRegistration {
	return kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: expiryOperation()}
}

func (p *cleanupPhase) aad(k kernel.RequestKeyPreparationBinding) (envelope.Context, error) {
	c := p.service.config()
	if k.Feature != p.registration() || k.Namespace != c.RequestKeys.Namespace || k.Scope.Method != "POST" || k.Scope.RouteID != expiryOperation().OperationID || k.Scope.ActorKind != authorization.SubjectServiceAccount || k.Scope.ActorID != c.ActorID || k.PolicyVersion != c.RequestKeys.Policy.PolicyVersion || k.IntentDigest == ([32]byte{}) || k.Admission.FingerprintKeyVersion == 0 {
		return envelope.Context{}, anonymous.ErrInvalidInput
	}
	if _, err := identity.ParseCommandID(string(k.Admission.CommandID)); err != nil {
		return envelope.Context{}, anonymous.ErrInvalidInput
	}
	frame, err := json.Marshal(struct {
		Binding signinStoredKey
		Profile [32]byte
	}{signinStoredKey(k), p.service.profile})
	if err != nil {
		return envelope.Context{}, err
	}
	defer clear(frame)
	digest := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"profile": "identity-anonymous-expiry-input-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func (p *cleanupPhase) PrepareRequestKey(ctx context.Context, k kernel.RequestKeyPreparationBinding, intent identity.RequestIntent) ([]byte, error) {
	s, c, r := p.service, p.service.config(), p.request
	aad, err := p.aad(k)
	if err != nil || k.Scope.TenantID != r.TenantID {
		return nil, anonymous.ErrInvalidInput
	}
	local := c.Clock.Now().UTC().Truncate(time.Microsecond)
	if !readInstant(local) {
		return nil, identity.UnavailableError{}
	}
	var at time.Time
	if err := s.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		return nil, identity.UnavailableError{}
	}
	at = at.UTC()
	until := at.Add(20 * time.Second)
	if end := local.Add(20 * time.Second); end.Before(until) {
		until = end
	}
	directory, err := s.directory.GetDirectoryAuthority(ctx, kernel.DirectoryAuthorityQuery{GlobalAuthorityID: c.GlobalAuthorityID, TenantID: r.TenantID})
	if err != nil {
		return nil, err
	}
	if !directory.Enabled {
		return nil, identity.ForbiddenError{}
	}
	subject, err := s.repository.Read(ctx, anonymous.SubjectQuery{TenantID: r.TenantID, UserID: r.UserID})
	if err != nil {
		return nil, err
	}
	if err := subject.RequireExpired(r.TenantID, at); err != nil {
		return nil, identity.ForbiddenError{}
	}
	record, _ := subject.Record()
	if record.Version == ^uint64(0) {
		return nil, identity.ForbiddenError{}
	}
	snapshot, err := s.directory.GetAnonymousDisposal(ctx, identity.UserStatusQuery{TenantID: r.TenantID, UserID: r.UserID})
	if err != nil {
		return nil, err
	}
	if err := s.allow(ctx, r.TenantID, string(r.UserID)); err != nil {
		return nil, err
	}
	action, disposal := identity.RetentionDelete, kernel.AnonymousDisposeDelete
	if record.Cleanup == anonymous.CleanupAnonymize {
		action, disposal = identity.RetentionAnonymize, kernel.AnonymousDisposeAnonymize
	}
	if record.Cleanup == anonymous.CleanupRetain {
		disposal = kernel.AnonymousDisposeRetain
	}
	retention, err := c.Retention.DecideRetention(ctx, identity.RetentionPolicyInput{TenantID: r.TenantID, ActorID: c.ActorID, SubjectID: r.UserID, OperationID: expiryOperation().OperationID, PolicyVersion: c.RetentionPolicyVersion, Deadline: until, Resource: identity.RetentionResource{Kind: "anonymous", ID: string(r.UserID)}, Action: action, LegalHold: snapshot.LegalHold, RequestedAt: at})
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	if retention.Disposition != identity.RetentionAllow {
		// The request-key owner deliberately redacts callback errors. Retain only
		// this validated negative decision in the call-local phase so the batch
		// can defer it without treating unavailable policy as an ordinary hold.
		p.deferred = true
		return nil, identity.ForbiddenError{}
	}
	i := kernel.AnonymousDisposalIntent{Snapshot: snapshot, Action: disposal, RetentionPolicyVersion: c.RetentionPolicyVersion}
	owned, err := kernel.AnonymousDisposalFields(i)
	if err != nil {
		return nil, identity.ForbiddenError{}
	}
	fields, err := ExpiryFields(subject)
	if err != nil {
		return nil, err
	}
	fields = append(fields, owned...)
	fields = append(fields,
		identity.FeatureField{Name: "cleanup.global-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: directory.GlobalVersion}},
		identity.FeatureField{Name: "cleanup.tenant-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: directory.TenantVersion}},
		identity.FeatureField{Name: "cleanup.observed-at", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: at}},
		identity.FeatureField{Name: "cleanup.local-start", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: local}},
		identity.FeatureField{Name: "cleanup.valid-until", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: until}},
		identity.FeatureField{Name: "cleanup.run", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(r.RunID)}},
	)
	b := identity.CommandBinding{CommandID: k.Admission.CommandID, TenantID: r.TenantID, UserID: r.UserID, RecordID: string(r.UserID), ActorID: c.ActorID, ActorKind: authorization.SubjectServiceAccount, OperationID: expiryOperation().OperationID, SchemaID: expiryOperation().SchemaID, SchemaVersion: 1, PolicyID: c.PolicyID, PolicyVersion: k.PolicyVersion, CorrelationID: string(r.RunID)}
	command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: expiryOperation(), Fields: fields})
	if err != nil {
		return nil, err
	}
	feature, _ := command.Feature()
	originalIntent, ok := intent.Fields()
	if !ok {
		return nil, anonymous.ErrInvalidInput
	}
	input := cleanupInput{Schema: 1, Command: feature, Kernel: storeDeletionKernel(i), Intent: originalIntent, RunID: r.RunID, GlobalVersion: directory.GlobalVersion, TenantVersion: directory.TenantVersion, ObservedAt: at, LocalStartedAt: local, Until: until}
	return sealAnonymousInput(ctx, s.crypto, c.ActiveEnvelopeKeyID, aad, input)
}

func (p *cleanupPhase) restore(ctx context.Context, k kernel.RequestKeyPreparationBinding, wire []byte, intent identity.RequestIntent) error {
	aad, err := p.aad(k)
	if err != nil {
		return err
	}
	var input cleanupInput
	if err := openAnonymousInput(ctx, p.service.crypto, aad, wire, &input); err != nil {
		return err
	}
	c, b := p.service.config(), input.Command.Binding
	if input.Schema != 1 || b.CommandID != k.Admission.CommandID || b.TenantID != k.Scope.TenantID || b.ActorID != c.ActorID || b.ActorKind != authorization.SubjectServiceAccount || b.RecordID != string(b.UserID) || b.AnonymousFlowID != "" || b.PolicyID != c.PolicyID || b.PolicyVersion != k.PolicyVersion || b.CorrelationID != string(input.RunID) || input.Command.Operation != expiryOperation() || input.GlobalVersion == 0 || input.TenantVersion == 0 || !readInstant(input.ObservedAt) || !readInstant(input.LocalStartedAt) || !input.Until.After(input.ObservedAt) || !input.Until.After(input.LocalStartedAt) || input.Until.After(input.ObservedAt.Add(20*time.Second)) || input.Until.After(input.LocalStartedAt.Add(20*time.Second)) {
		return anonymous.ErrInvalidInput
	}
	if _, err := identity.ParseCommandID(string(input.RunID)); err != nil {
		return anonymous.ErrInvalidInput
	}
	if expected, ok := intent.Fields(); ok && !reflect.DeepEqual(expected, input.Intent) {
		return identity.ConflictError{}
	}
	command, err := identity.NewFeatureCommand(input.Command)
	if err != nil {
		return err
	}
	subject, err := ExpirySubject(command)
	if err != nil {
		return err
	}
	spec, _ := subject.Record()
	if spec.Version == ^uint64(0) || input.Kernel.RetentionVersion != c.RetentionPolicyVersion || input.Kernel.User.TenantID != b.TenantID || input.Kernel.User.ID != b.UserID {
		return anonymous.ErrInvalidInput
	}
	if _, err := kernel.AnonymousDisposalFields(input.Kernel.intent()); err != nil {
		return err
	}
	p.input, p.command = input, command
	return nil
}

func (p *cleanupPhase) lifecycle() kernel.LifecyclePlan {
	subject, _ := ExpirySubject(p.command)
	spec, _ := subject.Record()
	return kernel.LifecyclePlan{EventType: "anonymous.expired.v1", BeforeVersion: spec.Version, AfterVersion: spec.Version + 1}
}

func (p *cleanupPhase) plan() (kernel.CommandPlan, error) {
	b, l := p.input.Command.Binding, p.lifecycle()
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	record, err := builder.Build(audit.RecordInput{OccurredAt: p.input.ObservedAt, Action: b.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "anonymous", ID: string(b.UserID)}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "anonymous", "aggregate.id": string(b.UserID), "aggregate.before_version": strconv.FormatUint(l.BeforeVersion, 10), "aggregate.after_version": strconv.FormatUint(l.AfterVersion, 10), "retention.class": "protected"}})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, expiryOperation(), "anonymous", record)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	registration := p.registration()
	return p.coordinator.PrepareCommandPlan(b, p.command, kernel.CommandPlan{Contributors: p.registry.Descriptors(), SubjectType: "anonymous", Feature: &registration, Lifecycle: &l, Audits: []kernel.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: p.service.config().RetentionPolicyVersion, RetentionClass: "protected", BindingDigest: digest}}})
}

func (p *cleanupPhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.service == nil || c == (identity.Command{}) || c != p.command || plan.Feature == nil || *plan.Feature != p.registration() || plan.SubjectType != "anonymous" || plan.Lifecycle == nil || *plan.Lifecycle != p.lifecycle() || len(plan.Audits) != 1 || plan.Audits[0].EventType != expiryOperation().OperationID || !plan.Audits[0].Required || plan.CommandCounters != nil || plan.OTP != nil || plan.Capability != nil || plan.Delivery != nil || plan.SignupAcceptance {
		return anonymous.ErrInvalidInput
	}
	_, err := ExpirySubject(c)
	return err
}

func (p *cleanupPhase) shared(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.command {
		return anonymous.ErrInvalidInput
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	local := p.service.config().Clock.Now()
	if !readInstant(local) || now.Before(p.input.ObservedAt) || local.Before(p.input.LocalStartedAt) || !now.Before(p.input.Until) || !local.Before(p.input.Until) {
		return identity.ForbiddenError{}
	}
	return w.RequireActiveDirectoryAuthority(ctx, p, kernel.DirectoryAuthorityAdmission{Query: kernel.DirectoryAuthorityQuery{GlobalAuthorityID: p.service.config().GlobalAuthorityID, TenantID: p.input.Command.Binding.TenantID}, GlobalVersion: p.input.GlobalVersion, TenantVersion: p.input.TenantVersion})
}

func (p *cleanupPhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if err := p.shared(ctx, w, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if _, err := p.service.domain.ApplyExpired(ctx, w, p, c, p.input.Kernel.intent()); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.service.repository.StageExpiredDisposal(ctx, w, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return p.service.effect.ApplyExpired(ctx, w, p, c)
}

func (p *cleanupPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if err := p.shared(ctx, w, c); err != nil {
		return err
	}
	if err := p.service.domain.CheckExpired(ctx, w, p, c, p.input.Kernel.intent()); err != nil {
		return err
	}
	if err := p.service.repository.RequireExpiredDisposal(ctx, w, p, c); err != nil {
		return err
	}
	return p.service.effect.CheckExpired(ctx, w, p, c, p.input.Until)
}

func (p *cleanupPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	a, err := p.service.repository.RecoverExpiredDisposal(ctx, w, p)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	b, err := p.service.effect.RecoverExpired(ctx, w, p)
	if err != nil || a != b {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	return a, nil
}
