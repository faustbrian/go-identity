package anonymouspostgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"slices"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	policy "github.com/faustbrian/go-authorization/v3/postgres"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	capability "github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

type upgradeOutput struct {
	Schema              uint8
	Grant               upgradeStoredCapability
	Checkpoint, Proof   []byte
	Result, FinalFields []identity.FeatureField
	Counters            deletionStoredCounters
}

func upgradeAudit(b identity.CommandBinding, operation identity.FeatureOperation, subject string, lifecycle kernel.LifecyclePlan, at time.Time, retention uint64) (kernel.AuditPlan, error) {
	id := b.RecordID
	if id == "" {
		id = string(b.UserID)
	}
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.AuditPlan{}, err
	}
	seed, err := builder.Build(audit.RecordInput{OccurredAt: at, Action: b.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: subject, ID: id}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": subject, "aggregate.id": id, "aggregate.before_version": strconv.FormatUint(lifecycle.BeforeVersion, 10), "aggregate.after_version": strconv.FormatUint(lifecycle.AfterVersion, 10), "retention.class": "protected"}})
	if err != nil {
		return kernel.AuditPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, operation, subject, seed)
	if err != nil {
		return kernel.AuditPlan{}, err
	}
	return kernel.AuditPlan{EventType: b.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: retention, RetentionClass: "protected", BindingDigest: digest}, nil
}

func (p *upgradePreparation) plan(original bool) (kernel.CommandPlan, error) {
	lifecycle := kernel.LifecyclePlan{EventType: "anonymous.upgrade.prepared.v1"}
	a, err := upgradeAudit(p.input.Preparation, upgradePreparationOperation(), "anonymous_upgrade_preparation", lifecycle, p.input.Started, p.service.config().Guest.RetentionPolicyVersion)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	registration := p.registration()
	plan := kernel.CommandPlan{Contributors: p.registry.Descriptors(), Feature: &registration, SubjectType: "anonymous_upgrade_preparation", Lifecycle: &lifecycle, Audits: []kernel.AuditPlan{a}}
	if original {
		plan.Contributors = plan.Contributors[:len(plan.Contributors)-1]
		return p.coordinator.PrepareFeaturePreparationPlan(p.original, plan)
	}
	plan.CapabilityIssuance = &p.issuance
	return p.coordinator.PrepareCommandPlan(p.input.Preparation, p.command, plan)
}

func (p *upgradePreparation) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.service == nil || p.original == (identity.Command{}) || c != p.original && (p.command == (identity.Command{}) || c != p.command) || plan.Feature == nil || *plan.Feature != p.registration() || plan.SubjectType != "anonymous_upgrade_preparation" || plan.Lifecycle == nil || *plan.Lifecycle != (kernel.LifecyclePlan{EventType: "anonymous.upgrade.prepared.v1"}) || len(plan.Audits) != 1 || plan.Audits[0].EventType != upgradeOperation().OperationID || !plan.Audits[0].Required || plan.CommandCounters != nil || plan.Capability != nil || plan.OTP != nil || plan.Delivery != nil {
		return anonymous.ErrInvalidInput
	}
	return p.ValidateAnonymousUpgradePreparation(c, plan.CapabilityIssuance)
}
func (p *upgradePreparation) ValidateAnonymousUpgradePreparation(c identity.Command, issuance *kernel.CapabilityIssuancePlan) error {
	if c == p.original && issuance == nil {
		return nil
	}
	if p.command == (identity.Command{}) || c != p.command || issuance == nil || !reflect.DeepEqual(*issuance, p.issuance) {
		return anonymous.ErrInvalidInput
	}
	return p.service.capability.ValidateCapabilityIssuance(p.input.Preparation, *issuance)
}
func (p *upgradePreparation) ValidateFeaturePreparation(c identity.Command, plan kernel.CommandPlan) error {
	if c != p.original || plan.CapabilityIssuance != nil {
		return anonymous.ErrInvalidInput
	}
	return p.ValidateFeatureCommand(c, plan)
}

func (p *upgradePreparation) checkTime(ctx context.Context, w kernel.Work) error {
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	local := p.service.config().Guest.Validation.Clock.Now()
	if !readInstant(local) || now.Before(p.input.Started) || local.Before(p.input.Started) || !now.Before(p.input.Until) || !local.Before(p.input.Until) {
		return identity.ForbiddenError{}
	}
	if _, err = p.target.Lifetime(now); err != nil {
		return identity.ForbiddenError{}
	}
	deadline, err := p.primary.Deadline()
	if err != nil || !now.Before(deadline) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *upgradePreparation) targetFence(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command) error {
	b, _, _, err := w.FeatureScope(owner)
	if err != nil {
		return err
	}
	directory, credential, authz, err := sessionpg.OriginalSessionAdmission(sessionpg.IdentifierAdmissionConfig(p.service.config().Target.Profile), p.target, b)
	if err != nil {
		return err
	}
	if err = w.RequireActiveDirectoryAuthority(ctx, owner, directory); err != nil {
		return err
	}
	if _, err = w.RequireActiveCredential(ctx, owner, credential); err != nil {
		return err
	}
	if err = w.RequireActiveUserAuthorization(ctx, owner, authz); err != nil {
		return err
	}
	if err = sessionpg.RequireSession(ctx, w, p.service.config().Guest.Sessions, p.target); err != nil {
		return err
	}
	if _, err = mfapg.RequireAnonymousUpgradeFactors(ctx, w, owner, command, p.input.FactorVersion); err != nil {
		return err
	}
	return p.checkTime(ctx, w)
}

func (p *upgradePreparation) guestPolicy(ctx context.Context, w kernel.Work) error {
	s, err := p.guest.Bindings()
	if err != nil {
		return err
	}
	a, err := s.Authority.Bindings()
	if err != nil {
		return err
	}
	c := p.service.config().Guest
	query := kernel.DirectoryAuthorityQuery{GlobalAuthorityID: c.Profile.GlobalAuthorityID, TenantID: s.TenantID}
	keys, err := kernel.KernelAuthorityKeys(query, s.UserID)
	if err != nil {
		return err
	}
	sk, err := sessionpg.SessionAuthorityKeys(s.TenantID, s.UserID, s.FamilyID, s.SessionID)
	if err != nil {
		return err
	}
	expected := p.input.Kernel.intent().Snapshot.Authority
	scope := policy.AuthorityScope{TenantID: authorization.TenantID(s.TenantID), PolicyNamespace: c.Profile.PolicyNamespace, SubjectID: authorization.SubjectID(s.UserID)}
	key, err := scope.Key()
	if err != nil {
		return err
	}
	target, _ := p.target.Bindings()
	ta, _ := target.Authority.Bindings()
	if a.Global != ta.Global || a.Tenant != ta.Tenant || a.Global.ScopeKey != keys.Global || a.Tenant.ScopeKey != keys.Tenant || a.User != (session.AuthorityBinding{ScopeKey: keys.User, Version: expected.UserAuthorityVersion}) || a.Identifier != (session.AuthorityBinding{ScopeKey: keys.Identifier, Version: expected.IdentifierAuthorityVersion}) || a.Credential != (session.AuthorityBinding{ScopeKey: keys.Credential, Version: expected.CredentialAuthorityVersion}) || a.Session != (session.AuthorityBinding{ScopeKey: sk.Session, Version: s.Version}) || a.SessionFamily != (session.AuthorityBinding{ScopeKey: sk.Family, Version: s.FamilyVersion}) || a.Authorization.ScopeKey != key || a.Organization.Present || a.Factor.Present || a.Passkey.Present {
		return identity.ForbiddenError{}
	}
	return policy.RequireAuthority(ctx, w, scope, a.Authorization.Version, c.Repository.MaximumDuration)
}

func (p *upgradePreparation) checkPreparation(ctx context.Context, w kernel.Work, command identity.Command) error {
	if err := p.targetFence(ctx, w, p, command); err != nil {
		return err
	}
	if err := p.guestPolicy(ctx, w); err != nil {
		return err
	}
	if err := p.service.guest.domain.RequireUpgradePreparation(ctx, w, p, command, p.input.Kernel.intent()); err != nil {
		return err
	}
	if err := sessionpg.RequireSession(ctx, w, p.service.config().Guest.Sessions, p.guest); err != nil {
		return err
	}
	rows, err := w.Query(ctx, subjectSelect(p.service.guest.repository.schema)+" WHERE tenant_id=$1 AND user_id=$2 FOR UPDATE", string(p.input.Preparation.TenantID), string(p.input.Subject.UserID))
	if err != nil {
		return err
	}
	current, err := readSubject(rows)
	rows.Close()
	if err != nil {
		return err
	}
	s, _ := current.Record()
	if s != anonymous.SubjectSpec(p.input.Subject) {
		return identity.ForbiddenError{}
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if err = current.RequireActive(s.TenantID, now); err != nil {
		return err
	}
	if _, err = p.guest.Lifetime(now); err != nil {
		return identity.ForbiddenError{}
	}
	return p.checkTime(ctx, w)
}
func (p *upgradePreparation) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, command identity.Command) error {
	if command != p.original {
		return anonymous.ErrInvalidInput
	}
	return p.checkPreparation(ctx, w, command)
}

func (p *upgradePreparation) outputAAD(generation uint64) (envelope.Context, error) {
	f, ok := p.original.Feature()
	if !ok || generation == 0 {
		return envelope.Context{}, anonymous.ErrInvalidInput
	}
	frame, err := json.Marshal(struct {
		Original   identity.FeatureCommandSpec
		Generation uint64
		Profile    [32]byte
	}{f, generation, p.service.profile})
	if err != nil {
		return envelope.Context{}, err
	}
	defer clear(frame)
	digest := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"profile": "identity-anonymous-upgrade-output-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func (p *upgradePreparation) GenerateFeaturePreparation(ctx context.Context, c identity.Command, generation uint64) ([]byte, error) {
	if c != p.original || !p.service.config().Guest.Validation.Clock.Now().Before(p.input.Until) {
		return nil, identity.ForbiddenError{}
	}
	// Generation occurs only after the existing coordinator's durable ACK. No
	// transaction/callback spans entropy or cryptography. The prospective token
	// remains invocation-local; only its digest-bearing record is checkpointed.
	s, _ := p.target.Bindings()
	authority, _ := s.Authority.Bindings()
	id, err := identity.NewSubjectID()
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	family, err := identity.NewSubjectID()
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	keys, err := sessionpg.SessionAuthorityKeys(s.TenantID, s.UserID, string(family), string(id))
	if err != nil {
		return nil, err
	}
	authority.Session, authority.SessionFamily = session.AuthorityBinding{ScopeKey: keys.Session, Version: 1}, session.AuthorityBinding{ScopeKey: keys.Family, Version: 1}
	vector, err := session.NewAuthoritySnapshot(authority)
	if err != nil {
		return nil, err
	}
	s.SessionID, s.FamilyID, s.Version, s.FamilyVersion, s.Lookup, s.Authority, s.IssuedAt, s.LastActivityAt = string(id), string(family), 1, 1, session.TokenDigest{}, vector, p.input.Started, p.input.Started
	prepared, err := p.issuer.PrepareAnonymousUpgrade(p.input.Final.Binding, s, p.input.Subject.Version, p.input.Until)
	if err != nil {
		return nil, err
	}
	result, ok := prepared.Session()
	if !ok {
		return nil, anonymous.ErrInvalidInput
	}
	resultFields, err := sessionpg.OriginalSessionFields(result)
	if err != nil {
		return nil, err
	}
	commitments, err := sessionpg.AnonymousUpgradeSessionFields(p.guest, result)
	if err != nil {
		return nil, err
	}
	fields := append(slices.Clone(p.input.Final.Fields), commitments...)
	command, err := identity.NewFeatureSessionCommand(identity.FeatureCommandSpec{Binding: p.input.Final.Binding, Operation: upgradeOperation(), Fields: fields}, p.request.TargetSession)
	if err != nil {
		return nil, err
	}
	gs, _ := p.guest.Bindings()
	command, counters, err := p.service.guest.risk.PrepareCommandCounters(command, risk.Subject{User: string(gs.UserID), Session: gs.SessionID, Network: p.input.Network}, p.input.Started)
	if err != nil {
		return nil, err
	}
	final, _ := command.Feature()
	merge, err := upgradeMergeDigest(p.merge)
	if err != nil {
		return nil, err
	}
	remember, _ := s.Remember.Bindings()
	rememberValue := "session"
	if remember.Choice == session.PersistentSession {
		rememberValue = "persistent"
	}
	expires := p.input.Until.Truncate(time.Second)
	issued, err := p.service.capability.Prepare(ctx, p.input.Preparation, []capability.Payload{{Version: 1, Issuer: p.service.config().Capability.Crypto.Issuer, Tenant: string(s.TenantID), Subject: string(s.UserID), Resource: string(gs.UserID), Operation: "identity.anonymous.upgrade", Audiences: []string{p.service.config().Capability.Audience}, IssuedAt: p.input.Started.Truncate(time.Second), NotBefore: p.input.Started.Truncate(time.Second), ExpiresAt: expires, MaxUses: 1, Caveats: map[string]string{"anonymous.source-version": strconv.FormatUint(p.input.Subject.Version, 10), "anonymous.source-session": gs.SessionID, "anonymous.target-session": sTargetID(p.target), "anonymous.merge-digest": base64.RawURLEncoding.EncodeToString(merge[:]), "anonymous.remember": rememberValue}}})
	if err != nil {
		return nil, err
	}
	plan, err := issued.Plan()
	if err != nil || len(plan.Grants) != 1 {
		return nil, anonymous.ErrInvalidInput
	}
	output := upgradeOutput{Schema: 1, Grant: upgradeStoredCapability(plan.Grants[0]), Result: resultFields, FinalFields: final.Fields, Counters: deletionStoredCounters(counters)}
	checkpoint, err := p.service.checkpoint.CheckpointPreparation(ctx, issued, generation, func(_ context.Context, index uint16, token []byte) error {
		if index != 0 || len(token) == 0 || len(token) > 16<<10 {
			return anonymous.ErrInvalidInput
		}
		output.Proof = append([]byte(nil), token...)
		return nil
	})
	if err != nil {
		clear(output.Proof)
		return nil, err
	}
	output.Checkpoint = checkpoint
	defer clear(output.Proof)
	defer clear(checkpoint)
	aad, err := p.outputAAD(generation)
	if err != nil {
		return nil, err
	}
	wire, err := sealAnonymousInput(ctx, p.service.guest.crypto, p.service.config().Guest.ActiveEnvelopeKeyID, aad, output)
	if err != nil {
		return nil, err
	}
	p.prospective = prepared
	return wire, nil
}

func sTargetID(record session.Session) string { s, _ := record.Bindings(); return s.SessionID }

func (p *upgradePreparation) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	return p.restoreOutput(ctx, c, generation, wire, true)
}

// A known committed issuance retry needs original metadata, not permission to
// stage a grant again. Retain native envelope authentication and command scope,
// but do not require an expired grant to become live merely to read its terminal
// result. A fresh protected execution still verifies original signed scope and
// exclusive expiry before Begin; staging restoration always uses the issuer.
func (p *upgradePreparation) restoreOutput(ctx context.Context, c identity.Command, generation uint64, wire []byte, staging bool) (identity.Command, kernel.CommandPlan, error) {
	if c != p.original {
		return identity.Command{}, kernel.CommandPlan{}, anonymous.ErrInvalidInput
	}
	aad, err := p.outputAAD(generation)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	var output upgradeOutput
	if err = openAnonymousInput(ctx, p.service.guest.crypto, aad, wire, &output); err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	defer clear(output.Proof)
	defer clear(output.Checkpoint)
	if output.Schema != 1 || len(output.Proof) == 0 || len(output.Proof) > 16<<10 {
		return identity.Command{}, kernel.CommandPlan{}, anonymous.ErrInvalidInput
	}
	result, err := sessionpg.OriginalSessionFromFields(p.input.Final.Binding.TenantID, p.input.Final.Binding.UserID, output.Result)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	command, err := identity.NewFeatureSessionCommand(identity.FeatureCommandSpec{Binding: p.input.Final.Binding, Operation: upgradeOperation(), Fields: output.FinalFields}, p.request.TargetSession)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	if sessionpg.ValidateAnonymousUpgradeSessionIntent(command, p.guest, result) != nil || ValidateUpgradePlan(command, p.merge) != nil {
		return identity.Command{}, kernel.CommandPlan{}, anonymous.ErrInvalidInput
	}
	if err = p.service.guest.risk.ValidateCommandCounters(command, kernel.CommandCounterPlan(output.Counters)); err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	// Checkpoint authentication reconstructs staging-only custody, never a new
	// signature or an exportable proof. The separate final phase re-verifies the
	// original signed envelope before the real one-use participant consumes it.
	issuance := kernel.CapabilityIssuancePlan{Contributor: kernel.ContributorDescriptor{Owner: "capability/postgres", ContractID: "capability.issuance", Version: 1}, Grants: []kernel.CapabilityPlan{kernel.CapabilityPlan(output.Grant)}}
	var issued capabilitypg.PreparedIssuance
	if staging {
		issued, err = p.service.checkpoint.RestorePreparation(ctx, p.input.Preparation, generation, issuance, output.Checkpoint)
		if err != nil {
			return identity.Command{}, kernel.CommandPlan{}, err
		}
	}
	proof := append([]byte(nil), output.Proof...)
	checkpoint := append([]byte(nil), output.Checkpoint...)
	output.Proof, output.Checkpoint = proof, checkpoint
	p.output, p.result, p.issuance, p.issued, p.outputDigest, p.generation = output, result, issuance, issued, sha256.Sum256(wire), generation
	fields := append(slices.Clone(p.input.Final.Fields), identity.FeatureField{Name: "anonymous.preparation.output", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: p.outputDigest[:]}})
	p.command, err = identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: p.input.Preparation, Operation: upgradePreparationOperation(), Fields: fields})
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	plan, err := p.plan(false)
	return p.command, plan, err
}

func (p *upgradePreparation) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if c != p.command || c == p.original {
		return identity.FeatureReceipt{}, anonymous.ErrInvalidInput
	}
	wire, generation, err := w.FeaturePreparationOutput(p)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	digest := sha256.Sum256(wire)
	clear(wire)
	if digest != p.outputDigest || generation != p.generation {
		return identity.FeatureReceipt{}, anonymous.ErrInvalidInput
	}
	if err = p.checkPreparation(ctx, w, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err = p.service.capability.Stage(ctx, w, p.issued); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: upgradePreparationOperation()}, nil
}
func (p *upgradePreparation) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.command {
		return anonymous.ErrInvalidInput
	}
	return p.checkPreparation(ctx, w, c)
}
func (p *upgradePreparation) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	// This owner has no durable domain effect to prove absent. The coordinator
	// independently requires every actual issuance/audit/lifecycle owner to prove
	// absence before terminalizing rollback. A committed journal returns its own
	// receipt, never this effect-free negative vote as proof of commitment.
	b, f, _, err := w.FeatureScope(p)
	if err != nil || b != p.input.Preparation || f != p.registration() {
		return kernel.RecoveryUnknown, anonymous.ErrInvalidInput
	}
	if err = ctx.Err(); err != nil {
		return kernel.RecoveryUnknown, err
	}
	return kernel.RecoveryNotCommitted, nil
}
