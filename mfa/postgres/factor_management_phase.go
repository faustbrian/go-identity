package mfapostgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

type factorUpdateInput struct {
	Schema             uint32
	Binding            identity.CommandBinding
	Primary            []byte
	Record             factorVerificationRecord
	Intent             []identity.FeatureField
	Before             mfa.FactorProjection
	CreatedAt, Until   time.Time
	Replacement        *PendingTOTPMetadata `json:",omitempty"`
	ReplacementOrigin  string               `json:",omitempty"`
	ReplacementNetwork string               `json:",omitempty"`
	ReplacementUntil   *time.Time           `json:",omitempty"`
}
type factorUpdateOutput struct {
	Schema      uint32
	Generation  uint64
	Risk        enrollmentStoredRisk
	Replacement *totpEnrollmentOutput `json:",omitempty"`
}
type factorUpdatePhase struct {
	state       *factorUpdateState
	request     mfa.FactorUpdateRequest
	input       *factorUpdateInput
	primary     TOTPActivePrimary
	command     identity.Command
	plan        kernel.CommandPlan
	counters    kernel.CommandCounterPlan
	coordinator *kernel.Coordinator
	registry    *kernel.ContributorRegistry
	risk        risk.ProtectedProviderAdmission
	result      mfa.FactorProjection
	applied     bool
	disable     *mfa.DisableRequest
	remaining   []mfa.FactorProjection
	replacement *totpEnrollmentOutput
}

func (p *factorUpdatePhase) operation() identity.FeatureOperation { return p.state.operation }

func (p *factorUpdatePhase) targetID() mfa.FactorID {
	if p.disable != nil && p.input != nil {
		return p.input.Before.ID
	}
	return p.request.FactorID
}

func (p *factorUpdatePhase) targetVersion() uint64 {
	if p.disable != nil && p.input != nil {
		return p.input.Before.Version
	}
	return p.request.ExpectedVersion
}

func (p *factorUpdatePhase) requestIntent() (identity.RequestIntent, error) {
	intent, err := p.state.requestIntent(p.request)
	if err != nil || p.disable == nil {
		return intent, err
	}
	fields, ok := intent.Fields()
	if !ok {
		return identity.RequestIntent{}, invalidAuthority()
	}
	fields = append(fields, identity.FeatureField{Name: "disable.target", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(p.disable.Target)}})
	return identity.NewRequestIntent(fields)
}

func (*factorUpdatePhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}
}
func (p *factorUpdatePhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{p.operation()}
}
func (p *factorUpdatePhase) lifecycle() kernel.LifecyclePlan {
	v := p.input.Record.FactorAuthorityVersion
	if p.request.Action == mfa.Replace {
		return kernel.LifecyclePlan{EventType: "factor.updated.v1", BeforeVersion: p.input.Before.Version, AfterVersion: p.input.Before.Version + 1}
	}
	if p.request.Action == mfa.Remove {
		return kernel.LifecyclePlan{EventType: "factor.removed.v1", BeforeVersion: v, AfterVersion: v + 1}
	}
	return kernel.LifecyclePlan{EventType: "factor.updated.v1", BeforeVersion: v, AfterVersion: v + 1}
}
func (p *factorUpdatePhase) inputAAD(k kernel.RequestKeyPreparationBinding) (envelope.Context, error) {
	if p == nil || p.state == nil || k.Namespace != p.state.shared.config.RequestKeys.Namespace || k.Scope.RouteID != p.operation().OperationID || k.Scope.Method != "POST" || k.Feature.Contributor != p.Descriptor() || k.Feature.Operation != p.operation() || k.PolicyVersion != p.state.shared.config.RequestKeys.Policy.PolicyVersion || k.IntentDigest == ([32]byte{}) || k.Admission.FingerprintKeyVersion == 0 {
		return envelope.Context{}, invalidAuthority()
	}
	frame, err := json.Marshal(struct {
		Namespace             string
		Scope                 kernel.RequestKeyScope
		Admission             kernel.RequestKeyAdmission
		Feature               kernel.FeatureRegistration
		Policy                uint64
		Intent, Configuration [32]byte
	}{k.Namespace, k.Scope, k.Admission, k.Feature, k.PolicyVersion, k.IntentDigest, p.state.identity})
	if err != nil {
		return envelope.Context{}, invalidAuthority()
	}
	defer clear(frame)
	digest := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"profile": "mfa-factor-update-input-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}
func (p *factorUpdatePhase) outputAAD(generation uint64) (envelope.Context, error) {
	if p == nil || p.input == nil || generation == 0 {
		return envelope.Context{}, invalidAuthority()
	}
	frame, err := json.Marshal(struct {
		Input         factorUpdateInput
		Configuration [32]byte
		Generation    uint64
	}{*p.input, p.state.identity, generation})
	if err != nil {
		return envelope.Context{}, invalidAuthority()
	}
	defer clear(frame)
	digest := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"profile": "mfa-factor-update-output-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}
func (p *factorUpdatePhase) PrepareRequestKey(ctx context.Context, k kernel.RequestKeyPreparationBinding, intent identity.RequestIntent) ([]byte, error) {
	aad, err := p.inputAAD(k)
	r := p.request
	if err != nil || k.Scope.TenantID != r.TenantID || k.Scope.ActorID != identity.ActorID(r.Caller.Request.Subject.ID) || k.Scope.ActorKind != authorization.SubjectUser {
		return nil, invalidAuthority()
	}
	if r.CommandID != "" && r.CommandID != k.Admission.CommandID {
		return nil, identity.ConflictError{}
	}
	if string(r.FactorProof.ID) == string(k.Admission.CommandID) {
		return nil, identity.ForbiddenError{}
	}
	var primary TOTPActivePrimary
	var observed session.GetResult
	if p.disable != nil {
		primary, observed, err = p.state.disablePrimary.PrepareDisable(ctx, *p.disable, k.Admission.CommandID)
	} else {
		primary, observed, err = p.state.config.Primary.PrepareFactorUpdate(ctx, r, k.Admission.CommandID)
	}
	if err != nil {
		return nil, err
	}
	original, err := primary.Original()
	if err != nil {
		return nil, err
	}
	s, err := original.Bindings()
	if err != nil || observed.ValidateAt(time.Now()) != nil || s.TenantID != r.TenantID || s.UserID != identity.UserID(k.Scope.ActorID) {
		return nil, identity.ForbiddenError{}
	}
	record, err := p.state.source.readRecord(ctx, r.FactorProof.ID)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidProof) {
			return nil, identity.ForbiddenError{}
		}
		return nil, err
	}
	defer clear(record.Original.Signature)
	if record.FactorAuthorityVersion == 0 || record.FactorAuthorityVersion == math.MaxUint64 || record.Original.Proof.SessionID != s.SessionID || record.Original.Proof.SessionVersion != s.Version || record.Original.Proof.Proof.ID != r.FactorProof.ID {
		return nil, identity.ForbiddenError{}
	}
	proof := auth.ReauthenticationProof{Proof: r.FactorProof, SessionID: s.SessionID, SessionVersion: s.Version, Action: p.operation().OperationID}
	use := auth.ReauthenticationUse{ProofUse: auth.ProofUse{Tenant: string(s.TenantID), Subject: string(s.UserID), Purpose: auth.Purpose(p.operation().OperationID), Audience: p.state.evidenceProfile().audience}, SessionID: s.SessionID, SessionVersion: s.Version, Action: p.operation().OperationID, MaximumAge: p.state.config.MaximumAge}
	if err := p.state.validator.ValidateReauthenticationProof(ctx, proof, use); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if errors.Is(err, auth.ErrAuthenticationUnavailable) {
			return nil, identity.UnavailableError{}
		}
		return nil, identity.ForbiddenError{}
	}
	var version string
	var label string
	var created, now time.Time
	factor := r.FactorID
	if p.disable != nil && p.disable.Target == mfa.AllFactors {
		factor = mfa.FactorID(record.Original.CredentialID)
	}
	err = p.state.shared.pool.Raw().QueryRow(ctx, `SELECT row_version::text,label,created_at,clock_timestamp() FROM `+p.state.factorTable()+` WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3 AND state=2 AND confirmed_at IS NOT NULL`, string(r.TenantID), string(s.UserID), string(factor)).Scan(&version, &label, &created, &now)
	if err != nil {
		return nil, enrollmentReadError(ctx)
	}
	expected := r.ExpectedVersion
	if p.disable != nil {
		expected, err = strconv.ParseUint(version, 10, 64)
		if err != nil || expected == 0 || expected == math.MaxUint64 {
			return nil, identity.UnavailableError{}
		}
	}
	if version != strconv.FormatUint(expected, 10) {
		return nil, identity.ConflictError{}
	}
	before := mfa.FactorProjection{ID: factor, Method: p.state.method(), Label: label, State: mfa.FactorActive, CreatedAt: created, Version: expected}
	if (mfa.ListResult{Factors: []mfa.FactorProjection{before}}).ValidateAt(now) != nil {
		return nil, identity.UnavailableError{}
	}
	until := observed.ValidUntil()
	for _, candidate := range []time.Time{record.Original.Proof.Proof.ExpiresAt, record.Original.Proof.Proof.IssuedAt.Add(p.state.config.MaximumAge), s.Authentication.Proof.IssuedAt.Add(p.state.config.PrimaryMaximumAge)} {
		if candidate.Before(until) {
			until = candidate
		}
	}
	if now.Before(s.Authentication.Proof.IssuedAt) || !now.Before(until) {
		return nil, identity.ForbiddenError{}
	}
	snapshot, err := primary.Snapshot()
	if err != nil {
		return nil, err
	}
	defer clear(snapshot)
	fields, ok := intent.Fields()
	if !ok {
		return nil, invalidAuthority()
	}
	op := p.operation()
	b := identity.CommandBinding{CommandID: k.Admission.CommandID, TenantID: r.TenantID, UserID: s.UserID, ActorID: k.Scope.ActorID, ActorKind: authorization.SubjectUser, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: p.state.shared.config.PolicyID, PolicyVersion: p.state.shared.config.Coordinator.AdmissionPolicy.PolicyVersion, CorrelationID: string(k.Admission.CommandID), RecordID: string(s.UserID)}
	in := factorUpdateInput{Schema: 1, Binding: b, Primary: snapshot, Record: record, Intent: fields, Before: before, CreatedAt: now.UTC().Truncate(time.Microsecond), Until: until}
	if r.Action == mfa.Replace {
		if factor != mfa.FactorID(record.Original.CredentialID) {
			return nil, identity.ForbiddenError{}
		}
		id, err := identity.NewCommandID()
		if err != nil || string(id) == string(factor) || id == k.Admission.CommandID {
			return nil, identity.UnavailableError{}
		}
		in.Replacement = &PendingTOTPMetadata{TenantID: b.TenantID, UserID: b.UserID, FactorID: string(id), AuthorityVersion: record.FactorAuthorityVersion, Profile: p.state.shared.config.Profile, CreatedAt: in.CreatedAt, ExpiresAt: in.CreatedAt.Add(p.state.shared.config.TTL)}
		in.ReplacementOrigin, in.ReplacementNetwork = r.Origin, r.Network
		ceiling := in.Replacement.ExpiresAt
		for _, candidate := range []time.Time{record.Original.Proof.Proof.ExpiresAt, record.Original.Proof.Proof.IssuedAt.Add(p.state.config.MaximumAge), s.Authentication.Proof.IssuedAt.Add(p.state.config.PrimaryMaximumAge)} {
			if candidate.Before(ceiling) {
				ceiling = candidate
			}
		}
		in.ReplacementUntil = &ceiling
	}
	plain, err := json.Marshal(in)
	if err != nil {
		return nil, invalidAuthority()
	}
	defer clear(plain)
	return (&totpEnrollmentPhase{state: p.state.shared}).seal(ctx, aad, plain)
}
func (p *factorUpdatePhase) restoreInput(ctx context.Context, k kernel.RequestKeyPreparationBinding, wire []byte) error {
	aad, err := p.inputAAD(k)
	if err != nil {
		return err
	}
	plain, err := (&totpEnrollmentPhase{state: p.state.shared}).open(ctx, aad, wire)
	if err != nil {
		return err
	}
	defer clear(plain)
	var in factorUpdateInput
	if err := decodeEnrollmentJSON(plain, &in); err != nil {
		clear(in.Primary)
		clear(in.Record.Original.Signature)
		return err
	}
	accepted := false
	defer func() {
		if !accepted {
			clear(in.Primary)
			clear(in.Record.Original.Signature)
		}
	}()
	intent, err := p.requestIntent()
	fields, ok := intent.Fields()
	b, r := in.Binding, p.request
	matched := in.Before.ID == r.FactorID && in.Before.Version == r.ExpectedVersion
	if p.disable != nil {
		matched = in.Before.ID == mfa.FactorID(in.Record.Original.CredentialID) && (p.disable.Target == mfa.AllFactors || in.Before.ID == p.disable.FactorID)
	}
	if err != nil || !ok || !reflect.DeepEqual(fields, in.Intent) || in.Schema != 1 || b.ValidateFor(p.operation()) != nil || b.CommandID != k.Admission.CommandID || b.TenantID != r.TenantID || b.UserID != identity.UserID(k.Scope.ActorID) || b.ActorID != k.Scope.ActorID || b.ActorKind != authorization.SubjectUser || b.RecordID != string(b.UserID) || b.PolicyID != p.state.shared.config.PolicyID || b.PolicyVersion != p.state.shared.config.Coordinator.AdmissionPolicy.PolicyVersion || b.CorrelationID != string(b.CommandID) || in.Record.FactorAuthorityVersion == 0 || in.Record.FactorAuthorityVersion == math.MaxUint64 || in.Record.Original.Proof.Proof != r.FactorProof || !matched || in.Before.State != mfa.FactorActive || in.Before.Method != p.state.method() || in.CreatedAt.IsZero() || in.CreatedAt.Nanosecond()%1000 != 0 || len(in.Primary) < 1 || len(in.Primary) > 32768 {
		return identity.ForbiddenError{}
	}
	if _, err := p.state.encodeRecord(in.Record); err != nil {
		return err
	}
	if (mfa.ListResult{Factors: []mfa.FactorProjection{in.Before}}).ValidateAt(in.CreatedAt) != nil {
		return invalidAuthority()
	}
	if !p.validReplacementInput(&in) {
		return invalidAuthority()
	}
	var primary TOTPActivePrimary
	if p.disable != nil {
		primary, err = p.state.disablePrimary.RestoreDisable(ctx, *p.disable, b.CommandID, in.Primary)
	} else {
		primary, err = p.state.config.Primary.RestoreFactorUpdate(ctx, r, b.CommandID, in.Primary)
	}
	if err != nil {
		return err
	}
	original, err := primary.Original()
	if err != nil {
		return err
	}
	s, err := original.Bindings()
	if err != nil || in.Record.Original.Proof.SessionID != s.SessionID || in.Record.Original.Proof.SessionVersion != s.Version {
		return identity.ForbiddenError{}
	}
	until, err := primary.Deadline()
	if err != nil {
		return err
	}
	for _, candidate := range []time.Time{in.Record.Original.Proof.Proof.ExpiresAt, in.Record.Original.Proof.Proof.IssuedAt.Add(p.state.config.MaximumAge), s.Authentication.Proof.IssuedAt.Add(p.state.config.PrimaryMaximumAge)} {
		if candidate.Before(until) {
			until = candidate
		}
	}
	if !until.Equal(in.Until) || !in.CreatedAt.Before(in.Until) || in.Record.Original.Issuer != p.state.evidenceProfile().issuer || in.Record.Original.Environment != p.state.evidenceProfile().environment {
		return identity.ForbiddenError{}
	}
	p.input, p.primary = &in, primary
	accepted = true
	return nil
}
func (p *factorUpdatePhase) buildCommand() error {
	i := p.input
	if i == nil || p.primary == nil {
		return invalidAuthority()
	}
	wire, err := p.state.encodeRecord(i.Record)
	if err != nil {
		return err
	}
	defer clear(wire)
	digest := sha256.Sum256(wire)
	fields := []identity.FeatureField{{Name: "factor.before", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: i.Record.FactorAuthorityVersion}}, {Name: "factor.after", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: i.Record.FactorAuthorityVersion + 1}}, {Name: "factor.proof", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(i.Record.Original.Proof.Proof.ID)}}, {Name: "factor.proof-record", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}}, {Name: "factor.target", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(p.targetID())}}, {Name: "factor.target-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: p.targetVersion()}}, {Name: "factor.label", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: p.request.Name}}}
	if p.request.Action == mfa.Replace {
		fields[1].Value.Uint64 = i.Record.FactorAuthorityVersion
		fields = append(fields, identity.FeatureField{Name: "factor.action", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(mfa.Replace)}}, identity.FeatureField{Name: "factor.replacement", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: i.Replacement.FactorID}})
	}
	if p.request.Action == mfa.Remove {
		if nilEnrollmentPrimary(p.state.config.RemovalRecovery) || p.state.config.RemovalRecoveryPath != auth.RecoveryPathEmail {
			return identity.ForbiddenError{}
		}
		recovery := p.state.config.RemovalRecovery.FactorRemovalRecoveryIdentity()
		if recovery == ([32]byte{}) {
			return identity.ForbiddenError{}
		}
		fields = append(fields, identity.FeatureField{Name: "factor.action", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(mfa.Remove)}}, identity.FeatureField{Name: "factor.recovery-path", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(auth.RecoveryPathEmail)}}, identity.FeatureField{Name: "factor.recovery", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: recovery[:]}})
	}
	if p.disable != nil {
		fields = append(fields, identity.FeatureField{Name: "disable.target", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(p.disable.Target)}})
	}
	c, err := p.primary.Command(i.Binding, fields)
	if err != nil {
		return err
	}
	original, err := p.primary.Original()
	if err != nil {
		return err
	}
	s, err := original.Bindings()
	if err != nil {
		return err
	}
	c, counters, err := p.state.shared.counters.PrepareCommandCounters(c, risk.Subject{User: string(i.Binding.UserID), Session: s.SessionID, Network: p.request.Network}, i.CreatedAt)
	if err != nil {
		return err
	}
	p.command, p.counters = c, counters
	l, b := p.lifecycle(), i.Binding
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return err
	}
	seed, err := builder.Build(audit.RecordInput{OccurredAt: i.CreatedAt, Action: b.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "user", ID: string(b.UserID)}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "user", "aggregate.id": string(b.UserID), "aggregate.before_version": strconv.FormatUint(l.BeforeVersion, 10), "aggregate.after_version": strconv.FormatUint(l.AfterVersion, 10), "retention.class": "protected"}})
	if err != nil {
		return err
	}
	ad, err := kernel.FeatureAuditBindingDigest(b, p.operation(), "user", seed)
	if err != nil {
		return err
	}
	p.plan, err = p.coordinator.PrepareFeaturePreparationPlan(c, kernel.CommandPlan{Contributors: p.registry.Descriptors(), Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: p.operation()}, SubjectType: "user", Lifecycle: &l, CommandCounters: &counters, Audits: []kernel.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: ad}}})
	return err
}
func (p *factorUpdatePhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.input == nil || c != p.command || plan.Feature == nil || *plan.Feature != (kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: p.operation()}) || plan.SubjectType != "user" || plan.Lifecycle == nil || *plan.Lifecycle != p.lifecycle() || plan.CommandCounters == nil || *plan.CommandCounters != p.counters || plan.Capability != nil || plan.OTP != nil || plan.Delivery != nil || plan.RiskEvidence != nil || plan.MFACompletion != nil || plan.MFAContinuation != nil || plan.CapabilityIssuance != nil || len(plan.Audits) != 1 {
		return invalidAuthority()
	}
	a := plan.Audits[0]
	if !a.Required || a.EventType != p.operation().OperationID || a.RequiredRecordCount != 1 || a.RetentionClass != "protected" {
		return invalidAuthority()
	}
	return nil
}
func (p *factorUpdatePhase) ValidateFeaturePreparation(c identity.Command, plan kernel.CommandPlan) error {
	return p.ValidateFeatureCommand(c, plan)
}
func (p *factorUpdatePhase) admit(ctx context.Context, w kernel.Work, c identity.Command, preparation bool) error {
	if p == nil || p.input == nil || c != p.command {
		return invalidAuthority()
	}
	var err error
	if preparation {
		err = p.primary.Admit(ctx, w, p, c)
	} else {
		err = p.primary.Check(ctx, w, p, c)
	}
	if err != nil {
		return err
	}
	if p.request.Action == mfa.Remove {
		if p.targetID() != mfa.FactorID(p.input.Record.Original.CredentialID) {
			return identity.ForbiddenError{}
		}
		if err := p.state.config.RemovalRecovery.CheckFactorRemovalRecovery(ctx, w, p, c); err != nil {
			return err
		}
	}
	r := p.input.Record
	if err := p.state.requireFactor(ctx, w, p, p.input.Binding.UserID, r, false); err != nil {
		return err
	}
	return p.lockProof(ctx, w, false)
}
func (p *factorUpdatePhase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, c identity.Command) error {
	return p.admit(ctx, w, c, true)
}

type factorUpdateAdmission struct {
	phase *factorUpdatePhase
	risk  risk.ProtectedProviderAdmission
}

func (a *factorUpdateAdmission) Check(ctx context.Context) error {
	if ctx == nil || a == nil || a.phase == nil || a.phase.input == nil {
		return invalidAuthority()
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if !time.Now().Before(a.phase.input.Until) {
		return identity.ForbiddenError{}
	}
	return a.risk.CheckAt(ctx, time.Now().UTC())
}
func (p *factorUpdatePhase) PrepareFeatureAdmission(ctx context.Context, c identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if p == nil || c != p.command {
		return nil, invalidAuthority()
	}
	scope := risk.Context{Tenant: string(p.request.TenantID), Operation: risk.Action(p.operation().OperationID), Attempt: string(p.input.Binding.CommandID)}
	assessment, err := p.state.shared.config.Risk.Evaluation.EvaluateProtectedProviders(ctx, risk.EvaluateRequest{Context: scope, Phase: risk.NonIssuing})
	if err != nil {
		return nil, enrollmentReadError(ctx)
	}
	admission, err := p.state.shared.custody.Prepare(ctx, assessment, scope)
	if err != nil {
		return nil, err
	}
	a := &factorUpdateAdmission{phase: p, risk: admission}
	return a, a.Check(ctx)
}
func (p *factorUpdatePhase) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, invalidAuthority()
}
func (a *factorUpdateAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	p := a.phase
	output := factorUpdateOutput{Schema: 1, Generation: generation, Risk: enrollmentStoredRisk(a.risk.Prepared())}
	if p.request.Action == mfa.Replace {
		material, err := generateEnrollmentMaterial(ctx, p.state.shared, *p.input.Replacement, generation, p.state.config.Replacement.RecoveryCodes)
		if err != nil {
			return nil, err
		}
		defer clearEnrollmentOutput(&material)
		output.Replacement = &material
	}
	plain, err := json.Marshal(output)
	if err != nil {
		return nil, invalidAuthority()
	}
	defer clear(plain)
	aad, err := p.outputAAD(generation)
	if err != nil {
		return nil, err
	}
	return (&totpEnrollmentPhase{state: p.state.shared}).seal(ctx, aad, plain)
}
func (p *factorUpdatePhase) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	if p == nil || c != p.command {
		return identity.Command{}, kernel.CommandPlan{}, invalidAuthority()
	}
	aad, err := p.outputAAD(generation)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	plain, err := (&totpEnrollmentPhase{state: p.state.shared}).open(ctx, aad, wire)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	defer clear(plain)
	var out factorUpdateOutput
	keepReplacement := false
	defer func() {
		if !keepReplacement && out.Replacement != nil {
			clearEnrollmentOutput(out.Replacement)
		}
	}()
	if decodeEnrollmentJSON(plain, &out) != nil || out.Schema != 1 || out.Generation != generation {
		return identity.Command{}, kernel.CommandPlan{}, invalidAuthority()
	}
	if p.request.Action == mfa.Replace {
		if err := p.restoreReplacementMaterial(ctx, generation, out.Replacement); err != nil {
			return identity.Command{}, kernel.CommandPlan{}, err
		}
	} else if out.Replacement != nil {
		clearEnrollmentOutput(out.Replacement)
		return identity.Command{}, kernel.CommandPlan{}, invalidAuthority()
	}
	scope := risk.Context{Tenant: string(p.request.TenantID), Operation: risk.Action(p.operation().OperationID), Attempt: string(p.input.Binding.CommandID)}
	p.risk, err = p.state.shared.custody.Restore(ctx, risk.PreparedProtectedProviderAdmission(out.Risk), scope)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	keepReplacement = true
	return p.command, p.plan, nil
}
func (p *factorUpdatePhase) RestoreFeatureAdmission(ctx context.Context, c identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if _, _, err := p.RestoreFeaturePreparation(ctx, c, generation, wire); err != nil {
		return nil, err
	}
	a := &factorUpdateAdmission{phase: p, risk: p.risk}
	return a, a.Check(ctx)
}
func (p *factorUpdatePhase) lockProof(ctx context.Context, w kernel.Work, used bool) error {
	i, b := p.input, p.input.Binding
	record := i.Record
	rows, err := w.Query(ctx, `SELECT v.record,v.used_command_id,v.used_purpose FROM `+p.state.proofTable()+` v
JOIN identity.commands j ON j.tenant_id=v.tenant_id AND j.command_id=v.command_id AND j.purpose=v.purpose
JOIN identity.identity_command_id_claims c ON c.command_id=j.command_id AND c.tenant_id=j.tenant_id AND c.purpose=j.purpose
WHERE v.tenant_id=$1 AND v.user_id=$2 AND v.proof_id=$3 AND v.factor_id=$4 AND v.enrollment_version=$5::numeric AND v.factor_authority_version=$6::numeric AND j.state='committed' AND NOT c.retired AND octet_length(v.record) BETWEEN 1 AND 32768 FOR UPDATE OF v`, string(b.TenantID), string(b.UserID), string(record.Original.Proof.Proof.ID), record.Original.CredentialID, strconv.FormatUint(record.Original.CredentialVersion, 10), strconv.FormatUint(record.FactorAuthorityVersion, 10))
	if err != nil {
		return err
	}
	var wire, usedID []byte
	var purpose *string
	if !rows.Next() {
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		return identity.ForbiddenError{}
	}
	err = rows.Scan(&wire, &usedID, &purpose)
	extra, rowErr := rows.Next(), rows.Err()
	rows.Close()
	defer clear(wire)
	want, encodeErr := p.state.encodeRecord(record)
	defer clear(want)
	if err != nil || extra || rowErr != nil || encodeErr != nil {
		return identity.UnavailableError{}
	}
	if !hmac.Equal(wire, want) {
		return identity.ForbiddenError{}
	}
	if used {
		if base64.RawURLEncoding.EncodeToString(usedID) != string(b.CommandID) || purpose == nil || *purpose != b.OperationID {
			return identity.ForbiddenError{}
		}
	} else if usedID != nil || purpose != nil {
		return identity.ConflictError{}
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	proof := record.Original.Proof
	use := auth.ReauthenticationUse{ProofUse: auth.ProofUse{Tenant: string(b.TenantID), Subject: string(b.UserID), Purpose: auth.Purpose(b.OperationID), Audience: p.state.evidenceProfile().audience, Now: now}, SessionID: proof.SessionID, SessionVersion: proof.SessionVersion, Action: b.OperationID, MaximumAge: p.state.config.MaximumAge}
	if proof.Validate(use) != nil || !now.Before(i.Until) {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *factorUpdatePhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if p == nil || p.input == nil || c != p.command {
		return identity.FeatureReceipt{}, invalidAuthority()
	}
	if err := w.RequireFeatureCommand(ctx, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.admit(ctx, w, c, false); err != nil {
		return identity.FeatureReceipt{}, err
	}
	b, r := p.input.Binding, p.request
	r.FactorID, r.ExpectedVersion = p.targetID(), p.targetVersion()
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.risk.CheckAt(ctx, now); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if r.Action == mfa.Replace {
		return p.applyReplacement(ctx, w, c, now)
	}
	rows, err := w.Query(ctx, `SELECT row_version::text,label,created_at FROM `+p.state.factorTable()+` WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3 AND state=2 AND confirmed_at IS NOT NULL FOR UPDATE`, string(b.TenantID), string(b.UserID), string(r.FactorID))
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	var version, label string
	var created time.Time
	if !rows.Next() {
		err = rows.Err()
		rows.Close()
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	err = rows.Scan(&version, &label, &created)
	extra, rowErr := rows.Next(), rows.Err()
	rows.Close()
	if err != nil || extra || rowErr != nil {
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	if version != strconv.FormatUint(r.ExpectedVersion, 10) || label != p.input.Before.Label || !created.Equal(p.input.Before.CreatedAt) {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	statement := `UPDATE ` + p.state.factorTable() + ` SET label=$5,row_version=row_version+1 WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3 AND state=2 AND row_version=$4::numeric`
	if r.Action == mfa.Remove {
		statement = `UPDATE identity_mfa.totp_factors SET label=$5,state=3,encrypted_secret=NULL,last_step=NULL,row_version=row_version+1 WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3 AND state=2 AND row_version=$4::numeric`
	}
	n, err := w.Exec(ctx, statement, string(b.TenantID), string(b.UserID), string(r.FactorID), version, r.Name)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	if p.disable != nil && p.disable.Target == mfa.AllFactors {
		if err := p.revokePendingForDisable(ctx, w); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	n, err = w.Exec(ctx, `UPDATE `+p.state.proofTable()+` SET used_command_id=$4,used_purpose=$5,used_at=$6 WHERE tenant_id=$1 AND user_id=$2 AND proof_id=$3 AND used_command_id IS NULL AND used_purpose IS NULL AND used_at IS NULL`, string(b.TenantID), string(b.UserID), string(p.input.Record.Original.Proof.Proof.ID), id, b.OperationID, now)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	if err := p.state.config.Sessions.Apply(ctx, w, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if r.Action == mfa.Remove {
		if _, err := w.Exec(ctx, `UPDATE identity_mfa.recovery_sets SET state=3,row_version=row_version+1 WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3 AND state<>3`, string(b.TenantID), string(b.UserID), string(r.FactorID)); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	statement = `UPDATE identity_mfa.factor_authorities SET version=version+1 WHERE tenant_id=$1 AND user_id=$2 AND version=$3::numeric AND active_factors BETWEEN 1 AND 64`
	if r.Action == mfa.Remove {
		statement = `UPDATE identity_mfa.factor_authorities SET version=version+1,active_factors=0 WHERE tenant_id=$1 AND user_id=$2 AND version=$3::numeric AND active_factors=1 AND NOT EXISTS(SELECT 1 FROM identity_mfa.totp_factors t WHERE t.tenant_id=$1 AND t.user_id=$2 AND t.state=2)`
	}
	n, err = w.Exec(ctx, statement, string(b.TenantID), string(b.UserID), strconv.FormatUint(p.input.Record.FactorAuthorityVersion, 10))
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	l := p.lifecycle()
	if p.disable != nil {
		recovery := p.state.config.RemovalRecovery.FactorRemovalRecoveryIdentity()
		n, err = w.Exec(ctx, `INSERT INTO identity_mfa.factor_update_effects(tenant_id,user_id,command_id,purpose,factor_id,before_version,after_version,before_authority,after_authority,proof_id,action,recovery_identity,disable_target) VALUES($1,$2,$3,$4,$5,$6::numeric,$7::numeric,$8::numeric,$9::numeric,$10,2,$11,$12)`, string(b.TenantID), string(b.UserID), id, b.OperationID, string(r.FactorID), version, strconv.FormatUint(r.ExpectedVersion+1, 10), strconv.FormatUint(l.BeforeVersion, 10), strconv.FormatUint(l.AfterVersion, 10), string(p.input.Record.Original.Proof.Proof.ID), recovery[:], int16(p.disable.Target))
	} else {
		n, err = w.Exec(ctx, `INSERT INTO `+p.state.effectsTable()+`(tenant_id,user_id,command_id,purpose,factor_id,before_version,after_version,before_authority,after_authority,proof_id) VALUES($1,$2,$3,$4,$5,$6::numeric,$7::numeric,$8::numeric,$9::numeric,$10)`, string(b.TenantID), string(b.UserID), id, b.OperationID, string(r.FactorID), version, strconv.FormatUint(r.ExpectedVersion+1, 10), strconv.FormatUint(l.BeforeVersion, 10), strconv.FormatUint(l.AfterVersion, 10), string(p.input.Record.Original.Proof.Proof.ID))
	}
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	if r.Action == mfa.Remove && p.disable == nil {
		recovery := p.state.config.RemovalRecovery.FactorRemovalRecoveryIdentity()
		n, err = w.Exec(ctx, `UPDATE identity_mfa.factor_update_effects SET action=2,recovery_identity=$4 WHERE tenant_id=$1 AND user_id=$2 AND command_id=$3 AND action=1 AND recovery_identity IS NULL`, string(b.TenantID), string(b.UserID), id, recovery[:])
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		if n != 1 {
			return identity.FeatureReceipt{}, identity.ConflictError{}
		}
	}
	if err := p.CheckFeatureCommit(ctx, w, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.disable != nil {
		if err := p.readDisableRemaining(ctx, w); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	p.result = p.input.Before
	p.result.Label, p.result.Version = r.Name, r.ExpectedVersion+1
	if r.Action == mfa.Remove {
		p.result.State = mfa.FactorRevoked
	}
	p.applied = true
	return identity.FeatureReceipt{Operation: p.operation(), BeforeVersion: l.BeforeVersion, AfterVersion: l.AfterVersion}, nil
}
func (p *factorUpdatePhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p == nil || p.input == nil || c != p.command {
		return invalidAuthority()
	}
	if p.request.Action == mfa.Replace {
		return p.checkReplacement(ctx, w, c)
	}
	if err := p.lockProof(ctx, w, true); err != nil {
		return err
	}
	b, r := p.input.Binding, p.input.Record
	if p.request.Action == mfa.Remove {
		if err := p.checkRemoval(ctx, w); err != nil {
			return err
		}
	} else {
		if err := p.state.requireFactor(ctx, w, p, b.UserID, r, true); err != nil {
			return err
		}
	}
	if err := p.state.config.Sessions.Check(ctx, w, p, c); err != nil {
		return err
	}
	wantedState := 2
	if p.request.Action == mfa.Remove {
		wantedState = 3
	}
	rows, err := w.Query(ctx, `SELECT row_version::text,label FROM `+p.state.factorTable()+` WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3 AND state=$4`, string(b.TenantID), string(b.UserID), string(p.targetID()), wantedState)
	if err != nil {
		return err
	}
	var version, label string
	if !rows.Next() {
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		return identity.ForbiddenError{}
	}
	err = rows.Scan(&version, &label)
	extra, rowErr := rows.Next(), rows.Err()
	rows.Close()
	if err != nil || extra || rowErr != nil {
		return identity.UnavailableError{}
	}
	if version != strconv.FormatUint(p.targetVersion()+1, 10) || label != p.request.Name {
		return identity.ForbiddenError{}
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if !now.Before(p.input.Until) {
		return identity.ForbiddenError{}
	}
	return p.risk.CheckAt(ctx, now)
}
func (p *factorUpdatePhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, f, l, err := w.FeatureScope(p)
	removed := l.EventType == "factor.removed.v1"
	if err != nil || f.Operation != p.operation() || f.Contributor != p.Descriptor() || l.EventType != "factor.updated.v1" && !removed || l.BeforeVersion == 0 || l.BeforeVersion == math.MaxUint64 || l.AfterVersion != l.BeforeVersion+1 {
		return kernel.RecoveryUnknown, invalidAuthority()
	}
	if p.state.config.Replacement != nil {
		matched, status, err := p.recoverReplacement(ctx, w, b, l)
		if matched || err != nil {
			return status, err
		}
	}
	status, err := p.state.config.Sessions.Recover(ctx, w, p)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	rows, err := w.Query(ctx, `SELECT e.before_version::text,e.after_version::text,e.before_authority::text,e.after_authority::text,v.used_purpose FROM `+p.state.effectsTable()+` e JOIN `+p.state.proofTable()+` v ON v.tenant_id=e.tenant_id AND v.user_id=e.user_id AND v.proof_id=e.proof_id AND v.used_command_id=e.command_id WHERE e.tenant_id=$1 AND e.user_id=$2 AND e.command_id=$3 AND e.purpose=$4`, string(b.TenantID), string(b.UserID), id, b.OperationID)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return kernel.RecoveryUnknown, rows.Err()
		}
		if status == kernel.RecoveryNotCommitted {
			return status, nil
		}
		return kernel.RecoveryUnknown, nil
	}
	var before, after, authorityBefore, authorityAfter, purpose string
	if rows.Scan(&before, &after, &authorityBefore, &authorityAfter, &purpose) != nil || rows.Next() || rows.Err() != nil || status != kernel.RecoveryCommitted || authorityBefore != strconv.FormatUint(l.BeforeVersion, 10) || authorityAfter != strconv.FormatUint(l.AfterVersion, 10) || purpose != b.OperationID {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	v, err := strconv.ParseUint(before, 10, 64)
	if err != nil || v == 0 || v == math.MaxUint64 || after != strconv.FormatUint(v+1, 10) {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	if removed {
		rows.Close()
		query := `SELECT recovery_identity FROM identity_mfa.factor_update_effects WHERE tenant_id=$1 AND user_id=$2 AND command_id=$3 AND action=2`
		if p.operation() == disableOperation() {
			query += ` AND purpose='identity.mfa.disable' AND disable_target IN(1,2)`
		}
		check, err := w.Query(ctx, query, string(b.TenantID), string(b.UserID), id)
		if err != nil {
			return kernel.RecoveryUnknown, err
		}
		defer check.Close()
		var recovery []byte
		if !check.Next() || check.Scan(&recovery) != nil || check.Next() || check.Err() != nil || len(recovery) != 32 || hmac.Equal(recovery, make([]byte, 32)) {
			return kernel.RecoveryUnknown, identity.UnavailableError{}
		}
	}
	return kernel.RecoveryCommitted, nil
}

func (p *factorUpdatePhase) checkRemoval(ctx context.Context, w kernel.Work) error {
	b, r := p.input.Binding, p.input.Record
	state, err := readFactorAuthority(ctx, w, b, b.UserID, r.FactorAuthorityVersion+1)
	if err != nil {
		return err
	}
	if state.RequireEmailRecovery(b.TenantID, b.UserID) != nil {
		return identity.ForbiddenError{}
	}
	if err := p.state.config.RemovalRecovery.CheckFactorRemovalRecovery(ctx, w, p, p.command); err != nil {
		return err
	}
	rows, err := w.Query(ctx, `SELECT t.enrollment_version::text,t.encrypted_secret IS NULL AND t.last_step IS NULL,NOT EXISTS(SELECT 1 FROM identity_mfa.recovery_sets s WHERE s.tenant_id=t.tenant_id AND s.user_id=t.user_id AND s.factor_id=t.factor_id AND s.state<>3) FROM identity_mfa.totp_factors t WHERE t.tenant_id=$1 AND t.user_id=$2 AND t.factor_id=$3 AND t.state=3`, string(b.TenantID), string(b.UserID), string(p.targetID()))
	if err != nil {
		return err
	}
	defer rows.Close()
	var version string
	var erased, retired bool
	if !rows.Next() {
		if rows.Err() != nil {
			return rows.Err()
		}
		return identity.ForbiddenError{}
	}
	if rows.Scan(&version, &erased, &retired) != nil || rows.Next() || rows.Err() != nil {
		return identity.UnavailableError{}
	}
	if version != strconv.FormatUint(r.Original.CredentialVersion, 10) || !erased || !retired {
		return identity.ForbiddenError{}
	}
	if p.disable != nil && p.disable.Target == mfa.AllFactors {
		rows.Close()
		all, err := w.Query(ctx, `SELECT NOT EXISTS(SELECT 1 FROM identity_mfa.totp_factors WHERE tenant_id=$1 AND user_id=$2 AND state<>3) AND NOT EXISTS(SELECT 1 FROM identity_mfa.recovery_sets WHERE tenant_id=$1 AND user_id=$2 AND state<>3)`, string(b.TenantID), string(b.UserID))
		if err != nil {
			return err
		}
		defer all.Close()
		var complete bool
		if !all.Next() || all.Scan(&complete) != nil || all.Next() || all.Err() != nil {
			return identity.UnavailableError{}
		}
		if !complete {
			return identity.ForbiddenError{}
		}
	}
	return nil
}

// All-target invalidation includes older unconfirmed enrollments, not only the
// active factor that authenticated the proof. Bound the selected pending set
// before any erasure; the supported total is at most64 including the active one.
// The coordinator tenant mutex owns serialization; rows are locked in stable
// order in the same Work and no callback or external IO occurs under these locks.
func (p *factorUpdatePhase) revokePendingForDisable(ctx context.Context, w kernel.Work) error {
	b := p.input.Binding
	rows, err := w.Query(ctx, `SELECT factor_id,row_version::text FROM identity_mfa.totp_factors WHERE tenant_id=$1 AND user_id=$2 AND state=1 ORDER BY factor_id LIMIT 64 FOR UPDATE`, string(b.TenantID), string(b.UserID))
	if err != nil {
		return err
	}
	type pending struct{ id, version string }
	selected := make([]pending, 0, 16)
	for rows.Next() {
		var item pending
		if rows.Scan(&item.id, &item.version) != nil {
			rows.Close()
			return identity.UnavailableError{}
		}
		v, parseErr := strconv.ParseUint(item.version, 10, 64)
		if _, idErr := identity.ParseCommandID(item.id); idErr != nil || parseErr != nil || v == 0 || v == math.MaxUint64 || item.version != strconv.FormatUint(v, 10) {
			rows.Close()
			return identity.UnavailableError{}
		}
		selected = append(selected, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if len(selected) == 64 {
		return identity.ConflictError{}
	}
	for _, item := range selected {
		n, err := w.Exec(ctx, `UPDATE identity_mfa.totp_factors SET state=3,label='',encrypted_secret=NULL,last_step=NULL,row_version=row_version+1 WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3 AND state=1 AND row_version=$4::numeric`, string(b.TenantID), string(b.UserID), item.id, item.version)
		if err != nil {
			return err
		}
		if n != 1 {
			return identity.ConflictError{}
		}
		if _, err := w.Exec(ctx, `UPDATE identity_mfa.recovery_sets SET state=3,row_version=row_version+1 WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3 AND state<>3`, string(b.TenantID), string(b.UserID), item.id); err != nil {
			return err
		}
	}
	return nil
}
func (p *factorUpdatePhase) destroy() {
	if p.replacement != nil {
		clearEnrollmentOutput(p.replacement)
		p.replacement = nil
	}
	if p.input != nil {
		clear(p.input.Primary)
		clear(p.input.Record.Original.Signature)
		p.input = nil
	}
}
