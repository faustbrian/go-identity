package mfapostgres

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	primitive "github.com/faustbrian/go-password/v2"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

type activeStepUpInput struct {
	Binding   identity.CommandBinding
	Primary   []byte
	Factor    TOTPActiveFactorMetadata
	Wire      []byte
	Intent    [32]byte
	CreatedAt time.Time
}
type activeStepUpOutput struct {
	Schema     uint32
	Generation uint64
	Input      activeStepUpInput
	Risk       enrollmentStoredRisk
}
type activeStepUpPhase struct {
	state       *activeStepUpState
	request     mfa.TotpVerifyRequest
	input       *activeStepUpInput
	primary     TOTPActivePrimary
	command     identity.Command
	plan        kernel.CommandPlan
	counters    kernel.CommandCounterPlan
	coordinator *kernel.Coordinator
	registry    *kernel.ContributorRegistry
	risk        risk.ProtectedProviderAdmission
	secret      primitive.Secret
	until       time.Time
	record      factorVerificationRecord
	applied     bool
}

func (*activeStepUpPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}
}
func (*activeStepUpPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{activeStepUpOperation()}
}
func (p *activeStepUpPhase) lifecycle() kernel.LifecyclePlan {
	return kernel.LifecyclePlan{EventType: "factor.verified.v1", BeforeVersion: p.input.Factor.Factor.RowVersion, AfterVersion: p.input.Factor.Factor.RowVersion + 1}
}
func (p *activeStepUpPhase) query() identity.RecoveryQuery {
	r := p.request
	return identity.RecoveryQuery{CommandID: r.CommandID, TenantID: r.TenantID, UserID: identity.UserID(r.Caller.Request.Subject.ID), ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: authorization.SubjectUser, OperationID: activeStepUpOperation().OperationID, RecordID: string(r.FactorID)}
}

func (p *activeStepUpPhase) aad(generation uint64) (envelope.Context, error) {
	if p == nil || p.state == nil || p.request.StepUp == nil || generation == 0 {
		return envelope.Context{}, invalidAuthority()
	}
	r := p.request
	frame, err := json.Marshal(struct {
		Profile, Tenant, User, Command, Factor string
		Configuration                          [32]byte
		Generation                             uint64
	}{"mfa-active-step-up-v1", string(r.TenantID), string(r.Caller.Request.Subject.ID), string(r.CommandID), string(r.FactorID), p.state.identity, generation})
	if err != nil {
		return envelope.Context{}, invalidAuthority()
	}
	defer clear(frame)
	digest := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"profile": "mfa-active-step-up-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func (p *activeStepUpPhase) load(ctx context.Context) error {
	id, _ := base64.RawURLEncoding.DecodeString(string(p.request.CommandID))
	var exists bool
	if err := p.state.shared.pool.Raw().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM identity.identity_command_id_claims WHERE command_id=$1)`, id).Scan(&exists); err != nil {
		return enrollmentReadError(ctx)
	}
	if exists {
		wire, generation, err := p.coordinator.QueryFeaturePreparation(ctx, p.query(), p.request.Caller, kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: activeStepUpOperation()}, p)
		if err != nil {
			return err
		}
		defer clear(wire)
		return p.restoreOutput(ctx, generation, wire)
	}
	primary, observed, err := p.state.config.Primary.PrepareStepUp(ctx, p.request)
	if err != nil {
		return err
	}
	active, err := p.state.reader.ReadForStepUp(ctx, observed, string(p.request.FactorID))
	if err != nil {
		return err
	}
	meta, err := active.Metadata()
	if err != nil {
		return err
	}
	if meta.Factor.RowVersion == math.MaxUint64 {
		return identity.ForbiddenError{}
	}
	sealed, err := active.Envelope()
	if err != nil {
		return err
	}
	wire, err := sealed.MarshalBinary()
	if err != nil {
		return err
	}
	snapshot, err := primary.Snapshot()
	if err != nil {
		clear(wire)
		return err
	}
	digest, err := p.state.intent(p.request)
	if err != nil {
		clear(wire)
		clear(snapshot)
		return err
	}
	op := activeStepUpOperation()
	r := p.request
	b := identity.CommandBinding{CommandID: r.CommandID, TenantID: r.TenantID, UserID: meta.Factor.UserID, ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: authorization.SubjectUser, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: p.state.shared.config.PolicyID, PolicyVersion: p.state.shared.config.Coordinator.AdmissionPolicy.PolicyVersion, RecordID: string(r.FactorID), CorrelationID: string(r.CommandID)}
	p.input = &activeStepUpInput{Binding: b, Primary: snapshot, Factor: meta, Wire: wire, Intent: digest, CreatedAt: time.Now().UTC().Truncate(time.Microsecond)}
	p.primary, p.until = primary, meta.ValidUntil
	return nil
}

func (p *activeStepUpPhase) buildCommand() error {
	if p == nil || p.input == nil || p.primary == nil {
		return invalidAuthority()
	}
	i := p.input
	m := i.Factor.Factor
	fields := []identity.FeatureField{
		{Name: "factor.enrollment", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: m.EnrollmentVersion}},
		{Name: "factor.before", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: m.RowVersion}},
		{Name: "factor.authority", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: m.FactorAuthorityVersion}},
		{Name: "factor.intent", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: i.Intent[:]}},
		{Name: "factor.created", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: i.CreatedAt}},
	}
	command, err := p.primary.Command(i.Binding, fields)
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
	command, counters, err := p.state.shared.counters.PrepareCommandCounters(command, risk.Subject{User: string(i.Binding.UserID), Session: s.SessionID, Network: p.request.Network}, i.CreatedAt)
	if err != nil {
		return err
	}
	p.command, p.counters = command, counters
	b := i.Binding
	life := p.lifecycle()
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return err
	}
	seed, err := builder.Build(audit.RecordInput{OccurredAt: i.CreatedAt, Action: b.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "factor", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "factor", "aggregate.id": b.RecordID, "aggregate.before_version": strconv.FormatUint(life.BeforeVersion, 10), "aggregate.after_version": strconv.FormatUint(life.AfterVersion, 10), "retention.class": "protected"}})
	if err != nil {
		return err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, activeStepUpOperation(), "factor", seed)
	if err != nil {
		return err
	}
	p.plan, err = p.coordinator.PrepareFeaturePreparationPlan(command, kernel.CommandPlan{Contributors: p.registry.Descriptors(), Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: activeStepUpOperation()}, SubjectType: "factor", CommandCounters: &counters, Lifecycle: &life, Audits: []kernel.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}})
	return err
}

func (p *activeStepUpPhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.input == nil || c != p.command || plan.Feature == nil || *plan.Feature != (kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: activeStepUpOperation()}) || plan.SubjectType != "factor" || plan.Lifecycle == nil || *plan.Lifecycle != p.lifecycle() || plan.CommandCounters == nil || *plan.CommandCounters != p.counters || plan.Capability != nil || plan.OTP != nil || plan.RiskEvidence != nil || plan.Delivery != nil || plan.MFACompletion != nil || plan.MFAContinuation != nil || plan.CapabilityIssuance != nil || len(plan.Audits) != 1 {
		return invalidAuthority()
	}
	a := plan.Audits[0]
	if !a.Required || a.EventType != activeStepUpOperation().OperationID || a.RequiredRecordCount != 1 || a.RetentionClass != "protected" {
		return invalidAuthority()
	}
	return nil
}
func (p *activeStepUpPhase) ValidateFeaturePreparation(c identity.Command, plan kernel.CommandPlan) error {
	return p.ValidateFeatureCommand(c, plan)
}
func (p *activeStepUpPhase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p == nil || p.input == nil || c != p.command {
		return invalidAuthority()
	}
	if err := p.primary.Admit(ctx, w, p, c); err != nil {
		return err
	}
	_, _, err := p.lockFactor(ctx, w)
	return err
}

type activeStepUpAdmission struct {
	phase *activeStepUpPhase
	risk  risk.ProtectedProviderAdmission
}

func (a *activeStepUpAdmission) Check(ctx context.Context) error {
	if ctx == nil || a == nil || a.phase == nil || a.phase.input == nil {
		return invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !time.Now().Before(a.phase.until) {
		return identity.ForbiddenError{}
	}
	return a.risk.CheckAt(ctx, time.Now().UTC())
}
func (p *activeStepUpPhase) PrepareFeatureAdmission(ctx context.Context, c identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if p == nil || c != p.command {
		return nil, invalidAuthority()
	}
	scope := risk.Context{Tenant: string(p.request.TenantID), Operation: risk.Action(activeStepUpOperation().OperationID), Attempt: string(p.request.CommandID)}
	assessment, err := p.state.shared.config.Risk.Evaluation.EvaluateProtectedProviders(ctx, risk.EvaluateRequest{Context: scope, Phase: risk.NonIssuing})
	if err != nil {
		return nil, enrollmentReadError(ctx)
	}
	admitted, err := p.state.shared.custody.Prepare(ctx, assessment, scope)
	if err != nil {
		return nil, err
	}
	a := &activeStepUpAdmission{phase: p, risk: admitted}
	return a, a.Check(ctx)
}
func (p *activeStepUpPhase) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, invalidAuthority()
}
func (a *activeStepUpAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	p := a.phase
	plain, err := json.Marshal(activeStepUpOutput{Schema: 1, Generation: generation, Input: *p.input, Risk: enrollmentStoredRisk(a.risk.Prepared())})
	if err != nil {
		return nil, invalidAuthority()
	}
	defer clear(plain)
	aad, err := p.aad(generation)
	if err != nil {
		return nil, err
	}
	return (&totpEnrollmentPhase{state: p.state.shared}).seal(ctx, aad, plain)
}

func (p *activeStepUpPhase) restoreOutput(ctx context.Context, generation uint64, wire []byte) error {
	aad, err := p.aad(generation)
	if err != nil {
		return err
	}
	plain, err := (&totpEnrollmentPhase{state: p.state.shared}).open(ctx, aad, wire)
	if err != nil {
		return err
	}
	defer clear(plain)
	var out activeStepUpOutput
	if decodeEnrollmentJSON(plain, &out) != nil || out.Schema != 1 || out.Generation != generation {
		return invalidAuthority()
	}
	digest, err := p.state.intent(p.request)
	i := out.Input
	m := i.Factor.Factor
	if err != nil || !hmac.Equal(digest[:], i.Intent[:]) || i.Binding.CommandID != p.request.CommandID || i.Binding.TenantID != p.request.TenantID || i.Binding.UserID != identity.UserID(p.request.Caller.Request.Subject.ID) || i.Binding.ActorID != identity.ActorID(p.request.Caller.Request.Subject.ID) || i.Binding.ActorKind != authorization.SubjectUser || i.Binding.RecordID != string(p.request.FactorID) || i.Binding.ValidateFor(activeStepUpOperation()) != nil || i.Binding.PolicyID != p.state.shared.config.PolicyID || i.Binding.PolicyVersion != p.state.shared.config.Coordinator.AdmissionPolicy.PolicyVersion || i.Binding.CorrelationID != string(i.Binding.CommandID) || m.TenantID != i.Binding.TenantID || m.UserID != i.Binding.UserID || m.FactorID != i.Binding.RecordID || m.EnrollmentVersion == 0 || m.RowVersion == 0 || m.RowVersion == math.MaxUint64 || m.FactorAuthorityVersion == 0 || m.Profile.Validate() != nil || m.ContinuationID != "" || m.ContinuationVersion != 0 || m.ScopeDigest != ([32]byte{}) || len(i.Wire) < 1 || len(i.Wire) > 4096 || len(i.Primary) < 1 || len(i.Primary) > 32768 || i.CreatedAt.IsZero() || i.CreatedAt.Nanosecond()%1000 != 0 {
		return identity.ForbiddenError{}
	}
	primary, err := p.state.config.Primary.RestoreStepUp(ctx, p.request, i.Primary)
	if err != nil {
		return err
	}
	original, err := primary.Original()
	if err != nil {
		return err
	}
	s, err := original.Bindings()
	if err != nil || i.Factor.SessionID != s.SessionID || i.Factor.SessionVersion != s.Version {
		return identity.ForbiddenError{}
	}
	until, err := primary.Deadline()
	if err != nil || !until.Equal(i.Factor.ValidUntil) {
		return identity.ForbiddenError{}
	}
	scope := risk.Context{Tenant: string(p.request.TenantID), Operation: risk.Action(activeStepUpOperation().OperationID), Attempt: string(p.request.CommandID)}
	admitted, err := p.state.shared.custody.Restore(ctx, risk.PreparedProtectedProviderAdmission(out.Risk), scope)
	if err != nil {
		return err
	}
	p.input, p.primary, p.until, p.risk = &i, primary, until, admitted
	sealed, err := envelope.ParseEnvelope(i.Wire)
	if err != nil {
		return invalidAuthority()
	}
	binding, err := totpEncryptionContext(m.TenantID, m.UserID, m.FactorID, m.EnrollmentVersion, m.Profile)
	if err != nil {
		return err
	}
	raw, err := p.state.shared.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: binding})
	if err != nil {
		return enrollmentReadError(ctx)
	}
	defer clear(raw)
	p.secret.Destroy()
	p.secret, err = primitive.NewSecret(raw)
	return err
}
func (p *activeStepUpPhase) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	if p == nil || c != p.command {
		return identity.Command{}, kernel.CommandPlan{}, invalidAuthority()
	}
	if err := p.restoreOutput(ctx, generation, wire); err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	return p.command, p.plan, nil
}
func (p *activeStepUpPhase) RestoreFeatureAdmission(ctx context.Context, c identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if _, _, err := p.RestoreFeaturePreparation(ctx, c, generation, wire); err != nil {
		return nil, err
	}
	a := &activeStepUpAdmission{phase: p, risk: p.risk}
	return a, a.Check(ctx)
}

func (p *activeStepUpPhase) lockFactor(ctx context.Context, w kernel.Work) (mfa.TOTPReplayState, time.Time, error) {
	m := p.input.Factor.Factor
	b := p.input.Binding
	if _, err := readFactorAuthority(ctx, w, b, b.UserID, m.FactorAuthorityVersion); err != nil {
		return mfa.TOTPReplayState{}, time.Time{}, err
	}
	var wire []byte
	var row, enrollment string
	var last *string
	var algorithm, issuer string
	var digits, period, skew int16
	err := completionTOTPStore(w).query(ctx, `SELECT encrypted_secret,row_version::text,enrollment_version::text,last_step::text,algorithm,digits,period_seconds,skew_steps,issuer FROM identity_mfa.totp_factors WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3 AND state=2 AND confirmed_at IS NOT NULL FOR UPDATE`, []any{string(b.TenantID), string(b.UserID), b.RecordID}, &wire, &row, &enrollment, &last, &algorithm, &digits, &period, &skew, &issuer)
	defer clear(wire)
	if err != nil {
		return mfa.TOTPReplayState{}, time.Time{}, attemptStoreError(ctx, err)
	}
	if row != strconv.FormatUint(m.RowVersion, 10) || enrollment != strconv.FormatUint(m.EnrollmentVersion, 10) || sha256.Sum256(wire) != sha256.Sum256(p.input.Wire) || algorithm != m.Profile.Algorithm || uint32(digits) != m.Profile.Digits || time.Duration(period)*time.Second != m.Profile.Period || uint32(skew) != m.Profile.AllowedSkewSteps || issuer != m.Profile.Issuer {
		return mfa.TOTPReplayState{}, time.Time{}, identity.ForbiddenError{}
	}
	replay := mfa.TOTPReplayState{}
	if last != nil {
		replay.Used = true
		replay.LastStep, err = strconv.ParseUint(*last, 10, 64)
		if err != nil {
			return replay, time.Time{}, identity.UnavailableError{}
		}
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return replay, time.Time{}, err
	}
	if !now.Before(p.until) {
		return replay, time.Time{}, identity.ForbiddenError{}
	}
	return replay, now, nil
}

func (p *activeStepUpPhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if p == nil || p.input == nil || c != p.command {
		return identity.FeatureReceipt{}, invalidAuthority()
	}
	if err := w.RequireFeatureCommand(ctx, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.primary.Check(ctx, w, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	replay, now, err := p.lockFactor(ctx, w)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.risk.CheckAt(ctx, now); err != nil {
		return identity.FeatureReceipt{}, err
	}
	scope, err := json.Marshal(struct {
		Profile, Tenant, User, Factor, Command string
		Version                                uint32
	}{"mfa-active-step-up-code-v1", string(p.input.Binding.TenantID), string(p.input.Binding.UserID), p.input.Binding.RecordID, string(p.input.Binding.CommandID), p.state.config.ComparisonKeyVersion})
	if err != nil {
		return identity.FeatureReceipt{}, invalidAuthority()
	}
	defer clear(scope)
	step, err := p.state.verifier.Verify(ctx, p.secret, p.request.Code, p.input.Factor.Factor.Profile, scope, now, replay)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	b := p.input.Binding
	m := p.input.Factor.Factor
	original, err := p.primary.Original()
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	s, err := original.Bindings()
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	life, err := original.Lifetime(now)
	if err != nil {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	expires := now.Add(p.state.config.TTL)
	if life.ExpiresAt.Before(expires) {
		expires = life.ExpiresAt
	}
	proof := auth.ReauthenticationProof{Proof: auth.Proof{ID: auth.ProofID(b.CommandID), Tenant: string(b.TenantID), Subject: string(b.UserID), Method: "totp", Assurance: auth.AssuranceMultiFactor, Purpose: p.request.StepUp.Purpose, Audience: p.state.config.Audience, IssuedAt: now, ExpiresAt: expires}, SessionID: s.SessionID, SessionVersion: s.Version, Action: string(p.request.StepUp.Purpose)}
	signed, err := p.state.config.SigningKey.sign(auth.SignedReauthenticationRecord{Issuer: p.state.config.Issuer, Environment: p.state.config.Environment, Proof: proof, ProofVersion: 1, CredentialID: m.FactorID, CredentialVersion: m.EnrollmentVersion})
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	p.record = factorVerificationRecord{Schema: 1, Original: signed, FactorAuthorityVersion: m.FactorAuthorityVersion}
	wire, err := encodeFactorVerificationRecord(p.record)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	defer clear(wire)
	n, err := w.Exec(ctx, `UPDATE identity_mfa.totp_factors SET last_step=$4::numeric,row_version=row_version+1 WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3 AND state=2 AND row_version=$5::numeric AND (last_step IS NULL OR last_step<$4::numeric)`, string(b.TenantID), string(b.UserID), m.FactorID, strconv.FormatUint(step, 10), strconv.FormatUint(m.RowVersion, 10))
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	n, err = w.Exec(ctx, `INSERT INTO identity_mfa.factor_verifications(proof_id,tenant_id,user_id,factor_id,enrollment_version,factor_authority_version,command_id,purpose,record) VALUES($1,$2,$3,$4,$5::numeric,$6::numeric,$7,$8,$9)`, string(b.CommandID), string(b.TenantID), string(b.UserID), m.FactorID, strconv.FormatUint(m.EnrollmentVersion, 10), strconv.FormatUint(m.FactorAuthorityVersion, 10), id, b.OperationID, wire)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	if err := p.CheckFeatureCommit(ctx, w, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	p.applied = true
	l := p.lifecycle()
	return identity.FeatureReceipt{Operation: activeStepUpOperation(), BeforeVersion: l.BeforeVersion, AfterVersion: l.AfterVersion}, nil
}
func (p *activeStepUpPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p == nil || p.input == nil || c != p.command {
		return invalidAuthority()
	}
	if err := p.primary.Check(ctx, w, p, c); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if !now.Before(p.until) {
		return identity.ForbiddenError{}
	}
	return p.risk.CheckAt(ctx, now)
}
func (p *activeStepUpPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, f, l, err := w.FeatureScope(p)
	if err != nil || f.Operation != activeStepUpOperation() || l.EventType != "factor.verified.v1" || l.BeforeVersion == 0 || l.AfterVersion != l.BeforeVersion+1 {
		return kernel.RecoveryUnknown, invalidAuthority()
	}
	rows, err := w.Query(ctx, `SELECT record FROM identity_mfa.factor_verifications WHERE tenant_id=$1 AND user_id=$2 AND proof_id=$3 AND factor_id=$4 AND octet_length(record) BETWEEN 1 AND 32768`, string(b.TenantID), string(b.UserID), string(b.CommandID), b.RecordID)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return kernel.RecoveryUnknown, rows.Err()
		}
		return kernel.RecoveryNotCommitted, nil
	}
	var wire []byte
	if rows.Scan(&wire) != nil || rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	defer clear(wire)
	r, err := decodeFactorVerificationRecord(auth.ProofID(b.CommandID), string(b.TenantID), string(b.UserID), wire)
	if err != nil || r.Original.CredentialID != b.RecordID {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	frame, err := r.Original.SigningBytes()
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer clear(frame)
	key := p.state.config.VerificationKeys[r.Original.KeyID]
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, frame, r.Original.Signature) {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	return kernel.RecoveryCommitted, nil
}
func (p *activeStepUpPhase) destroy() {
	p.secret.Destroy()
	if p.input != nil {
		clear(p.input.Primary)
		clear(p.input.Wire)
		p.input = nil
	}
	clear(p.record.Original.Signature)
}
