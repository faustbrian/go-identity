package mfapostgres

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"slices"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// Explicit code-free DTOs are confined to the existing encrypted preparation.
// They deliberately do not invoke public custody types' forbidden serializers.
type otpActiveFactor OTPFactorMetadata
type otpActiveInput struct {
	Schema                  uint32
	Binding                 identity.CommandBinding
	Factor                  otpActiveFactor
	Primary, NativeInput    []byte
	SessionID               string
	SessionVersion          uint64
	CreatedAt, Until        time.Time
	ExpiresAt               time.Time
	Action, Origin, Network string
	Intent                  [32]byte
	Root                    *identity.FeatureCommandSpec
}
type otpActiveOutput struct {
	Schema     uint32
	Generation uint64
	Input      otpActiveInput
	Risk       enrollmentStoredRisk
	Data       []byte
}
type otpActivePhase struct {
	state         *otpActiveState
	verify        bool
	sendRequest   mfa.OtpSendRequest
	verifyRequest mfa.OtpVerifyRequest
	input, source *otpActiveInput
	primary       OTPActivePrimary
	prepared      OTPEnrollmentPreparedSend
	verification  OTPActiveVerification
	command       identity.Command
	generated     identity.Command
	plan          kernel.CommandPlan
	otpPlan       *kernel.OTPAttemptPlan
	counters      kernel.CommandCounterPlan
	coordinator   *kernel.Coordinator
	registry      *kernel.ContributorRegistry
	risk          risk.ProtectedProviderAdmission
	until         time.Time
	record        factorVerificationRecord
	applied       bool
}

func (*otpActivePhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}
}
func (p *otpActivePhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{otpActiveOperation(p.verify)}
}
func (p *otpActivePhase) lifecycle() kernel.LifecyclePlan {
	event := "otp.sent.v1"
	if p.verify {
		event = "factor.verified.v1"
	}
	return kernel.LifecyclePlan{EventType: event, BeforeVersion: p.input.Factor.RowVersion, AfterVersion: p.input.Factor.RowVersion + 1}
}
func (p *otpActivePhase) buildCommand() error {
	if p == nil || p.input == nil || p.primary == nil || p.input.Factor.RowVersion == ^uint64(0) {
		return invalidAuthority()
	}
	i := p.input
	inputHash := sha256.Sum256(i.NativeInput)
	fields := []identity.FeatureField{
		{Name: "factor.action", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: i.Action}},
		{Name: "factor.before", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: i.Factor.RowVersion}},
		{Name: "factor.enrollment", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: i.Factor.EnrollmentVersion}},
		{Name: "factor.authority", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: i.Factor.FactorAuthorityVersion}},
		{Name: "factor.intent", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: slices.Clone(i.Intent[:])}},
		{Name: "factor.input", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: inputHash[:]}},
		{Name: "factor.created", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: i.CreatedAt}},
	}
	if p.verify {
		fields = append(fields, identity.FeatureField{Name: "factor.source-send", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(p.verifyRequest.StepUp.SendCommandID)}})
	}
	c, err := p.primary.Command(i.Binding, fields)
	if err != nil {
		return err
	}
	c, p.counters, err = p.state.shared.counters.PrepareCommandCounters(c, risk.Subject{User: string(i.Binding.UserID), Session: i.SessionID, Network: i.Network}, i.CreatedAt)
	if err != nil {
		return err
	}
	root, ok := c.Feature()
	if !ok || i.Root != nil && !reflect.DeepEqual(root, *i.Root) {
		return invalidAuthority()
	}
	if i.Root == nil {
		i.Root = &root
	}
	p.command = c
	b, life := i.Binding, p.lifecycle()
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return err
	}
	seed, err := builder.Build(audit.RecordInput{OccurredAt: i.CreatedAt, Action: b.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "factor", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "factor", "aggregate.id": b.RecordID, "aggregate.before_version": strconv.FormatUint(life.BeforeVersion, 10), "aggregate.after_version": strconv.FormatUint(life.AfterVersion, 10), "retention.class": "protected"}})
	if err != nil {
		return err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, otpActiveOperation(p.verify), "factor", seed)
	if err != nil {
		return err
	}
	contributors := p.registry.Descriptors()
	deferred := p.state.config.Issuance.DeliveryContributor().Descriptor()
	if p.verify {
		deferred = p.state.config.Issuance.ConfirmationContributor().Descriptor()
	}
	contributors = slices.DeleteFunc(contributors, func(d kernel.ContributorDescriptor) bool { return d == deferred })
	p.plan, err = p.coordinator.PrepareFeaturePreparationPlan(c, kernel.CommandPlan{Contributors: contributors, Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: otpActiveOperation(p.verify)}, SubjectType: "factor", CommandCounters: &p.counters, Lifecycle: &life, Audits: []kernel.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}})
	return err
}

func (p *otpActivePhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.input == nil || c != p.command && c != p.generated || plan.Feature == nil || *plan.Feature != (kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: otpActiveOperation(p.verify)}) || plan.SubjectType != "factor" || plan.Lifecycle == nil || *plan.Lifecycle != p.lifecycle() || plan.CommandCounters == nil || *plan.CommandCounters != p.counters || plan.Capability != nil || plan.CapabilityIssuance != nil || plan.MFACompletion != nil || plan.MFAContinuation != nil || plan.RiskEvidence != nil || len(plan.Audits) != 1 {
		return invalidAuthority()
	}
	if plan.OTP != nil && (!p.verify || p.otpPlan == nil || *plan.OTP != *p.otpPlan || c != p.generated) || plan.OTP == nil && c != p.command {
		return invalidAuthority()
	}
	if plan.Delivery != nil {
		if p.verify || p.prepared == nil {
			return invalidAuthority()
		}
		want, err := p.prepared.Plan()
		if err != nil || !reflect.DeepEqual(want, *plan.Delivery) {
			return invalidAuthority()
		}
	}
	return nil
}
func (p *otpActivePhase) ValidateFeaturePreparation(c identity.Command, plan kernel.CommandPlan) error {
	if c != p.command || plan.OTP != nil || plan.Delivery != nil {
		return invalidAuthority()
	}
	return p.ValidateFeatureCommand(c, plan)
}
func (p *otpActivePhase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p == nil || p.input == nil || c != p.command && c != p.generated {
		return invalidAuthority()
	}
	if err := p.primary.Admit(ctx, w, p, c); err != nil {
		return err
	}
	return p.checkFactor(ctx, w, false)
}

type otpActiveAdmission struct {
	phase *otpActivePhase
	risk  risk.ProtectedProviderAdmission
}

func (a *otpActiveAdmission) Check(ctx context.Context) error {
	if ctx == nil || a == nil || a.phase == nil || a.phase.input == nil {
		return invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	now := time.Now().UTC()
	if !now.Before(a.phase.until) || !now.Before(a.phase.input.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	return a.risk.CheckAt(ctx, now)
}
func (p *otpActivePhase) PrepareFeatureAdmission(ctx context.Context, c identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if p == nil || p.input == nil || c != p.command {
		return nil, invalidAuthority()
	}
	scope := risk.Context{Tenant: string(p.input.Binding.TenantID), Operation: risk.Action(otpActiveOperation(p.verify).OperationID), Attempt: string(p.input.Binding.CommandID)}
	assessment, err := p.state.shared.config.Risk.Evaluation.EvaluateProtectedProviders(ctx, risk.EvaluateRequest{Context: scope, Phase: risk.NonIssuing})
	if err != nil {
		return nil, enrollmentReadError(ctx)
	}
	admitted, err := p.state.shared.custody.Prepare(ctx, assessment, scope)
	if err != nil {
		return nil, err
	}
	a := &otpActiveAdmission{phase: p, risk: admitted}
	return a, a.Check(ctx)
}
func (*otpActivePhase) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, invalidAuthority()
}
func (a *otpActiveAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	p := a.phase
	var data []byte
	var err error
	if p.verify {
		mapped, _, e := p.verification.Prepare(ctx, p.state.shared.pool, p.command, p.verifyRequest.Code, p.state.config.AttemptKeyVersion)
		if e != nil {
			return nil, e
		}
		metadata, ok := mapped.Feature()
		if !ok {
			return nil, invalidAuthority()
		}
		data, err = json.Marshal(metadata)
	} else {
		data, err = p.state.config.Issuance.GenerateStepUpSend(ctx, p.command, p.input.NativeInput, generation)
	}
	if err != nil {
		return nil, err
	}
	defer clear(data)
	plain, err := json.Marshal(otpActiveOutput{Schema: 1, Generation: generation, Input: *p.input, Risk: enrollmentStoredRisk(a.risk.Prepared()), Data: data})
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

func (p *otpActivePhase) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	bad := func(err error) (identity.Command, kernel.CommandPlan, error) {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	if p == nil || c != p.command {
		return bad(invalidAuthority())
	}
	output, err := p.openOutput(ctx, generation, wire)
	if err != nil {
		return bad(err)
	}
	defer clear(output.Data)
	defer clear(output.Input.Primary)
	defer clear(output.Input.NativeInput)
	if !reflect.DeepEqual(output.Input, *p.input) {
		return bad(invalidAuthority())
	}
	scope := risk.Context{Tenant: string(p.input.Binding.TenantID), Operation: risk.Action(otpActiveOperation(p.verify).OperationID), Attempt: string(p.input.Binding.CommandID)}
	p.risk, err = p.state.shared.custody.Restore(ctx, risk.PreparedProtectedProviderAdmission(output.Risk), scope)
	if err != nil {
		return bad(err)
	}
	plan := p.plan
	plan.Digest = [32]byte{}
	if p.verify {
		var metadata identity.FeatureCommandSpec
		if decodeEnrollmentJSON(output.Data, &metadata) != nil {
			return bad(invalidAuthority())
		}
		mapped, attempt, err := p.verification.RestorePrepared(ctx, c, p.verifyRequest.Code, metadata)
		if err != nil {
			return bad(err)
		}
		p.generated, p.otpPlan = mapped, &attempt
		plan.OTP = &attempt
		plan.Contributors = append(slices.Clone(plan.Contributors), p.verification.Contributor().Descriptor())
		return mapped, plan, nil
	}
	p.prepared, err = p.state.config.Issuance.RestoreStepUpSend(ctx, c, p.input.NativeInput, generation, output.Data)
	if err != nil {
		return bad(err)
	}
	delivery, err := p.prepared.Plan()
	if err != nil {
		return bad(err)
	}
	plan.Delivery = &delivery
	plan.Contributors = append(slices.Clone(plan.Contributors), delivery.Contributor)
	return c, plan, nil
}
func (p *otpActivePhase) RestoreFeatureAdmission(ctx context.Context, c identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if _, _, err := p.RestoreFeaturePreparation(ctx, c, generation, wire); err != nil {
		return nil, err
	}
	a := &otpActiveAdmission{phase: p, risk: p.risk}
	return a, a.Check(ctx)
}

func (p *otpActivePhase) checkFactor(ctx context.Context, w kernel.Work, applied bool) error {
	i := p.input
	if i == nil {
		return invalidAuthority()
	}
	b, m := i.Binding, i.Factor
	if _, err := readFactorAuthority(ctx, w, b, b.UserID, m.FactorAuthorityVersion); err != nil {
		return err
	}
	var row, enrollment, identifier, iv, vv, channel string
	var send []byte
	err := completionTOTPStore(w).query(ctx, `SELECT row_version::text,enrollment_version::text,identifier_id,identifier_version::text,verification_version::text,channel,last_send_command_id
FROM identity_mfa.otp_factors WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3 AND state=2 AND confirmed_at IS NOT NULL FOR UPDATE`, []any{string(b.TenantID), string(b.UserID), b.RecordID}, &row, &enrollment, &identifier, &iv, &vv, &channel, &send)
	if err != nil {
		return attemptStoreError(ctx, err)
	}
	expected := m.RowVersion
	if applied {
		expected++
	}
	if row != strconv.FormatUint(expected, 10) || enrollment != strconv.FormatUint(m.EnrollmentVersion, 10) || identifier != string(m.IdentifierID) || iv != strconv.FormatUint(m.IdentifierVersion, 10) || vv != strconv.FormatUint(m.VerificationVersion, 10) || channel != "email" {
		return identity.ForbiddenError{}
	}
	if p.verify && base64.RawURLEncoding.EncodeToString(send) != string(p.verifyRequest.StepUp.SendCommandID) || !p.verify && applied && base64.RawURLEncoding.EncodeToString(send) != string(b.CommandID) {
		return identity.ForbiddenError{}
	}
	rows, err := w.Query(ctx, `SELECT identifier_id FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3 AND kind='email' AND verified AND verification_state=2 AND verified_at IS NOT NULL AND version=$4::numeric AND verification_version=$5::numeric FOR SHARE`, string(b.TenantID), string(b.UserID), string(m.IdentifierID), strconv.FormatUint(m.IdentifierVersion, 10), strconv.FormatUint(m.VerificationVersion, 10))
	if err != nil {
		return err
	}
	var selected string
	err = readSessionFactorRow(rows, &selected)
	rows.Close()
	if err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if now.Before(i.CreatedAt) || !now.Before(p.until) || !now.Before(i.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *otpActivePhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	bad := func(err error) (identity.FeatureReceipt, error) { return identity.FeatureReceipt{}, err }
	if p == nil || p.input == nil || p.verify && c != p.generated || !p.verify && c != p.command {
		return bad(invalidAuthority())
	}
	if err := w.RequireFeatureCommand(ctx, p, c); err != nil {
		return bad(err)
	}
	if err := p.primary.Check(ctx, w, p, c); err != nil {
		return bad(err)
	}
	if err := p.checkFactor(ctx, w, false); err != nil {
		return bad(err)
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return bad(err)
	}
	if err := p.risk.CheckAt(ctx, now); err != nil {
		return bad(err)
	}
	b, m := p.input.Binding, p.input.Factor
	if p.verify {
		consumed, err := w.OTPConsumption(p)
		if err != nil || p.otpPlan == nil || consumed.Plan != *p.otpPlan || consumed.Command.CommandID != b.CommandID || consumed.Plan.ChallengeID != string(p.verifyRequest.StepUp.SendCommandID) {
			return bad(invalidAuthority())
		}
		if err := p.persistProof(ctx, w, now); err != nil {
			return bad(err)
		}
	} else {
		if p.prepared == nil {
			return bad(invalidAuthority())
		}
		if err := p.prepared.Persist(ctx, w, p, c); err != nil {
			return bad(err)
		}
	}
	query := `UPDATE identity_mfa.otp_factors SET row_version=row_version+1 WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3 AND state=2 AND row_version=$4::numeric`
	args := []any{string(b.TenantID), string(b.UserID), b.RecordID, strconv.FormatUint(m.RowVersion, 10)}
	if !p.verify {
		id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
		query = `UPDATE identity_mfa.otp_factors SET row_version=row_version+1,last_send_command_id=$5,last_send_before_version=row_version WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3 AND state=2 AND row_version=$4::numeric`
		args = append(args, id)
	}
	n, err := w.Exec(ctx, query, args...)
	if err != nil {
		return bad(err)
	}
	if n != 1 {
		return bad(identity.ConflictError{})
	}
	p.applied = true
	if err := p.CheckFeatureCommit(ctx, w, c); err != nil {
		return bad(err)
	}
	life := p.lifecycle()
	return identity.FeatureReceipt{Operation: otpActiveOperation(p.verify), BeforeVersion: life.BeforeVersion, AfterVersion: life.AfterVersion}, nil
}
func (p *otpActivePhase) persistProof(ctx context.Context, w kernel.Work, now time.Time) error {
	i := p.input
	original, err := p.primary.Original()
	if err != nil {
		return err
	}
	life, err := original.Lifetime(now)
	if err != nil {
		return identity.ForbiddenError{}
	}
	expires := now.Add(p.state.config.TTL)
	if life.ExpiresAt.Before(expires) {
		expires = life.ExpiresAt
	}
	proof := auth.ReauthenticationProof{Proof: auth.Proof{ID: auth.ProofID(i.Binding.CommandID), Tenant: string(i.Binding.TenantID), Subject: string(i.Binding.UserID), Method: "otp", Assurance: auth.AssuranceMultiFactor, Purpose: auth.Purpose(i.Action), Audience: p.state.config.Audience, IssuedAt: now, ExpiresAt: expires}, SessionID: i.SessionID, SessionVersion: i.SessionVersion, Action: i.Action}
	signed, err := p.state.config.SigningKey.sign(auth.SignedReauthenticationRecord{Issuer: p.state.config.Issuer, Environment: p.state.config.Environment, Proof: proof, ProofVersion: 1, CredentialID: i.Binding.RecordID, CredentialVersion: i.Factor.EnrollmentVersion})
	if err != nil {
		return err
	}
	p.record = factorVerificationRecord{Schema: 2, Original: signed, FactorAuthorityVersion: i.Factor.FactorAuthorityVersion}
	wire, err := encodeOTPFactorVerificationRecord(p.record)
	if err != nil {
		return err
	}
	defer clear(wire)
	id, _ := base64.RawURLEncoding.DecodeString(string(i.Binding.CommandID))
	n, err := w.Exec(ctx, `INSERT INTO identity_mfa.otp_factor_verifications(proof_id,tenant_id,user_id,factor_id,enrollment_version,factor_authority_version,command_id,purpose,record) VALUES($1,$2,$3,$4,$5::numeric,$6::numeric,$7,$8,$9)`, string(i.Binding.CommandID), string(i.Binding.TenantID), string(i.Binding.UserID), i.Binding.RecordID, strconv.FormatUint(i.Factor.EnrollmentVersion, 10), strconv.FormatUint(i.Factor.FactorAuthorityVersion, 10), id, i.Binding.OperationID, wire)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}
func (p *otpActivePhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p == nil || p.input == nil || c != p.command && c != p.generated {
		return invalidAuthority()
	}
	if err := p.primary.Check(ctx, w, p, c); err != nil {
		return err
	}
	if err := p.checkFactor(ctx, w, p.applied); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	return p.risk.CheckAt(ctx, now)
}
func (p *otpActivePhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	if !p.verify {
		return p.state.config.Issuance.RecoverStepUpSend(ctx, w, p)
	}
	b, f, life, err := w.FeatureScope(p)
	if err != nil || f.Operation != otpActiveOperation(true) || life.EventType != "factor.verified.v1" || life.BeforeVersion == 0 || life.AfterVersion != life.BeforeVersion+1 {
		return kernel.RecoveryUnknown, invalidAuthority()
	}
	rows, err := w.Query(ctx, `SELECT record FROM identity_mfa.otp_factor_verifications WHERE tenant_id=$1 AND user_id=$2 AND proof_id=$3 AND factor_id=$4 AND octet_length(record) BETWEEN 1 AND 32768`, string(b.TenantID), string(b.UserID), string(b.CommandID), b.RecordID)
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
	r, err := decodeOTPFactorVerificationRecord(auth.ProofID(b.CommandID), string(b.TenantID), string(b.UserID), wire)
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
func (p *otpActivePhase) destroy() {
	for _, input := range []*otpActiveInput{p.input, p.source} {
		if input != nil {
			clear(input.Primary)
			clear(input.NativeInput)
		}
	}
	clear(p.record.Original.Signature)
}

func otpActiveEnvelope(profile string, value any) (envelope.Context, error) {
	wire, err := json.Marshal(value)
	if err != nil || len(wire) > maximumEnrollmentCustody {
		clear(wire)
		return envelope.Context{}, invalidAuthority()
	}
	digest := sha256.Sum256(wire)
	clear(wire)
	return envelope.NewContext(map[string]string{"profile": profile, "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func (s *otpActiveState) verifyIntent(r mfa.OtpVerifyRequest) ([32]byte, error) {
	frame, err := json.Marshal(struct{ Tenant, User, Factor, Command, Send, Action, Origin, Network string }{string(r.TenantID), string(r.Caller.Request.Subject.ID), string(r.FactorID), string(r.CommandID), string(r.StepUp.SendCommandID), string(r.StepUp.Purpose), r.Origin, r.Network})
	if err != nil {
		return [32]byte{}, invalidAuthority()
	}
	defer clear(frame)
	key := s.shared.config.intentKey()
	defer clear(key[:])
	code, err := r.Code.CommandDigest(key, "mfa-otp-active-verify-v1\x00"+string(frame))
	if err != nil {
		return [32]byte{}, err
	}
	defer clear(code[:])
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write(frame)
	_, _ = mac.Write(code[:])
	_, _ = mac.Write([]byte(r.StepUp.Session.Token()))
	_, _ = mac.Write(s.identity[:])
	var digest [32]byte
	copy(digest[:], mac.Sum(nil))
	return digest, nil
}
