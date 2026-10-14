package mfapostgres

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	primitive "github.com/faustbrian/go-password"
	envelope "github.com/faustbrian/go-secret-envelope"
)

type recoveryRegenerationInput struct {
	Binding          identity.CommandBinding
	Primary          []byte
	Record           factorVerificationRecord
	Intent           [32]byte
	CreatedAt, Until time.Time
}
type recoveryRegenerationOutput struct {
	Schema     uint32
	Generation uint64
	Input      recoveryRegenerationInput
	Codes      [][]byte
	Digests    [][32]byte
	Risk       enrollmentStoredRisk
}
type recoveryRegenerationPhase struct {
	state       *recoveryRegenerationState
	request     mfa.RecoveryRegenerateRequest
	input       *recoveryRegenerationInput
	primary     TOTPActivePrimary
	command     identity.Command
	plan        kernel.CommandPlan
	counters    kernel.CommandCounterPlan
	coordinator *kernel.Coordinator
	registry    *kernel.ContributorRegistry
	output      *recoveryRegenerationOutput
	risk        risk.ProtectedProviderAdmission
	applied     bool
}

func (*recoveryRegenerationPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}
}
func (*recoveryRegenerationPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{recoveryRegenerationOperation()}
}
func (p *recoveryRegenerationPhase) lifecycle() kernel.LifecyclePlan {
	v := p.input.Record.FactorAuthorityVersion
	return kernel.LifecyclePlan{EventType: "factor.recovery-regenerated.v1", BeforeVersion: v, AfterVersion: v + 1}
}
func (p *recoveryRegenerationPhase) query() identity.RecoveryQuery {
	r := p.request
	return identity.RecoveryQuery{CommandID: r.CommandID, TenantID: r.TenantID, UserID: identity.UserID(r.Caller.Request.Subject.ID), ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: authorization.SubjectUser, OperationID: recoveryRegenerationOperation().OperationID, RecordID: string(r.Caller.Request.Subject.ID)}
}
func (p *recoveryRegenerationPhase) aad(generation uint64) (envelope.Context, error) {
	if p == nil || p.state == nil || generation == 0 {
		return envelope.Context{}, invalidAuthority()
	}
	r := p.request
	frame, err := json.Marshal(struct {
		Profile, Tenant, User, Command string
		Configuration                  [32]byte
		Generation                     uint64
	}{"mfa-recovery-regenerate-v1", string(r.TenantID), string(r.Caller.Request.Subject.ID), string(r.CommandID), p.state.identity, generation})
	if err != nil {
		return envelope.Context{}, invalidAuthority()
	}
	defer clear(frame)
	digest := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"profile": "mfa-recovery-regenerate-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func (p *recoveryRegenerationPhase) load(ctx context.Context) error {
	id, _ := base64.RawURLEncoding.DecodeString(string(p.request.CommandID))
	var exists bool
	if err := p.state.shared.pool.Raw().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM identity.identity_command_id_claims WHERE command_id=$1)`, id).Scan(&exists); err != nil {
		return enrollmentReadError(ctx)
	}
	if exists {
		wire, generation, err := p.coordinator.QueryFeaturePreparation(ctx, p.query(), p.request.Caller, kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: recoveryRegenerationOperation()}, p)
		if err != nil {
			return err
		}
		defer clear(wire)
		return p.restoreOutput(ctx, generation, wire)
	}
	primary, observed, err := p.state.config.Primary.PrepareRegeneration(ctx, p.request)
	if err != nil {
		return err
	}
	original, err := primary.Original()
	if err != nil {
		return err
	}
	s, err := original.Bindings()
	if err != nil {
		return err
	}
	record, err := p.state.source.readRecord(ctx, p.request.FactorProof.ID)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidProof) {
			return identity.ForbiddenError{}
		}
		return err
	}
	if record.FactorAuthorityVersion == math.MaxUint64 || record.Original.CredentialID == string(p.request.CommandID) {
		return identity.ForbiddenError{}
	}
	proof := auth.ReauthenticationProof{Proof: p.request.FactorProof, SessionID: s.SessionID, SessionVersion: s.Version, Action: "identity.mfa.recovery-regenerate"}
	use := auth.ReauthenticationUse{ProofUse: auth.ProofUse{Tenant: string(s.TenantID), Subject: string(s.UserID), Purpose: "identity.mfa.recovery-regenerate", Audience: p.state.stepup.config.Audience}, SessionID: s.SessionID, SessionVersion: s.Version, Action: "identity.mfa.recovery-regenerate", MaximumAge: p.state.config.MaximumAge}
	if err := p.state.validator.ValidateReauthenticationProof(ctx, proof, use); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, auth.ErrAuthenticationUnavailable) {
			return identity.UnavailableError{}
		}
		return identity.ForbiddenError{}
	}
	if record.Original.Proof.SessionID != s.SessionID || record.Original.Proof.SessionVersion != s.Version || record.Original.Proof.Proof.ID != proof.Proof.ID {
		return identity.ForbiddenError{}
	}
	snapshot, err := primary.Snapshot()
	if err != nil {
		return err
	}
	digest, err := p.state.intent(p.request)
	if err != nil {
		clear(snapshot)
		return err
	}
	until := observed.ValidUntil()
	if record.Original.Proof.Proof.ExpiresAt.Before(until) {
		until = record.Original.Proof.Proof.ExpiresAt
	}
	op := recoveryRegenerationOperation()
	r := p.request
	b := identity.CommandBinding{CommandID: r.CommandID, TenantID: r.TenantID, UserID: s.UserID, ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: authorization.SubjectUser, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: p.state.shared.config.PolicyID, PolicyVersion: p.state.shared.config.Coordinator.AdmissionPolicy.PolicyVersion, CorrelationID: string(r.CommandID), RecordID: string(s.UserID)}
	p.primary, p.input = primary, &recoveryRegenerationInput{Binding: b, Primary: snapshot, Record: record, Intent: digest, CreatedAt: time.Now().UTC().Truncate(time.Microsecond), Until: until}
	return nil
}

func (p *recoveryRegenerationPhase) buildCommand() error {
	if p == nil || p.input == nil || p.primary == nil {
		return invalidAuthority()
	}
	i := p.input
	b := i.Binding
	proofWire, err := encodeFactorVerificationRecord(i.Record)
	if err != nil {
		return err
	}
	defer clear(proofWire)
	proofDigest := sha256.Sum256(proofWire)
	fields := []identity.FeatureField{
		{Name: "factor.before", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: i.Record.FactorAuthorityVersion}},
		{Name: "factor.after", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: i.Record.FactorAuthorityVersion + 1}},
		{Name: "factor.proof", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(i.Record.Original.Proof.Proof.ID)}},
		{Name: "factor.proof-record", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: proofDigest[:]}},
		{Name: "factor.intent", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: i.Intent[:]}},
		{Name: "recovery.count", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(p.state.config.CodeCount)}},
		{Name: "recovery.key-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(p.state.shared.config.RecoveryKeyVersion)}},
		{Name: "recovery.set", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(b.CommandID)}},
		{Name: "recovery.created", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: i.CreatedAt}},
	}
	c, err := p.primary.Command(b, fields)
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
	c, counters, err := p.state.shared.counters.PrepareCommandCounters(c, risk.Subject{User: string(b.UserID), Session: s.SessionID, Network: p.request.Network}, i.CreatedAt)
	if err != nil {
		return err
	}
	p.command, p.counters = c, counters
	l := p.lifecycle()
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return err
	}
	seed, err := builder.Build(audit.RecordInput{OccurredAt: i.CreatedAt, Action: b.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "user", ID: string(b.UserID)}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "user", "aggregate.id": string(b.UserID), "aggregate.before_version": strconv.FormatUint(l.BeforeVersion, 10), "aggregate.after_version": strconv.FormatUint(l.AfterVersion, 10), "retention.class": "protected"}})
	if err != nil {
		return err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, recoveryRegenerationOperation(), "user", seed)
	if err != nil {
		return err
	}
	p.plan, err = p.coordinator.PrepareFeaturePreparationPlan(c, kernel.CommandPlan{Contributors: p.registry.Descriptors(), Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: recoveryRegenerationOperation()}, SubjectType: "user", Lifecycle: &l, CommandCounters: &counters, Audits: []kernel.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}})
	return err
}
func (p *recoveryRegenerationPhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.input == nil || c != p.command || plan.Feature == nil || *plan.Feature != (kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: recoveryRegenerationOperation()}) || plan.SubjectType != "user" || plan.Lifecycle == nil || *plan.Lifecycle != p.lifecycle() || plan.CommandCounters == nil || *plan.CommandCounters != p.counters || plan.Capability != nil || plan.OTP != nil || plan.Delivery != nil || plan.RiskEvidence != nil || plan.MFACompletion != nil || plan.MFAContinuation != nil || plan.CapabilityIssuance != nil || len(plan.Audits) != 1 {
		return invalidAuthority()
	}
	a := plan.Audits[0]
	if !a.Required || a.EventType != recoveryRegenerationOperation().OperationID || a.RequiredRecordCount != 1 || a.RetentionClass != "protected" {
		return invalidAuthority()
	}
	return nil
}
func (p *recoveryRegenerationPhase) ValidateFeaturePreparation(c identity.Command, plan kernel.CommandPlan) error {
	return p.ValidateFeatureCommand(c, plan)
}

func (p *recoveryRegenerationPhase) lockProof(ctx context.Context, w kernel.Work, used bool) error {
	i := p.input
	b := i.Binding
	record := i.Record
	rows, err := w.Query(ctx, `SELECT v.record,v.used_command_id,v.used_purpose FROM identity_mfa.factor_verifications v
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
	extra := rows.Next()
	rowErr := rows.Err()
	rows.Close()
	defer clear(wire)
	want, encodeErr := encodeFactorVerificationRecord(record)
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
	use := auth.ReauthenticationUse{ProofUse: auth.ProofUse{Tenant: string(b.TenantID), Subject: string(b.UserID), Purpose: "identity.mfa.recovery-regenerate", Audience: p.state.stepup.config.Audience, Now: now}, SessionID: proof.SessionID, SessionVersion: proof.SessionVersion, Action: b.OperationID, MaximumAge: p.state.config.MaximumAge}
	if proof.Validate(use) != nil || !now.Before(i.Until) {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *recoveryRegenerationPhase) admit(ctx context.Context, w kernel.Work, c identity.Command, preparation bool) error {
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
	r := p.input.Record
	if err := RequireTOTPSessionFactor(ctx, w, p, p.input.Binding.UserID, r.Original.CredentialID, TOTPSessionFactorState{EnrollmentVersion: r.Original.CredentialVersion, AuthorityVersion: r.FactorAuthorityVersion}); err != nil {
		return err
	}
	return p.lockProof(ctx, w, false)
}
func (p *recoveryRegenerationPhase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, c identity.Command) error {
	return p.admit(ctx, w, c, true)
}

type regenerationAdmission struct {
	phase *recoveryRegenerationPhase
	risk  risk.ProtectedProviderAdmission
}

func (a *regenerationAdmission) Check(ctx context.Context) error {
	if ctx == nil || a == nil || a.phase == nil || a.phase.input == nil {
		return invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !time.Now().Before(a.phase.input.Until) {
		return identity.ForbiddenError{}
	}
	return a.risk.CheckAt(ctx, time.Now().UTC())
}
func (p *recoveryRegenerationPhase) PrepareFeatureAdmission(ctx context.Context, c identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if p == nil || c != p.command {
		return nil, invalidAuthority()
	}
	scope := risk.Context{Tenant: string(p.request.TenantID), Operation: risk.Action(recoveryRegenerationOperation().OperationID), Attempt: string(p.request.CommandID)}
	assessment, err := p.state.shared.config.Risk.Evaluation.EvaluateProtectedProviders(ctx, risk.EvaluateRequest{Context: scope, Phase: risk.NonIssuing})
	if err != nil {
		return nil, enrollmentReadError(ctx)
	}
	admission, err := p.state.shared.custody.Prepare(ctx, assessment, scope)
	if err != nil {
		return nil, err
	}
	a := &regenerationAdmission{phase: p, risk: admission}
	return a, a.Check(ctx)
}
func (p *recoveryRegenerationPhase) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, invalidAuthority()
}
func (p *recoveryRegenerationPhase) setMetadata() RecoverySetMetadata {
	b := p.input.Binding
	r := p.input.Record
	return RecoverySetMetadata{TenantID: b.TenantID, UserID: b.UserID, FactorID: r.Original.CredentialID, SetID: string(b.CommandID), SetVersion: r.FactorAuthorityVersion + 1, RowVersion: 1, FactorEnrollmentVersion: r.Original.CredentialVersion, KeyVersion: p.state.shared.config.RecoveryKeyVersion, CodeCount: p.state.config.CodeCount}
}
func (a *regenerationAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	p := a.phase
	out := recoveryRegenerationOutput{Schema: 1, Generation: generation, Input: *p.input, Risk: enrollmentStoredRisk(a.risk.Prepared())}
	defer func() {
		for _, raw := range out.Codes {
			clear(raw)
		}
	}()
	binding, err := recoveryCodeBinding(p.setMetadata())
	if err != nil {
		return nil, err
	}
	defer clear(binding)
	key := p.state.shared.config.recoveryKey()
	defer clear(key[:])
	for range p.state.config.CodeCount {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err != nil {
			clear(raw)
			return nil, identity.UnavailableError{}
		}
		encoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(raw)))
		base64.RawURLEncoding.Encode(encoded, raw)
		clear(raw)
		code, err := auth.NewRecoveryCode(string(encoded))
		if err != nil {
			clear(encoded)
			return nil, err
		}
		digest, err := code.KeyedDigest(key, binding)
		if err != nil {
			clear(encoded)
			return nil, err
		}
		out.Codes = append(out.Codes, encoded)
		out.Digests = append(out.Digests, digest)
	}
	plain, err := json.Marshal(out)
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

func (p *recoveryRegenerationPhase) restoreOutput(ctx context.Context, generation uint64, wire []byte) error {
	aad, err := p.aad(generation)
	if err != nil {
		return err
	}
	plain, err := (&totpEnrollmentPhase{state: p.state.shared}).open(ctx, aad, wire)
	if err != nil {
		return err
	}
	defer clear(plain)
	var out recoveryRegenerationOutput
	defer func() {
		if p.output != &out {
			for _, raw := range out.Codes {
				clear(raw)
			}
		}
	}()
	if decodeEnrollmentJSON(plain, &out) != nil || out.Schema != 1 || out.Generation != generation || len(out.Codes) != int(p.state.config.CodeCount) || len(out.Digests) != len(out.Codes) {
		return invalidAuthority()
	}
	i := out.Input
	digest, err := p.state.intent(p.request)
	b := i.Binding
	if err != nil || !hmac.Equal(digest[:], i.Intent[:]) || b.ValidateFor(recoveryRegenerationOperation()) != nil || b.CommandID != p.request.CommandID || b.TenantID != p.request.TenantID || b.UserID != identity.UserID(p.request.Caller.Request.Subject.ID) || b.ActorID != identity.ActorID(p.request.Caller.Request.Subject.ID) || b.ActorKind != authorization.SubjectUser || b.PolicyID != p.state.shared.config.PolicyID || b.PolicyVersion != p.state.shared.config.Coordinator.AdmissionPolicy.PolicyVersion || b.CorrelationID != string(b.CommandID) || i.Record.FactorAuthorityVersion == 0 || i.Record.FactorAuthorityVersion == math.MaxUint64 || len(i.Primary) < 1 || len(i.Primary) > 32768 || i.CreatedAt.IsZero() || i.CreatedAt.Nanosecond()%1000 != 0 || i.Until.IsZero() {
		return identity.ForbiddenError{}
	}
	if _, err := encodeFactorVerificationRecord(i.Record); err != nil {
		return err
	}
	primary, err := p.state.config.Primary.RestoreRegeneration(ctx, p.request, i.Primary)
	if err != nil {
		return err
	}
	original, err := primary.Original()
	if err != nil {
		return err
	}
	s, err := original.Bindings()
	if err != nil || i.Record.Original.Proof.SessionID != s.SessionID || i.Record.Original.Proof.SessionVersion != s.Version {
		return identity.ForbiddenError{}
	}
	until, err := primary.Deadline()
	if err != nil {
		return err
	}
	if i.Record.Original.Proof.Proof.ExpiresAt.Before(until) {
		until = i.Record.Original.Proof.Proof.ExpiresAt
	}
	if !until.Equal(i.Until) {
		return identity.ForbiddenError{}
	}
	if i.Record.Original.Issuer != p.state.stepup.config.Issuer || i.Record.Original.Environment != p.state.stepup.config.Environment || i.Record.Original.Proof.Proof.ID != p.request.FactorProof.ID {
		return identity.ForbiddenError{}
	}
	p.input, p.primary = &i, primary
	bound, err := recoveryCodeBinding(p.setMetadata())
	if err != nil {
		return err
	}
	defer clear(bound)
	key := p.state.shared.config.recoveryKey()
	defer clear(key[:])
	for index, raw := range out.Codes {
		if len(raw) != 22 {
			return invalidAuthority()
		}
		code, err := auth.NewRecoveryCode(string(raw))
		if err != nil {
			return err
		}
		digest, err := code.KeyedDigest(key, bound)
		if err != nil || !hmac.Equal(digest[:], out.Digests[index][:]) {
			return invalidAuthority()
		}
	}
	scope := risk.Context{Tenant: string(p.request.TenantID), Operation: risk.Action(recoveryRegenerationOperation().OperationID), Attempt: string(p.request.CommandID)}
	admission, err := p.state.shared.custody.Restore(ctx, risk.PreparedProtectedProviderAdmission(out.Risk), scope)
	if err != nil {
		return err
	}
	if p.output != nil {
		for _, raw := range p.output.Codes {
			clear(raw)
		}
	}
	p.output, p.risk = &out, admission
	return nil
}
func (p *recoveryRegenerationPhase) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	if p == nil || c != p.command {
		return identity.Command{}, kernel.CommandPlan{}, invalidAuthority()
	}
	if err := p.restoreOutput(ctx, generation, wire); err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	return p.command, p.plan, nil
}
func (p *recoveryRegenerationPhase) RestoreFeatureAdmission(ctx context.Context, c identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if _, _, err := p.RestoreFeaturePreparation(ctx, c, generation, wire); err != nil {
		return nil, err
	}
	a := &regenerationAdmission{phase: p, risk: p.risk}
	return a, a.Check(ctx)
}

func (p *recoveryRegenerationPhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if p == nil || p.output == nil || c != p.command {
		return identity.FeatureReceipt{}, invalidAuthority()
	}
	if err := w.RequireFeatureCommand(ctx, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.admit(ctx, w, c, false); err != nil {
		return identity.FeatureReceipt{}, err
	}
	i := p.input
	b := i.Binding
	m := p.setMetadata()
	id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.risk.CheckAt(ctx, now); err != nil {
		return identity.FeatureReceipt{}, err
	}
	rows, err := w.Query(ctx, `SELECT set_id,row_version::text FROM identity_mfa.recovery_sets WHERE tenant_id=$1 AND user_id=$2 AND state IN(1,2) ORDER BY set_id LIMIT 65 FOR UPDATE`, string(b.TenantID), string(b.UserID))
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	type predecessor struct{ id, version string }
	old := make([]predecessor, 0, 64)
	for rows.Next() {
		var v predecessor
		if err = rows.Scan(&v.id, &v.version); err != nil {
			break
		}
		if len(old) == 64 || v.id == m.SetID {
			err = identity.ForbiddenError{}
			break
		}
		version, e := strconv.ParseUint(v.version, 10, 64)
		if e != nil || version == 0 || version == math.MaxUint64 {
			err = identity.UnavailableError{}
			break
		}
		old = append(old, v)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if len(old) == 0 {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	for _, v := range old {
		n, err := w.Exec(ctx, `UPDATE identity_mfa.recovery_sets SET state=3,row_version=row_version+1 WHERE tenant_id=$1 AND user_id=$2 AND set_id=$3 AND state IN(1,2) AND row_version=$4::numeric`, string(b.TenantID), string(b.UserID), v.id, v.version)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		if n != 1 {
			return identity.FeatureReceipt{}, identity.ConflictError{}
		}
	}
	n, err := w.Exec(ctx, `INSERT INTO identity_mfa.recovery_sets(tenant_id,user_id,set_id,factor_id,set_version,row_version,state,code_count,key_version,created_command_id,created_purpose,created_at) VALUES($1,$2,$3,$4,$5::numeric,1,2,$6,$7,$8,$9,$10)`, string(b.TenantID), string(b.UserID), m.SetID, m.FactorID, strconv.FormatUint(m.SetVersion, 10), int(m.CodeCount), int64(m.KeyVersion), id, b.OperationID, now)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	for index, digest := range p.output.Digests {
		n, err := w.Exec(ctx, `INSERT INTO identity_mfa.recovery_codes(tenant_id,set_id,code_index,digest) VALUES($1,$2,$3,$4)`, string(b.TenantID), m.SetID, index, digest[:])
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		if n != 1 {
			return identity.FeatureReceipt{}, identity.ConflictError{}
		}
	}
	n, err = w.Exec(ctx, `UPDATE identity_mfa.factor_verifications SET used_command_id=$4,used_purpose=$5,used_at=$6 WHERE tenant_id=$1 AND user_id=$2 AND proof_id=$3 AND used_command_id IS NULL AND used_purpose IS NULL AND used_at IS NULL`, string(b.TenantID), string(b.UserID), string(i.Record.Original.Proof.Proof.ID), id, b.OperationID, now)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	if err := p.state.config.Sessions.Apply(ctx, w, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	n, err = w.Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=version+1 WHERE tenant_id=$1 AND user_id=$2 AND version=$3::numeric AND active_factors BETWEEN 1 AND 64`, string(b.TenantID), string(b.UserID), strconv.FormatUint(i.Record.FactorAuthorityVersion, 10))
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
	return identity.FeatureReceipt{Operation: recoveryRegenerationOperation(), BeforeVersion: l.BeforeVersion, AfterVersion: l.AfterVersion}, nil
}
func (p *recoveryRegenerationPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p == nil || p.input == nil || c != p.command {
		return invalidAuthority()
	}
	b := p.input.Binding
	m := p.setMetadata()
	if err := p.lockProof(ctx, w, true); err != nil {
		return err
	}
	if err := RequireTOTPSessionFactor(ctx, w, p, b.UserID, m.FactorID, TOTPSessionFactorState{EnrollmentVersion: m.FactorEnrollmentVersion, AuthorityVersion: m.SetVersion}); err != nil {
		return err
	}
	if err := p.state.config.Sessions.Check(ctx, w, p, c); err != nil {
		return err
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

func (p *recoveryRegenerationPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, f, l, err := w.FeatureScope(p)
	if err != nil || f.Operation != recoveryRegenerationOperation() || f.Contributor != p.Descriptor() || l.EventType != "factor.recovery-regenerated.v1" || l.BeforeVersion == 0 || l.BeforeVersion == math.MaxUint64 || l.AfterVersion != l.BeforeVersion+1 {
		return kernel.RecoveryUnknown, invalidAuthority()
	}
	status, err := p.state.config.Sessions.Recover(ctx, w, p)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	rows, err := w.Query(ctx, `SELECT r.set_id,r.set_version::text,r.code_count,r.user_id,v.used_purpose,(SELECT count(*) FROM identity_mfa.recovery_codes c WHERE c.tenant_id=r.tenant_id AND c.set_id=r.set_id) FROM identity_mfa.recovery_sets r JOIN identity_mfa.factor_verifications v ON v.tenant_id=r.tenant_id AND v.user_id=r.user_id AND v.used_command_id=r.created_command_id WHERE r.tenant_id=$1 AND r.user_id=$2 AND r.created_command_id=$3 AND r.created_purpose=$4`, string(b.TenantID), string(b.UserID), id, b.OperationID)
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
	var set, version, user, purpose string
	var count int16
	var actual int64
	if rows.Scan(&set, &version, &count, &user, &purpose, &actual) != nil || rows.Next() || rows.Err() != nil || status != kernel.RecoveryCommitted || set != string(b.CommandID) || version != strconv.FormatUint(l.AfterVersion, 10) || user != string(b.UserID) || purpose != b.OperationID || count < 1 || count > 64 || actual != int64(count) {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	return kernel.RecoveryCommitted, nil
}
func (p *recoveryRegenerationPhase) delivery(ctx context.Context) (mfa.RevealOnceCodes, error) {
	if ctx == nil || p == nil || !p.applied || p.output == nil || p.input == nil || !time.Now().Before(p.input.Until) {
		return mfa.RevealOnceCodes{}, identity.ForbiddenError{}
	}
	out := mfa.RevealOnceCodes{Codes: make([]primitive.Secret, 0, len(p.output.Codes))}
	for _, raw := range p.output.Codes {
		if err := ctx.Err(); err != nil {
			for _, code := range out.Codes {
				code.Destroy()
			}
			return mfa.RevealOnceCodes{}, err
		}
		code, err := primitive.NewSecret(raw)
		if err != nil {
			for _, old := range out.Codes {
				old.Destroy()
			}
			return mfa.RevealOnceCodes{}, err
		}
		out.Codes = append(out.Codes, code)
	}
	return out, nil
}
func (p *recoveryRegenerationPhase) destroy() {
	if p.input != nil {
		clear(p.input.Primary)
		clear(p.input.Record.Original.Signature)
		p.input = nil
	}
	if p.output != nil {
		for _, raw := range p.output.Codes {
			clear(raw)
		}
		p.output = nil
	}
}
