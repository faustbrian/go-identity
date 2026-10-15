package mfapostgres

import (
	"context"
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
	primitive "github.com/faustbrian/go-password/v2"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// One invocation owns restored plaintext and original admission. The registered
// participant is never shared across requests; the kernel owns every transaction.
type totpEnrollmentPhase struct {
	state       *totpEnrollmentState
	request     func() mfa.EnableRequest
	input       *totpEnrollmentInput
	primary     TOTPEnrollmentPrimary
	command     identity.Command
	plan        kernel.CommandPlan
	counterPlan kernel.CommandCounterPlan
	coordinator *kernel.Coordinator
	registry    *kernel.ContributorRegistry
	output      *totpEnrollmentRestored
	applied     bool
	arm         func(time.Time) error
}
type totpEnrollmentRestored struct {
	metadata PendingTOTPMetadata
	pending  PreparedTOTPEnrollment
	otp      PreparedOTPEnrollment
	stored   totpEnrollmentOutput
	risk     risk.ProtectedProviderAdmission
}

func (*totpEnrollmentPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}
}
func (*totpEnrollmentPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{enrollmentOperation()}
}

func (p *totpEnrollmentPhase) staticFields() ([]identity.FeatureField, error) {
	if p == nil || p.input == nil || p.request == nil {
		return nil, invalidEnrollment()
	}
	m := p.input.Meta
	metadata := PreparedTOTPEnrollment{custody: func() preparedTOTPEnrollment { return preparedTOTPEnrollment{metadata: m} }}
	fields, err := metadata.Fields()
	if p.state.method == "otp" {
		if p.input.OTP == nil {
			return nil, invalidEnrollment()
		}
		pending, prepareErr := NewPreparedOTPEnrollment(*p.input.OTP)
		if prepareErr != nil {
			return nil, prepareErr
		}
		fields, err = pending.Fields()
	}
	if err != nil {
		return nil, err
	}
	fields = append(fields, identity.FeatureField{Name: "recovery.count", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(p.request().FactorPolicy.RecoveryCodes)}}, identity.FeatureField{Name: "recovery.key-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(p.state.config.RecoveryKeyVersion)}})
	return fields, nil
}

func (p *totpEnrollmentPhase) buildCommand() error {
	fields, err := p.staticFields()
	if err != nil {
		return err
	}
	command, err := p.primary.Command(p.input.Binding, fields)
	if err != nil {
		return err
	}
	original, err := p.primary.Original()
	if err != nil {
		return err
	}
	session, err := original.Bindings()
	if err != nil {
		return err
	}
	r := p.request()
	command, counters, err := p.state.counters.PrepareCommandCounters(command, risk.Subject{User: string(p.input.Binding.UserID), Session: session.SessionID, Network: r.Network}, p.input.Meta.CreatedAt)
	if err != nil {
		return err
	}
	p.command, p.counterPlan = command, counters
	b := p.input.Binding
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return err
	}
	seed, err := builder.Build(audit.RecordInput{OccurredAt: p.input.Meta.CreatedAt, Action: b.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "factor", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "factor", "aggregate.id": b.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "protected"}})
	if err != nil {
		return err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, enrollmentOperation(), "factor", seed)
	if err != nil {
		return err
	}
	declaration := kernel.CommandPlan{Contributors: p.registry.Descriptors(), SubjectType: "factor", Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: enrollmentOperation()}, CommandCounters: &counters, Lifecycle: &kernel.LifecyclePlan{EventType: "factor.enrollment-created.v1", BeforeVersion: 0, AfterVersion: 1}, Audits: []kernel.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}}
	p.plan, err = p.coordinator.PrepareFeaturePreparationPlan(command, declaration)
	return err
}

func (p *totpEnrollmentPhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.input == nil || c != p.command || plan.Feature == nil || plan.Feature.Contributor != p.Descriptor() || plan.Feature.Operation != enrollmentOperation() || plan.SubjectType != "factor" || plan.Lifecycle == nil || *plan.Lifecycle != (kernel.LifecyclePlan{EventType: "factor.enrollment-created.v1", BeforeVersion: 0, AfterVersion: 1}) || plan.CommandCounters == nil || *plan.CommandCounters != p.counterPlan || plan.Capability != nil || plan.OTP != nil || plan.RiskEvidence != nil || plan.Delivery != nil || plan.MFACompletion != nil || plan.MFAContinuation != nil || plan.CapabilityIssuance != nil || len(plan.Audits) != 1 {
		return invalidEnrollment()
	}
	a := plan.Audits[0]
	if !a.Required || a.EventType != enrollmentOperation().OperationID || a.RequiredRecordCount != 1 || a.RetentionClass != "protected" {
		return invalidEnrollment()
	}
	return nil
}
func (p *totpEnrollmentPhase) ValidateFeaturePreparation(c identity.Command, plan kernel.CommandPlan) error {
	return p.ValidateFeatureCommand(c, plan)
}

func (p *totpEnrollmentPhase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p == nil || p.input == nil || c != p.command {
		return invalidEnrollment()
	}
	if err := p.primary.Admit(ctx, w, p, c); err != nil {
		return err
	}
	state, err := readFactorAuthority(ctx, w, p.input.Binding, p.input.Binding.UserID, p.input.Meta.AuthorityVersion)
	if err != nil {
		return err
	}
	if err := state.RequireEmailRecovery(p.input.Binding.TenantID, p.input.Binding.UserID); err != nil {
		return err
	}
	if p.state.method == "otp" {
		if p.input.OTP == nil {
			return invalidEnrollment()
		}
		pending, err := NewPreparedOTPEnrollment(*p.input.OTP)
		if err != nil {
			return err
		}
		if err := pending.checkRecipient(ctx, w); err != nil {
			return err
		}
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if now.Before(p.input.Meta.CreatedAt) || !now.Before(p.input.Meta.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	return p.primary.Check(ctx, w, p, c)
}

type totpEnrollmentAdmission struct {
	phase *totpEnrollmentPhase
	risk  risk.ProtectedProviderAdmission
}

func (a *totpEnrollmentAdmission) Check(ctx context.Context) error {
	if ctx == nil || a == nil || a.phase == nil || a.phase.input == nil || a.phase.arm == nil {
		return invalidEnrollment()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline, err := a.phase.primary.Deadline()
	if err != nil {
		return err
	}
	if a.phase.input.Meta.ExpiresAt.Before(deadline) {
		deadline = a.phase.input.Meta.ExpiresAt
	}
	prepared := a.risk.Prepared()
	for _, signal := range prepared.Signals {
		if signal.ExpiresAt.Before(deadline) {
			deadline = signal.ExpiresAt
		}
	}
	if err := a.phase.arm(deadline); err != nil {
		return err
	}
	return a.risk.CheckAt(ctx, time.Now().UTC())
}
func (a *totpEnrollmentAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	p := a.phase
	if generation == 0 {
		return nil, invalidEnrollment()
	}
	var output totpEnrollmentOutput
	var err error
	if p.state.method == "otp" {
		output, err = generateOTPEnrollmentMaterial(ctx, p.state, p.input.Meta, p.input.OTP, generation, p.request().FactorPolicy.RecoveryCodes)
	} else {
		output, err = generateEnrollmentMaterial(ctx, p.state, p.input.Meta, generation, p.request().FactorPolicy.RecoveryCodes)
	}
	if err != nil {
		return nil, err
	}
	defer clearEnrollmentOutput(&output)
	output.Risk = enrollmentStoredRisk(a.risk.Prepared())
	plain, err := json.Marshal(output)
	if err != nil {
		return nil, invalidEnrollment()
	}
	defer clear(plain)
	aad, err := p.outputAAD(generation)
	if err != nil {
		return nil, err
	}
	return p.seal(ctx, aad, plain)
}

func (p *totpEnrollmentPhase) PrepareFeatureAdmission(ctx context.Context, c identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if p == nil || p.input == nil || c != p.command {
		return nil, invalidEnrollment()
	}
	b := p.input.Binding
	scope := risk.Context{Tenant: string(b.TenantID), Operation: risk.Action(b.OperationID), Attempt: string(b.CommandID)}
	assessment, err := p.state.config.Risk.Evaluation.EvaluateProtectedProviders(ctx, risk.EvaluateRequest{Context: scope, Phase: risk.NonIssuing})
	if err != nil {
		return nil, enrollmentReadError(ctx)
	}
	admission, err := p.state.custody.Prepare(ctx, assessment, scope)
	if err != nil {
		return nil, err
	}
	a := &totpEnrollmentAdmission{phase: p, risk: admission}
	return a, a.Check(ctx)
}
func (*totpEnrollmentPhase) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, invalidEnrollment()
}

func (p *totpEnrollmentPhase) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	bad := func(err error) (identity.Command, kernel.CommandPlan, error) {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	if p == nil || p.input == nil || c != p.command || generation == 0 {
		return bad(invalidEnrollment())
	}
	aad, err := p.outputAAD(generation)
	if err != nil {
		return bad(err)
	}
	plain, err := p.open(ctx, aad, wire)
	if err != nil {
		return bad(err)
	}
	defer clear(plain)
	var stored totpEnrollmentOutput
	if err := decodeEnrollmentJSON(plain, &stored); err != nil {
		clearEnrollmentOutput(&stored)
		return bad(err)
	}
	keep := false
	defer func() {
		if !keep {
			clearEnrollmentOutput(&stored)
		}
	}()
	if stored.Schema != p.input.Schema || stored.Generation != generation || stored.RecoveryKeyVersion != p.state.config.RecoveryKeyVersion || !reflect.DeepEqual(stored.Meta, p.input.Meta) || !reflect.DeepEqual(stored.OTP, p.input.OTP) || len(stored.Codes) != int(p.request().FactorPolicy.RecoveryCodes) || len(stored.Digests) != len(stored.Codes) {
		return bad(identity.ForbiddenError{})
	}
	var ctxBinding envelope.Context
	var otpPending PreparedOTPEnrollment
	if p.state.method == "otp" {
		if stored.OTP == nil || len(stored.Envelope) != 0 {
			return bad(identity.ForbiddenError{})
		}
		otpPending, err = NewPreparedOTPEnrollment(*stored.OTP)
		if err != nil {
			return bad(err)
		}
	} else {
		if stored.OTP != nil || len(stored.Envelope) == 0 || len(stored.Envelope) > 4096 {
			return bad(identity.ForbiddenError{})
		}
		ctxBinding, err = totpEncryptionContext(stored.Meta.TenantID, stored.Meta.UserID, stored.Meta.FactorID, 1, stored.Meta.Profile)
		if err != nil {
			return bad(err)
		}
		sealed, err := envelope.ParseEnvelope(stored.Envelope)
		if err != nil {
			return bad(invalidEnrollment())
		}
		secret, err := p.state.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: ctxBinding})
		if err != nil || len(secret) != 32 {
			clear(secret)
			return bad(identity.UnavailableError{})
		}
		clear(secret)
	}
	key := p.state.config.recoveryKey()
	defer clear(key[:])
	binding, err := enrollmentRecoveryBinding(stored.Meta)
	if err != nil {
		return bad(err)
	}
	defer clear(binding)
	seen := make(map[[32]byte]bool, len(stored.Codes))
	for i, raw := range stored.Codes {
		if len(raw) != 22 {
			return bad(invalidEnrollment())
		}
		code, err := auth.NewRecoveryCode(string(raw))
		if err != nil {
			return bad(invalidEnrollment())
		}
		digest, err := code.KeyedDigest(key, binding)
		if err != nil || digest != stored.Digests[i] || seen[digest] {
			return bad(identity.ForbiddenError{})
		}
		seen[digest] = true
	}
	b := p.input.Binding
	scope := risk.Context{Tenant: string(b.TenantID), Operation: risk.Action(b.OperationID), Attempt: string(b.CommandID)}
	admission, err := p.state.custody.Restore(ctx, risk.PreparedProtectedProviderAdmission(stored.Risk), scope)
	if err != nil {
		return bad(err)
	}
	if p.output != nil {
		clearEnrollmentOutput(&p.output.stored)
	}
	owned := preparedTOTPEnrollment{metadata: stored.Meta, wire: slices.Clone(stored.Envelope), binding: ctxBinding}
	p.output = &totpEnrollmentRestored{metadata: stored.Meta, pending: PreparedTOTPEnrollment{custody: func() preparedTOTPEnrollment { return owned }}, otp: otpPending, stored: stored, risk: admission}
	keep = true
	return p.command, p.plan, nil
}
func (p *totpEnrollmentPhase) RestoreFeatureAdmission(ctx context.Context, c identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if _, _, err := p.RestoreFeaturePreparation(ctx, c, generation, wire); err != nil {
		return nil, err
	}
	a := &totpEnrollmentAdmission{phase: p, risk: p.output.risk}
	return a, a.Check(ctx)
}

func (p *totpEnrollmentPhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if p == nil || p.output == nil || c != p.command {
		return identity.FeatureReceipt{}, invalidEnrollment()
	}
	if err := w.RequireFeatureCommand(ctx, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.output.risk.CheckAt(ctx, now); err != nil {
		return identity.FeatureReceipt{}, err
	}
	var persistErr error
	if p.state.method == "otp" {
		persistErr = p.output.otp.Persist(ctx, w, p, c, p.primary)
	} else {
		persistErr = p.output.pending.Persist(ctx, w, p, c, p.primary)
	}
	if persistErr != nil {
		return identity.FeatureReceipt{}, persistErr
	}
	if err := p.persistRecovery(ctx, w, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.CheckFeatureCommit(ctx, w, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	p.applied = true
	return identity.FeatureReceipt{Operation: enrollmentOperation(), BeforeVersion: 0, AfterVersion: 1}, nil
}
func (p *totpEnrollmentPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p == nil || p.output == nil || c != p.command {
		return invalidEnrollment()
	}
	if err := p.primary.Check(ctx, w, p, c); err != nil {
		return err
	}
	if p.state.method == "otp" {
		if err := p.output.otp.checkRecipient(ctx, w); err != nil {
			return err
		}
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if !now.Before(p.output.metadata.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	return p.output.risk.CheckAt(ctx, now)
}

func (p *totpEnrollmentPhase) recoveryDelivery(ctx context.Context) (mfa.RevealOnceCodes, error) {
	var out mfa.RevealOnceCodes
	if p == nil || p.output == nil || !p.applied || ctx == nil || ctx.Err() != nil {
		return out, enrollmentReadError(ctx)
	}
	return enrollmentRecoveryDelivery(ctx, p.output.stored.Codes)
}

// Copy delivery custody only after the owning invocation established its fresh
// known commitment. This helper grants no factor or transaction authority.
func enrollmentRecoveryDelivery(ctx context.Context, codes [][]byte) (mfa.RevealOnceCodes, error) {
	var out mfa.RevealOnceCodes
	if ctx == nil || ctx.Err() != nil {
		return out, enrollmentReadError(ctx)
	}
	for _, raw := range codes {
		secret, err := primitive.NewSecret(raw)
		if err != nil {
			for _, code := range out.Codes {
				code.Destroy()
			}
			return mfa.RevealOnceCodes{}, identity.UnavailableError{}
		}
		out.Codes = append(out.Codes, secret)
	}
	return out, nil
}

func clearEnrollmentOutput(output *totpEnrollmentOutput) {
	for _, code := range output.Codes {
		clear(code)
	}
	clear(output.Envelope)
	clear(output.Digests)
	*output = totpEnrollmentOutput{}
}
func (p *totpEnrollmentPhase) destroy() {
	if p.input != nil {
		clear(p.input.Primary)
	}
	if p.output != nil {
		clearEnrollmentOutput(&p.output.stored)
		if p.output.pending.custody != nil {
			clear(p.output.pending.custody().wire)
		}
	}
}
