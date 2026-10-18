package passwordpostgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"slices"
	"time"

	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/username"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

type usernameRenamePhase struct {
	service       *UsernameRenameService
	request       username.RenameRequest
	primary       ActionPrimaryAdmission
	intent        kernel.UsernameRenameIntent
	command       identity.Command
	counter       kernel.CommandCounterPlan
	factorVersion uint64
	coordinator   *kernel.Coordinator
	registry      *kernel.ContributorRegistry
	admission     risk.ProtectedProviderAdmission
	outputDigest  [32]byte
	generation    uint64
}

var _ kernel.UsernameRenameContributor = (*usernameRenamePhase)(nil)
var _ kernel.RequestKeyPreparationContributor = (*usernameRenamePhase)(nil)
var _ kernel.FeatureAdmissionPreparationContributor = (*usernameRenamePhase)(nil)

func (*usernameRenamePhase) Descriptor() kernel.ContributorDescriptor {
	return actionPrimaryDescriptor("identity.username.update")
}
func (*usernameRenamePhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{actionPrimaryOperation("identity.username.update")}
}
func (p *usernameRenamePhase) UsernameRename(c identity.Command) (kernel.UsernameRenameIntent, *kernel.UsernameRenameDomain, error) {
	if p == nil || p.service == nil || c != p.command {
		return kernel.UsernameRenameIntent{}, nil, password.ErrPasswordWork
	}
	return p.intent, p.service.domain, nil
}
func (p *usernameRenamePhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.service == nil || c != p.command || p.factorVersion == 0 {
		return password.ErrPasswordWork
	}
	spec, ok := c.Feature()
	if !ok || spec.Operation != p.FeatureOperations()[0] || plan.Feature == nil || plan.Feature.Contributor != p.Descriptor() || plan.Feature.Operation != spec.Operation || plan.SubjectType != "identifier" || plan.CommandCounters == nil || *plan.CommandCounters != p.counter || plan.Lifecycle == nil || plan.Lifecycle.EventType != "identifier.updated.v1" || plan.Lifecycle.BeforeVersion != p.intent.Change.ExpectedIdentifierVersion || plan.Lifecycle.AfterVersion != plan.Lifecycle.BeforeVersion+1 || len(plan.Audits) != 1 || !plan.Audits[0].Required || plan.Audits[0].RetentionClass != "protected" || plan.Capability != nil || plan.OTP != nil || plan.Delivery != nil || plan.CapabilityIssuance != nil {
		return password.ErrPasswordWork
	}
	actor, target, profile := false, false, false
	for _, f := range spec.Fields {
		switch f.Name {
		case "action-primary.actor-factor-version":
			actor = f.Value.Kind == identity.FeatureUint64 && f.Value.Uint64 == p.factorVersion
		case "action-primary.target-factor-version":
			target = f.Value.Kind == identity.FeatureUint64 && f.Value.Uint64 == p.factorVersion
		case "username.rename.profile":
			profile = f.Value.Kind == identity.FeatureBytes && slices.Equal(f.Value.Bytes, p.service.profile[:])
		}
	}
	if !actor || !target || !profile {
		return password.ErrPasswordWork
	}
	return nil
}
func (p *usernameRenamePhase) ValidateFeaturePreparation(c identity.Command, plan kernel.CommandPlan) error {
	return p.ValidateFeatureCommand(c, plan)
}
func (p *usernameRenamePhase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.command {
		return password.ErrPasswordWork
	}
	if err := p.primary.Admit(ctx, w, p, c); err != nil {
		return err
	}
	return p.requireFactors(ctx, w, c)
}
func (p *usernameRenamePhase) requireFactors(ctx context.Context, w kernel.Work, c identity.Command) error {
	return mfapg.RequireActionPrimaryFactors(ctx, w, p, c, p.factorVersion, p.factorVersion)
}
func (p *usernameRenamePhase) plan(final bool) (kernel.CommandPlan, error) {
	spec, ok := p.command.Feature()
	if !ok || p.registry == nil || p.coordinator == nil {
		return kernel.CommandPlan{}, password.ErrPasswordWork
	}
	before := p.intent.Change.ExpectedIdentifierVersion
	plan, err := resetServiceAuditDeclaration(spec.Binding, spec.Operation, p.registry.Descriptors(), "identifier", before, before+1, p.request.Proof.Proof.IssuedAt.UTC().Truncate(time.Microsecond))
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	plan.Feature.Contributor = p.Descriptor()
	plan.Lifecycle.EventType = "identifier.updated.v1"
	plan.CommandCounters = &p.counter
	if !final {
		return p.coordinator.PrepareFeaturePreparationPlan(p.command, plan)
	}
	return p.coordinator.PrepareCommandPlan(spec.Binding, p.command, plan)
}
func (p *usernameRenamePhase) riskScope() (risk.Context, error) {
	spec, ok := p.command.Feature()
	if !ok {
		return risk.Context{}, password.ErrPasswordWork
	}
	return risk.Context{Tenant: string(spec.Binding.TenantID), Operation: risk.Action(spec.Binding.OperationID), Attempt: string(spec.Binding.CommandID)}, nil
}

type usernameRenameAdmission struct {
	phase     *usernameRenamePhase
	admission risk.ProtectedProviderAdmission
}

func (a *usernameRenameAdmission) Check(ctx context.Context) error {
	if a == nil || a.phase == nil || ctx == nil {
		return password.ErrPasswordWork
	}
	until, err := a.phase.primary.Deadline()
	if err != nil {
		return err
	}
	if !time.Now().Before(until) {
		return identity.ForbiddenError{}
	}
	return a.admission.Check(ctx)
}
func (a *usernameRenameAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	aad, err := a.phase.outputAAD(generation)
	if err != nil {
		return nil, err
	}
	plain, err := json.Marshal(emailManagementStoredRisk(a.admission.Prepared()))
	defer clear(plain)
	if err != nil || len(plain) > maximumKeyedPasswordCustody-4096 {
		return nil, password.ErrPasswordWork
	}
	sealed, err := a.phase.service.crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, KeyReference: a.phase.service.config().ActiveEnvelopeKeyID, Context: aad})
	if err != nil {
		return nil, readerFailure(ctx)
	}
	wire, err := sealed.MarshalBinary()
	if err != nil || len(wire) > maximumKeyedPasswordCustody {
		clear(wire)
		return nil, password.ErrPasswordWork
	}
	return wire, nil
}
func (p *usernameRenamePhase) outputAAD(generation uint64) (envelope.Context, error) {
	spec, ok := p.command.Feature()
	if !ok || generation == 0 {
		return envelope.Context{}, password.ErrPasswordWork
	}
	frame, err := json.Marshal(struct {
		Binding    identity.CommandBinding
		Generation uint64
		Profile    [32]byte
	}{spec.Binding, generation, p.service.profile})
	if err != nil {
		return envelope.Context{}, password.ErrPasswordWork
	}
	digest := sha256.Sum256(frame)
	clear(frame)
	return envelope.NewContext(map[string]string{"profile": "identity-username-rename-admission-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}
func (p *usernameRenamePhase) PrepareFeatureAdmission(ctx context.Context, c identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if c != p.command {
		return nil, password.ErrPasswordWork
	}
	scope, err := p.riskScope()
	if err != nil {
		return nil, err
	}
	result, err := p.service.config().Risk.Evaluation.EvaluateProtectedProviders(ctx, risk.EvaluateRequest{Context: scope, Phase: risk.NonIssuing})
	if err != nil {
		return nil, err
	}
	admission, err := p.service.custody.Prepare(ctx, result, scope)
	if err != nil {
		return nil, err
	}
	a := &usernameRenameAdmission{phase: p, admission: admission}
	return a, a.Check(ctx)
}
func (*usernameRenamePhase) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, password.ErrPasswordWork
}
func (p *usernameRenamePhase) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	if c != p.command || len(wire) == 0 || len(wire) > maximumKeyedPasswordCustody {
		return identity.Command{}, kernel.CommandPlan{}, password.ErrPasswordWork
	}
	aad, err := p.outputAAD(generation)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, password.ErrPasswordWork
	}
	plain, err := p.service.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, readerFailure(ctx)
	}
	var stored emailManagementStoredRisk
	if decodeKeyedPasswordJSON(plain, &stored) != nil {
		return identity.Command{}, kernel.CommandPlan{}, password.ErrPasswordWork
	}
	scope, err := p.riskScope()
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	admission, err := p.service.custody.Restore(ctx, risk.PreparedProtectedProviderAdmission(stored), scope)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	p.admission, p.outputDigest, p.generation = admission, sha256.Sum256(wire), generation
	plan, err := p.plan(true)
	return c, plan, err
}
func (p *usernameRenamePhase) RestoreFeatureAdmission(ctx context.Context, c identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if _, _, err := p.RestoreFeaturePreparation(ctx, c, generation, wire); err != nil {
		return nil, err
	}
	a := &usernameRenameAdmission{phase: p, admission: p.admission}
	return a, a.Check(ctx)
}
func (p *usernameRenamePhase) check(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.command || p.generation == 0 {
		return password.ErrPasswordWork
	}
	if err := p.primary.Check(ctx, w, p, c); err != nil {
		return err
	}
	if err := p.requireFactors(ctx, w, c); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	return p.admission.CheckAt(ctx, now)
}
func (p *usernameRenamePhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if err := w.RequireFeatureCommand(ctx, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	wire, generation, err := w.FeaturePreparationOutput(p)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	digest := sha256.Sum256(wire)
	clear(wire)
	if generation != p.generation || digest != p.outputDigest {
		return identity.FeatureReceipt{}, password.ErrPasswordWork
	}
	if err := p.check(ctx, w, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.primary.Consume(ctx, w, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	before := p.intent.Change.ExpectedIdentifierVersion
	return identity.FeatureReceipt{Operation: p.FeatureOperations()[0], BeforeVersion: before, AfterVersion: before + 1}, nil
}
func (p *usernameRenamePhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	return p.check(ctx, w, c)
}
func (p *usernameRenamePhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return p.service.primary.Recover(ctx, w, p)
}
