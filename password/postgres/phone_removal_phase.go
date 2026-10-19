package passwordpostgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"slices"
	"time"

	identity "github.com/faustbrian/go-identity"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/phone"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

type phoneRemovalPhase struct {
	service       *phoneRemovalService
	request       phone.RemoveRequestSpec
	primary       ActionPrimaryAdmission
	intent        kernel.PhoneRemovalIntent
	command       identity.Command
	counter       kernel.CommandCounterPlan
	factorVersion uint64
	coordinator   *kernel.Coordinator
	registry      *kernel.ContributorRegistry
	admission     risk.ProtectedProviderAdmission
	outputDigest  [32]byte
	generation    uint64
	notice        deliverypg.PreparedDelivery
}

var _ kernel.PhoneRemovalContributor = (*phoneRemovalPhase)(nil)
var _ kernel.RequestKeyPreparationContributor = (*phoneRemovalPhase)(nil)
var _ kernel.FeatureAdmissionPreparationContributor = (*phoneRemovalPhase)(nil)

func (*phoneRemovalPhase) Descriptor() kernel.ContributorDescriptor {
	return actionPrimaryDescriptor("identity.phone.remove")
}
func (*phoneRemovalPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{actionPrimaryOperation("identity.phone.remove")}
}
func (p *phoneRemovalPhase) PhoneRemoval(c identity.Command) (kernel.PhoneRemovalIntent, *kernel.PhoneRemovalDomain, error) {
	if p == nil || p.service == nil || c != p.command {
		return kernel.PhoneRemovalIntent{}, nil, password.ErrPasswordWork
	}
	return p.intent, p.service.domain, nil
}
func (p *phoneRemovalPhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.service == nil || c != p.command || p.factorVersion == 0 {
		return password.ErrPasswordWork
	}
	spec, ok := c.Feature()
	if !ok || spec.Operation != p.FeatureOperations()[0] || plan.Feature == nil || plan.Feature.Contributor != p.Descriptor() || plan.Feature.Operation != spec.Operation || plan.SubjectType != "identifier" || plan.CommandCounters == nil || *plan.CommandCounters != p.counter || plan.Lifecycle == nil || plan.Lifecycle.EventType != "identifier.removed.v1" || plan.Lifecycle.BeforeVersion != p.intent.Change.ExpectedIdentifierVersion || plan.Lifecycle.AfterVersion != plan.Lifecycle.BeforeVersion+1 || len(plan.Audits) != 1 || !plan.Audits[0].Required || plan.Audits[0].RetentionClass != "protected" || plan.Capability != nil || plan.OTP != nil || plan.CapabilityIssuance != nil {
		return password.ErrPasswordWork
	}
	factor, profile := false, false
	for _, f := range spec.Fields {
		switch f.Name {
		case "phone.factor-version":
			factor = f.Value.Kind == identity.FeatureUint64 && f.Value.Uint64 == p.factorVersion
		case "phone.removal.profile":
			profile = f.Value.Kind == identity.FeatureBytes && slices.Equal(f.Value.Bytes, p.service.profile[:])
		}
	}
	if !factor || !profile {
		return password.ErrPasswordWork
	}
	if plan.Audits[0].EventType != "identity.identifier.remove" {
		return password.ErrPasswordWork
	}
	if p.generation != 0 {
		expected, err := p.notice.Plan()
		if err != nil || plan.Delivery == nil || plan.Delivery.Contributor != expected.Contributor || !slices.Equal(plan.Delivery.Intents, expected.Intents) {
			return password.ErrPasswordWork
		}
	} else if plan.Delivery != nil {
		return password.ErrPasswordWork
	}
	return nil
}
func (p *phoneRemovalPhase) ValidateFeaturePreparation(c identity.Command, plan kernel.CommandPlan) error {
	return p.ValidateFeatureCommand(c, plan)
}
func (p *phoneRemovalPhase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.command {
		return password.ErrPasswordWork
	}
	// Acquire the directory writer lock before credential/session/factor share
	// locks. A later lock upgrade would allow two removals to deadlock or race.
	if err := w.RequirePhoneRemovalTarget(ctx, p, c); err != nil {
		return err
	}
	if err := p.primary.Admit(ctx, w, p, c); err != nil {
		return err
	}
	if err := p.requireFactors(ctx, w, c); err != nil {
		return err
	}
	return p.remainingRecovery(ctx, w)
}
func (p *phoneRemovalPhase) requireFactors(ctx context.Context, w kernel.Work, c identity.Command) error {
	_, err := mfapg.RequirePhoneFactors(ctx, w, p, c, p.factorVersion)
	return err
}
func (p *phoneRemovalPhase) plan(final bool) (kernel.CommandPlan, error) {
	spec, ok := p.command.Feature()
	if !ok || p.registry == nil || p.coordinator == nil {
		return kernel.CommandPlan{}, password.ErrPasswordWork
	}
	before := p.intent.Change.ExpectedIdentifierVersion
	contributors := p.registry.Descriptors()
	if !final {
		// The existing preparation contract adds delivery only with the final
		// authenticated plan, as for phone enrollment; no placeholder effect.
		owner := p.service.notices.Descriptor()
		contributors = slices.DeleteFunc(contributors, func(d kernel.ContributorDescriptor) bool { return d == owner })
	}
	plan, err := resetServiceAuditDeclaration(spec.Binding, spec.Operation, contributors, "identifier", before, before+1, p.request.Proof.Proof.IssuedAt.UTC().Truncate(time.Microsecond))
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	plan.Feature.Contributor = p.Descriptor()
	plan.Lifecycle.EventType = "identifier.removed.v1"
	plan.CommandCounters = &p.counter
	if !final {
		return p.coordinator.PrepareFeaturePreparationPlan(p.command, plan)
	}
	notice, err := p.notice.Plan()
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	plan.Delivery = &notice
	return p.coordinator.PrepareCommandPlan(spec.Binding, p.command, plan)
}
func (p *phoneRemovalPhase) riskScope() (risk.Context, error) {
	spec, ok := p.command.Feature()
	if !ok {
		return risk.Context{}, password.ErrPasswordWork
	}
	return risk.Context{Tenant: string(spec.Binding.TenantID), Operation: risk.Action(spec.Binding.OperationID), Attempt: string(spec.Binding.CommandID)}, nil
}

type phoneRemovalAdmission struct {
	phase     *phoneRemovalPhase
	admission risk.ProtectedProviderAdmission
}

type phoneRemovalOutput struct {
	Schema uint8
	Risk   emailManagementStoredRisk
	Notice []byte
}

func (a *phoneRemovalAdmission) Check(ctx context.Context) error {
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
func (a *phoneRemovalAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	aad, err := a.phase.outputAAD(generation)
	if err != nil {
		return nil, err
	}
	p := a.phase
	spec, ok := p.command.Feature()
	if !ok {
		return nil, password.ErrPasswordWork
	}
	notice, err := p.service.prepareNotice(ctx, spec.Binding, p.intent, p.request.Proof.Proof.IssuedAt)
	if err != nil {
		return nil, err
	}
	checkpoint, err := p.service.notices.CheckpointPreparation(ctx, notice, generation)
	defer clear(checkpoint)
	if err != nil {
		return nil, err
	}
	plain, err := json.Marshal(phoneRemovalOutput{Schema: 1, Risk: emailManagementStoredRisk(a.admission.Prepared()), Notice: checkpoint})
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
func (p *phoneRemovalPhase) outputAAD(generation uint64) (envelope.Context, error) {
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
	return envelope.NewContext(map[string]string{"profile": "identity-phone-removal-admission-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}
func (p *phoneRemovalPhase) PrepareFeatureAdmission(ctx context.Context, c identity.Command) (kernel.FeaturePreparationAdmission, error) {
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
	a := &phoneRemovalAdmission{phase: p, admission: admission}
	return a, a.Check(ctx)
}
func (*phoneRemovalPhase) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, password.ErrPasswordWork
}
func (p *phoneRemovalPhase) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
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
	var stored phoneRemovalOutput
	if decodeKeyedPasswordJSON(plain, &stored) != nil || stored.Schema != 1 {
		return identity.Command{}, kernel.CommandPlan{}, password.ErrPasswordWork
	}
	scope, err := p.riskScope()
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	admission, err := p.service.custody.Restore(ctx, risk.PreparedProtectedProviderAdmission(stored.Risk), scope)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	spec, ok := c.Feature()
	if !ok {
		return identity.Command{}, kernel.CommandPlan{}, password.ErrPasswordWork
	}
	notice, err := p.service.notices.RestorePreparation(ctx, spec.Binding, generation, stored.Notice)
	clear(stored.Notice)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	p.notice = notice
	p.admission, p.outputDigest, p.generation = admission, sha256.Sum256(wire), generation
	plan, err := p.plan(true)
	return c, plan, err
}
func (p *phoneRemovalPhase) RestoreFeatureAdmission(ctx context.Context, c identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if _, _, err := p.RestoreFeaturePreparation(ctx, c, generation, wire); err != nil {
		return nil, err
	}
	a := &phoneRemovalAdmission{phase: p, admission: p.admission}
	return a, a.Check(ctx)
}
func (p *phoneRemovalPhase) check(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.command || p.generation == 0 {
		return password.ErrPasswordWork
	}
	if err := p.primary.Check(ctx, w, p, c); err != nil {
		return err
	}
	// Removal advances its own identifier epoch, so repeating whole-directory
	// admission would reject the intended successor. Still fence the exact
	// original session/family (including its stored synchronizer) before commit:
	// time-only proof checks must not accept an independently revoked session.
	original, err := p.primary.Original()
	if err != nil {
		return err
	}
	if err := sessionpg.RequireSession(ctx, w, p.service.primary.primary.source.c.Session, original); err != nil {
		return err
	}
	if err := p.requireFactors(ctx, w, c); err != nil {
		return err
	}
	if err := p.remainingRecovery(ctx, w); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	return p.admission.CheckAt(ctx, now)
}
func (p *phoneRemovalPhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
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
	if err := p.service.notices.Stage(ctx, w, p.notice); err != nil {
		return identity.FeatureReceipt{}, err
	}
	before := p.intent.Change.ExpectedIdentifierVersion
	return identity.FeatureReceipt{Operation: p.FeatureOperations()[0], BeforeVersion: before, AfterVersion: before + 1}, nil
}
func (p *phoneRemovalPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	return p.check(ctx, w, c)
}
func (p *phoneRemovalPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return p.service.primary.Recover(ctx, w, p)
}

// This is the selected real email/password recovery profile, not a count or a
// caller-selected fallback. Hold the actual credential and every eligible email
// row in Work and require both configured owners to accept the stored canonical
// identity. Repeat after the removal's own identifier-epoch successor, without
// requiring or treating the removed phone as a remaining recovery path.
func (p *phoneRemovalPhase) remainingRecovery(ctx context.Context, w kernel.Work) error {
	return requireIndependentPhoneRecovery(ctx, w, p.primary, p.intent.Change.TenantID, p.intent.Change.UserID, p.service.signin, p.service.reset)
}
