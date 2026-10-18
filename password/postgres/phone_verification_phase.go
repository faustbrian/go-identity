package passwordpostgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"slices"
	"time"

	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/phone"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

type phoneEnrollmentPhase struct {
	service       *phoneVerificationService
	request       phone.EnrollmentRequestSpec
	primary       ActionPrimaryAdmission
	intent        kernel.PhoneEnrollmentIntent
	command       identity.Command
	subject       risk.Subject
	factorVersion uint64
	input         otppg.PhoneEnrollmentSendInput
	prepared      otppg.PreparedPhoneEnrollmentSend
	admission     risk.AuthenticationAdmission
	at, until     time.Time
	coordinator   *kernel.Coordinator
	registry      *kernel.ContributorRegistry
	outputDigest  [32]byte
	generation    uint64
	applied       bool
}

var _ kernel.PhoneEnrollmentContributor = (*phoneEnrollmentPhase)(nil)
var _ kernel.RequestKeyPreparationContributor = (*phoneEnrollmentPhase)(nil)
var _ kernel.FeatureAdmissionPreparationContributor = (*phoneEnrollmentPhase)(nil)

func (*phoneEnrollmentPhase) Descriptor() kernel.ContributorDescriptor {
	return phoneVerificationDescriptor()
}
func (*phoneEnrollmentPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{phoneEnrollmentOperation()}
}
func (p *phoneEnrollmentPhase) PhoneEnrollment(c identity.Command) (kernel.PhoneEnrollmentIntent, *kernel.PhoneEnrollmentDomain, error) {
	if p == nil || p.service == nil || c != p.command {
		return kernel.PhoneEnrollmentIntent{}, nil, password.ErrPasswordWork
	}
	return p.intent, p.service.domain, nil
}
func (p *phoneEnrollmentPhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.service == nil || c != p.command || !phoneCommandProfile(c, p.service.profile, p.factorVersion) {
		return password.ErrPasswordWork
	}
	spec, _ := c.Feature()
	if spec.Operation != phoneEnrollmentOperation() || plan.Feature == nil || plan.Feature.Contributor != p.Descriptor() || plan.Feature.Operation != spec.Operation || plan.SubjectType != "identifier" || plan.Lifecycle == nil || plan.Lifecycle.EventType != "identifier.attached.v1" || plan.Lifecycle.BeforeVersion != 0 || plan.Lifecycle.AfterVersion != 1 || len(plan.Audits) != 1 || !plan.Audits[0].Required || plan.Audits[0].RetentionClass != "protected" || plan.Capability != nil || plan.OTP != nil || plan.CapabilityIssuance != nil || plan.RiskEvidence != nil || plan.CommandCounters != nil {
		return password.ErrPasswordWork
	}
	if p.generation != 0 {
		expected, err := p.prepared.Plan()
		if err != nil || !reflect.DeepEqual(plan.Delivery, &expected) {
			return password.ErrPasswordWork
		}
	} else if plan.Delivery != nil {
		return password.ErrPasswordWork
	}
	_, err := kernel.PhoneEnrollmentFields(p.intent)
	return err
}
func (p *phoneEnrollmentPhase) ValidateFeaturePreparation(c identity.Command, plan kernel.CommandPlan) error {
	return p.ValidateFeatureCommand(c, plan)
}
func (p *phoneEnrollmentPhase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.command {
		return password.ErrPasswordWork
	}
	if err := p.primary.Admit(ctx, w, p, c); err != nil {
		return err
	}
	_, err := mfapg.RequirePhoneFactors(ctx, w, p, c, p.factorVersion)
	return err
}
func (p *phoneEnrollmentPhase) plan(final bool) (kernel.CommandPlan, error) {
	spec, ok := p.command.Feature()
	if !ok || p.registry == nil || p.coordinator == nil {
		return kernel.CommandPlan{}, password.ErrPasswordWork
	}
	contributors := p.registry.Descriptors()
	if !final {
		// The kernel's base preparation has no delivery yet. Register the real
		// owner for final restoration, but declare it only with its delivery plan.
		delivery := p.service.config().Issuer.DeliveryContributor().Descriptor()
		contributors = slices.DeleteFunc(contributors, func(d kernel.ContributorDescriptor) bool { return d == delivery })
	}
	plan, err := resetServiceAuditDeclaration(spec.Binding, spec.Operation, contributors, "identifier", 0, 1, p.at)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	plan.Feature.Contributor = p.Descriptor()
	plan.Lifecycle.EventType = "identifier.attached.v1"
	if !final {
		return p.coordinator.PrepareFeaturePreparationPlan(p.command, plan)
	}
	delivery, err := p.prepared.Plan()
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	plan.Delivery = &delivery
	return p.coordinator.PrepareCommandPlan(spec.Binding, p.command, plan)
}

type phoneEnrollmentOutput struct {
	Schema    uint8
	OTP       []byte
	Admission phoneAuthenticationAdmission
}

func (s *phoneVerificationService) enrollmentOutputAAD(b identity.CommandBinding, generation uint64) (envelope.Context, error) {
	if b.ValidateFor(phoneEnrollmentOperation()) != nil || generation == 0 {
		return envelope.Context{}, password.ErrPasswordWork
	}
	frame, err := json.Marshal(struct {
		Binding    identity.CommandBinding
		Generation uint64
		Profile    [32]byte
	}{b, generation, s.profile})
	if err != nil {
		return envelope.Context{}, password.ErrPasswordWork
	}
	digest := sha256.Sum256(frame)
	clear(frame)
	return envelope.NewContext(map[string]string{"profile": "identity-phone-enrollment-output-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}
func (s *phoneVerificationService) readEnrollmentOutput(ctx context.Context, b identity.CommandBinding, generation uint64, wire []byte) (phoneEnrollmentOutput, error) {
	aad, err := s.enrollmentOutputAAD(b, generation)
	if err != nil {
		return phoneEnrollmentOutput{}, err
	}
	plain, err := s.openPhone(ctx, wire, aad)
	if err != nil {
		return phoneEnrollmentOutput{}, err
	}
	defer clear(plain)
	var stored phoneEnrollmentOutput
	if decodeKeyedPasswordJSON(plain, &stored) != nil || stored.Schema != 1 || len(stored.OTP) == 0 || len(stored.OTP) > maximumKeyedPasswordCustody {
		return phoneEnrollmentOutput{}, password.ErrPasswordWork
	}
	return stored, nil
}

type phoneEnrollmentAdmission struct {
	phase     *phoneEnrollmentPhase
	admission risk.AuthenticationAdmission
}

func (a *phoneEnrollmentAdmission) Check(ctx context.Context) error {
	if ctx == nil || a == nil || a.phase == nil || !time.Now().Before(a.phase.until) {
		return identity.ForbiddenError{}
	}
	return a.admission.Check(ctx)
}
func (a *phoneEnrollmentAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	p := a.phase
	spec, _ := p.command.Feature()
	// Only the coordinator's acknowledged generation path calls the actual OTP
	// generator. Retained/ambiguous generations restore their checkpoint instead.
	output, err := p.service.config().Issuer.Generate(ctx, p.command, p.input, generation)
	if err != nil {
		return nil, err
	}
	defer clear(output)
	plain, err := json.Marshal(phoneEnrollmentOutput{Schema: 1, OTP: output, Admission: phoneAuthenticationAdmission(a.admission.Prepared())})
	defer clear(plain)
	if err != nil || len(plain) > maximumKeyedPasswordCustody-4096 {
		return nil, password.ErrPasswordWork
	}
	aad, err := p.service.enrollmentOutputAAD(spec.Binding, generation)
	if err != nil {
		return nil, err
	}
	return p.service.sealPhone(ctx, plain, aad)
}
func (p *phoneEnrollmentPhase) PrepareFeatureAdmission(ctx context.Context, c identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if c != p.command {
		return nil, password.ErrPasswordWork
	}
	spec, _ := c.Feature()
	admission, err := p.service.prepareRisk(ctx, spec.Binding, p.subject)
	if err != nil {
		return nil, err
	}
	a := &phoneEnrollmentAdmission{phase: p, admission: admission}
	return a, a.Check(ctx)
}
func (*phoneEnrollmentPhase) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, password.ErrPasswordWork
}
func (p *phoneEnrollmentPhase) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	bad := func(err error) (identity.Command, kernel.CommandPlan, error) {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	if c != p.command {
		return bad(password.ErrPasswordWork)
	}
	spec, _ := c.Feature()
	stored, err := p.service.readEnrollmentOutput(ctx, spec.Binding, generation, wire)
	if err != nil {
		return bad(err)
	}
	defer clear(stored.OTP)
	prepared, err := p.service.config().Issuer.Restore(ctx, c, p.input, generation, stored.OTP)
	if err != nil {
		return bad(err)
	}
	scope := risk.Context{Tenant: string(spec.Binding.TenantID), Operation: risk.Action(spec.Binding.OperationID), Attempt: string(spec.Binding.CommandID)}
	admission, err := p.service.custody.Restore(ctx, risk.PreparedAuthenticationAdmission(stored.Admission), scope, p.subject)
	if err != nil {
		return bad(err)
	}
	p.prepared, p.admission, p.outputDigest, p.generation = prepared, admission, sha256.Sum256(wire), generation
	plan, err := p.plan(true)
	return c, plan, err
}
func (p *phoneEnrollmentPhase) RestoreFeatureAdmission(ctx context.Context, c identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if _, _, err := p.RestoreFeaturePreparation(ctx, c, generation, wire); err != nil {
		return nil, err
	}
	a := &phoneEnrollmentAdmission{phase: p, admission: p.admission}
	return a, a.Check(ctx)
}
func (p *phoneEnrollmentPhase) check(ctx context.Context, w kernel.Work, c identity.Command, final bool) error {
	if c != p.command || p.generation == 0 {
		return password.ErrPasswordWork
	}
	if err := p.primary.Check(ctx, w, p, c); err != nil {
		return err
	}
	if final {
		original, err := p.primary.Original()
		if err != nil {
			return err
		}
		b, _, _, err := w.FeatureScope(p)
		if err != nil {
			return err
		}
		directory, credential, policy, err := p.service.primary.primary.originalAdmission(original, b)
		if err != nil {
			return err
		}
		// The kernel persisted this Work's sole pending attachment. Check only
		// that exact successor; readmitting the original identifier epoch would
		// reject our own mutation or tempt a dangerous freshness refresh.
		credential.IdentifierAuthorityVersion = p.intent.Change.ExpectedAuthorityVersion + 1
		if err = w.RequireActiveDirectoryAuthority(ctx, p, directory); err != nil {
			return err
		}
		if _, err = w.RequireActiveCredential(ctx, p, credential); err != nil {
			return err
		}
		if err = w.RequireActiveUserAuthorization(ctx, p, policy); err != nil {
			return err
		}
		if err = sessionpg.RequireSession(ctx, w, p.service.primary.primary.source.c.Session, original); err != nil {
			return err
		}
		state := p.primary.primary.custody()
		if err = p.service.requireCSRF(ctx, w, original, state.request.CSRFToken); err != nil {
			return err
		}
	}
	if _, err := mfapg.RequirePhoneFactors(ctx, w, p, c, p.factorVersion); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	return p.admission.CheckAt(ctx, now)
}
func (p *phoneEnrollmentPhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
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
	if err = p.check(ctx, w, c, false); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err = p.primary.Consume(ctx, w, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err = p.prepared.Persist(ctx, w, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	p.applied = true
	return identity.FeatureReceipt{Operation: phoneEnrollmentOperation(), BeforeVersion: 0, AfterVersion: 1}, nil
}
func (p *phoneEnrollmentPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	return p.check(ctx, w, c, true)
}
func (p *phoneEnrollmentPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	a, err := p.service.primary.Recover(ctx, w, p)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	b, err := p.service.config().Issuer.Recover(ctx, w, p)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	if a == kernel.RecoveryNotCommitted && b == kernel.RecoveryNotCommitted {
		return kernel.RecoveryNotCommitted, nil
	}
	return kernel.RecoveryUnknown, nil
}
