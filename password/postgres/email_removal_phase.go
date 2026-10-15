package passwordpostgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"slices"
	"time"

	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

type emailRemovalPhase struct {
	service       *EmailRemovalService
	request       email.AddressRemoveRequest
	primary       EmailPrimaryAdmission
	intent        kernel.EmailRemovalIntent
	command       identity.Command
	counter       kernel.CommandCounterPlan
	factorVersion uint64
	coordinator   *kernel.Coordinator
	registry      *kernel.ContributorRegistry
	admission     risk.ProtectedProviderAdmission
	outputDigest  [32]byte
	generation    uint64
}

var _ kernel.EmailRemovalContributor = (*emailRemovalPhase)(nil)
var _ kernel.RequestKeyPreparationContributor = (*emailRemovalPhase)(nil)
var _ kernel.FeatureAdmissionPreparationContributor = (*emailRemovalPhase)(nil)

func (*emailRemovalPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/email/postgres", ContractID: "identity.email", Version: 1}
}
func (*emailRemovalPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{emailPrimaryOperation("identity.email.address-remove")}
}
func (p *emailRemovalPhase) EmailRemoval(c identity.Command) (kernel.EmailRemovalIntent, *kernel.EmailRemovalDomain, error) {
	if p == nil || p.service == nil || c != p.command {
		return kernel.EmailRemovalIntent{}, nil, password.ErrPasswordWork
	}
	return p.intent, p.service.domain, nil
}
func (p *emailRemovalPhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.service == nil || c != p.command || p.factorVersion == 0 {
		return password.ErrPasswordWork
	}
	spec, ok := c.Feature()
	if !ok || spec.Operation != p.FeatureOperations()[0] || plan.Feature == nil || plan.Feature.Contributor != p.Descriptor() || plan.Feature.Operation != spec.Operation || plan.SubjectType != "identifier" || plan.CommandCounters == nil || *plan.CommandCounters != p.counter || plan.Lifecycle == nil || plan.Lifecycle.EventType != "identifier.removed.v1" || plan.Lifecycle.BeforeVersion != p.intent.Change.ExpectedIdentifierVersion || plan.Lifecycle.AfterVersion != plan.Lifecycle.BeforeVersion+1 || len(plan.Audits) != 1 || !plan.Audits[0].Required || plan.Audits[0].RetentionClass != "protected" || plan.Capability != nil || plan.OTP != nil || plan.Delivery != nil || plan.CapabilityIssuance != nil {
		return password.ErrPasswordWork
	}
	matchedFactor, matchedProfile := false, false
	for _, f := range spec.Fields {
		switch f.Name {
		case "email.removal.factor-version":
			matchedFactor = f.Value.Kind == identity.FeatureUint64 && f.Value.Uint64 == p.factorVersion
		case "email.removal.profile":
			matchedProfile = f.Value.Kind == identity.FeatureBytes && slices.Equal(f.Value.Bytes, p.service.profile[:])
		}
	}
	if !matchedFactor || !matchedProfile {
		return password.ErrPasswordWork
	}
	return nil
}
func (p *emailRemovalPhase) ValidateFeaturePreparation(c identity.Command, plan kernel.CommandPlan) error {
	return p.ValidateFeatureCommand(c, plan)
}
func (p *emailRemovalPhase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.command {
		return password.ErrPasswordWork
	}
	if err := p.primary.Admit(ctx, w, p, c); err != nil {
		return err
	}
	if _, err := mfapg.RequireManagedEmailFactors(ctx, w, p, c, p.factorVersion); err != nil {
		return err
	}
	return p.remainingRecovery(ctx, w)
}
func (p *emailRemovalPhase) plan(final bool) (kernel.CommandPlan, error) {
	spec, ok := p.command.Feature()
	if !ok || p.registry == nil || p.coordinator == nil {
		return kernel.CommandPlan{}, password.ErrPasswordWork
	}
	before := p.intent.Change.ExpectedIdentifierVersion
	plan, err := resetServiceAuditDeclaration(spec.Binding, spec.Operation, p.registry.Descriptors(), "identifier", before, before+1, p.request.Primary.Proof.Proof.IssuedAt.UTC().Truncate(time.Microsecond))
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	plan.Feature.Contributor = p.Descriptor()
	plan.Lifecycle.EventType = "identifier.removed.v1"
	plan.CommandCounters = &p.counter
	if !final {
		return p.coordinator.PrepareFeaturePreparationPlan(p.command, plan)
	}
	return p.coordinator.PrepareCommandPlan(spec.Binding, p.command, plan)
}

func (p *emailRemovalPhase) riskScope() (risk.Context, error) {
	spec, ok := p.command.Feature()
	if !ok {
		return risk.Context{}, password.ErrPasswordWork
	}
	return risk.Context{Tenant: string(spec.Binding.TenantID), Operation: risk.Action(spec.Binding.OperationID), Attempt: string(spec.Binding.CommandID)}, nil
}

type emailRemovalAdmission struct {
	phase     *emailRemovalPhase
	admission risk.ProtectedProviderAdmission
}

func (a *emailRemovalAdmission) Check(ctx context.Context) error {
	if a == nil || a.phase == nil || a.phase.primary.custody == nil || ctx == nil {
		return password.ErrPasswordWork
	}
	if err := a.phase.primary.custody().checkTime(time.Now().UTC()); err != nil {
		return err
	}
	return a.admission.Check(ctx)
}
func (a *emailRemovalAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
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
func (p *emailRemovalPhase) outputAAD(generation uint64) (envelope.Context, error) {
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
	return envelope.NewContext(map[string]string{"profile": "identity-email-removal-admission-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}
func (p *emailRemovalPhase) PrepareFeatureAdmission(ctx context.Context, c identity.Command) (kernel.FeaturePreparationAdmission, error) {
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
	a := &emailRemovalAdmission{phase: p, admission: admission}
	return a, a.Check(ctx)
}
func (*emailRemovalPhase) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	// The admission-bearing interface above is mandatory. The older generator
	// cannot skip actual provider admission or create unbound output.
	return nil, password.ErrPasswordWork
}
func (p *emailRemovalPhase) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
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
func (p *emailRemovalPhase) RestoreFeatureAdmission(ctx context.Context, c identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if _, _, err := p.RestoreFeaturePreparation(ctx, c, generation, wire); err != nil {
		return nil, err
	}
	a := &emailRemovalAdmission{phase: p, admission: p.admission}
	return a, a.Check(ctx)
}

func (p *emailRemovalPhase) check(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.command || p.generation == 0 {
		return password.ErrPasswordWork
	}
	if err := p.primary.Check(ctx, w, p, c); err != nil {
		return err
	}
	if _, err := mfapg.RequireManagedEmailFactors(ctx, w, p, c, p.factorVersion); err != nil {
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
func (p *emailRemovalPhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
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
	if err := issuerpg.RetireEmailVerificationGrants(ctx, w, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	before := p.intent.Change.ExpectedIdentifierVersion
	return identity.FeatureReceipt{Operation: p.FeatureOperations()[0], BeforeVersion: before, AfterVersion: before + 1}, nil
}
func (p *emailRemovalPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	return p.check(ctx, w, c)
}
func (p *emailRemovalPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return recoverEmailPrimaryUse(ctx, w, p)
}

// The actual configured signin and reset parsers must both preserve the stored
// canonical mailbox. Current root/password authority is locked by primary Admit;
// the query retains exact active credential and surviving verified-email rows.
// No provider, password comparison, message delivery or caller callback occurs.
func (p *emailRemovalPhase) remainingRecovery(ctx context.Context, w kernel.Work) error {
	original, err := p.primary.Original()
	if err != nil {
		return err
	}
	b, err := original.Bindings()
	if err != nil {
		return err
	}
	rows, err := w.Query(ctx, `SELECT i.canonical_value FROM identity.identifiers i
JOIN identity.users u USING(tenant_id,user_id)
JOIN identity.credential_references c USING(tenant_id,user_id)
WHERE i.tenant_id=$1 AND i.user_id=$2 AND i.identifier_id<>$3 AND i.kind='email'
AND i.verified AND i.verification_state=2 AND i.verified_at IS NOT NULL AND u.status='active'
AND c.credential_id=$4 AND c.kind=1 AND c.owner='identity/password' AND c.enabled
AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp())
AND NOT EXISTS(SELECT 1 FROM identity.credential_references other
 WHERE other.tenant_id=c.tenant_id AND other.user_id=c.user_id AND other.kind=1
 AND other.owner='identity/password' AND other.credential_id<>c.credential_id)
ORDER BY i.is_primary DESC,i.identifier_id LIMIT 128 FOR SHARE OF u,i,c`, string(b.TenantID), string(b.UserID), string(p.intent.Change.ID), string(b.Authentication.CredentialID))
	if err != nil {
		return err
	}
	defer rows.Close()
	usable := false
	for rows.Next() {
		var canonical string
		if rows.Scan(&canonical) != nil {
			return identity.UnavailableError{}
		}
		signin, first := p.service.signin.address.Parse(email.AddressInput(canonical))
		reset, second := p.service.reset.request.config.Address.Parse(email.AddressInput(canonical))
		if first == nil && second == nil && signin.Canonical().Record().Value == canonical && reset.Canonical().Record().Value == canonical {
			usable = true
		}
	}
	if rows.Err() != nil {
		return identity.UnavailableError{}
	}
	if !usable {
		return identity.ForbiddenError{}
	}
	return ctx.Err()
}
