package passwordpostgres

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/url"
	"slices"
	"time"

	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	email "github.com/faustbrian/go-identity/email"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

type emailManagementPhase struct {
	service       *EmailManagementService
	primary       EmailPrimaryAdmission
	intent        kernel.EmailAttachmentIntent
	link          email.ManagedVerificationSpec
	command       identity.Command
	counter       kernel.CommandCounterPlan
	factorVersion uint64
	family        issuerpg.ManagedEmailSupersessionScope
	coordinator   *kernel.Coordinator
	registry      *kernel.ContributorRegistry
	keyed         *keyedEmailInvocation
	execution     *emailManagementExecution
}

type emailManagementExecution struct {
	admission  risk.ProtectedProviderAdmission
	issuance   issuerpg.PreparedIssuance
	delivery   deliverypg.PreparedDelivery
	digest     [32]byte
	generation uint64
}

var _ kernel.EmailAttachmentContributor = (*emailManagementPhase)(nil)
var _ kernel.FeatureAdmissionPreparationContributor = (*emailManagementPhase)(nil)

func (*emailManagementPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/email/postgres", ContractID: "identity.email", Version: 1}
}
func (p *emailManagementPhase) FeatureOperations() []identity.FeatureOperation {
	ops := []identity.FeatureOperation{emailPrimaryOperation(p.service.primary.config.Action)}
	if p.service.primary.config.Action == "identity.email.verification-send" && p.service.config().ResendInterval != 0 {
		ops = append(ops, managedResendOperation())
	}
	return ops
}

func (p *emailManagementPhase) lifecycle() (string, uint64, uint64) {
	if p.intent.Change.Action == identity.IdentifierRestartVerification {
		before := p.intent.Change.ExpectedVerificationVersion
		return "identifier.verification-requested.v1", before, before + 1
	}
	return "identifier.attached.v1", 0, 1
}
func (p *emailManagementPhase) EmailAttachment(c identity.Command) (kernel.EmailAttachmentIntent, *kernel.EmailAttachmentDomain, error) {
	if c != p.command {
		return kernel.EmailAttachmentIntent{}, nil, password.ErrPasswordWork
	}
	return p.intent, p.service.domain, nil
}
func (p *emailManagementPhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.service == nil || c != p.command {
		return password.ErrPasswordWork
	}
	spec, ok := c.Feature()
	event, before, after := p.lifecycle()
	if !ok || !slices.Contains(p.FeatureOperations(), spec.Operation) || plan.Feature == nil || plan.Feature.Contributor != p.Descriptor() || plan.Feature.Operation != spec.Operation || plan.SubjectType != "identifier" || plan.CommandCounters == nil || *plan.CommandCounters != p.counter || plan.Lifecycle == nil || plan.Lifecycle.EventType != event || plan.Lifecycle.BeforeVersion != before || plan.Lifecycle.AfterVersion != after || len(plan.Audits) != 1 || !plan.Audits[0].Required || plan.Audits[0].RetentionClass != "protected" || plan.Capability != nil || plan.OTP != nil {
		return password.ErrPasswordWork
	}
	if p.service.config().ResendInterval != 0 {
		matched := false
		digest := p.family.Digest()
		for _, f := range spec.Fields {
			if f.Name == "email.management.family" {
				matched = f.Value.Kind == identity.FeatureBytes && bytes.Equal(f.Value.Bytes, digest[:]) && digest != ([32]byte{})
			}
		}
		if !matched {
			return password.ErrPasswordWork
		}
	}
	return nil
}
func (p *emailManagementPhase) ValidateFeaturePreparation(c identity.Command, plan kernel.CommandPlan) error {
	return p.ValidateFeatureCommand(c, plan)
}
func (p *emailManagementPhase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.command {
		return password.ErrPasswordWork
	}
	if err := p.primary.Admit(ctx, w, p, c); err != nil {
		return err
	}
	_, err := mfapg.RequireManagedEmailFactors(ctx, w, p, c, p.factorVersion)
	return err
}
func (p *emailManagementPhase) plan(final bool) (kernel.CommandPlan, error) {
	spec, ok := p.command.Feature()
	if !ok || p.registry == nil || p.coordinator == nil {
		return kernel.CommandPlan{}, password.ErrPasswordWork
	}
	contributors := make([]kernel.ContributorDescriptor, 0, 7)
	for _, d := range p.registry.Descriptors() {
		if d.ContractID != "capability.issuance" && d.ContractID != "identity.delivery.effects" {
			contributors = append(contributors, d)
		}
	}
	event, before, after := p.lifecycle()
	plan, err := resetServiceAuditDeclaration(spec.Binding, spec.Operation, contributors, "identifier", before, after, p.link.IssuedAt)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	plan.Feature.Contributor = p.Descriptor()
	plan.Lifecycle.EventType = event
	plan.CommandCounters = &p.counter
	if !final {
		return p.coordinator.PrepareFeaturePreparationPlan(p.command, plan)
	}
	if p.execution == nil {
		return kernel.CommandPlan{}, password.ErrPasswordWork
	}
	issue, err := p.execution.issuance.Plan()
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	message, err := p.execution.delivery.Plan()
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	plan.CapabilityIssuance = &issue
	plan.Delivery = &message
	plan.Contributors = append(plan.Contributors, issue.Contributor, message.Contributor)
	return p.coordinator.PrepareCommandPlan(spec.Binding, p.command, plan)
}

type emailManagementAdmission struct {
	phase     *emailManagementPhase
	admission risk.ProtectedProviderAdmission
}

func (a *emailManagementAdmission) Check(ctx context.Context) error {
	if a == nil || a.phase == nil || ctx == nil {
		return password.ErrPasswordWork
	}
	if err := a.phase.primary.custody().checkTime(time.Now().UTC()); err != nil {
		return err
	}
	return a.admission.CheckAt(ctx, time.Now().UTC())
}
func (a *emailManagementAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	return a.phase.generate(ctx, generation, a.admission)
}
func (p *emailManagementPhase) PrepareFeatureAdmission(ctx context.Context, c identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if c != p.command {
		return nil, password.ErrPasswordWork
	}
	spec, _ := c.Feature()
	scope := risk.Context{Tenant: string(spec.Binding.TenantID), Operation: risk.Action(spec.Binding.OperationID), Attempt: string(spec.Binding.CommandID)}
	result, err := p.service.config().Risk.Evaluation.EvaluateProtectedProviders(ctx, risk.EvaluateRequest{Context: scope, Phase: risk.NonIssuing})
	if err != nil {
		return nil, err
	}
	admission, err := p.service.custody.Prepare(ctx, result, scope)
	if err != nil {
		return nil, err
	}
	a := &emailManagementAdmission{phase: p, admission: admission}
	return a, a.Check(ctx)
}
func (*emailManagementPhase) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, password.ErrPasswordWork
}
func (p *emailManagementPhase) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	if c != p.command {
		return identity.Command{}, kernel.CommandPlan{}, password.ErrPasswordWork
	}
	if err := p.restore(ctx, generation, wire); err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	plan, err := p.plan(true)
	return c, plan, err
}
func (p *emailManagementPhase) RestoreFeatureAdmission(ctx context.Context, c identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if _, _, err := p.RestoreFeaturePreparation(ctx, c, generation, wire); err != nil {
		return nil, err
	}
	a := &emailManagementAdmission{phase: p, admission: p.execution.admission}
	return a, a.Check(ctx)
}
func (p *emailManagementPhase) check(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p.execution == nil || c != p.command {
		return password.ErrPasswordWork
	}
	if err := p.primary.Check(ctx, w, p, c); err != nil {
		return err
	}
	if _, err := mfapg.RequireManagedEmailFactors(ctx, w, p, c, p.factorVersion); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	return p.execution.admission.CheckAt(ctx, now)
}
func (p *emailManagementPhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if p.execution == nil || c != p.command {
		return identity.FeatureReceipt{}, password.ErrPasswordWork
	}
	if err := w.RequireFeatureCommand(ctx, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	wire, generation, err := w.FeaturePreparationOutput(p)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	digest := sha256.Sum256(wire)
	clear(wire)
	if generation != p.execution.generation || digest != p.execution.digest {
		return identity.FeatureReceipt{}, password.ErrPasswordWork
	}
	if err := p.check(ctx, w, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.intent.Change.Action == identity.IdentifierRestartVerification {
		if err := issuerpg.CheckManagedEmailResendCooldown(ctx, w, p, p.family, p.service.config().ResendInterval); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	if err := p.primary.Consume(ctx, w, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.service.issuer.Stage(ctx, w, p.execution.issuance); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.service.config().Delivery.Owner.Stage(ctx, w, p.execution.delivery); err != nil {
		return identity.FeatureReceipt{}, err
	}
	spec, _ := c.Feature()
	_, before, after := p.lifecycle()
	return identity.FeatureReceipt{Operation: spec.Operation, BeforeVersion: before, AfterVersion: after}, nil
}
func (p *emailManagementPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	return p.check(ctx, w, c)
}
func (p *emailManagementPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, f, _, err := w.FeatureScope(p)
	if err != nil || f.Contributor != p.Descriptor() {
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	key, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil {
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	rows, err := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM identity_password.reauthentication_records WHERE tenant_id=$1 AND user_id=$2 AND consumed_command_id=$3)`, string(b.TenantID), string(b.UserID), key)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	var used bool
	if !rows.Next() || rows.Scan(&used) != nil || rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	if used {
		return kernel.RecoveryUnknown, nil
	}
	return kernel.RecoveryNotCommitted, nil
}

// Only the existing journal retains this authenticated output. Nested issuer
// and delivery checkpoints keep original encrypted custody; no token is JSON.
type emailManagementStoredRisk risk.PreparedProtectedProviderAdmission
type emailManagementOutput struct {
	Schema                     uint8
	Spec                       identity.FeatureCommandSpec
	IssuedAt, ExpiresAt        time.Time
	TokenGeneration            uint64
	Risk                       emailManagementStoredRisk
	Issuance                   signupStoredIssuance
	IssuanceWire, DeliveryWire []byte
}

func (p *emailManagementPhase) outputContext(generation uint64) (envelope.Context, error) {
	spec, ok := p.command.Feature()
	if !ok || generation == 0 {
		return envelope.Context{}, password.ErrPasswordWork
	}
	return p.service.outputContext(spec.Binding, generation)
}

// The original primary binding and journal generation are available before
// decryption. Full intent remains inside authenticated ciphertext, so a link
// reader needs neither the historical session nor caller-reconstructed intent.
func (s *EmailManagementService) outputContext(binding identity.CommandBinding, generation uint64) (envelope.Context, error) {
	if s == nil || s.primary == nil || generation == 0 {
		return envelope.Context{}, password.ErrPasswordWork
	}
	op := emailPrimaryOperation(s.primary.config.Action)
	if binding.SchemaID == managedResendOperation().SchemaID && s.primary.config.Action == "identity.email.verification-send" && s.config().ResendInterval != 0 {
		op = managedResendOperation()
	}
	if binding.ValidateFor(op) != nil {
		return envelope.Context{}, password.ErrPasswordWork
	}
	frame, err := json.Marshal(struct {
		Binding    identity.CommandBinding
		Generation uint64
		Profile    [32]byte
	}{binding, generation, s.profile})
	defer clear(frame)
	if err != nil {
		return envelope.Context{}, password.ErrPasswordWork
	}
	digest := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"profile": "identity-managed-email-output-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}
func (p *emailManagementPhase) generate(ctx context.Context, generation uint64, admission risk.ProtectedProviderAdmission) (out []byte, err error) {
	if ctx == nil || generation == 0 {
		return nil, password.ErrPasswordWork
	}
	payload, err := p.service.payload(p.link)
	if err != nil {
		return nil, err
	}
	issuance, err := p.service.issuer.Prepare(ctx, p.link.Binding, []capability.Payload{payload})
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = issuance.TransferForDelivery(context.Background(), 0, func(context.Context, []byte) error { return nil })
		}
	}()
	issuePlan, err := issuance.Plan()
	if err != nil {
		return nil, err
	}
	var deliveryWire []byte
	defer func() { clear(deliveryWire) }()
	issueWire, err := p.service.codec.CheckpointPreparation(ctx, issuance, generation, func(ctx context.Context, index uint16, token []byte) error {
		if index != 0 || len(deliveryWire) != 0 {
			return password.ErrPasswordWork
		}
		prepared, err := p.prepareDelivery(ctx, token)
		if err != nil {
			return err
		}
		deliveryWire, err = p.service.config().Delivery.Owner.CheckpointPreparation(ctx, prepared, generation)
		return err
	})
	defer clear(issueWire)
	if err != nil {
		return nil, err
	}
	if len(issuePlan.Grants) != 1 || len(deliveryWire) == 0 {
		return nil, password.ErrPasswordWork
	}
	spec, _ := p.command.Feature()
	stored := emailManagementOutput{Schema: 1, Spec: spec, IssuedAt: p.link.IssuedAt, ExpiresAt: p.link.ExpiresAt, TokenGeneration: p.link.Payload.Version, Risk: emailManagementStoredRisk(admission.Prepared()), Issuance: signupStoredIssuance{Contributor: issuePlan.Contributor, Grants: []signupStoredGrant{signupStoredGrant(issuePlan.Grants[0])}}, IssuanceWire: issueWire, DeliveryWire: deliveryWire}
	plain, err := json.Marshal(stored)
	defer clear(plain)
	if err != nil || len(plain) > maximumSignupOutput-4096 {
		return nil, password.ErrPasswordWork
	}
	aad, err := p.outputContext(generation)
	if err != nil {
		return nil, err
	}
	sealed, err := p.service.crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, KeyReference: p.service.config().ActiveEnvelopeKeyID, Context: aad})
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	out, err = sealed.MarshalBinary()
	if err != nil || len(out) > maximumSignupOutput {
		clear(out)
		return nil, password.ErrPasswordWork
	}
	return out, nil
}
func (p *emailManagementPhase) restore(ctx context.Context, generation uint64, wire []byte) error {
	spec, ok := p.command.Feature()
	if !ok {
		return password.ErrPasswordWork
	}
	stored, err := p.service.readOutput(ctx, spec.Binding, generation, wire)
	defer clear(stored.IssuanceWire)
	defer clear(stored.DeliveryWire)
	if err != nil {
		return err
	}
	expected, err := json.Marshal(spec)
	defer clear(expected)
	original, originalErr := json.Marshal(stored.Spec)
	defer clear(original)
	if err != nil || originalErr != nil || !bytes.Equal(expected, original) || !stored.IssuedAt.Equal(p.link.IssuedAt) || !stored.ExpiresAt.Equal(p.link.ExpiresAt) || stored.TokenGeneration != p.link.Payload.Version {
		return password.ErrPasswordWork
	}
	scope := risk.Context{Tenant: string(p.link.Binding.TenantID), Operation: risk.Action(p.link.Binding.OperationID), Attempt: string(p.link.Binding.CommandID)}
	admission, err := p.service.custody.Restore(ctx, risk.PreparedProtectedProviderAdmission(stored.Risk), scope)
	if err != nil {
		return err
	}
	issuePlan := kernel.CapabilityIssuancePlan{Contributor: stored.Issuance.Contributor, Grants: []kernel.CapabilityPlan{kernel.CapabilityPlan(stored.Issuance.Grants[0])}}
	if issuePlan.Grants[0].Purpose != "identity.identifier.verify" || !issuePlan.Grants[0].ExpiresAt.Equal(p.link.ExpiresAt) {
		return password.ErrPasswordWork
	}
	issued, err := p.service.codec.RestorePreparation(ctx, p.link.Binding, generation, issuePlan, stored.IssuanceWire)
	if err != nil {
		return err
	}
	message, err := p.service.config().Delivery.Owner.RestorePreparation(ctx, p.link.Binding, generation, stored.DeliveryWire)
	if err != nil {
		return err
	}
	plan, err := message.Plan()
	if err != nil || len(plan.Intents) != 1 || plan.Intents[0].SubjectID != string(p.link.Binding.UserID) || plan.Intents[0].Purpose != "identity.email.verification-request" || !plan.Intents[0].ExpiresAt.Equal(p.link.ExpiresAt) {
		return password.ErrPasswordWork
	}
	p.execution = &emailManagementExecution{admission: admission, issuance: issued, delivery: message, digest: sha256.Sum256(wire), generation: generation}
	return nil
}

func (s *EmailManagementService) readOutput(ctx context.Context, binding identity.CommandBinding, generation uint64, wire []byte) (stored emailManagementOutput, err error) {
	defer func() {
		if err != nil {
			clear(stored.IssuanceWire)
			clear(stored.DeliveryWire)
			stored = emailManagementOutput{}
		}
	}()
	if ctx == nil || len(wire) == 0 || len(wire) > maximumSignupOutput {
		return stored, password.ErrPasswordWork
	}
	aad, err := s.outputContext(binding, generation)
	if err != nil {
		return stored, err
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return stored, password.ErrPasswordWork
	}
	plain, err := s.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil || len(plain) > maximumSignupOutput-4096 {
		return stored, password.ErrPasswordWork
	}
	d := json.NewDecoder(bytes.NewReader(plain))
	d.DisallowUnknownFields()
	if d.Decode(&stored) != nil {
		return stored, password.ErrPasswordWork
	}
	var trailing any
	if d.Decode(&trailing) != io.EOF || stored.Schema != 1 || len(stored.Issuance.Grants) != 1 || stored.Issuance.RegistrationUserID != "" || len(stored.IssuanceWire) == 0 || len(stored.DeliveryWire) == 0 || len(stored.IssuanceWire)+len(stored.DeliveryWire) > 512<<10 {
		return stored, password.ErrPasswordWork
	}
	canonical, err := json.Marshal(stored)
	defer clear(canonical)
	if err != nil || !bytes.Equal(plain, canonical) {
		return stored, password.ErrPasswordWork
	}
	if stored.Spec.Binding != binding || !slices.Contains((&emailManagementPhase{service: s}).FeatureOperations(), stored.Spec.Operation) {
		return stored, password.ErrPasswordWork
	}
	if _, err := identity.NewFeatureCommand(stored.Spec); err != nil {
		return stored, password.ErrPasswordWork
	}
	return stored, nil
}
func (p *emailManagementPhase) prepareDelivery(ctx context.Context, token []byte) (deliverypg.PreparedDelivery, error) {
	c := p.service.config().Delivery
	if len(token) == 0 || len(token) > 2048-len(c.Endpoint)-7 {
		return deliverypg.PreparedDelivery{}, password.ErrPasswordWork
	}
	work, stop := context.WithTimeout(ctx, c.Timeout)
	defer stop()
	now := time.Now().UTC()
	grant, err := capability.Verify(work, string(token), c.Resolver, capability.VerifyOptions{Issuer: p.service.config().Issuer.Crypto.Issuer, Now: now, Limits: capability.DefaultLimits()})
	if err != nil || p.service.policy.Authorize(grant, p.link, now) != nil {
		return deliverypg.PreparedDelivery{}, password.ErrPasswordWork
	}
	u, err := url.Parse(c.Endpoint)
	if err != nil {
		return deliverypg.PreparedDelivery{}, password.ErrPasswordWork
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return deliverypg.PreparedDelivery{}, password.ErrPasswordWork
	}
	q.Set("token", string(token))
	u.RawQuery = q.Encode()
	link := u.String()
	if len(link) > 2048 {
		return deliverypg.PreparedDelivery{}, password.ErrPasswordWork
	}
	frame, err := json.Marshal(struct {
		Binding             identity.CommandBinding
		Address, Identifier string
		Generation          uint64
		Expires             time.Time
	}{p.link.Binding, p.link.Payload.CanonicalAddress.Record().Value, string(p.link.IdentifierID), p.link.Payload.Version, p.link.ExpiresAt})
	defer clear(frame)
	if err != nil {
		return deliverypg.PreparedDelivery{}, password.ErrPasswordWork
	}
	mac := hmac.New(sha256.New, c.ScopeKey[:])
	_, _ = mac.Write([]byte("identity-managed-email-recipient-v1\x00"))
	_, _ = mac.Write(frame)
	recipient := delivery.Recipient{Channel: delivery.ChannelEmail, Address: p.link.Payload.CanonicalAddress.Record().Value, ScopeDigest: hex.EncodeToString(mac.Sum(nil))}
	message := delivery.Message{Purpose: "identity.email.verification-request", Channel: delivery.ChannelEmail, Recipient: recipient, TemplateID: c.TemplateID, TemplateVersion: uint64(c.TemplateVersion), LocaleChain: slices.Clone(c.Locales), Variables: []delivery.TemplateVariable{{Name: "link", Kind: "url", URLValue: link, Sensitive: true}}}
	rendered, err := c.Renderer.Render(work, message)
	if err != nil {
		return deliverypg.PreparedDelivery{}, password.ErrPasswordWork
	}
	return c.Owner.Prepare(work, p.link.Binding, []deliverypg.IntentInput{{Purpose: message.Purpose, SubjectID: string(p.link.Binding.UserID), TemplateID: c.TemplateID, TemplateVersion: c.TemplateVersion, ProviderConfigVersion: c.ProviderVersion, ExpiresAt: p.link.ExpiresAt, Recipient: recipient, Rendered: rendered}})
}
