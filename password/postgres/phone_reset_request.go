package passwordpostgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"slices"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/phone"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// Invocation-local composition of the real owners. The keyed public workflow
// retains this original input before execution; this phase owns no journal,
// transaction, replay store, password comparison or SMS provider.
type phoneResetRequestPhase struct {
	source      phonePasswordRecoverySelection
	recipient   kernel.RecipientRecord
	config      SigninConfig
	command     identity.Command
	input       otppg.PhonePasswordResetSendInput
	sms         *otppg.PhonePasswordResetIssuer
	prepared    otppg.PreparedPhonePasswordResetSend
	risk        *phonePasswordRecoveryRisk
	riskPlan    kernel.RiskEvidencePlan
	link        resetRequestDeliveryPreparation
	origin      password.ResetGrantSpec
	material    *Repository
	artifacts   resetRequestDelivery
	crypto      *envelope.Service
	key         string
	caller      authorization.DecisionContext
	coordinator *kernel.Coordinator
	registry    *kernel.ContributorRegistry
	generation  uint64
	output      [32]byte
}

var _ kernel.FeatureAdmissionPreparationContributor = (*phoneResetRequestPhase)(nil)
var _ kernel.FeatureCommitContributor = (*phoneResetRequestPhase)(nil)

func newPhoneResetRequestPhase(ctx context.Context, pool *database.Pool, config SigninConfig, selected phonePasswordRecoverySelection, request phone.PasswordResetRequestRequestSpec, admitted *phonePasswordRecoveryRisk, original risk.PhoneEvidenceRequest, use risk.EvidenceUse, sms *otppg.PhonePasswordResetIssuer, link resetRequestDeliveryPreparation, crypto *envelope.Service, key string) (*phoneResetRequestPhase, error) {
	return restorePhoneResetRequestPhase(ctx, pool, config, selected, request, admitted, original, use, sms, link, crypto, key, request.CommandID, 1, nil, kernel.RiskEvidencePlan{})
}

// A keyed request's canonical consumer is distinct from its original external
// attempt and risk issuance. Restoration preserves the original signed check;
// it must not call PrepareUse again and thereby renew CheckedAt on a retry.
func restorePhoneResetRequestPhase(ctx context.Context, pool *database.Pool, config SigninConfig, selected phonePasswordRecoverySelection, request phone.PasswordResetRequestRequestSpec, admitted *phonePasswordRecoveryRisk, original risk.PhoneEvidenceRequest, use risk.EvidenceUse, sms *otppg.PhonePasswordResetIssuer, link resetRequestDeliveryPreparation, crypto *envelope.Service, key string, consumer identity.CommandID, numberVersion uint32, frozen *identity.FeatureCommandSpec, frozenPlan kernel.RiskEvidencePlan) (*phoneResetRequestPhase, error) {
	if request.Validate() != nil || admitted == nil || admitted.repository == nil || sms == nil || sms.DeliveryContributor() != link.owner || crypto == nil || !reauthenticationText(key, 128) {
		return nil, password.ErrPasswordWork
	}
	f, err := selected.flow.Bindings()
	if err != nil || selected.recipient.User.ID == "" || numberVersion == 0 || original.CommandID != string(request.RiskIssuanceCommandID) || original.Recovery.Binding.Attempt != string(request.CommandID) {
		return nil, password.ErrPasswordWork
	}
	op := phoneResetRequestOperation()
	b := identity.CommandBinding{CommandID: consumer, TenantID: request.TenantID, UserID: selected.recipient.User.ID, RecordID: string(consumer), ActorID: identity.ActorID(request.Caller.Request.Subject.ID), ActorKind: request.Caller.Request.Subject.Kind, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: config.PolicyID, PolicyVersion: f.Binding.Intent.PolicyVersion, CorrelationID: string(consumer)}
	domain, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: config.Repository.MaximumDuration})
	if err != nil {
		return nil, err
	}
	// The SMS owner's known-user grammar uses an exact-user recipient query.
	// Perform that actual narrower read, retaining every selected predecessor;
	// it must not replace withdrawn authority with a newer current snapshot.
	query := selected.recipient.Query
	query.UserID = b.UserID
	smsRecipient, err := domain.ResolveRecipient(ctx, query)
	expected := selected.recipient
	expected.Query, expected.ObservedAt = query, smsRecipient.ObservedAt
	if err != nil || !reflect.DeepEqual(smsRecipient, expected) {
		return nil, identity.ForbiddenError{}
	}
	if selected.smsObservedAt.IsZero() {
		selected.smsObservedAt = smsRecipient.ObservedAt
	}
	// appendSendRecipient in the OTP owner binds this timestamp into the
	// encrypted original. Retain its real first known-user read across pending
	// retry/completion; a later current read checks predecessors, not freshness.
	smsRecipient.ObservedAt = selected.smsObservedAt
	a := otppg.AttemptAuthority{Directory: selected.directory, Credential: selected.credential.Credential, UserAuthorization: selected.policy, UserAuthorityVersion: selected.recipient.UserAuthorityVersion, IdentifierAuthorityVersion: selected.recipient.IdentifierAuthorityVersion, CredentialAuthorityVersion: selected.recipient.CredentialAuthorityVersion}
	input, err := sms.CaptureInput(ctx, b, selected.flow, smsRecipient, a, selected.factor, selected.observedAt, minPhoneResetExpiry(selected.observedAt, f.Binding.ExpiresAt))
	if err != nil {
		return nil, err
	}
	fields, err := input.Fields()
	if err != nil {
		return nil, err
	}
	var command identity.Command
	var plan kernel.RiskEvidencePlan
	var spec identity.FeatureCommandSpec
	if frozen == nil {
		command, plan, err = admitted.repository.PrepareEvidenceUse(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields}, original, use)
		if err != nil {
			return nil, err
		}
		spec, _ = command.Feature()
	} else {
		spec, plan = *frozen, frozenPlan
		if spec.Binding != b || spec.Operation != op || len(spec.Fields) != len(fields)+7 {
			return nil, password.ErrPasswordWork
		}
		for _, field := range fields {
			found := false
			for _, retained := range spec.Fields {
				if reflect.DeepEqual(field, retained) {
					found = true
					break
				}
			}
			if !found {
				return nil, password.ErrPasswordWork
			}
		}
	}
	_, _, cookie, err := request.Flow.Bindings()
	if err != nil {
		return nil, err
	}
	command, err = identity.NewFeaturePreAuthCommand(spec, cookie)
	if err != nil {
		return nil, err
	}
	if err = admitted.repository.ValidateRiskEvidenceCommand(command, plan); err != nil {
		return nil, err
	}
	material, err := NewRepository(pool, config.Repository)
	if err != nil {
		return nil, err
	}
	meta, err := selected.factor.Metadata()
	if err != nil {
		return nil, err
	}
	at, until, err := input.Timeline()
	if err != nil {
		return nil, err
	}
	// Canonical capabilities encode whole seconds. Round the upper bound down,
	// never up beyond the original SMS or browser's exclusive deadline.
	at, until = at.Truncate(time.Second), until.Truncate(time.Second)
	origin := password.ResetGrantSpec{TenantID: b.TenantID, UserID: b.UserID, CredentialID: a.Credential.ID, CredentialVersion: a.Credential.Version, CredentialAuthorityVersion: a.CredentialAuthorityVersion, UserAuthorityVersion: a.UserAuthorityVersion, IdentifierID: selected.recipient.Identifier.ID, IdentifierVersion: selected.recipient.Identifier.Version, FactorVersion: meta.FactorAuthorityVersion, OriginCommandID: b.CommandID, RecoveryPath: auth.RecoveryPathPhone, CallbackURL: f.Binding.Intent.CallbackURL, IssuedAt: at, ExpiresAt: until, Phone: password.PhoneResetBinding{PreAuthTransaction: string(f.Binding.ID), OTPChallengeID: string(b.CommandID), AttemptID: b.CommandID, NumberDigest: f.Binding.Intent.IdentifierBinding, NumberKeyVersion: numberVersion, VerificationVersion: selected.recipient.Verification.Version, FactorID: meta.FactorID, FactorVersion: meta.EnrollmentVersion, RiskPolicyVersion: b.PolicyVersion}}
	if _, err = link.profile.Payload(origin); err != nil {
		return nil, err
	}
	p := &phoneResetRequestPhase{source: selected, recipient: smsRecipient, config: config, command: command, input: input, sms: sms, risk: admitted, riskPlan: plan, link: link, origin: origin, material: material, crypto: crypto, key: key, caller: request.Caller.Clone()}
	audits, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, err
	}
	outbox, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, err
	}
	p.registry, err = kernel.NewContributorRegistry([]kernel.Contributor{domain, audits, outbox, p, admitted.repository, link.issuer, link.owner})
	if err != nil {
		return nil, err
	}
	p.coordinator, err = kernel.NewCoordinator(pool, p.registry, config.Coordinator)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func minPhoneResetExpiry(at, original time.Time) time.Time {
	if bound := at.Add(time.Minute); bound.Before(original) {
		return bound
	}
	return original
}

func (*phoneResetRequestPhase) Descriptor() kernel.ContributorDescriptor {
	return phoneVerificationDescriptor()
}
func (*phoneResetRequestPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{phoneResetRequestOperation()}
}

func (p *phoneResetRequestPhase) plan(final bool) (kernel.CommandPlan, error) {
	b := sourceBinding(p.command)
	contributors := slices.Clone(p.registry.Descriptors())
	if !final {
		contributors = slices.DeleteFunc(contributors, func(d kernel.ContributorDescriptor) bool {
			return d == p.link.issuer.Descriptor() || d == p.link.owner.Descriptor()
		})
	}
	plan, err := resetServiceAuditDeclaration(b, phoneResetRequestOperation(), contributors, "otp_challenge", 0, 1, p.source.observedAt)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	plan.Feature.Contributor = p.Descriptor()
	plan.Lifecycle.EventType = "otp.sent.v1"
	plan.RiskEvidence = &p.riskPlan
	if !final {
		return p.coordinator.PrepareFeaturePreparationPlan(p.command, plan)
	}
	sms, err := p.prepared.Plan()
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	link, err := p.artifacts.delivery.Plan()
	if err != nil || sms.Contributor != link.Contributor {
		return kernel.CommandPlan{}, password.ErrPasswordWork
	}
	sms.Intents = append(slices.Clone(sms.Intents), link.Intents...)
	issue, err := p.artifacts.issuance.Plan()
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	plan.Delivery, plan.CapabilityIssuance = &sms, &issue
	return p.coordinator.PrepareCommandPlan(b, p.command, plan)
}

func (p *phoneResetRequestPhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil || c != p.command || plan.Feature == nil || plan.Feature.Contributor != p.Descriptor() || plan.Feature.Operation != phoneResetRequestOperation() || plan.SubjectType != "otp_challenge" || plan.Lifecycle == nil || *plan.Lifecycle != (kernel.LifecyclePlan{EventType: "otp.sent.v1", AfterVersion: 1}) || plan.RiskEvidence == nil || *plan.RiskEvidence != p.riskPlan || plan.Capability != nil || plan.OTP != nil || plan.CommandCounters != nil || plan.CaptchaEvidence != nil || len(plan.Audits) != 1 || !plan.Audits[0].Required {
		return password.ErrPasswordWork
	}
	if p.generation == 0 {
		if plan.CapabilityIssuance != nil || plan.Delivery != nil {
			return password.ErrPasswordWork
		}
	} else {
		issue, err := p.artifacts.issuance.Plan()
		if err != nil || !reflect.DeepEqual(plan.CapabilityIssuance, &issue) {
			return password.ErrPasswordWork
		}
		sms, err := p.prepared.Plan()
		link, e := p.artifacts.delivery.Plan()
		if err != nil || e != nil {
			return password.ErrPasswordWork
		}
		sms.Intents = append(slices.Clone(sms.Intents), link.Intents...)
		if !reflect.DeepEqual(plan.Delivery, &sms) {
			return password.ErrPasswordWork
		}
	}
	return p.risk.repository.ValidateRiskEvidenceCommand(c, p.riskPlan)
}
func (p *phoneResetRequestPhase) ValidateFeaturePreparation(c identity.Command, plan kernel.CommandPlan) error {
	return p.ValidateFeatureCommand(c, plan)
}

func (p *phoneResetRequestPhase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.command {
		return password.ErrPasswordWork
	}
	s := p.source
	if err := w.RequireActiveDirectoryAuthority(ctx, p, s.directory); err != nil {
		return err
	}
	if err := w.RequireActiveUserAuthority(ctx, p, kernel.UserAuthorityAdmission{UserAuthorityVersion: s.recipient.UserAuthorityVersion, IdentifierAuthorityVersion: s.recipient.IdentifierAuthorityVersion, CredentialAuthorityVersion: s.recipient.CredentialAuthorityVersion}); err != nil {
		return err
	}
	if _, err := w.RequireActiveCredential(ctx, p, s.credential); err != nil {
		return err
	}
	if err := w.RequireActiveUserAuthorization(ctx, p, s.policy); err != nil {
		return err
	}
	if err := sessionpg.RequirePreAuth(ctx, w, p.config.Session, s.flow); err != nil {
		return err
	}
	if err := w.RequireRecipient(ctx, p, p.recipient); err != nil {
		return err
	}
	return mfapg.RequirePhoneResetIssuancePreparation(ctx, w, p, c, s.factor, s.flow)
}

type phoneResetRequestAdmission struct{ phase *phoneResetRequestPhase }

func (a phoneResetRequestAdmission) Check(ctx context.Context) error {
	if ctx == nil || a.phase == nil {
		return password.ErrPasswordWork
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !time.Now().Before(a.phase.riskPlan.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	return nil
}
func (a phoneResetRequestAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	return a.phase.GenerateFeaturePreparation(ctx, a.phase.command, generation)
}
func (p *phoneResetRequestPhase) PrepareFeatureAdmission(ctx context.Context, c identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if c != p.command {
		return nil, password.ErrPasswordWork
	}
	a := phoneResetRequestAdmission{p}
	return a, a.Check(ctx)
}
func (p *phoneResetRequestPhase) RestoreFeatureAdmission(ctx context.Context, c identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if _, _, err := p.RestoreFeaturePreparation(ctx, c, generation, wire); err != nil {
		return nil, err
	}
	return p.PrepareFeatureAdmission(ctx, c)
}

type phoneResetRequestOutput struct {
	Schema                  uint8
	SMS, Issuance, Delivery []byte
	Plan                    resetStoredRequestIssuance
}

func (p *phoneResetRequestPhase) aad(generation uint64) (envelope.Context, error) {
	spec, ok := p.command.Feature()
	if !ok || generation == 0 {
		return envelope.Context{}, password.ErrPasswordWork
	}
	wire, err := json.Marshal(struct {
		Spec       identity.FeatureCommandSpec
		Generation uint64
	}{spec, generation})
	if err != nil {
		return envelope.Context{}, err
	}
	defer clear(wire)
	digest := sha256.Sum256(wire)
	return envelope.NewContext(map[string]string{"profile": "identity-phone-reset-request-output-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func (p *phoneResetRequestPhase) GenerateFeaturePreparation(ctx context.Context, c identity.Command, generation uint64) ([]byte, error) {
	if c != p.command {
		return nil, password.ErrPasswordWork
	}
	aad, err := p.aad(generation)
	if err != nil {
		return nil, err
	}
	sms, err := p.sms.Generate(ctx, c, p.input, generation)
	if err != nil {
		return nil, err
	}
	defer clear(sms)
	artifacts, err := p.material.generatePhoneResetRequestDelivery(ctx, sourceBinding(c), p.origin, p.source.recipient, generation, p.link)
	defer clear(artifacts.issuanceWire)
	defer clear(artifacts.deliveryWire)
	if err != nil {
		return nil, err
	}
	plan, err := artifacts.issuance.Plan()
	if err != nil {
		return nil, err
	}
	stored := resetStoredRequestIssuance{Contributor: plan.Contributor, ResetRecipientUserID: plan.ResetRecipientUserID}
	for _, grant := range plan.Grants {
		stored.Grants = append(stored.Grants, signupStoredGrant(grant))
	}
	plain, err := json.Marshal(phoneResetRequestOutput{Schema: 1, SMS: sms, Issuance: artifacts.issuanceWire, Delivery: artifacts.deliveryWire, Plan: stored})
	defer clear(plain)
	if err != nil || len(plain) > maximumKeyedPasswordCustody-4096 {
		return nil, password.ErrPasswordWork
	}
	sealed, err := p.crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, KeyReference: p.key, Context: aad})
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	return sealed.MarshalBinary()
}

func (p *phoneResetRequestPhase) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	bad := func(err error) (identity.Command, kernel.CommandPlan, error) {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	if c != p.command || len(wire) == 0 || len(wire) > maximumKeyedPasswordCustody {
		return bad(password.ErrPasswordWork)
	}
	aad, err := p.aad(generation)
	if err != nil {
		return bad(err)
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return bad(password.ErrPasswordWork)
	}
	plain, err := p.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil || len(plain) > maximumKeyedPasswordCustody {
		return bad(password.ErrPasswordWork)
	}
	var output phoneResetRequestOutput
	if decodeKeyedPasswordJSON(plain, &output) != nil || output.Schema != 1 || len(output.Plan.Grants) != 1 {
		return bad(password.ErrPasswordWork)
	}
	defer clear(output.SMS)
	defer clear(output.Issuance)
	defer clear(output.Delivery)
	p.prepared, err = p.sms.Restore(ctx, c, p.input, generation, output.SMS)
	if err != nil {
		return bad(err)
	}
	plan := kernel.CapabilityIssuancePlan{Contributor: output.Plan.Contributor, ResetRecipientUserID: output.Plan.ResetRecipientUserID}
	for _, grant := range output.Plan.Grants {
		plan.Grants = append(plan.Grants, kernel.CapabilityPlan(grant))
	}
	p.artifacts.issuance, err = p.link.codec.RestorePreparation(ctx, sourceBinding(c), generation, plan, output.Issuance)
	if err != nil {
		return bad(err)
	}
	p.artifacts.delivery, err = p.link.owner.RestorePreparation(ctx, sourceBinding(c), generation, output.Delivery)
	if err != nil {
		return bad(err)
	}
	p.generation, p.output = generation, sha256.Sum256(wire)
	final, err := p.plan(true)
	return c, final, err
}

func (p *phoneResetRequestPhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if c != p.command || p.generation == 0 {
		return identity.FeatureReceipt{}, password.ErrPasswordWork
	}
	wire, generation, err := w.FeaturePreparationOutput(p)
	digest := sha256.Sum256(wire)
	clear(wire)
	if err != nil || generation != p.generation || digest != p.output {
		return identity.FeatureReceipt{}, password.ErrPasswordWork
	}
	if err = p.prepared.Persist(ctx, w, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err = p.link.issuer.Stage(ctx, w, p.artifacts.issuance); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err = p.link.owner.Stage(ctx, w, p.artifacts.delivery); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: phoneResetRequestOperation(), AfterVersion: 1}, nil
}

func (p *phoneResetRequestPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	b, f, _, err := w.FeatureScope(p)
	if err != nil || c != p.command || b != sourceBinding(c) || f.Contributor != p.Descriptor() || f.Operation != phoneResetRequestOperation() {
		return password.ErrPasswordWork
	}
	// The SMS owner retains current primary, original flow and MFA row locks.
	// Check time again after all participant work without repeating writes or
	// extending either the source evidence or the canonical grant deadline.
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if !now.Before(p.origin.ExpiresAt) || !now.Before(p.riskPlan.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *phoneResetRequestPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return p.sms.Recover(ctx, w, p)
}
func (p *phoneResetRequestPhase) execute(ctx context.Context) (identity.CommandResult, error) {
	// A prior in-memory final plan must not be mistaken for a new preparation.
	if p.generation != 0 {
		b := sourceBinding(p.command)
		caller := p.caller.Clone()
		caller.Request.Resource = authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}
		return p.coordinator.RecoverFeatureCommand(ctx, identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, RecordID: b.RecordID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID}, caller)
	}
	plan, err := p.plan(false)
	if err != nil {
		return identity.CommandResult{}, err
	}
	return p.coordinator.ExecutePreparedFeature(ctx, p.command, plan)
}
