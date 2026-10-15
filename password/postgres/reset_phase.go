package passwordpostgres

import (
	"context"
	"crypto/sha256"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// Native invocation-local composition. The public service must obtain origin,
// grant and consumption from the real durable issuer and select current primary
// recipient/directory/policy snapshots. None is accepted from transport input.
// The coordinator serially owns this phase throughout its synchronous call;
// another public invocation gets another instance, never shared mutable state.
type resetCompletionPhase struct {
	repository          *Repository
	coordinator         *kernel.Coordinator
	original, generated identity.Command
	intent              kernel.CredentialResetIntent
	profile             password.ResetProfile
	origin              password.ResetGrantSpec
	grant               capability.Grant
	consumption         kernel.CapabilityPlan
	directory           kernel.DirectoryAuthorityAdmission
	userAuthorization   kernel.UserAuthorizationAdmission
	recipient           kernel.RecipientRecord
	sessions            *sessionpg.PasswordResetEffect
	declaration         kernel.CommandPlan
	screening           password.HashPreparationConfig
	collectReset        ResetScreeningCollector
	verifier            capability.Service
	crypto              *envelope.Service
	envelopeKey         string
	configuration       [32]byte
	riskConfig          risk.AuthenticationAdmissionCustodyConfig
	subject             risk.Subject
	admission           risk.AuthenticationAdmission
	facts               []risk.Signal
	outputDigest        [32]byte
	outputGeneration    uint64
}

var _ kernel.CredentialResetContributor = (*resetCompletionPhase)(nil)
var _ kernel.FeatureAdmissionPreparationContributor = (*resetCompletionPhase)(nil)
var _ kernel.FeatureCommitContributor = (*resetCompletionPhase)(nil)

func (*resetCompletionPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}
}
func (*resetCompletionPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{resetOperation()}
}

func (p *resetCompletionPhase) CredentialReset(c identity.Command) (kernel.CredentialResetIntent, error) {
	if p == nil || p.repository == nil || p.generated == (identity.Command{}) || c != p.generated {
		return kernel.CredentialResetIntent{}, password.ErrPasswordWork
	}
	i, _, err := passwordResetOriginalMaterial(c, p.repository.policy, p.profile, p.origin, p.grant, p.consumption, p.origin.IssuedAt)
	if err != nil || i != p.intent {
		return kernel.CredentialResetIntent{}, password.ErrPasswordWork
	}
	return i, nil
}

func (p *resetCompletionPhase) validatePlan(plan kernel.CommandPlan) error {
	if p == nil || p.repository == nil || p.origin.FactorVersion == 0 || plan.Feature == nil || *plan.Feature != (kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: resetOperation()}) || plan.SubjectType != "credential" || plan.Capability == nil || *plan.Capability != p.consumption || plan.CommandCounters != nil || plan.OTP != nil || plan.RiskEvidence != nil || plan.CaptchaEvidence != nil || plan.Delivery != nil || plan.CapabilityIssuance != nil || plan.Lifecycle == nil || plan.Lifecycle.EventType != "password.reset.v1" || plan.Lifecycle.BeforeVersion != p.intent.Replacement.Credential.Version || plan.Lifecycle.AfterVersion != p.intent.Replacement.Credential.Version+1 || len(plan.Audits) != 1 {
		return password.ErrPasswordWork
	}
	a := plan.Audits[0]
	if a.EventType != resetOperation().OperationID || !a.Required || a.RequiredRecordCount != 1 || a.RetentionClass != "protected" {
		return password.ErrPasswordWork
	}
	return nil
}
func (p *resetCompletionPhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if err := p.validatePlan(plan); err != nil {
		return err
	}
	_, err := p.CredentialReset(c)
	return err
}
func (p *resetCompletionPhase) ValidateFeaturePreparation(c identity.Command, plan kernel.CommandPlan) error {
	if err := p.validatePlan(plan); err != nil {
		return err
	}
	if c != p.original {
		return password.ErrPasswordWork
	}
	spec, ok := c.PasswordResetInputFeature()
	i, err := passwordResetIntent(spec)
	if !ok || err != nil || i != p.intent {
		return password.ErrPasswordWork
	}
	return passwordResetOriginalIntent(i, p.profile, p.origin, p.grant, p.consumption, p.origin.IssuedAt)
}

// All current authority checks use owned primary rows in the sole Work. Final
// checking compares only the successor created by this reset; it never alters
// signed original intent or upgrades the input's authority to a current epoch.
func (p *resetCompletionPhase) current(ctx context.Context, w kernel.Work, successor bool) error {
	if p == nil || p.repository == nil || p.recipient.Validate() != nil || p.recipient.Suppressed || p.recipient.Query.UserID != p.origin.UserID || p.recipient.Identifier.ID != p.origin.IdentifierID || p.recipient.Identifier.Version != p.origin.IdentifierVersion || p.recipient.UserAuthorityVersion != p.origin.UserAuthorityVersion || p.recipient.CredentialAuthorityVersion != p.origin.CredentialAuthorityVersion {
		return identity.ForbiddenError{}
	}
	if err := w.RequireActiveDirectoryAuthority(ctx, p, p.directory); err != nil {
		return err
	}
	if err := w.RequireActiveUserAuthorization(ctx, p, p.userAuthorization); err != nil {
		return err
	}
	recipient := p.recipient
	if successor {
		recipient.CredentialAuthorityVersion++
	}
	return w.RequireRecipient(ctx, p, recipient)
}
func (p *resetCompletionPhase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p == nil || c != p.original {
		return password.ErrPasswordWork
	}
	if err := p.current(ctx, w, false); err != nil {
		return err
	}
	_, err := mfapg.RequireEmailRecoveryPreparation(ctx, w, p, c, p.origin.UserID, p.origin.FactorVersion)
	return err
}
func (*resetCompletionPhase) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, password.ErrPasswordWork
}

type resetCompletionAdmission struct {
	owner     *resetCompletionPhase
	admission risk.AuthenticationAdmission
}

func (a *resetCompletionAdmission) Check(ctx context.Context) error {
	if ctx == nil || a == nil || a.owner == nil {
		return password.ErrPasswordWork
	}
	p := a.owner
	now := time.Now().UTC()
	if err := a.admission.CheckAt(ctx, now); err != nil {
		return err
	}
	return p.profile.Authorize(p.grant, p.origin, now)
}
func (a *resetCompletionAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	p := a.owner
	command, facts, err := p.repository.generateResetCommandWithCollector(ctx, p.original, p.screening, a.admission, p.verifier, p.profile, p.origin, p.grant, p.consumption, p.collectReset)
	if err != nil {
		return nil, err
	}
	return p.repository.sealResetOutput(ctx, p.crypto, p.envelopeKey, p.original, generation, p.configuration, command, a.admission, facts)
}
func (p *resetCompletionPhase) PrepareFeatureAdmission(ctx context.Context, c identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if ctx == nil || p == nil || c != p.original {
		return nil, password.ErrPasswordWork
	}
	spec, ok := c.PasswordResetInputFeature()
	if !ok {
		return nil, password.ErrPasswordWork
	}
	b := spec.Binding
	scope := risk.Context{Tenant: string(b.TenantID), Operation: risk.Action(b.OperationID), Attempt: string(b.CommandID)}
	result, err := p.riskConfig.Evaluation.Evaluate(ctx, risk.EvaluateRequest{Context: scope, Phase: risk.NonIssuing, Subject: p.subject, Attribution: &risk.DecisionAttribution{CommandID: b.CommandID, CorrelationID: b.CommandID, Actor: audit.ActorInput{Kind: audit.ActorAnonymous}, Subject: identity.SecurityAuthenticationAttempt, SubjectID: string(b.CommandID)}})
	if err != nil {
		return nil, readerFailure(ctx)
	}
	custody, err := risk.NewAuthenticationAdmissionCustody(p.riskConfig)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	admission, err := custody.Prepare(ctx, result, scope, p.subject)
	if err != nil {
		return nil, readerFailure(ctx)
	}
	a := &resetCompletionAdmission{owner: p, admission: admission}
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	return a, nil
}
func (p *resetCompletionPhase) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	if p == nil || p.coordinator == nil || c != p.original {
		return identity.Command{}, kernel.CommandPlan{}, password.ErrPasswordWork
	}
	command, retained, facts, err := p.repository.restoreResetOutput(ctx, p.crypto, c, generation, p.configuration, wire)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	custody, err := risk.NewAuthenticationAdmissionCustody(p.riskConfig)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, password.ErrPasswordWork
	}
	admission, err := custody.Restore(ctx, retained, retained.Scope, p.subject)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, readerFailure(ctx)
	}
	if _, _, err := passwordResetOriginalMaterial(command, p.repository.policy, p.profile, p.origin, p.grant, p.consumption, time.Now().UTC()); err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	p.generated, p.admission, p.facts = command, admission, facts
	p.outputDigest, p.outputGeneration = sha256.Sum256(wire), generation
	spec, _ := command.PasswordResetFeature()
	plan, err := p.coordinator.PrepareCommandPlan(spec.Binding, command, p.declaration)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	return command, plan, nil
}
func (p *resetCompletionPhase) RestoreFeatureAdmission(ctx context.Context, c identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if _, _, err := p.RestoreFeaturePreparation(ctx, c, generation, wire); err != nil {
		return nil, err
	}
	a := &resetCompletionAdmission{owner: p, admission: p.admission}
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	return a, nil
}

func (p *resetCompletionPhase) checkTime(ctx context.Context, w kernel.Work) error {
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if err := p.profile.Authorize(p.grant, p.origin, now); err != nil {
		return identity.ForbiddenError{}
	}
	if err := p.admission.CheckAt(ctx, now); err != nil {
		return err
	}
	return p.repository.checkResetScreening(ctx, p.screening.Policy, p.admission.Prepared().Scope, p.facts, now)
}
func (p *resetCompletionPhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if p == nil || p.sessions == nil || c != p.generated {
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
	if generation != p.outputGeneration || digest != p.outputDigest || p.outputGeneration == 0 {
		return identity.FeatureReceipt{}, password.ErrPasswordWork
	}
	if err := p.current(ctx, w, false); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if _, err := mfapg.RequireEmailRecovery(ctx, w, p, c, p.origin.UserID, p.origin.FactorVersion); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.checkTime(ctx, w); err != nil {
		return identity.FeatureReceipt{}, err
	}
	receipt, err := p.repository.applyResetMaterial(ctx, w, p, c)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if _, err := p.sessions.Apply(ctx, w, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.checkTime(ctx, w); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return receipt, nil
}
func (p *resetCompletionPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p == nil || c != p.generated {
		return password.ErrPasswordWork
	}
	if err := p.current(ctx, w, true); err != nil {
		return err
	}
	// The owned MFA FOR UPDATE fence acquired during Apply remains held until
	// this same commit. No other participant in this profile owns factor writes.
	return p.checkTime(ctx, w)
}
func (p *resetCompletionPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	if ctx == nil || p == nil || p.repository == nil || p.sessions == nil {
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	material, err := p.repository.recoverReplacement(ctx, w, p)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	sessions, err := p.sessions.Recover(ctx, w, p)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	if material == sessions {
		return material, nil
	}
	return kernel.RecoveryUnknown, nil
}
