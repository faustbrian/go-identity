package passwordpostgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/faustbrian/go-audit"
	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
)

// Every public call owns a phase; no request state enters a shared registry.
// The kernel owns start/output journaling, SQL and all retry/recovery decisions.
type resetRequestPhase struct {
	service     *ResetService
	runtime     *resetRequestRuntime
	request     password.ResetRequestRequest
	canonical   string
	subject     risk.Subject
	coordinator *kernel.Coordinator
	registry    *kernel.ContributorRegistry
	original    identity.Command
	selected    resetRequestSelection
	execution   *resetRequestExecution
}

type resetRequestSelection struct {
	recipient      kernel.RecipientRecord
	credential     kernel.CredentialAdmission
	enabled        bool
	origin         password.ResetGrantSpec
	global, tenant uint64
}

type resetRequestExecution struct {
	selected     resetRequestSelection
	admission    risk.AuthenticationAdmission
	artifacts    resetRequestDelivery
	outputDigest [32]byte
	generation   uint64
}

var _ kernel.FeatureAdmissionPreparationContributor = (*resetRequestPhase)(nil)
var _ kernel.FeatureCommitContributor = (*resetRequestPhase)(nil)
var _ kernel.RecoveryContributor = (*resetRequestPhase)(nil)
var _ password.ResetService = (*ResetService)(nil)

func (*resetRequestPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}
}
func (*resetRequestPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{resetRequestOperation()}
}
func (p *resetRequestPhase) registration() kernel.FeatureRegistration {
	return kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: resetRequestOperation()}
}

func (p *resetRequestPhase) plan(at time.Time, final bool) (kernel.CommandPlan, error) {
	spec, ok := p.original.Feature()
	if !ok {
		return kernel.CommandPlan{}, password.ErrPasswordWork
	}
	contributors := p.registry.Descriptors()[:4]
	if final && !p.execution.selected.recipient.Suppressed {
		contributors = p.registry.Descriptors()
	}
	declaration, err := resetServiceAuditDeclaration(spec.Binding, spec.Operation, contributors, "user", 0, 0, at)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	declaration.Lifecycle.EventType = "password.reset.requested.v1"
	if final && !p.execution.selected.recipient.Suppressed {
		issue, e := p.execution.artifacts.issuance.Plan()
		if e != nil {
			return kernel.CommandPlan{}, e
		}
		message, e := p.execution.artifacts.delivery.Plan()
		if e != nil {
			return kernel.CommandPlan{}, e
		}
		declaration.CapabilityIssuance = &issue
		declaration.Delivery = &message
	}
	if final {
		return p.coordinator.PrepareCommandPlan(spec.Binding, p.original, declaration)
	}
	return p.coordinator.PrepareFeaturePreparationPlan(p.original, declaration)
}

func (p *resetRequestPhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.service == nil || p.runtime == nil || c != p.original || p.original == (identity.Command{}) || plan.Feature == nil || *plan.Feature != p.registration() || plan.SubjectType != "user" || plan.Lifecycle == nil || plan.Lifecycle.EventType != "password.reset.requested.v1" || plan.Lifecycle.BeforeVersion != 0 || plan.Lifecycle.AfterVersion != 0 || len(plan.Audits) != 1 || plan.Capability != nil || plan.OTP != nil {
		return password.ErrPasswordWork
	}
	return nil
}
func (p *resetRequestPhase) ValidateFeaturePreparation(c identity.Command, plan kernel.CommandPlan) error {
	return p.ValidateFeatureCommand(c, plan)
}

func (p *resetRequestPhase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.original {
		return password.ErrPasswordWork
	}
	b, f, _, err := w.FeatureScope(p)
	if err != nil || f != p.registration() {
		return password.ErrPasswordWork
	}
	q := kernel.RecipientQuery{TenantID: b.TenantID, Kind: identity.IdentifierEmail, CanonicalValue: p.canonical, Eligibility: kernel.RecipientVerified}
	recipient, credential, enabled, err := w.SelectResetRecipientCredential(ctx, p, q)
	if err != nil {
		return err
	}
	p.selected = resetRequestSelection{recipient: recipient, credential: credential, enabled: enabled, global: p.selected.global, tenant: p.selected.tenant}
	if recipient.Suppressed {
		return nil
	}
	if _, err = w.RequireResetRecipientCredential(ctx, p, recipient, credential, enabled); err != nil {
		return err
	}
	factor, err := mfapg.RequireEmailRecoveryRequestPreparation(ctx, w, p, c, recipient.User.ID)
	var forbidden identity.ForbiddenError
	if errors.As(err, &forbidden) {
		p.selected = resetRequestSelection{recipient: kernel.RecipientRecord{Query: q, Suppressed: true}, global: p.selected.global, tenant: p.selected.tenant}
		return nil
	}
	if err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	now = now.UTC().Truncate(time.Second)
	p.selected.origin = password.ResetGrantSpec{TenantID: b.TenantID, UserID: recipient.User.ID, CredentialID: credential.Credential.ID, CredentialVersion: credential.Credential.Version, CredentialAuthorityVersion: credential.CredentialAuthorityVersion, UserAuthorityVersion: recipient.UserAuthorityVersion, IdentifierID: recipient.Identifier.ID, IdentifierVersion: recipient.Identifier.Version, FactorVersion: factor.Version(), OriginCommandID: b.CommandID, RecoveryPath: auth.RecoveryPathEmail, CallbackURL: p.request.CallbackURL, IssuedAt: now, ExpiresAt: now.Add(p.runtime.config.Lifetime)}
	return nil
}

func (*resetRequestPhase) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, password.ErrPasswordWork
}

type resetRequestAdmission struct {
	owner     *resetRequestPhase
	admission risk.AuthenticationAdmission
}

func (a *resetRequestAdmission) Check(ctx context.Context) error {
	if a == nil || a.owner == nil || ctx == nil {
		return password.ErrPasswordWork
	}
	return a.admission.CheckAt(ctx, time.Now().UTC())
}
func (a *resetRequestAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	p := a.owner
	if p.selected.recipient.Validate() != nil {
		return nil, password.ErrPasswordWork
	}
	spec, _ := p.original.Feature()
	var artifacts resetRequestDelivery
	var err error
	if !p.selected.recipient.Suppressed {
		artifacts, err = p.service.repository.generateResetRequestDelivery(ctx, spec.Binding, p.selected.origin, p.selected.recipient, a.admission, generation, p.runtime.delivery)
		if err != nil {
			return nil, err
		}
		defer clear(artifacts.issuanceWire)
		defer clear(artifacts.deliveryWire)
	}
	return p.sealOutput(ctx, generation, p.selected, a.admission, artifacts)
}

func (p *resetRequestPhase) PrepareFeatureAdmission(ctx context.Context, c identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if c != p.original {
		return nil, password.ErrPasswordWork
	}
	spec, _ := c.Feature()
	b := spec.Binding
	scope := risk.Context{Tenant: string(b.TenantID), Operation: risk.Action(b.OperationID), Attempt: string(b.CommandID)}
	evaluation, err := p.service.config().Risk.Evaluation.Evaluate(ctx, risk.EvaluateRequest{Context: scope, Phase: risk.NonIssuing, Subject: p.subject, Attribution: &risk.DecisionAttribution{CommandID: b.CommandID, CorrelationID: b.CommandID, Actor: audit.ActorInput{Kind: audit.ActorAnonymous}, Subject: identity.SecurityAuthenticationAttempt, SubjectID: string(b.CommandID)}})
	if err != nil {
		return nil, readerFailure(ctx)
	}
	admission, err := p.runtime.custody.Prepare(ctx, evaluation, scope, p.subject)
	if err != nil {
		return nil, readerFailure(ctx)
	}
	// No remote provider is called under SQL. Global/tenant epochs are retained
	// here and fenced again inside final Work; expiry is never renewed on retry.
	directory, err := p.service.directory.GetDirectoryAuthority(ctx, kernel.DirectoryAuthorityQuery{GlobalAuthorityID: p.service.config().GlobalAuthorityID, TenantID: b.TenantID})
	if err != nil {
		return nil, err
	}
	if !directory.Enabled {
		return nil, identity.ForbiddenError{}
	}
	p.selected.global, p.selected.tenant = directory.GlobalVersion, directory.TenantVersion
	a := &resetRequestAdmission{owner: p, admission: admission}
	return a, a.Check(ctx)
}

func (p *resetRequestPhase) RestoreFeatureAdmission(ctx context.Context, c identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if _, _, err := p.RestoreFeaturePreparation(ctx, c, generation, wire); err != nil {
		return nil, err
	}
	a := &resetRequestAdmission{owner: p, admission: p.execution.admission}
	return a, a.Check(ctx)
}
func (p *resetRequestPhase) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	if c != p.original {
		return identity.Command{}, kernel.CommandPlan{}, password.ErrPasswordWork
	}
	e, err := p.restoreOutput(ctx, generation, wire)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	p.execution = e
	at := e.selected.recipient.ObservedAt
	if at.IsZero() {
		at = time.Now().UTC()
	}
	plan, err := p.plan(at, true)
	return c, plan, err
}

func (p *resetRequestPhase) checkCurrent(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p.execution == nil || c != p.original {
		return password.ErrPasswordWork
	}
	e := p.execution
	spec, _ := c.Feature()
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if err = e.admission.CheckAt(ctx, now); err != nil {
		return err
	}
	if err = w.RequireActiveDirectoryAuthority(ctx, p, kernel.DirectoryAuthorityAdmission{Query: kernel.DirectoryAuthorityQuery{GlobalAuthorityID: p.service.config().GlobalAuthorityID, TenantID: spec.Binding.TenantID}, GlobalVersion: e.selected.global, TenantVersion: e.selected.tenant}); err != nil {
		return err
	}
	if e.selected.recipient.Suppressed {
		return nil
	}
	if !now.Before(e.selected.origin.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	if _, err = w.RequireResetRecipientCredential(ctx, p, e.selected.recipient, e.selected.credential, e.selected.enabled); err != nil {
		return err
	}
	_, err = mfapg.RequireEmailRecovery(ctx, w, p, c, e.selected.origin.UserID, e.selected.origin.FactorVersion)
	return err
}
func (p *resetRequestPhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if err := w.RequireFeatureCommand(ctx, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.execution == nil {
		return identity.FeatureReceipt{}, password.ErrPasswordWork
	}
	wire, generation, err := w.FeaturePreparationOutput(p)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	digest := sha256.Sum256(wire)
	clear(wire)
	if digest != p.execution.outputDigest || generation != p.execution.generation {
		return identity.FeatureReceipt{}, password.ErrPasswordWork
	}
	if err = p.checkCurrent(ctx, w, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if !p.execution.selected.recipient.Suppressed {
		if err = p.service.issuer.Stage(ctx, w, p.execution.artifacts.issuance); err != nil {
			return identity.FeatureReceipt{}, err
		}
		if err = p.runtime.delivery.owner.Stage(ctx, w, p.execution.artifacts.delivery); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	return identity.FeatureReceipt{Operation: resetRequestOperation()}, nil
}
func (p *resetRequestPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	// Apply retained the primary account/identifier/credential/directory share
	// locks and factor update lock through this same transaction. The Apply-only
	// command guard must not be borrowed at commit; recheck expiring admission
	// against primary time without releasing or renewing any authority fence.
	if p.execution == nil || c != p.original {
		return password.ErrPasswordWork
	}
	b, f, _, err := w.FeatureScope(p)
	spec, ok := c.Feature()
	if err != nil || !ok || b != spec.Binding || f != p.registration() {
		return password.ErrPasswordWork
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if err = p.execution.admission.CheckAt(ctx, now); err != nil {
		return err
	}
	if !p.execution.selected.recipient.Suppressed && !now.Before(p.execution.selected.origin.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	return nil
}

// This participant owns no independent durable mutation. Issuer, delivery,
// audit and lifecycle participants must each prove absence in the same locked
// recovery scope; this negative result cannot certify those owners' effects.
func (p *resetRequestPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, f, l, err := w.FeatureScope(p)
	if ctx == nil || err != nil || f != p.registration() || b.UserID != "" || b.AnonymousFlowID == "" || l.EventType != "password.reset.requested.v1" || l.BeforeVersion != 0 || l.AfterVersion != 0 {
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	return kernel.RecoveryNotCommitted, nil
}
