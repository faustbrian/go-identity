package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

func rpSigninStartOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/oauth", OperationID: "identity.oauth.signin-start", SchemaID: "identity.oauth.signin-start.rp-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}

func (*signinStartPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/oauth/postgres", ContractID: "identity.oauth.rp-initiation", Version: 1}
}
func (*signinStartPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{rpSigninStartOperation()}
}
func (p *signinStartPhase) registration() kernel.FeatureRegistration {
	return kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: rpSigninStartOperation()}
}

func (p *signinStartPhase) command() (identity.Command, error) {
	if p == nil || p.input == nil {
		return identity.Command{}, identity.InvalidInputError{Field: "oauth_signin_input"}
	}
	frame, err := json.Marshal(p.input)
	if err != nil {
		return identity.Command{}, err
	}
	digest := sha256.Sum256(frame)
	clear(frame)
	return identity.NewFeaturePreAuthCommand(identity.FeatureCommandSpec{Binding: identity.CommandBinding(p.input.Binding), Operation: rpSigninStartOperation(), Fields: []identity.FeatureField{{Name: "oauth.signin.input", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}}}}, p.request.FlowCookie)
}

func (p *signinStartPhase) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.service == nil || p.input == nil {
		return identity.InvalidInputError{Field: "oauth_signin_input"}
	}
	expected, err := p.command()
	want, _ := expected.Feature()
	actual, ok := command.Feature()
	cookie, hasCookie := command.PreAuthCookie()
	if err != nil || !ok || !hasCookie || actual.Binding != want.Binding || actual.Operation != want.Operation || !sameRPFields(actual.Fields, want.Fields) {
		return identity.InvalidInputError{Field: "oauth_signin_command"}
	}
	request := p.request
	request.FlowCookie = cookie
	if checkSigninBrowser(request, p.flow, p.service.config.FlowKeys, actual.Binding.PolicyID, actual.Binding.PolicyVersion, p.input.Started) != nil {
		return identity.ForbiddenError{}
	}
	if plan.Feature != nil && (*plan.Feature != p.registration() || plan.SubjectType != "oauth_transaction" || plan.CommandCounters != nil || plan.Lifecycle == nil || *plan.Lifecycle != rpStartLifecycle()) {
		return identity.InvalidInputError{Field: "oauth_signin_plan"}
	}
	return nil
}

func (p *signinStartPhase) ValidateFeaturePreparation(command identity.Command, plan kernel.CommandPlan) error {
	if plan.CapabilityIssuance != nil || plan.Capability != nil || plan.Delivery != nil {
		return identity.InvalidInputError{Field: "oauth_signin_preparation"}
	}
	return p.ValidateFeatureCommand(command, plan)
}

func (p *signinStartPhase) plan(ctx context.Context, registry *kernel.ContributorRegistry, issuance *kernel.CapabilityIssuancePlan) (kernel.CommandPlan, error) {
	if p == nil || p.input == nil || registry == nil {
		return kernel.CommandPlan{}, identity.InvalidInputError{Field: "oauth_signin_plan"}
	}
	b := identity.CommandBinding(p.input.Binding)
	auditing, err := rpTransactionAudit(ctx, b, rpSigninStartOperation(), 0, 1, p.input.Started, p.service.config.AuditRetentionPolicyVersion)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	contributors := registry.Descriptors()
	if len(contributors) != 5 || contributors[4] != p.service.issuer.Descriptor() {
		return kernel.CommandPlan{}, identity.InvalidInputError{Field: "oauth_signin_plan"}
	}
	if issuance == nil {
		contributors = contributors[:4]
	}
	feature, lifecycle := p.registration(), rpStartLifecycle()
	return kernel.CommandPlan{Contributors: contributors, Feature: &feature, SubjectType: "oauth_transaction", Audits: []kernel.AuditPlan{auditing}, Lifecycle: &lifecycle, CapabilityIssuance: issuance}, nil
}

func (p *signinStartPhase) check(ctx context.Context, w kernel.Work, command identity.Command, applying bool) error {
	b, feature, lifecycle, err := w.FeatureScope(p)
	if err != nil || p.input == nil || b != identity.CommandBinding(p.input.Binding) || feature != p.registration() || lifecycle != rpStartLifecycle() || p.ValidateFeatureCommand(command, kernel.CommandPlan{}) != nil {
		return identity.ForbiddenError{}
	}
	if applying {
		if err := w.RequireFeatureCommand(ctx, p, command); err != nil {
			return err
		}
	}
	if err := w.RequireActiveDirectoryAuthority(ctx, p, kernel.DirectoryAuthorityAdmission{Query: kernel.DirectoryAuthorityQuery{GlobalAuthorityID: p.service.config.GlobalAuthorityID, TenantID: b.TenantID}, GlobalVersion: p.input.GlobalVersion, TenantVersion: p.input.TenantVersion}); err != nil {
		return err
	}
	if err := sessionpg.RequirePreAuth(ctx, w, p.service.config.Session, p.flow); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if now.Before(p.input.Started) || !now.Before(p.input.ValidUntil) {
		return identity.ForbiddenError{}
	}
	return checkSigninBrowser(p.request, p.flow, p.service.config.FlowKeys, b.PolicyID, b.PolicyVersion, now)
}

func (p *signinStartPhase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, command identity.Command) error {
	return p.check(ctx, w, command, false)
}

func (p *signinStartPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, command identity.Command) error {
	return p.check(ctx, w, command, false)
}

func (p *signinStartPhase) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	if err := p.check(ctx, w, command, true); err != nil {
		return identity.FeatureReceipt{}, err
	}
	wire, generation, err := w.FeaturePreparationOutput(p)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	defer clear(wire)
	output, issued, _, err := p.restoreOutput(ctx, generation, wire)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.persist(ctx, w, output); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.service.issuer.Stage(ctx, w, issued); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: rpSigninStartOperation(), AfterVersion: 1}, nil
}

func (p *signinStartPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, err := w.Scope()
	if err != nil || b.ValidateFor(rpSigninStartOperation()) != nil {
		return kernel.RecoveryUnknown, identity.InvalidInputError{Field: "oauth_signin_recovery"}
	}
	id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	rows, err := w.Query(ctx, `SELECT transaction_id,preauth_id FROM `+rpQuotedSchema(p.service.config.Schema)+`.transactions WHERE tenant_id=$1 AND origin_command_id=$2 AND operation=$3 AND user_id IS NULL AND session_id IS NULL`, string(b.TenantID), id, b.OperationID)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return kernel.RecoveryUnknown, identity.UnavailableError{}
		}
		return kernel.RecoveryNotCommitted, nil
	}
	var transaction, flow string
	if rows.Scan(&transaction, &flow) != nil || rows.Next() || rows.Err() != nil || transaction != b.RecordID || flow != b.AnonymousFlowID {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	return kernel.RecoveryCommitted, nil
}

type signinStartAdmission struct {
	owner     *signinStartPhase
	admission risk.AuthenticationAdmission
}

func (a *signinStartAdmission) Check(ctx context.Context) error {
	if a == nil || a.owner == nil || a.owner.input == nil {
		return identity.ForbiddenError{}
	}
	if err := a.admission.CheckAt(ctx, time.Now().UTC()); err != nil {
		return err
	}
	if !time.Now().UTC().Before(a.owner.input.ValidUntil) {
		return identity.ForbiddenError{}
	}
	return ctx.Err()
}
func (a *signinStartAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	return a.owner.generateOutput(ctx, generation, a.admission)
}

func (p *signinStartPhase) PrepareFeatureAdmission(ctx context.Context, command identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if err := p.ValidateFeatureCommand(command, kernel.CommandPlan{}); err != nil {
		return nil, err
	}
	b := identity.CommandBinding(p.input.Binding)
	scope := risk.Context{Tenant: string(b.TenantID), Operation: risk.Action(b.OperationID), Attempt: string(b.CommandID)}
	subject := risk.Subject{Network: p.input.Network, Device: p.input.Device}
	result, err := p.service.config.Risk.Evaluation.Evaluate(ctx, risk.EvaluateRequest{Context: scope, Phase: risk.NonIssuing, Subject: subject, Attribution: &risk.DecisionAttribution{CommandID: b.CommandID, CorrelationID: b.CommandID, Actor: audit.ActorInput{Kind: audit.ActorAnonymous}, Subject: identity.SecurityAuthenticationAttempt, SubjectID: string(b.CommandID)}})
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	admission, err := p.service.custody.Prepare(ctx, result, scope, subject)
	if err != nil {
		return nil, err
	}
	a := &signinStartAdmission{owner: p, admission: admission}
	return a, a.Check(ctx)
}

// External-admission generation must be invoked through the exact admitted
// invocation, never the legacy preparation entry point.
func (*signinStartPhase) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, identity.ForbiddenError{}
}

func (p *signinStartPhase) RestoreFeatureAdmission(ctx context.Context, command identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if err := p.ValidateFeatureCommand(command, kernel.CommandPlan{}); err != nil {
		return nil, err
	}
	out, _, _, err := p.restoreOutput(ctx, generation, wire)
	if err != nil {
		return nil, err
	}
	b := identity.CommandBinding(p.input.Binding)
	scope := risk.Context{Tenant: string(b.TenantID), Operation: risk.Action(b.OperationID), Attempt: string(b.CommandID)}
	admission, err := p.service.custody.Restore(ctx, risk.PreparedAuthenticationAdmission(out.Admission), scope, risk.Subject{Network: p.input.Network, Device: p.input.Device})
	if err != nil {
		return nil, err
	}
	a := &signinStartAdmission{owner: p, admission: admission}
	return a, a.Check(ctx)
}

func (p *signinStartPhase) RestoreFeaturePreparation(ctx context.Context, command identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	if err := p.ValidateFeaturePreparation(command, kernel.CommandPlan{}); err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	_, _, issuance, err := p.restoreOutput(ctx, generation, wire)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	_, registry, err := p.service.startCoordinator(p)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	plan, err := p.plan(ctx, registry, &issuance)
	return command, plan, err
}
