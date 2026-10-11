package passwordpostgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

// Invocation-local phase; closure custody never enters a shared registry or
// survives its synchronous public call. The kernel alone owns generation.
type signupPhase struct {
	service     *SignupService
	request     func() password.SignupRequest
	coordinator *kernel.Coordinator
	registry    *kernel.ContributorRegistry
	original    identity.Command
	input       signupExecutionPreparation
	execution   *signupExecution
}

var _ kernel.RequestKeyPreparationContributor = (*signupPhase)(nil)
var _ kernel.FeatureAdmissionPreparationContributor = (*signupPhase)(nil)
var _ kernel.FeatureCommitContributor = (*signupPhase)(nil)
var _ kernel.RecoveryContributor = (*signupPhase)(nil)

func (*signupPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}
}
func (*signupPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{passwordSignupOperation()}
}
func (p *signupPhase) registration() kernel.FeatureRegistration {
	return kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: passwordSignupOperation()}
}
func (p *signupPhase) PrepareRequestKey(ctx context.Context, k kernel.RequestKeyPreparationBinding, intent identity.RequestIntent) ([]byte, error) {
	if p == nil || p.service == nil || p.request == nil {
		return nil, password.ErrPasswordWork
	}
	return p.service.repository.prepareSignupKeyInput(ctx, k, p.request(), intent, p.service.keyPreparation())
}

func (p *signupPhase) initialize(r password.SignupRequest, b identity.CommandBinding, selected kernel.PasswordRegistrationIntent, flow session.PreAuthTransaction, at time.Time) error {
	fields, err := kernel.PasswordRegistrationFields(selected)
	if err != nil {
		return err
	}
	command, err := identity.NewFeaturePasswordSignupInputCommand(identity.FeatureCommandSpec{Binding: b, Operation: passwordSignupOperation(), Fields: fields}, r.Password, r.Cookie)
	if err != nil {
		return err
	}
	c := p.service.config()
	var key session.DigestKey
	possessed := false
	for _, candidate := range c.FlowKeys {
		if p.service.repository.admitSignupFlow(r, flow, candidate, c.PolicyID, c.RequestKeys.Policy.PolicyVersion, at) == nil {
			key = candidate
			possessed = true
			break
		}
	}
	if !possessed {
		return identity.ForbiddenError{}
	}
	mac := hmac.New(sha256.New, c.IntentKey[:])
	_, _ = mac.Write([]byte("identity-password-signup-counter-v1\x00" + string(b.TenantID) + "\x00" + selected.Identifier.CanonicalValue))
	p.original = command
	p.input = signupExecutionPreparation{owner: p, original: command, selected: selected, flow: flow, flowKey: key, storage: c.Session, at: at, request: r, domain: p.service.domain, generation: p.service.generation(), risk: c.Risk, subject: risk.Subject{Network: r.Network, Device: r.Device, IdentifierDigest: hex.EncodeToString(mac.Sum(nil))}}
	p.input.authorizationNamespace = c.AuthorizationNamespace
	return nil
}

func (p *signupPhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.service == nil || p.original == (identity.Command{}) || plan.Feature == nil || *plan.Feature != p.registration() || plan.SubjectType != "user" || !plan.SignupAcceptance || plan.Lifecycle == nil || plan.Lifecycle.EventType != "user.created.v1" || plan.Lifecycle.BeforeVersion != 0 || plan.Lifecycle.AfterVersion != 0 || len(plan.Audits) != 1 || plan.OTP != nil || plan.Capability != nil {
		return password.ErrPasswordWork
	}
	if c == p.original {
		return nil
	}
	if p.execution != nil && c == p.execution.command {
		return nil
	}
	return password.ErrPasswordWork
}
func (p *signupPhase) ValidateFeaturePreparation(c identity.Command, plan kernel.CommandPlan) error {
	if c != p.original {
		return password.ErrPasswordWork
	}
	return p.ValidateFeatureCommand(c, plan)
}
func (p *signupPhase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.original {
		return password.ErrPasswordWork
	}
	b, f, _, err := w.FeatureScope(p)
	spec, ok := c.PasswordSignupInputFeature()
	if err != nil || !ok || b != spec.Binding || f != p.registration() {
		return password.ErrPasswordWork
	}
	if err := sessionpg.RequirePreAuth(ctx, w, p.input.storage, p.input.flow); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	return p.service.repository.admitSignupFlow(p.input.request, p.input.flow, p.input.flowKey, b.PolicyID, b.PolicyVersion, now)
}
func (p *signupPhase) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, password.ErrPasswordWork
}
func (p *signupPhase) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	if c != p.original {
		return identity.Command{}, kernel.CommandPlan{}, password.ErrPasswordWork
	}
	var err error
	p.execution, err = p.service.repository.restoreSignupExecution(ctx, p.input, generation, wire)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	plan, err := signupExecutionPlan(p.coordinator, p.registry, p, p.execution.command, p.input.at, p.execution.issuancePlan, p.execution.deliveryPlan)
	return p.execution.command, plan, err
}
func (p *signupPhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if p == nil || p.execution == nil {
		return identity.FeatureReceipt{}, password.ErrPasswordWork
	}
	return p.execution.apply(ctx, w, c)
}
func (p *signupPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p == nil || p.execution == nil {
		return password.ErrPasswordWork
	}
	return p.execution.checkCommit(ctx, w, c)
}

type signupAdmission struct {
	owner     *signupPhase
	admission risk.AuthenticationAdmission
}

func (a *signupAdmission) Check(ctx context.Context) error {
	if a == nil || a.owner == nil || ctx == nil {
		return password.ErrPasswordWork
	}
	// The coordinator may call Check under SQL locks. No injected clock or
	// provider is called here; primary-time checks also fence final execution.
	now := time.Now().UTC()
	if err := a.admission.CheckAt(ctx, now); err != nil {
		return err
	}
	p := a.owner
	b := p.input.selected.Creation.Binding
	return p.service.repository.admitSignupFlow(p.input.request, p.input.flow, p.input.flowKey, b.PolicyID, b.PolicyVersion, now)
}
func (a *signupAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	p := a.owner
	return p.service.repository.generateSignupOutput(ctx, p.original, p.input.selected, p.input.flow, p.input.at, a.admission, generation, p.input.generation)
}
func (p *signupPhase) PrepareFeatureAdmission(ctx context.Context, c identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if p == nil || c != p.original || p.service == nil {
		return nil, password.ErrPasswordWork
	}
	spec, _ := c.PasswordSignupInputFeature()
	b := spec.Binding
	scope := risk.Context{Tenant: string(b.TenantID), Operation: risk.Action(b.OperationID), Attempt: string(b.CommandID)}
	evaluation, err := p.service.config().Risk.Evaluation.Evaluate(ctx, risk.EvaluateRequest{Context: scope, Phase: risk.NonIssuing, Subject: p.input.subject, Attribution: &risk.DecisionAttribution{CommandID: b.CommandID, CorrelationID: b.CommandID, Actor: audit.ActorInput{Kind: audit.ActorAnonymous}, Subject: identity.SecurityAuthenticationAttempt, SubjectID: string(b.CommandID)}})
	if err != nil {
		return nil, readerFailure(ctx)
	}
	admission, err := p.service.custody.Prepare(ctx, evaluation, scope, p.input.subject)
	if err != nil {
		return nil, readerFailure(ctx)
	}
	a := &signupAdmission{owner: p, admission: admission}
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	return a, nil
}
func (p *signupPhase) RestoreFeatureAdmission(ctx context.Context, c identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if _, _, err := p.RestoreFeaturePreparation(ctx, c, generation, wire); err != nil {
		return nil, err
	}
	a := &signupAdmission{owner: p, admission: p.execution.admission}
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	return a, nil
}

// Read actual material evidence inside the kernel's recovery scope. A neutral
// binding proves no credential was owned here; absent binding plus absent
// proposed material proves this participant did not commit. Conflicting or
// deleted committed evidence stays unknown; the coordinator combines owners.
func (p *signupPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	if ctx == nil || p == nil || p.service == nil {
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	b, f, transition, err := w.FeatureScope(p)
	if err != nil || f != p.registration() || b.OperationID != passwordSignupOperation().OperationID || b.UserID != "" || b.AnonymousFlowID == "" || transition.BeforeVersion != 0 || transition.AfterVersion != 0 || transition.EventType != "user.created.v1" && transition.EventType != "identity.password.signup.accepted.v1" {
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	selected := p.input.selected
	if err != nil || len(id) != 16 || selected.Creation.Binding.UserID == "" {
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	// Work admits nullable int64 destinations, not nullable smallint pointers.
	// Preserve LEFT JOIN absence explicitly rather than substituting a zero kind.
	rows, err := w.Query(ctx, `SELECT r.command_id IS NOT NULL,r.user_id,r.credential_id,p.version::text,c.version::text,c.kind::bigint,c.owner,EXISTS(SELECT 1 FROM identity_password.credentials WHERE tenant_id=$1 AND user_id=$4)
FROM (SELECT true) anchor LEFT JOIN identity.registration_bindings r ON r.tenant_id=$1 AND r.purpose=$2 AND r.command_id=$3
LEFT JOIN identity_password.credentials p ON p.tenant_id=r.tenant_id AND p.user_id=r.user_id AND p.credential_id=r.credential_id
LEFT JOIN identity.credential_references c ON c.tenant_id=p.tenant_id AND c.user_id=p.user_id AND c.credential_id=p.credential_id`, string(b.TenantID), b.OperationID, id, string(selected.Creation.Binding.UserID))
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return kernel.RecoveryUnknown, password.ErrPasswordWork
		}
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	var bound, materialExists bool
	var user, credential, materialVersion, referenceVersion, owner *string
	var kind *int64
	if rows.Scan(&bound, &user, &credential, &materialVersion, &referenceVersion, &kind, &owner, &materialExists) != nil || rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	if !bound {
		if !materialExists {
			return kernel.RecoveryNotCommitted, nil
		}
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	if transition.EventType == "identity.password.signup.accepted.v1" {
		if user == nil && credential == nil && materialVersion == nil && !materialExists {
			return kernel.RecoveryCommitted, nil
		}
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	if user == nil || credential == nil || materialVersion == nil || referenceVersion == nil || kind == nil || owner == nil || *kind != int64(identity.CredentialPassword) || *owner != "identity/password" || *materialVersion != *referenceVersion {
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	// Original namespace is anonymous, never the selected user's authority.
	if string(selected.Creation.Binding.UserID) != *user || string(selected.Credential.ID) != *credential {
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	return kernel.RecoveryCommitted, nil
}
