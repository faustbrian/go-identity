package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

type signinCallbackPhase struct {
	service           *SigninCompletionService
	request           oauth.SigninCallbackRequest
	flow              signinCallbackFlow
	original, command identity.Command
	coordinator       *kernel.Coordinator
	registry          *kernel.ContributorRegistry
	issuer            *session.SessionIssuer
	prepared          session.PreparedIssuance
	execution         *signinExecution
	authenticatedAt   time.Time
	receipt           identity.CommandResult
	deliverable       bool
}

type signinExecution struct {
	record          session.Session
	account         kernel.ProviderAccountAdmission
	admission       risk.AuthenticationAdmission
	generation      uint64
	digest          [32]byte
	readStarted     time.Time
	terminalBinding []byte
}

func (*signinCallbackPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/oauth/postgres", ContractID: "identity.oauth.signin", Version: 1}
}
func (*signinCallbackPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{signinCallbackOperation()}
}
func (p *signinCallbackPhase) registration() kernel.FeatureRegistration {
	return kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: signinCallbackOperation()}
}

func (p *signinCallbackPhase) plan() (kernel.CommandPlan, error) {
	if p == nil || p.registry == nil || p.original == (identity.Command{}) {
		return kernel.CommandPlan{}, identity.InvalidInputError{Field: "oauth_signin_plan"}
	}
	f, _ := p.original.Feature()
	b := f.Binding
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	seed, err := builder.Build(audit.RecordInput{OccurredAt: p.flow.loadedAt, Action: "identity.oauth.handle_callback", Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "authentication_attempt", ID: b.AnonymousFlowID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "authentication_attempt", "aggregate.id": b.AnonymousFlowID, "aggregate.before_version": "0", "aggregate.after_version": "0", "retention.class": "protected"}})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, signinCallbackOperation(), "authentication_attempt", seed)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	feature, proof := p.registration(), p.flow.statePlan
	return kernel.CommandPlan{Contributors: p.registry.Descriptors(), Feature: &feature, SubjectType: "authentication_attempt", Capability: &proof, Lifecycle: &kernel.LifecyclePlan{EventType: "session.created.v1"}, Audits: []kernel.AuditPlan{{EventType: "identity.oauth.handle_callback", SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: p.service.start.config.AuditRetentionPolicyVersion, RetentionClass: "protected", BindingDigest: digest}}}, nil
}

func (p *signinCallbackPhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.service == nil || c == (identity.Command{}) || (c != p.original && c != p.command) {
		return identity.InvalidInputError{Field: "oauth_signin_command"}
	}
	if plan.Feature == nil || *plan.Feature != p.registration() || plan.SubjectType != "authentication_attempt" || plan.Capability == nil || plan.CommandCounters != nil || plan.RiskEvidence != nil || plan.OTP != nil || plan.Delivery != nil || plan.CapabilityIssuance != nil || plan.Lifecycle == nil || *plan.Lifecycle != (kernel.LifecyclePlan{EventType: "session.created.v1"}) || len(plan.Audits) != 1 {
		return identity.InvalidInputError{Field: "oauth_signin_plan"}
	}
	return p.ValidateOAuthSigninConsumption(c, *plan.Capability)
}
func (p *signinCallbackPhase) ValidateFeaturePreparation(c identity.Command, plan kernel.CommandPlan) error {
	if c != p.original {
		return identity.ForbiddenError{}
	}
	return p.ValidateFeatureCommand(c, plan)
}
func (p *signinCallbackPhase) ValidateOAuthSigninConsumption(c identity.Command, proof kernel.CapabilityPlan) error {
	if p == nil || p.service == nil || proof != p.flow.statePlan || (c != p.original && c != p.command) {
		return identity.ForbiddenError{}
	}
	if c == p.original {
		return nil
	}
	if p.execution == nil {
		return identity.ForbiddenError{}
	}
	record, err := sessionpg.OAuthSigninSession(c)
	if err != nil {
		return err
	}
	fields, err := sessionpg.OAuthSigninSessionFields(record)
	expected, e := sessionpg.OAuthSigninSessionFields(p.execution.record)
	account, e2 := kernel.OAuthSigninAccount(c)
	a, accountErr := kernel.OAuthSigninAccountFields(account)
	want, wantErr := kernel.OAuthSigninAccountFields(p.execution.account)
	if err != nil || e != nil || e2 != nil || accountErr != nil || wantErr != nil || !sameRPFields(fields, expected) || !sameRPFields(a, want) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *signinCallbackPhase) checkBrowser(now time.Time) error {
	v := p.flow.binding
	readStarted := p.flow.loadedAt
	if p.execution != nil {
		readStarted = p.execution.readStarted
	}
	if now.Before(readStarted) || !now.Before(readStarted.Add(20*time.Second)) || now.Before(v.IssuedAt) || !now.Before(v.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	spec, err := p.flow.original.Bindings()
	if err != nil {
		return err
	}
	b := v.Input.Binding
	return checkSigninOriginalBrowser(signinBrowserScope{Tenant: p.request.TenantID, FlowID: spec.Binding.ID, Cookie: p.request.FlowCookie, Remember: spec.Binding.Intent.Remember, Origin: p.request.Origin, Callback: v.Input.Callback}, p.flow.original, p.service.start.config.FlowKeys, b.PolicyID, b.PolicyVersion, now)
}

type signinRPStage uint8

const (
	signinRPActive signinRPStage = iota + 1
	signinRPConsumed
)

func (p *signinCallbackPhase) requireTransaction(ctx context.Context, w kernel.Work, stage signinRPStage) error {
	v := p.flow.binding
	b, provider := v.Input.Binding, v.Provider
	origin, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil {
		return identity.ForbiddenError{}
	}
	rows, err := w.Query(ctx, `SELECT transaction_id FROM `+rpQuotedSchema(p.service.start.config.Schema)+`.transactions WHERE tenant_id=$1 AND transaction_id=$2 AND origin_command_id=$3 AND operation='identity.oauth.signin-start' AND preauth_id=$4 AND user_id IS NULL AND session_id IS NULL AND provider_id=$5 AND configuration_version=$6::numeric AND issuer=$7 AND client_id=$8 AND redirect_uri=$9 AND response_mode='query' AND state_key_version=$10 AND state_digest=$11 AND pkce_key_version=$12 AND pkce_commitment=$13 AND issued_at=$14 AND expires_at=$15 AND version=$16 AND CASE WHEN $16=1 THEN secrets_erased_at IS NULL AND pkce_ciphertext IS NOT NULL AND state_proof_ciphertext IS NOT NULL ELSE secrets_erased_at IS NOT NULL AND pkce_ciphertext IS NULL AND state_proof_ciphertext IS NULL END FOR UPDATE`, string(b.TenantID), b.RecordID, origin, b.AnonymousFlowID, provider.ID, provider.Version, provider.Issuer, provider.ClientID, provider.RedirectURI, v.StateKeyVersion, v.StateDigest[:], v.PKCEKeyVersion, v.PKCECommitment[:], v.IssuedAt, v.ExpiresAt, uint64(stage))
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return identity.UnavailableError{}
		}
		return identity.ForbiddenError{}
	}
	var transaction string
	if rows.Scan(&transaction) != nil || transaction != b.RecordID || rows.Next() || rows.Err() != nil {
		return identity.UnavailableError{}
	}
	return nil
}

func (p *signinCallbackPhase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.original || p.flow.erased {
		return identity.ForbiddenError{}
	}
	b, feature, _, err := w.FeatureScope(p)
	original, _ := p.original.Feature()
	if err != nil || b != original.Binding || feature != p.registration() {
		return identity.ForbiddenError{}
	}
	v := p.flow.binding.Input
	if err := w.RequireActiveDirectoryAuthority(ctx, p, kernel.DirectoryAuthorityAdmission{Query: kernel.DirectoryAuthorityQuery{GlobalAuthorityID: p.service.start.config.GlobalAuthorityID, TenantID: b.TenantID}, GlobalVersion: v.GlobalVersion, TenantVersion: v.TenantVersion}); err != nil {
		return err
	}
	if err := sessionpg.RequirePreAuth(ctx, w, p.service.start.config.Session, p.flow.original); err != nil {
		return err
	}
	if err := p.requireTransaction(ctx, w, signinRPActive); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if err := p.checkBrowser(now); err != nil {
		return err
	}
	p.authenticatedAt = now
	return nil
}

type signinCallbackAdmission struct {
	owner     *signinCallbackPhase
	admission risk.AuthenticationAdmission
}

func (a *signinCallbackAdmission) Check(ctx context.Context) error {
	if a == nil || a.owner == nil || ctx == nil {
		return identity.ForbiddenError{}
	}
	if err := a.admission.CheckAt(ctx, time.Now().UTC()); err != nil {
		return err
	}
	return a.owner.checkBrowser(time.Now().UTC())
}
func (a *signinCallbackAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	return a.owner.generate(ctx, generation, a.admission)
}
func (p *signinCallbackPhase) riskScope() (risk.Context, risk.Subject) {
	f, _ := p.original.Feature()
	return risk.Context{Tenant: string(f.Binding.TenantID), Operation: risk.Action(f.Binding.OperationID), Attempt: string(f.Binding.CommandID)}, risk.Subject{Network: p.request.Network, Device: p.request.Device}
}
func (p *signinCallbackPhase) PrepareFeatureAdmission(ctx context.Context, c identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if c != p.original || p.authenticatedAt.IsZero() {
		return nil, identity.ForbiddenError{}
	}
	scope, subject := p.riskScope()
	b := p.flow.binding
	result, err := p.service.start.config.Risk.Evaluation.Evaluate(ctx, risk.EvaluateRequest{Context: scope, Phase: risk.NonIssuing, Subject: subject, Attribution: &risk.DecisionAttribution{CommandID: b.CallbackCommandID, CorrelationID: b.CallbackCommandID, Actor: audit.ActorInput{Kind: audit.ActorAnonymous}, Subject: identity.SecurityAuthenticationAttempt, SubjectID: string(b.CallbackCommandID)}})
	if err != nil {
		return nil, err
	}
	admission, err := p.service.start.custody.Prepare(ctx, result, scope, subject)
	if err != nil {
		return nil, err
	}
	a := &signinCallbackAdmission{owner: p, admission: admission}
	return a, a.Check(ctx)
}
func (*signinCallbackPhase) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, identity.ForbiddenError{}
}
func (p *signinCallbackPhase) RestoreFeatureAdmission(ctx context.Context, c identity.Command, g uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if _, _, err := p.RestoreFeaturePreparation(ctx, c, g, wire); err != nil {
		return nil, err
	}
	a := &signinCallbackAdmission{owner: p, admission: p.execution.admission}
	return a, a.Check(ctx)
}
func (p *signinCallbackPhase) RestoreFeaturePreparation(ctx context.Context, c identity.Command, g uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	if c != p.original {
		return identity.Command{}, kernel.CommandPlan{}, identity.ForbiddenError{}
	}
	execution, command, err := p.restore(ctx, g, wire)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	p.execution, p.command = execution, command
	plan, err := p.plan()
	return command, plan, err
}

func (p *signinCallbackPhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if p.execution == nil || c != p.command {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	if err := w.RequireFeatureCommand(ctx, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	wire, g, err := w.FeaturePreparationOutput(p)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	digest := sha256.Sum256(wire)
	clear(wire)
	if digest != p.execution.digest || g != p.execution.generation {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	if err := p.requireTransaction(ctx, w, signinRPActive); err != nil {
		return identity.FeatureReceipt{}, err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.checkBrowser(now); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.execution.admission.CheckAt(ctx, now); err != nil {
		return identity.FeatureReceipt{}, err
	}
	receipt, err := p.service.effect.Apply(ctx, w, p, c, p.flow.original)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	b := p.flow.binding.Input.Binding
	n, err := w.Exec(ctx, `UPDATE `+rpQuotedSchema(p.service.start.config.Schema)+`.transactions SET version=2,secrets_erased_at=clock_timestamp(),pkce_ciphertext=NULL,state_proof_ciphertext=NULL,binding_ciphertext=$3 WHERE tenant_id=$1 AND transaction_id=$2 AND version=1 AND secrets_erased_at IS NULL`, string(b.TenantID), b.RecordID, p.execution.terminalBinding)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	return receipt, nil
}
func (p *signinCallbackPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p.execution == nil || c != p.command {
		return identity.ForbiddenError{}
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if err := p.checkBrowser(now); err != nil {
		return err
	}
	if err := p.execution.admission.CheckAt(ctx, now); err != nil {
		return err
	}
	if err := p.requireTransaction(ctx, w, signinRPConsumed); err != nil {
		return err
	}
	return p.service.effect.CheckCurrent(ctx, w, p, c)
}
func (p *signinCallbackPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return p.service.effect.Recover(ctx, w, p)
}
func (p *signinCallbackPhase) ExecuteIssue(ctx context.Context, r session.IssueRequest) (session.IssueExecution, error) {
	if ctx == nil || ctx.Err() != nil || p == nil || !p.deliverable || p.execution == nil {
		return session.IssueExecution{}, identity.ForbiddenError{}
	}
	c, record, ok := r.OAuthCommand()
	if !ok || c != p.command || p.receipt.Outcome != identity.CommitOutcomeCommitted || p.receipt.Validate() != nil {
		return session.IssueExecution{}, identity.ForbiddenError{}
	}
	fields, err := sessionpg.OAuthSigninSessionFields(record)
	want, e := sessionpg.OAuthSigninSessionFields(p.execution.record)
	if err != nil || e != nil || !sameRPFields(fields, want) {
		return session.IssueExecution{}, identity.ForbiddenError{}
	}
	p.deliverable = false
	return session.IssueExecution{Receipt: p.receipt, Session: p.execution.record}, nil
}
func (*signinCallbackPhase) RecoverIssue(context.Context, session.IssueRequest) (session.IssueExecution, error) {
	return session.IssueExecution{}, identity.ForbiddenError{}
}

var _ kernel.OAuthSigninContributor = (*signinCallbackPhase)(nil)
var _ kernel.FeatureAdmissionPreparationContributor = (*signinCallbackPhase)(nil)
var _ session.IssueExecutor = (*signinCallbackPhase)(nil)
