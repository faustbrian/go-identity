package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"

	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

type signinDeniedPhase struct {
	caller   *signinCallbackPhase
	terminal []byte
}

func signinDeniedOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/oauth", OperationID: "identity.oauth.callback", SchemaID: "identity.oauth.callback.anonymous-denied-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}
func (*signinDeniedPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/oauth/postgres", ContractID: "identity.oauth.callback-denial", Version: 1}
}
func (*signinDeniedPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{signinDeniedOperation()}
}
func (p *signinDeniedPhase) registration() kernel.FeatureRegistration {
	return kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: signinDeniedOperation()}
}

func (p *signinDeniedPhase) command() (identity.Command, error) {
	if p == nil || p.caller == nil || !p.caller.request.Callback.Denied() {
		return identity.Command{}, identity.ForbiddenError{}
	}
	v := p.caller.flow.binding
	b := identity.CommandBinding(v.Input.Binding)
	op := signinDeniedOperation()
	b.CommandID, b.CorrelationID = v.CallbackCommandID, string(v.CallbackCommandID)
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	frame, err := json.Marshal(v)
	if err != nil {
		return identity.Command{}, err
	}
	digest := sha256.Sum256(frame)
	clear(frame)
	return identity.NewFeaturePreAuthCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: []identity.FeatureField{{Name: "oauth.flow-digest", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}}}}, p.caller.request.FlowCookie)
}
func (p *signinDeniedPhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	expected, err := p.command()
	want, _ := expected.Feature()
	got, ok := c.Feature()
	_, cookie := c.PreAuthCookie()
	if err != nil || !ok || !cookie || got.Binding != want.Binding || got.Operation != want.Operation || !sameRPFields(got.Fields, want.Fields) || plan.Feature == nil || *plan.Feature != p.registration() || plan.Capability == nil || *plan.Capability != p.caller.flow.statePlan || plan.Lifecycle == nil || *plan.Lifecycle != rpDenialLifecycle() || plan.SubjectType != "oauth_transaction" {
		return identity.ForbiddenError{}
	}
	return nil
}

func (s *SigninCompletionService) deniedCallback(ctx context.Context, r oauth.SigninCallbackRequest, flow signinCallbackFlow) (oauth.SigninCallbackResult, error) {
	p := &signinDeniedPhase{caller: &signinCallbackPhase{service: s, request: r, flow: flow}}
	command, err := p.command()
	if err != nil {
		return oauth.SigninCallbackResult{}, err
	}
	f, _ := command.Feature()
	b := f.Binding
	decision, err := s.start.config.Coordinator.AdmissionPolicy.Authorization.Decide(ctx, authorization.DecisionContext{PolicyRevision: authorization.Revision(b.PolicyVersion), CorrelationID: b.CorrelationID, Request: authorization.Request{Tenant: authorization.TenantID(b.TenantID), Subject: authorization.Subject{Kind: b.ActorKind, ID: authorization.SubjectID(b.ActorID)}, Action: authorization.Action(b.OperationID), Resource: authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(b.AnonymousFlowID)}, Environment: authorization.Environment{Time: flow.loadedAt}}})
	if err != nil {
		return oauth.SigninCallbackResult{}, err
	}
	if decision.Outcome != authorization.Allow || uint64(decision.Revision) != b.PolicyVersion {
		return oauth.SigninCallbackResult{}, identity.ForbiddenError{}
	}
	aad, err := signinBindingAAD(flow.binding, "binding")
	if err != nil {
		return oauth.SigninCallbackResult{}, err
	}
	plain, err := json.Marshal(signinStoredTransaction{Binding: flow.binding, State: rpStoredGrant(flow.statePlan), Denied: true})
	if err != nil {
		return oauth.SigninCallbackResult{}, err
	}
	defer clear(plain)
	p.terminal, err = s.start.seal(ctx, aad, plain)
	if err != nil {
		return oauth.SigninCallbackResult{}, err
	}
	defer clear(p.terminal)
	a, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return oauth.SigninCallbackResult{}, err
	}
	l, err := lifecyclepg.NewContributor()
	if err != nil {
		return oauth.SigninCallbackResult{}, err
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{s.start.directory, a, l, p, capabilitypg.NewParticipant()})
	if err != nil {
		return oauth.SigninCallbackResult{}, err
	}
	c, err := kernel.NewCoordinator(s.start.pool, registry, s.start.config.Coordinator)
	if err != nil {
		return oauth.SigninCallbackResult{}, err
	}
	auditing, err := rpTransactionAudit(ctx, b, signinDeniedOperation(), 1, 2, flow.loadedAt, s.start.config.AuditRetentionPolicyVersion)
	if err != nil {
		return oauth.SigninCallbackResult{}, err
	}
	feature, life, proof := p.registration(), rpDenialLifecycle(), flow.statePlan
	plan, err := c.PrepareCommandPlan(b, command, kernel.CommandPlan{Contributors: registry.Descriptors(), Feature: &feature, SubjectType: "oauth_transaction", Capability: &proof, Audits: []kernel.AuditPlan{auditing}, Lifecycle: &life})
	if err != nil {
		return oauth.SigninCallbackResult{}, err
	}
	reservation, receipt, err := c.ReserveCommand(ctx, b, command, plan)
	if err != nil {
		return oauth.SigninCallbackResult{}, err
	}
	if reservation != (kernel.Reservation{}) {
		w, e := c.Begin(ctx, reservation)
		if e != nil {
			return oauth.SigninCallbackResult{}, e
		}
		defer c.Abort(w, identity.UnavailableError{})
		applied, e := c.ApplyFeature(ctx, w, command)
		if e != nil {
			_, e = c.Abort(w, e)
			return oauth.SigninCallbackResult{}, e
		}
		receipt, err = c.Commit(w, applied)
		if err != nil {
			return oauth.SigninCallbackResult{}, err
		}
	}
	if receipt.Outcome == identity.CommitOutcomeConflict {
		return oauth.SigninCallbackResult{}, identity.ConflictError{CommandID: b.CommandID}
	}
	if receipt.Outcome != identity.CommitOutcomeCommitted {
		return oauth.SigninCallbackResult{}, identity.ForbiddenError{}
	}
	callback, err := oauth.NewValidatedCallbackURL(flow.binding.Input.ErrorCallback, s.start.config.CallbackAllowlist)
	if err != nil {
		return oauth.SigninCallbackResult{}, err
	}
	return oauth.NewDeniedSigninCallbackResult(receipt, callback)
}

func (p *signinDeniedPhase) check(ctx context.Context, w kernel.Work, c identity.Command, stage signinRPStage) error {
	b, f, life, err := w.FeatureScope(p)
	spec, ok := c.Feature()
	if err != nil || !ok || spec.Binding != b || f != p.registration() || life != rpDenialLifecycle() || p.caller.flow.erased {
		return identity.ForbiddenError{}
	}
	if stage == signinRPActive {
		if err := w.RequireFeatureCommand(ctx, p, c); err != nil {
			return err
		}
	}
	v := p.caller.flow.binding.Input
	if err := w.RequireActiveDirectoryAuthority(ctx, p, kernel.DirectoryAuthorityAdmission{Query: kernel.DirectoryAuthorityQuery{GlobalAuthorityID: p.caller.service.start.config.GlobalAuthorityID, TenantID: b.TenantID}, GlobalVersion: v.GlobalVersion, TenantVersion: v.TenantVersion}); err != nil {
		return err
	}
	if err := sessionpg.RequirePreAuth(ctx, w, p.caller.service.start.config.Session, p.caller.flow.original); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if err := p.caller.checkBrowser(now); err != nil {
		return err
	}
	return p.caller.requireTransaction(ctx, w, stage)
}
func (p *signinDeniedPhase) erase(ctx context.Context, w kernel.Work) error {
	b := p.caller.flow.binding.Input.Binding
	n, err := w.Exec(ctx, `UPDATE `+rpQuotedSchema(p.caller.service.start.config.Schema)+`.transactions SET version=2,secrets_erased_at=clock_timestamp(),pkce_ciphertext=NULL,state_proof_ciphertext=NULL,binding_ciphertext=$3 WHERE tenant_id=$1 AND transaction_id=$2 AND version=1 AND secrets_erased_at IS NULL`, string(b.TenantID), b.RecordID, p.terminal)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *signinDeniedPhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if err := p.check(ctx, w, c, signinRPActive); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.erase(ctx, w); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: signinDeniedOperation(), BeforeVersion: 1, AfterVersion: 2}, nil
}
func (p *signinDeniedPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	return p.check(ctx, w, c, signinRPConsumed)
}
func (p *signinDeniedPhase) CleanupFeatureTerminal(ctx context.Context, w kernel.Work) error {
	b, f, life, err := w.FeatureScope(p)
	expected, _ := p.command()
	spec, _ := expected.Feature()
	if err != nil || b != spec.Binding || f != p.registration() || life != rpDenialLifecycle() {
		return identity.ForbiddenError{}
	}
	state, err := w.OAuthCallbackDenialState(p)
	if err != nil || state != p.caller.flow.statePlan {
		return identity.ForbiddenError{}
	}
	return p.erase(ctx, w)
}
func (p *signinDeniedPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, f, life, err := w.FeatureScope(p)
	command, _ := p.command()
	spec, _ := command.Feature()
	if err != nil || b != spec.Binding || f != p.registration() || life != rpDenialLifecycle() {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	state, err := w.OAuthCallbackDenialState(p)
	if err != nil || state != p.caller.flow.statePlan {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	rows, err := w.Query(ctx, `SELECT version::text,pkce_ciphertext IS NOT NULL AND state_proof_ciphertext IS NOT NULL AND secrets_erased_at IS NULL FROM `+rpQuotedSchema(p.caller.service.start.config.Schema)+`.transactions WHERE tenant_id=$1 AND transaction_id=$2 AND preauth_id=$3 AND state_digest=$4`, string(b.TenantID), b.RecordID, b.AnonymousFlowID, p.caller.flow.binding.StateDigest[:])
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	var version string
	var intact bool
	if !rows.Next() || rows.Scan(&version, &intact) != nil || rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	if version == "1" && intact {
		return kernel.RecoveryNotCommitted, nil
	}
	return kernel.RecoveryUnknown, nil
}

var _ kernel.FeatureCommitContributor = (*signinDeniedPhase)(nil)
var _ kernel.FeatureTerminalCleanupContributor = (*signinDeniedPhase)(nil)
