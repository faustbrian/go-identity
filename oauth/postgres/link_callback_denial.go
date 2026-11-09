package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
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

type rpDenialPhase struct {
	service *LinkService
	flow    rpCallbackFlow
	request oauth.CallbackRequest
}

func rpDenialOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/oauth", OperationID: "identity.oauth.callback", SchemaID: "identity.oauth.callback.denied-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func (*rpDenialPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/oauth/postgres", ContractID: "identity.oauth.callback-denial", Version: 1}
}

func (*rpDenialPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{rpDenialOperation()}
}

func (p *rpDenialPhase) registration() kernel.FeatureRegistration {
	return kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: rpDenialOperation()}
}

func rpDenialLifecycle() kernel.LifecyclePlan {
	return kernel.LifecyclePlan{EventType: "oauth.rp_transaction.denied.v1", BeforeVersion: 1, AfterVersion: 2}
}

func (p *rpDenialPhase) command() (identity.Command, error) {
	if p == nil || p.service == nil || !p.request.Callback.Denied() {
		return identity.Command{}, identity.InvalidInputError{Field: "oauth_denial"}
	}
	if _, err := callbackSpecification(p.flow); err != nil {
		return identity.Command{}, err
	}
	b := p.flow.binding.Input.binding()
	op := rpDenialOperation()
	b.CommandID, b.CorrelationID = p.flow.binding.CallbackCommandID, string(p.flow.binding.CallbackCommandID)
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	frame, err := json.Marshal(p.flow.binding)
	if err != nil {
		return identity.Command{}, identity.ForbiddenError{}
	}
	digest := sha256.Sum256(frame)
	clear(frame)
	// Only a commitment to the authenticated original flow enters root intent.
	// Error text is discarded by the parser and no authorization code exists.
	fields := []identity.FeatureField{{Name: "oauth.flow-digest", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}}}
	return identity.NewFeatureSessionCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields}, p.request.Session)
}

func (p *rpDenialPhase) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	expected, err := p.command()
	want, valid := expected.Feature()
	got, ok := command.Feature()
	bearer, hasBearer := command.SessionToken()
	if err != nil || !valid || !ok || !hasBearer || got.Binding != want.Binding || got.Operation != want.Operation || !sameRPFields(got.Fields, want.Fields) || !p.service.ownsSessionBearer(got.Binding.TenantID, bearer, p.flow.original) || plan.Feature == nil || *plan.Feature != p.registration() || plan.Capability == nil || *plan.Capability != p.flow.statePlan || plan.SubjectType != "oauth_transaction" || plan.Lifecycle == nil || *plan.Lifecycle != rpDenialLifecycle() {
		return identity.ForbiddenError{}
	}
	return nil
}

func (s *LinkService) deniedCallback(ctx context.Context, r oauth.CallbackRequest, flow rpCallbackFlow) (oauth.CallbackResult, error) {
	p := &rpDenialPhase{service: s, flow: flow, request: r}
	command, err := p.command()
	if err != nil {
		return oauth.CallbackResult{}, err
	}
	spec, _ := command.Feature()
	b := spec.Binding
	caller := authorization.DecisionContext{PolicyRevision: authorization.Revision(b.PolicyVersion), CorrelationID: b.CorrelationID, Request: authorization.Request{Tenant: authorization.TenantID(b.TenantID), Subject: authorization.Subject{Kind: b.ActorKind, ID: authorization.SubjectID(b.ActorID)}, Action: authorization.Action(b.OperationID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}, Environment: authorization.Environment{Time: flow.loadedAt}}}
	decision, err := s.config().Coordinator.AdmissionPolicy.Authorization.Decide(ctx, caller)
	if err != nil {
		return oauth.CallbackResult{}, identity.UnavailableError{}
	}
	if decision.Outcome != authorization.Allow || uint64(decision.Revision) != b.PolicyVersion {
		return oauth.CallbackResult{}, identity.ForbiddenError{}
	}
	auditing, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return oauth.CallbackResult{}, err
	}
	lifecycle, err := lifecyclepg.NewContributor()
	if err != nil {
		return oauth.CallbackResult{}, err
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{s.directory, auditing, lifecycle, p, capabilitypg.NewParticipant()})
	if err != nil {
		return oauth.CallbackResult{}, err
	}
	c, err := kernel.NewCoordinator(s.pool, registry, s.config().Coordinator)
	if err != nil {
		return oauth.CallbackResult{}, err
	}
	auditPlan, err := rpTransactionAudit(ctx, b, rpDenialOperation(), 1, 2, flow.loadedAt, s.config().AuditRetentionPolicyVersion)
	if err != nil {
		return oauth.CallbackResult{}, err
	}
	feature, transition, proof := p.registration(), rpDenialLifecycle(), flow.statePlan
	plan, err := c.PrepareCommandPlan(b, command, kernel.CommandPlan{Contributors: registry.Descriptors(), Feature: &feature, SubjectType: "oauth_transaction", Capability: &proof, Audits: []kernel.AuditPlan{auditPlan}, Lifecycle: &transition})
	if err != nil {
		return oauth.CallbackResult{}, err
	}
	reservation, result, err := c.ReserveCommand(ctx, b, command, plan)
	if err != nil {
		return oauth.CallbackResult{}, err
	}
	if reservation != (kernel.Reservation{}) {
		work, err := c.Begin(ctx, reservation)
		if err != nil {
			return oauth.CallbackResult{}, err
		}
		defer c.Abort(work, identity.UnavailableError{})
		applied, err := c.ApplyFeature(ctx, work, command)
		if err != nil {
			_, err = c.Abort(work, err)
			return oauth.CallbackResult{}, err
		}
		result, err = c.Commit(work, applied)
		if err != nil {
			return oauth.CallbackResult{}, err
		}
	}
	switch result.Outcome {
	case identity.CommitOutcomeCommitted:
	case identity.CommitOutcomeNotCommitted:
		return oauth.CallbackResult{}, identity.ForbiddenError{}
	case identity.CommitOutcomeConflict:
		return oauth.CallbackResult{}, identity.ConflictError{}
	default:
		return oauth.CallbackResult{}, identity.UnknownCommitError{CommandID: b.CommandID}
	}
	callback, err := oauth.NewValidatedCallbackURL(flow.binding.Input.ErrorCallback, s.config().CallbackAllowlist)
	if err != nil {
		return oauth.CallbackResult{}, err
	}
	return oauth.NewDeniedCallbackResult(result, callback)
}

func (p *rpDenialPhase) check(ctx context.Context, w kernel.Work, command identity.Command, applied bool) error {
	b, feature, lifecycle, err := w.FeatureScope(p)
	spec, ok := command.Feature()
	if err != nil || !ok || spec.Binding != b || feature != p.registration() || lifecycle != rpDenialLifecycle() || p.flow.erased {
		return identity.ForbiddenError{}
	}
	if !applied {
		if err := w.RequireFeatureCommand(ctx, p, command); err != nil {
			return err
		}
	}
	directory, credential, policy, err := sessionpg.OriginalSessionAdmission(p.service.config().Session.Profile, p.flow.original, b)
	if err != nil {
		return err
	}
	if err := w.RequireActiveDirectoryAuthority(ctx, p, directory); err != nil {
		return err
	}
	if _, err := w.RequireActiveCredential(ctx, p, credential); err != nil {
		return err
	}
	if err := w.RequireActiveUserAuthorization(ctx, p, policy); err != nil {
		return err
	}
	if err := sessionpg.RequireSession(ctx, w, p.service.config().Session.Repository, p.flow.original); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	// Cancellation grants no identity or credential. Current directory/session
	// authority is still required, but enrolling another factor need not prevent
	// safely disposing of a previously issued RP transaction.
	if err := (&rpLinkPhase{flow: p.flow}).requireFresh(now); err != nil {
		return err
	}
	if !applied {
		return p.service.requireCallbackTransaction(ctx, w, p.flow, now)
	}
	rows, err := w.Query(ctx, `SELECT transaction_id FROM `+rpQuotedSchema(p.service.config().Schema)+`.transactions WHERE tenant_id=$1 AND transaction_id=$2 AND user_id=$3 AND state_key_version=$4 AND state_digest=$5 AND version=2 AND secrets_erased_at IS NOT NULL AND pkce_ciphertext IS NULL AND state_proof_ciphertext IS NULL`, string(b.TenantID), b.RecordID, string(b.UserID), p.flow.binding.StateKeyVersion, p.flow.binding.StateDigest[:])
	if err != nil {
		return err
	}
	defer rows.Close()
	var transaction string
	if !rows.Next() || rows.Scan(&transaction) != nil || transaction != b.RecordID || rows.Next() || rows.Err() != nil {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *rpDenialPhase) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	if err := p.check(ctx, w, command, false); err != nil {
		return identity.FeatureReceipt{}, err
	}
	b := p.flow.binding.Input.binding()
	n, err := w.Exec(ctx, `UPDATE `+rpQuotedSchema(p.service.config().Schema)+`.transactions SET pkce_ciphertext=NULL,state_proof_ciphertext=NULL,secrets_erased_at=clock_timestamp(),version=2 WHERE tenant_id=$1 AND transaction_id=$2 AND user_id=$3 AND state_key_version=$4 AND state_digest=$5 AND version=1 AND secrets_erased_at IS NULL`, string(b.TenantID), b.RecordID, string(b.UserID), p.flow.binding.StateKeyVersion, p.flow.binding.StateDigest[:])
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	return identity.FeatureReceipt{Operation: rpDenialOperation(), BeforeVersion: 1, AfterVersion: 2}, nil
}

func (p *rpDenialPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, command identity.Command) error {
	return p.check(ctx, w, command, true)
}

func (p *rpDenialPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, feature, _, err := w.FeatureScope(p)
	if err != nil || feature != p.registration() || b.CommandID != p.flow.binding.CallbackCommandID || b.RecordID != p.flow.binding.Input.binding().RecordID {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	state, err := w.OAuthCallbackDenialState(p)
	if err != nil || state != p.flow.statePlan {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	origin, err := base64.RawURLEncoding.Strict().DecodeString(string(p.flow.binding.Input.binding().CommandID))
	if err != nil {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	rows, err := w.Query(ctx, `SELECT version::text,secrets_erased_at IS NULL AND pkce_ciphertext IS NOT NULL AND state_proof_ciphertext IS NOT NULL FROM `+rpQuotedSchema(p.service.config().Schema)+`.transactions WHERE tenant_id=$1 AND transaction_id=$2 AND origin_command_id=$3 AND user_id=$4 AND state_key_version=$5 AND state_digest=$6`, string(b.TenantID), b.RecordID, origin, string(b.UserID), p.flow.binding.StateKeyVersion, p.flow.binding.StateDigest[:])
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
	// Erasure alone cannot reconstruct a historical committed callback receipt.
	return kernel.RecoveryUnknown, nil
}
