package anonymouspostgres

import (
	"context"
	"reflect"

	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	capability "github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

type upgradeExecution struct {
	preparation *upgradePreparation
	coordinator *kernel.Coordinator
	registry    *kernel.ContributorRegistry
	command     identity.Command
	receipt     identity.CommandResult
	deliverable bool
}

func (*upgradeExecution) Descriptor() kernel.ContributorDescriptor { return creationOwner() }
func (*upgradeExecution) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{upgradeOperation()}
}
func (p *upgradeExecution) registration() kernel.FeatureRegistration {
	return kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: upgradeOperation()}
}

func (p *upgradeExecution) plan() (kernel.CommandPlan, error) {
	s := p.preparation
	lifecycle := kernel.LifecyclePlan{EventType: "anonymous.upgraded.v1", BeforeVersion: s.input.Subject.Version, AfterVersion: s.input.Subject.Version + 1}
	a, err := upgradeAudit(s.input.Final.Binding, upgradeOperation(), "anonymous", lifecycle, s.input.Started, s.service.config().Guest.RetentionPolicyVersion)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	registration := p.registration()
	counters := kernel.CommandCounterPlan(s.output.Counters)
	grant := kernel.CapabilityPlan(s.output.Grant)
	return p.coordinator.PrepareCommandPlan(s.input.Final.Binding, p.command, kernel.CommandPlan{Contributors: p.registry.Descriptors(), Feature: &registration, SubjectType: "anonymous", Lifecycle: &lifecycle, CommandCounters: &counters, Capability: &grant, Audits: []kernel.AuditPlan{a}})
}

func (p *upgradeExecution) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.preparation == nil || p.command == (identity.Command{}) || c != p.command || plan.Feature == nil || *plan.Feature != p.registration() || plan.SubjectType != "anonymous" || plan.Lifecycle == nil || *plan.Lifecycle != (kernel.LifecyclePlan{EventType: "anonymous.upgraded.v1", BeforeVersion: p.preparation.input.Subject.Version, AfterVersion: p.preparation.input.Subject.Version + 1}) || plan.CommandCounters == nil || *plan.CommandCounters != kernel.CommandCounterPlan(p.preparation.output.Counters) || plan.Capability == nil || len(plan.Audits) != 1 || plan.Audits[0].EventType != upgradeOperation().OperationID || !plan.Audits[0].Required || plan.CapabilityIssuance != nil || plan.OTP != nil || plan.Delivery != nil {
		return anonymous.ErrInvalidInput
	}
	if err := p.ValidateAnonymousUpgrade(c, *plan.Capability); err != nil {
		return err
	}
	return p.preparation.service.guest.risk.ValidateCommandCounters(c, *plan.CommandCounters)
}
func (p *upgradeExecution) ValidateAnonymousUpgrade(c identity.Command, grant kernel.CapabilityPlan) error {
	s := p.preparation
	if s == nil || c != p.command || grant != kernel.CapabilityPlan(s.output.Grant) || ValidateUpgradePlan(c, s.merge) != nil || sessionpg.ValidateAnonymousUpgradeSessionIntent(c, s.guest, s.result) != nil {
		return anonymous.ErrInvalidInput
	}
	return nil
}

func (p *upgradeExecution) execute(ctx context.Context, out anonymous.UpgradeResult) (anonymous.UpgradeResult, error) {
	s := p.preparation
	defer clear(s.output.Proof)
	defer clear(s.output.Checkpoint)
	var err error
	p.command, err = identity.NewFeatureSessionCommand(identity.FeatureCommandSpec{Binding: s.input.Final.Binding, Operation: upgradeOperation(), Fields: s.output.FinalFields}, s.request.TargetSession)
	if err != nil {
		return out, err
	}
	p.coordinator, p.registry, err = s.coordinatorFor(true)
	if err != nil {
		return out, err
	}
	plan, err := p.plan()
	if err != nil {
		return out, err
	}
	reservation, receipt, err := p.coordinator.ReserveCommand(ctx, s.input.Final.Binding, p.command, plan)
	if receipt.Outcome != identity.CommitOutcomeInvalid {
		out.Outcome = receipt.Outcome
	}
	out.RetryAfter = receipt.RetryAfter
	if err != nil || reservation == (kernel.Reservation{}) {
		out.Replayed = err == nil && receipt.Outcome == identity.CommitOutcomeCommitted
		return out, err
	}
	// The original checkpoint authenticated issuance custody. Before protected
	// execution additionally verify its exact signed consumption scope, outside
	// SQL; never derive a fresh envelope, replay key or expiry from current policy.
	proof, err := capability.ParseProof(string(s.output.Proof), capability.DefaultLimits())
	if err != nil {
		return out, identity.ForbiddenError{}
	}
	merge, err := upgradeMergeDigest(s.merge)
	if err != nil {
		return out, err
	}
	guest, _ := s.guest.Bindings()
	target, _ := s.target.Bindings()
	remember, _ := guest.Remember.Bindings()
	grant, err := s.service.capability.PrepareAnonymousUpgradeConsumption(ctx, s.input.Final.Binding, proof, kernel.CapabilityPlan(s.output.Grant).ProofFingerprint, kernel.CapabilityPlan(s.output.Grant).ReplayKeyVersion, capabilitypg.AnonymousUpgradeScope{SourceVersion: s.input.Subject.Version, SourceSessionID: guest.SessionID, TargetSessionID: target.SessionID, MergeDigest: merge, Remember: remember.Choice == session.PersistentSession, SourceExpiresAt: s.input.Subject.ExpiresAt})
	if err != nil {
		return out, err
	}
	if grant != kernel.CapabilityPlan(s.output.Grant) {
		return out, identity.ForbiddenError{}
	}
	w, err := p.coordinator.Begin(ctx, reservation)
	if err != nil {
		return out, err
	}
	defer p.coordinator.Abort(w, identity.UnavailableError{})
	provisional, err := p.coordinator.ApplyFeature(ctx, w, p.command)
	if err != nil {
		receipt, err = p.coordinator.Abort(w, err)
	} else {
		receipt, err = p.coordinator.Commit(w, provisional)
	}
	if receipt.Outcome != identity.CommitOutcomeInvalid {
		out.Outcome = receipt.Outcome
	}
	out.RetryAfter = receipt.RetryAfter
	if err != nil || receipt.Outcome != identity.CommitOutcomeCommitted {
		return out, err
	}
	if s.prospective == (session.PreparedIssuance{}) {
		out.Replayed = true
		return out, nil
	}
	p.receipt, p.deliverable = receipt, true
	bound, err := s.issuer.BindAnonymousUpgrade(s.prospective, p.command)
	if err != nil {
		return out, err
	}
	out.Session, err = s.issuer.Issue(ctx, bound)
	if err != nil {
		return out, err
	}
	out.CSRFToken, err = bound.CSRFToken()
	return out, err
}

func (p *upgradeExecution) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if c != p.command {
		return identity.FeatureReceipt{}, anonymous.ErrInvalidInput
	}
	s := p.preparation
	if err := s.targetFence(ctx, w, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := s.primary.Admit(ctx, w, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := s.guestPolicy(ctx, w); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := sessionpg.RequireSession(ctx, w, s.service.config().Guest.Sessions, s.guest); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := s.primary.Consume(ctx, w, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if _, err := s.service.guest.domain.ApplyUpgrade(ctx, w, p, c, s.input.Kernel.intent()); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := s.service.guest.repository.StageUpgrade(ctx, w, p, c, s.merge); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return s.service.effect.Apply(ctx, w, p, c, s.guest, s.result, s.input.Until)
}
func (p *upgradeExecution) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.command {
		return anonymous.ErrInvalidInput
	}
	s := p.preparation
	if err := s.targetFence(ctx, w, p, c); err != nil {
		return err
	}
	if err := s.primary.Admit(ctx, w, p, c); err != nil {
		return err
	}
	if err := s.primary.Check(ctx, w, p, c); err != nil {
		return err
	}
	if _, err := mfapg.RequireAnonymousUpgradeFactors(ctx, w, p, c, s.input.FactorVersion); err != nil {
		return err
	}
	if err := s.guestPolicy(ctx, w); err != nil {
		return err
	}
	if err := s.service.guest.domain.CheckUpgrade(ctx, w, p, c, s.input.Kernel.intent()); err != nil {
		return err
	}
	if err := s.service.guest.repository.RequireUpgrade(ctx, w, p, c, s.merge); err != nil {
		return err
	}
	return s.service.effect.Check(ctx, w, p, c, s.guest, s.result, s.input.Until)
}
func (p *upgradeExecution) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	s := p.preparation
	a, err := s.service.guest.repository.RecoverUpgrade(ctx, w, p, s.merge)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	b, err := s.service.effect.Recover(ctx, w, p, s.guest)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	c, err := s.service.primary.Recover(ctx, w, p)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	if a != b || b != c {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	return a, nil
}

func (p *upgradeExecution) ExecuteIssue(ctx context.Context, r session.IssueRequest) (session.IssueExecution, error) {
	if ctx == nil || ctx.Err() != nil || p == nil || !p.deliverable || p.receipt.Outcome != identity.CommitOutcomeCommitted || p.receipt.Validate() != nil {
		return session.IssueExecution{}, anonymous.ErrInvalidInput
	}
	c, record, before, until, ok := r.AnonymousUpgradeCommand()
	s := p.preparation
	if !ok || c != p.command || before != s.input.Subject.Version || !until.Equal(s.input.Until) {
		return session.IssueExecution{}, anonymous.ErrInvalidInput
	}
	a, err := sessionpg.OriginalSessionFields(record)
	if err != nil {
		return session.IssueExecution{}, err
	}
	b, err := sessionpg.OriginalSessionFields(s.result)
	if err != nil || !reflect.DeepEqual(a, b) {
		return session.IssueExecution{}, anonymous.ErrInvalidInput
	}
	p.deliverable = false
	return session.IssueExecution{Receipt: p.receipt, Session: s.result}, nil
}
func (*upgradeExecution) RecoverIssue(context.Context, session.IssueRequest) (session.IssueExecution, error) {
	return session.IssueExecution{}, anonymous.ErrInvalidInput
}
