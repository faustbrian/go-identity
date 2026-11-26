package postgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

const (
	oneTapCallbackSubject = "authentication_attempt"
	oneTapCallbackAudit   = "identity.oauth.verify_one_tap"
)

type oneTapCallbackPhase struct {
	service                      *OneTapCompletionService
	registry                     *kernel.ContributorRegistry
	request                      OneTapCallbackRequest
	original, command            identity.Command
	binding                      identity.CommandBinding
	browser                      session.PreAuthTransaction
	browserSpec                  session.ProviderPreAuthTransactionSpec
	cookie                       session.TokenDigest
	grant                        oneTapVerifiedCallbackGrant
	readStarted, authenticatedAt time.Time
	directory                    kernel.DirectoryAuthorityAdmission
	issuer                       *session.SessionIssuer
	prepared                     session.PreparedIssuance
	execution                    *oneTapCallbackExecution
	generated                    uint64
	applied, deliverable         bool
	receipt                      identity.CommandResult
}

type oneTapCallbackExecution struct {
	record      session.Session
	admission   risk.AuthenticationAdmission
	readStarted time.Time
	generation  uint64
	digest      [32]byte
}

func (*oneTapCallbackPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/oauth/postgres", ContractID: "identity.oauth.onetap-completion", Version: 1}
}

func (*oneTapCallbackPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{kernel.OneTapCallbackOperation()}
}

func (p *oneTapCallbackPhase) registration() kernel.FeatureRegistration {
	return kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: kernel.OneTapCallbackOperation()}
}

func oneTapCallbackLifecycle() kernel.LifecyclePlan {
	return kernel.LifecyclePlan{EventType: "session.created.v1", BeforeVersion: 1, AfterVersion: 2}
}

func (p *oneTapCallbackPhase) plan() (kernel.CommandPlan, error) {
	if p == nil || p.registry == nil || p.original == (identity.Command{}) {
		return kernel.CommandPlan{}, identity.ForbiddenError{}
	}
	b := p.binding
	builder, err := audit.NewBuilder(audit.BuilderConfig{IDGenerator: func() (string, error) { return "onetap-callback-declaration", nil }})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	seed, err := builder.Build(audit.RecordInput{OccurredAt: p.grant.IssuedAt, Action: oneTapCallbackAudit, Outcome: audit.OutcomeSucceeded,
		Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: oneTapCallbackSubject, ID: b.AnonymousFlowID},
		Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)},
		Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": oneTapCallbackSubject,
			"aggregate.id": b.AnonymousFlowID, "aggregate.before_version": "1", "aggregate.after_version": "2", "retention.class": "protected"}})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, kernel.OneTapCallbackOperation(), oneTapCallbackSubject, seed)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	feature, proof, lifecycle := p.registration(), p.grant.Grant, oneTapCallbackLifecycle()
	return kernel.CommandPlan{Contributors: p.registry.Descriptors(), Feature: &feature, SubjectType: oneTapCallbackSubject,
		Capability: &proof, Lifecycle: &lifecycle, Audits: []kernel.AuditPlan{{EventType: oneTapCallbackAudit, SchemaVersion: 1, Required: true,
			RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: p.service.start.config().AuditRetentionPolicyVersion,
			RetentionClass: "protected", BindingDigest: digest}}}, nil
}

func (p *oneTapCallbackPhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil || plan.Feature == nil || *plan.Feature != p.registration() || plan.SubjectType != oneTapCallbackSubject ||
		plan.Capability == nil || plan.Lifecycle == nil || *plan.Lifecycle != oneTapCallbackLifecycle() || len(plan.Audits) != 1 ||
		plan.CommandCounters != nil || plan.RiskEvidence != nil || plan.OTP != nil || plan.Delivery != nil || plan.CapabilityIssuance != nil {
		return identity.ForbiddenError{}
	}
	return p.ValidateOneTapCallbackConsumption(c, *plan.Capability)
}

func (p *oneTapCallbackPhase) ValidateFeaturePreparation(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil || c != p.original {
		return identity.ForbiddenError{}
	}
	return p.ValidateFeatureCommand(c, plan)
}

func (p *oneTapCallbackPhase) ValidateOneTapCallbackConsumption(c identity.Command, proof kernel.CapabilityPlan) error {
	if p == nil || p.service == nil || c == (identity.Command{}) || proof != p.grant.Grant || (c != p.original && (p.execution == nil || c != p.command)) {
		return identity.ForbiddenError{}
	}
	f, ok := c.Feature()
	if !ok || f.Binding != p.binding || f.Operation != kernel.OneTapCallbackOperation() {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *oneTapCallbackPhase) checkBrowser(now, observed time.Time) error {
	if !rpUTCTime(now) || !rpUTCTime(observed) || now.Before(observed) || !now.Before(observed.Add(20*time.Second)) ||
		!now.Before(p.grant.Grant.ExpiresAt) || p.browser.CheckProvider(now, p.browserSpec.Transaction.Binding, p.service.start.selected, p.cookie) != nil {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *oneTapCallbackPhase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.original {
		return identity.ForbiddenError{}
	}
	b, feature, _, err := w.FeatureScope(p)
	if err != nil || b != p.binding || feature != p.registration() {
		return identity.ForbiddenError{}
	}
	if err := w.RequireActiveDirectoryAuthority(ctx, p, p.directory); err != nil {
		return err
	}
	start := p.service.start
	if err := sessionpg.RequireProviderPreAuth(ctx, w, start.config().Session, p.browser, start.selected); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if err := p.checkBrowser(now, p.readStarted); err != nil {
		return err
	}
	p.authenticatedAt = now
	return nil
}

type oneTapCallbackAdmission struct {
	owner    *oneTapCallbackPhase
	risk     risk.AuthenticationAdmission
	observed time.Time
}

func (a *oneTapCallbackAdmission) Check(ctx context.Context) error {
	if a == nil || a.owner == nil || ctx == nil {
		return identity.ForbiddenError{}
	}
	now := a.owner.service.start.config().Issuance.Clock.Now().UTC()
	if err := a.owner.checkBrowser(now, a.observed); err != nil {
		return err
	}
	return a.risk.CheckAt(ctx, now)
}

func (a *oneTapCallbackAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	return a.owner.generate(ctx, generation, a.risk)
}

func (p *oneTapCallbackPhase) riskInputs() (risk.Context, risk.Subject) {
	network := ""
	if p.request.Network.IsValid() {
		network = p.request.Network.Unmap().String()
	}
	// Count across issued flows for this provider selection. Neither the flow,
	// the token nor a provider-subject claim is a pre-credential rate key.
	key := p.service.start.config().IntentKey
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("identity-onetap-callback-risk-v1\x00"))
	_, _ = mac.Write(p.service.profile[:])
	return risk.Context{Tenant: string(p.binding.TenantID), Operation: risk.Action(p.binding.OperationID), Attempt: string(p.binding.CommandID)},
		risk.Subject{Network: network, Device: p.request.Device, IdentifierDigest: hex.EncodeToString(mac.Sum(nil))}
}

func (p *oneTapCallbackPhase) PrepareFeatureAdmission(ctx context.Context, c identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if c != p.original || p.authenticatedAt.IsZero() {
		return nil, identity.ForbiddenError{}
	}
	scope, subject := p.riskInputs()
	start := p.service.start
	result, err := start.config().Risk.Evaluation.Evaluate(ctx, risk.EvaluateRequest{Context: scope, Phase: risk.NonIssuing, Subject: subject,
		Attribution: &risk.DecisionAttribution{CommandID: p.binding.CommandID, CorrelationID: p.binding.CommandID, Actor: audit.ActorInput{Kind: audit.ActorAnonymous},
			Subject: identity.SecurityAuthenticationAttempt, SubjectID: string(p.binding.CommandID)}})
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	admission, err := start.custody.Prepare(ctx, result, scope, subject)
	if err != nil {
		return nil, err
	}
	a := &oneTapCallbackAdmission{owner: p, risk: admission, observed: p.readStarted}
	return a, a.Check(ctx)
}

func (*oneTapCallbackPhase) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, identity.ForbiddenError{}
}

func (p *oneTapCallbackPhase) RestoreFeatureAdmission(ctx context.Context, c identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if _, _, err := p.RestoreFeaturePreparation(ctx, c, generation, wire); err != nil {
		return nil, err
	}
	a := &oneTapCallbackAdmission{owner: p, risk: p.execution.admission, observed: p.execution.readStarted}
	return a, a.Check(ctx)
}

func (p *oneTapCallbackPhase) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	if c != p.original {
		return identity.Command{}, kernel.CommandPlan{}, identity.ForbiddenError{}
	}
	execution, command, err := p.restore(ctx, generation, wire)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	p.execution, p.command = execution, command
	plan, err := p.plan()
	return command, plan, err
}

func (p *oneTapCallbackPhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if p.execution == nil || c != p.command {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
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
	if digest != p.execution.digest || generation != p.execution.generation {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	if err := p.checkCurrent(ctx, w); err != nil {
		return identity.FeatureReceipt{}, err
	}
	receipt, err := p.service.effect.Apply(ctx, w, p, c, p.browser)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.service.start.eraseOneTapCallbackGrant(ctx, w, p, c, p.grant); err != nil {
		return identity.FeatureReceipt{}, err
	}
	p.applied = p.generated == generation && p.prepared != (session.PreparedIssuance{})
	return receipt, nil
}

func (p *oneTapCallbackPhase) checkCurrent(ctx context.Context, w kernel.Work) error {
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if err := p.checkBrowser(now, p.execution.readStarted); err != nil {
		return err
	}
	return p.execution.admission.CheckAt(ctx, now)
}

func (p *oneTapCallbackPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p.execution == nil || c != p.command {
		return identity.ForbiddenError{}
	}
	if err := p.checkCurrent(ctx, w); err != nil {
		return err
	}
	return p.service.effect.CheckCurrent(ctx, w, p, c)
}

func (p *oneTapCallbackPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return p.service.effect.Recover(ctx, w, p)
}

func (p *oneTapCallbackPhase) ExecuteIssue(ctx context.Context, r session.IssueRequest) (session.IssueExecution, error) {
	if ctx == nil || ctx.Err() != nil || p == nil || !p.deliverable || p.execution == nil {
		return session.IssueExecution{}, identity.ForbiddenError{}
	}
	c, record, ok := r.OneTapCommand()
	if !ok || c != p.command || p.receipt.Outcome != identity.CommitOutcomeCommitted || p.receipt.Validate() != nil {
		return session.IssueExecution{}, identity.ForbiddenError{}
	}
	actual, err := sessionpg.OneTapCallbackSessionFields(record)
	expected, e := sessionpg.OneTapCallbackSessionFields(p.execution.record)
	if err != nil || e != nil || !sameRPFields(actual, expected) {
		return session.IssueExecution{}, identity.ForbiddenError{}
	}
	p.deliverable = false
	return session.IssueExecution{Receipt: p.receipt, Session: p.execution.record}, nil
}

func (*oneTapCallbackPhase) RecoverIssue(context.Context, session.IssueRequest) (session.IssueExecution, error) {
	return session.IssueExecution{}, identity.ForbiddenError{}
}

var _ kernel.OneTapCallbackContributor = (*oneTapCallbackPhase)(nil)
var _ kernel.FeatureAdmissionPreparationContributor = (*oneTapCallbackPhase)(nil)
var _ session.IssueExecutor = (*oneTapCallbackPhase)(nil)
