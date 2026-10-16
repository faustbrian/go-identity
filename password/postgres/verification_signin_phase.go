package passwordpostgres

import (
	"context"
	"reflect"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// One invocation owns the ephemeral issuer/executor. Only the coordinator owns
// durable reservation, transaction, outcome classification and reconciliation.
type verificationSigninPhase struct {
	service       *VerificationSigninService
	request       email.VerificationSigninRequest
	origin        email.RegistrationVerificationSpec
	flow          session.PreAuthTransaction
	recipient     kernel.RecipientRecord
	confirmation  identity.CommandResult
	factorVersion uint64
	admission     risk.AuthenticationAdmission
	command       identity.Command
	record        session.Session
	coordinator   *kernel.Coordinator
	registry      *kernel.ContributorRegistry
	plan          kernel.CommandPlan
	attempted     atomic.Bool
}

func (*verificationSigninPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/email/postgres", ContractID: "identity.email", Version: 1}
}

func (*verificationSigninPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{verificationSigninOperation()}
}

func (s *VerificationSigninService) coordinator(p *verificationSigninPhase) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	audits, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, err
	}
	outbox, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, nil, err
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{s.signup.directory, audits, outbox, p})
	if err != nil {
		return nil, nil, err
	}
	c, err := kernel.NewCoordinator(s.signup.pool, registry, s.signup.config().Coordinator)
	return c, registry, err
}

func (p *verificationSigninPhase) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.service == nil || p.command == (identity.Command{}) || command != p.command || p.factorVersion == 0 {
		return email.ErrInvalidVerification
	}
	f, _ := command.Feature()
	restored, err := sessionpg.EmailVerificationSigninSession(command)
	if err != nil || restored == (session.Session{}) || plan.Feature == nil || plan.Feature.Contributor != p.Descriptor() || plan.Feature.Operation != verificationSigninOperation() || plan.SubjectType != "session" || plan.Lifecycle == nil || *plan.Lifecycle != (kernel.LifecyclePlan{EventType: "session.created.v1", AfterVersion: 1}) || plan.Capability != nil || plan.CapabilityIssuance != nil || plan.CommandCounters != nil || plan.RiskEvidence != nil || plan.OTP != nil || plan.Delivery != nil || plan.MFAContinuation != nil || len(plan.Audits) != 1 {
		return email.ErrInvalidVerification
	}
	expected, err := sessionpg.MagicLinkSigninSessionFields(p.record)
	if err != nil || len(f.Fields) != len(expected)+1 {
		return email.ErrInvalidVerification
	}
	for _, field := range f.Fields {
		if field.Name == "verification.factor-version" {
			if field.Value.Kind != identity.FeatureUint64 || field.Value.Uint64 != p.factorVersion {
				return email.ErrInvalidVerification
			}
			continue
		}
		found := false
		for _, want := range expected {
			if field.Name == want.Name && reflect.DeepEqual(field.Value, want.Value) {
				found = true
				break
			}
		}
		if !found {
			return email.ErrInvalidVerification
		}
	}
	return nil
}

func (p *verificationSigninPhase) checkTime(ctx context.Context, at time.Time) error {
	if p == nil || p.service == nil || p.command == (identity.Command{}) {
		return email.ErrInvalidVerification
	}
	if err := p.service.originalBrowser(p.request, p.origin, p.flow, at); err != nil {
		return err
	}
	metadata, err := p.record.MagicLinkAuthentication().Bindings()
	if err != nil || at.Before(metadata.AuthenticatedAt) || !at.Before(metadata.ValidUntil) {
		return identity.ForbiddenError{}
	}
	return p.admission.CheckAt(ctx, at)
}

func (p *verificationSigninPhase) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	if p == nil || p.service == nil || command != p.command {
		return identity.FeatureReceipt{}, email.ErrInvalidVerification
	}
	if err := p.CheckFeatureCommit(ctx, w, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return p.service.effect.Apply(ctx, w, p, command, p.recipient, p.confirmation)
}

func (p *verificationSigninPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, command identity.Command) error {
	if p == nil || p.service == nil || command != p.command || command == (identity.Command{}) {
		return email.ErrInvalidVerification
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if err := p.checkTime(ctx, now); err != nil {
		return err
	}
	if err := p.service.effect.CheckCurrent(ctx, w, p, command, p.recipient, p.confirmation); err != nil {
		return err
	}
	_, err = mfapg.RequireEmailVerificationSigninFactors(ctx, w, p, command, p.factorVersion)
	return err
}

func (p *verificationSigninPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	if p == nil || p.service == nil || p.service.effect == nil {
		return kernel.RecoveryUnknown, email.ErrInvalidVerification
	}
	return p.service.effect.Recover(ctx, w, p)
}

func (p *verificationSigninPhase) ExecuteIssue(ctx context.Context, request session.IssueRequest) (session.IssueExecution, error) {
	if ctx == nil || p == nil || p.coordinator == nil {
		return session.IssueExecution{}, email.ErrInvalidVerification
	}
	command, record, ok := request.EmailVerificationCommand()
	if !ok || command != p.command || record != p.record {
		return session.IssueExecution{}, email.ErrInvalidVerification
	}
	if !p.attempted.CompareAndSwap(false, true) {
		return session.IssueExecution{}, session.ErrIssuanceAlreadyAttempted
	}
	f, _ := command.Feature()
	result := func(receipt identity.CommandResult, replay bool) session.IssueExecution {
		out := session.IssueExecution{Receipt: receipt, Replayed: replay}
		if receipt.Outcome == identity.CommitOutcomeCommitted {
			out.Session = p.record
		}
		return out
	}
	reservation, receipt, err := p.coordinator.ReserveCommand(ctx, f.Binding, command, p.plan)
	if err != nil || reservation == (kernel.Reservation{}) {
		return result(receipt, true), err
	}
	w, err := p.coordinator.Begin(ctx, reservation)
	if err != nil {
		return result(identity.CommandResult{Binding: f.Binding, Outcome: identity.CommitOutcomeUnknown, Feature: &identity.FeatureReceipt{Operation: f.Operation}}, false), err
	}
	defer p.coordinator.Abort(w, identity.UnavailableError{})
	receipt, err = p.coordinator.ApplyFeature(ctx, w, command)
	if err != nil {
		receipt, err = p.coordinator.Abort(w, err)
		return result(receipt, false), err
	}
	receipt, err = p.coordinator.Commit(w, receipt)
	if err == nil && receipt.Outcome == identity.CommitOutcomeCommitted {
		err = p.checkTime(ctx, p.service.c.Issuance.Clock.Now())
	}
	return result(receipt, false), err
}

func (*verificationSigninPhase) RecoverIssue(context.Context, session.IssueRequest) (session.IssueExecution, error) {
	return session.IssueExecution{}, email.ErrInvalidVerification
}

func (p *verificationSigninPhase) preparePlan(at time.Time) (kernel.CommandPlan, error) {
	f, ok := p.command.Feature()
	if !ok || p.coordinator == nil || p.registry == nil {
		return kernel.CommandPlan{}, email.ErrInvalidVerification
	}
	b, op := f.Binding, f.Operation
	kind := audit.ActorService
	if b.ActorKind == authorization.SubjectUser {
		kind = audit.ActorHuman
	}
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	seed, err := builder.Build(audit.RecordInput{OccurredAt: at, Action: b.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: kind, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "session", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "session", "aggregate.id": b.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "protected"}})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, op, "session", seed)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	return p.coordinator.PrepareCommandPlan(b, p.command, kernel.CommandPlan{Contributors: p.registry.Descriptors(), Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op}, SubjectType: "session", Lifecycle: &kernel.LifecyclePlan{EventType: "session.created.v1", AfterVersion: 1}, Audits: []kernel.AuditPlan{{EventType: op.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}})
}
