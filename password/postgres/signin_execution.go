package passwordpostgres

import (
	"context"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// Invocation-local execution borrows the sole coordinator. It neither owns a
// transaction nor a journal and cannot substitute comparison/session custody.
// Retained command recovery is deliberately separate from this password-bearing
// executor; a restart must not reconstruct or resubmit the original secrets.
type signinExecution struct {
	coordinator *kernel.Coordinator
	phase       *signinPhase
	plan        kernel.CommandPlan
	record      session.Session
	clock       session.IssuerClock
	attempted   atomic.Bool
}

var _ session.IssueExecutor = (*signinExecution)(nil)

func (e *signinExecution) ExecuteIssue(ctx context.Context, request session.IssueRequest) (session.IssueExecution, error) {
	if ctx == nil || e == nil || e.coordinator == nil || e.phase == nil || e.clock == nil {
		return session.IssueExecution{}, password.ErrPasswordWork
	}
	command, record, ok := request.PasswordCommand()
	if !ok || record != e.record || !e.phase.matches(command) {
		return session.IssueExecution{}, password.ErrPasswordWork
	}
	f, _ := command.PasswordSigninFeature()
	if err := ctx.Err(); err != nil {
		return session.IssueExecution{}, err
	}
	if !e.attempted.CompareAndSwap(false, true) {
		return session.IssueExecution{}, session.ErrIssuanceAlreadyAttempted
	}
	reservation, receipt, err := e.coordinator.ReserveCommand(ctx, f.Binding, command, e.plan)
	if err != nil || reservation == (kernel.Reservation{}) {
		return e.result(receipt, true), err
	}
	work, err := e.coordinator.Begin(ctx, reservation)
	if err != nil {
		// Reservation is not a rollback receipt. Keep exact original correlation
		// while withholding credentials; primary recovery owns reconciliation.
		receipt = identity.CommandResult{Binding: f.Binding, Outcome: identity.CommitOutcomeUnknown, Feature: &identity.FeatureReceipt{Operation: f.Operation}}
		return e.result(receipt, false), err
	}
	defer e.coordinator.Abort(work, identity.UnavailableError{})
	receipt, err = e.coordinator.ApplyFeature(ctx, work, command)
	if err != nil {
		receipt, err = e.coordinator.Abort(work, err)
		return e.result(receipt, false), err
	}
	receipt, err = e.coordinator.Commit(work, receipt)
	if err == nil && receipt.Outcome == identity.CommitOutcomeCommitted {
		if err = ctx.Err(); err == nil {
			err = e.phase.checkDelivery(ctx, e.clock.Now())
		}
	}
	return e.result(receipt, false), err
}

// Password-bearing requests are never recovery inputs, even while still live.
// The public native service uses the password-free SigninRecovery selector.
func (*signinExecution) RecoverIssue(context.Context, session.IssueRequest) (session.IssueExecution, error) {
	return session.IssueExecution{}, password.ErrPasswordWork
}

func (e *signinExecution) result(receipt identity.CommandResult, replay bool) session.IssueExecution {
	out := session.IssueExecution{Receipt: receipt, Replayed: replay}
	if receipt.Outcome == identity.CommitOutcomeCommitted {
		out.Session = e.record
	}
	return out
}

// Build the mandatory protected plan inside the native owner, not in an
// application callback. The kernel retains the actual generated audit/outbox;
// this seed binds their scope without persisting or disclosing input secrets.
func signinPlan(coordinator *kernel.Coordinator, registry *kernel.ContributorRegistry, p *signinPhase, command identity.Command, now time.Time) (kernel.CommandPlan, error) {
	if coordinator == nil || registry == nil || !p.matches(command) {
		return kernel.CommandPlan{}, password.ErrPasswordWork
	}
	f, _ := command.PasswordSigninFeature()
	b, op := f.Binding, f.Operation
	actor := audit.ActorHuman
	switch b.ActorKind {
	case authorization.SubjectUser:
	case authorization.SubjectServiceAccount, authorization.SubjectAPIKey:
		actor = audit.ActorService
	default:
		return kernel.CommandPlan{}, password.ErrPasswordWork
	}
	target := string(b.UserID)
	if target == "" {
		target = b.AnonymousFlowID
	}
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	seed, err := builder.Build(audit.RecordInput{OccurredAt: now, Action: op.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: actor, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "session", ID: target}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "session", "aggregate.id": target, "aggregate.before_version": "0", "aggregate.after_version": "0", "retention.class": "protected"}})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, op, "session", seed)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	return coordinator.PrepareCommandPlan(b, command, kernel.CommandPlan{Contributors: registry.Descriptors(), Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op}, SubjectType: "session", Lifecycle: &kernel.LifecyclePlan{EventType: "session.created.v1"}, Audits: []kernel.AuditPlan{{EventType: op.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}})
}
