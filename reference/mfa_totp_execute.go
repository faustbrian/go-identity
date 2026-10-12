package reference

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/v2/postgres/identity"
)

func (p *magicTOTPPhase) compose() error {
	auditing, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return err
	}
	lifecycle, err := lifecyclepg.NewContributor()
	if err != nil {
		return err
	}
	p.registry, err = kernel.NewContributorRegistry([]kernel.Contributor{p.state.directory, auditing, lifecycle, p, p.state.counters, capabilitypg.NewParticipant()})
	if err != nil {
		return err
	}
	p.coordinator, err = kernel.NewCoordinator(p.state.pool, p.registry, p.state.config.Coordinator)
	if err != nil {
		return err
	}
	p.delivery = &magicTOTPDelivery{}
	// Recovery has no submitted input or decrypted primary. The explicitly
	// composed owner selects the profile without requiring secret custody.
	if p.state.password != nil {
		p.issuer, err = session.NewMFAPasswordSessionIssuerWithCSRF(p.delivery, p.state.config.SessionIssuer, p.state.config.CSRF)
	} else {
		p.issuer, err = session.NewMFAMagicLinkSessionIssuerWithCSRF(p.delivery, p.state.config.SessionIssuer, p.state.config.CSRF)
	}
	return err
}

func (p *magicTOTPPhase) declaration() (kernel.CommandPlan, error) {
	completion, err := p.completion()
	if err != nil || p.registry == nil {
		return kernel.CommandPlan{}, invalidTOTPCompletion()
	}
	f, _ := p.input.command.Feature()
	b := f.Binding
	actor := audit.ActorService
	if b.ActorKind == authorization.SubjectUser {
		actor = audit.ActorHuman
	}
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	subject := "authentication_attempt"
	seed, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC().Truncate(time.Microsecond), Action: b.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: actor, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: subject, ID: b.AnonymousFlowID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": subject, "aggregate.id": b.AnonymousFlowID, "aggregate.before_version": "0", "aggregate.after_version": "0", "retention.class": "protected"}})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, f.Operation, subject, seed)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	child := p.input.child
	cp := p.counterPlan
	return kernel.CommandPlan{Contributors: p.registry.Descriptors(), Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: f.Operation}, SubjectType: subject, MFACompletion: &completion, Capability: &child, CommandCounters: &cp, Lifecycle: &kernel.LifecyclePlan{EventType: "session.created.v1"}, Audits: []kernel.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}}, nil
}

func (p *magicTOTPPhase) admitRisk(ctx context.Context) error {
	f, _ := p.input.command.Feature()
	b := f.Binding
	p.subject = risk.Subject{Network: p.input.request.Network, User: string(p.input.recipient.User.ID)}
	scope := risk.Context{Tenant: string(b.TenantID), Operation: risk.Action(b.OperationID), Attempt: string(b.CommandID)}
	result, err := p.state.config.Risk.Evaluation.EvaluateProtectedProviders(ctx, risk.EvaluateRequest{Context: scope, Phase: risk.NonIssuing})
	if err != nil {
		return identity.UnavailableError{}
	}
	p.admission, err = p.state.custody.Prepare(ctx, result, scope)
	if err != nil {
		return err
	}
	completion, err := p.completion()
	if err != nil {
		return err
	}
	p.counterCommand, p.counterPlan, err = p.state.counters.PrepareMFACompletionCommandCounters(p.input.command, p.subject, p.input.child, completion, time.Now().UTC().Truncate(time.Microsecond))
	return err
}

func totpReceipt(id identity.CommandID, receipt identity.CommandResult) mfa.TotpVerifyResult {
	return mfa.TotpVerifyResult{Outcome: receipt.Outcome, Session: session.IssueResult{CommandID: id, CommitOutcome: receipt.Outcome, Replayed: receipt.Outcome == identity.CommitOutcomeCommitted, RetryAfter: receipt.RetryAfter}}
}

func (s *magicLinkTOTPService) TotpVerify(ctx context.Context, request mfa.TotpVerifyRequest) (out mfa.TotpVerifyResult, err error) {
	if ctx == nil || s == nil || s.state == nil || request.Enrollment != nil || request.Validate() != nil {
		return out, invalidTOTPCompletion()
	}
	state := s.state()
	ctx, stop := context.WithTimeout(ctx, state.config.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			out, err = mfa.TotpVerifyResult{}, identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			clearTOTPDelivery(&out)
		}
	}()
	input, err := s.readInput(ctx, request)
	if err != nil {
		return out, err
	}
	defer input.destroy()
	if input.historical != nil {
		return totpReceipt(request.CommandID, *input.historical), input.historyError
	}
	p := &magicTOTPPhase{state: state, input: input}
	if err = p.compose(); err != nil {
		return out, err
	}
	if err = p.admitRisk(ctx); err != nil {
		return out, err
	}
	declaration, err := p.declaration()
	if err != nil {
		return out, err
	}
	denialPlan, err := p.coordinator.PrepareMFATOTPAttemptPlanWithOriginal(input.command, p.counterCommand, declaration)
	if err != nil {
		return out, err
	}
	receipt, err := p.coordinator.RecordMFATOTPAttemptDenialWithOriginal(ctx, input.command, p.counterCommand, denialPlan)
	// Only this callback's successful comparison and proven rollback permit the
	// generation phase. A generic conflict is never interpreted as a valid code.
	var conflict identity.ConflictError
	if !p.correct || receipt.Outcome != identity.CommitOutcomeConflict || !errors.As(err, &conflict) {
		if receipt.Outcome == identity.CommitOutcomeConflict {
			caller := request.Caller.Clone()
			caller.Request.Resource = authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(request.PreAuthID)}
			if original, found, queryErr := state.history.QueryMFATOTPCommand(ctx, input.command, caller); found && original.Validate() == nil {
				return totpReceipt(request.CommandID, original), queryErr
			}
		}
		return totpReceipt(request.CommandID, receipt), err
	}
	preparedPlan, err := p.coordinator.PrepareMFATOTPFeaturePlanWithOriginal(input.command, p.counterCommand, declaration)
	if err != nil {
		return out, err
	}
	receipt, err = p.coordinator.ExecutePreparedMFATOTPFeature(ctx, input.command, p.counterCommand, preparedPlan)
	out = totpReceipt(request.CommandID, receipt)
	if err != nil || receipt.Outcome != identity.CommitOutcomeCommitted || p.prepared == (session.PreparedIssuance{}) || p.command == (identity.Command{}) {
		return out, err
	}
	record, ok := p.prepared.Session()
	if !ok {
		return out, identity.UnavailableError{}
	}
	p.delivery.command, p.delivery.receipt, p.delivery.record, p.delivery.deliverable = p.command, receipt, record, true
	bound, err := p.issuer.BindMFA(p.prepared, p.command)
	if err != nil {
		return out, err
	}
	out.Session, err = p.issuer.Issue(ctx, bound)
	out.Outcome = out.Session.CommitOutcome
	if err == nil && out.Session.Token != (session.Token{}) {
		out.CSRFToken, err = bound.CSRFToken()
	}
	return out, err
}

// RecoverTotpVerify uses only exact command correlation and current result
// policy. It never needs a live child, browser cookie, code or factor plaintext,
// generates nothing, and cannot reveal credentials from retained session fields.
func (s *magicLinkTOTPService) RecoverTotpVerify(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (out mfa.TotpVerifyResult, err error) {
	if ctx == nil || s == nil || s.state == nil || q.OperationID != magicTOTPCompletionOperation().OperationID || q.UserID != "" || q.RecordID != "" || q.AnonymousFlowID == "" || caller.Validate() != nil {
		return out, invalidTOTPCompletion()
	}
	if _, err := identity.ParsePreAuthTransactionID(q.AnonymousFlowID); err != nil {
		return out, invalidTOTPCompletion()
	}
	state := s.state()
	ctx, stop := context.WithTimeout(ctx, state.config.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			out, err = mfa.TotpVerifyResult{}, identity.UnavailableError{}
		}
		clearTOTPDelivery(&out)
		if ctx.Err() != nil {
			err = ctx.Err()
		}
	}()
	p := &magicTOTPPhase{state: state}
	if err := p.compose(); err != nil {
		return out, err
	}
	caller = caller.Clone()
	caller.Request.Resource = authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(q.AnonymousFlowID)}
	receipt, err := p.coordinator.RecoverFeatureCommand(ctx, q, caller)
	if receipt.Feature != nil && receipt.Feature.Operation != magicTOTPCompletionOperation() {
		return out, identity.UnavailableError{}
	}
	return totpReceipt(q.CommandID, receipt), err
}

var _ mfa.TOTPCompletionService = (*magicLinkTOTPService)(nil)
