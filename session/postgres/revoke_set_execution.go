package postgres

import (
	"context"
	"crypto/subtle"
	"fmt"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// RevokeSetExecutorConfig selects the existing owned execution profile and the
// exact trusted reader that prepared each opaque request. Final-signin issuance
// is not required. Install kernel, authorization, session, set-revocation,
// audit and outbox migrations first. Dependencies are borrowed through calls.
type RevokeSetExecutorConfig struct {
	Execution IssueExecutorConfig
	Sessions  *session.SessionService
}

// RevokeSetExecutor owns native bulk execution and scoped historical result
// recovery. It starts no goroutines and accepts no application-written stores,
// transactions or journals. Configuration is immutable and concurrent calls are
// safe. Historical receipts never supply current authentication or admission.
type RevokeSetExecutor struct {
	owned    *IssueExecutor
	sessions *session.SessionService
}

var _ session.RevokeSetExecutor = (*RevokeSetExecutor)(nil)

// NewRevokeSetExecutor validates explicit composition without IO. The primary
// pool and dependencies must outlive calls. Missing migrations fail closed at
// execution; construction never installs them or grants authority.
func NewRevokeSetExecutor(pool *database.Pool, c RevokeSetExecutorConfig) (*RevokeSetExecutor, error) {
	if c.Sessions == nil {
		return nil, session.ErrInvalidInput
	}
	owned, err := newOwnedSessionExecution(pool, c.Execution, false)
	if err != nil {
		return nil, err
	}
	return &RevokeSetExecutor{owned, c.Sessions}, nil
}

// ExecuteRevokeSet admits only original same-reader custody, authorizes before
// reservation, then delegates whole-set mutation and audit/lifecycle to the sole
// coordinator. Primary time narrows the unchanged deadline through final commit;
// slower effect persistence cannot renew it. Replay never executes another set.
// Known committed receipts remain committed if retained metadata cannot be read;
// such calls return an error and no count/disposition, never fabricated success.
// Detached terminal cleanup has the coordinator's separate bounded budget.
func (e *RevokeSetExecutor) ExecuteRevokeSet(ctx context.Context, request session.RevokeSetRequest) (out session.RevokeSetExecutionResult, err error) {
	entered := false
	var b identity.CommandBinding
	var op identity.FeatureOperation
	defer func() {
		if recover() != nil {
			out.RevokedCount, out.SubjectVersion, out.CurrentSessionRevoked = 0, 0, false
			if out.Receipt.Outcome == identity.CommitOutcomeCommitted {
				err = session.ErrUnavailable
			} else if entered {
				out.Receipt = unknownSetReceipt(b, op)
				err = identity.UnknownCommitError{CommandID: b.CommandID}
			} else {
				out = session.RevokeSetExecutionResult{}
				err = session.ErrUnavailable
			}
		}
	}()
	if ctx == nil || e == nil || e.owned == nil || e.sessions == nil {
		return out, session.ErrInvalidInput
	}
	now := e.owned.clock.Now()
	if err = request.Validate(e.sessions, now); err != nil {
		return out, err
	}
	budget := e.owned.maximumDuration
	if remaining := request.ValidUntil().Sub(now); remaining < budget {
		budget = remaining
	}
	bounded, stop := context.WithTimeout(ctx, budget)
	defer stop()
	if bounded.Err() != nil {
		return out, readError(bounded, bounded.Err())
	}
	// The single-session executor already owns the unchanged primary-time
	// conversion policy. Reuse it instead of a competing clock/validity owner.
	bounded, stopPrimary, err := (&RevokeOneExecutor{owned: e.owned, sessions: e.sessions}).primaryDeadline(bounded, request.ValidUntil())
	if err != nil {
		return out, err
	}
	defer stopPrimary()
	b, command, plan, caller, err := e.prepareSet(request)
	if err != nil {
		return out, err
	}
	feature, _ := command.Feature()
	op = feature.Operation
	if err = e.owned.allow(bounded, caller); err != nil {
		return out, err
	}
	if err = request.Validate(e.sessions, e.owned.clock.Now()); err != nil {
		return out, err
	}
	entered = true
	reservation, receipt, err := e.owned.coordinator.ReserveCommand(bounded, b, command, plan)
	out.Receipt = receipt
	if err != nil || reservation == (kernel.Reservation{}) {
		if receipt.Outcome == identity.CommitOutcomeCommitted && err == nil {
			return e.setExecutionMetadata(bounded, receipt)
		}
		return out, err
	}
	work, err := e.owned.coordinator.Begin(bounded, reservation)
	if err != nil {
		out.Receipt = unknownSetReceipt(b, op)
		return out, err
	}
	defer e.owned.coordinator.Abort(work, identity.UnavailableError{})
	provisional, err := e.owned.coordinator.ApplyFeature(bounded, work, command)
	if err != nil {
		out.Receipt, err = e.owned.coordinator.Abort(work, err)
		return out, err
	}
	if err = request.Validate(e.sessions, e.owned.clock.Now()); err != nil {
		out.Receipt, err = e.owned.coordinator.Abort(work, identity.ForbiddenError{})
		return out, err
	}
	out.Receipt, err = e.owned.coordinator.Commit(work, provisional)
	if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
		return out, err
	}
	return e.setExecutionMetadata(bounded, out.Receipt)
}

func unknownSetReceipt(b identity.CommandBinding, op identity.FeatureOperation) identity.CommandResult {
	return identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeUnknown, Feature: &identity.FeatureReceipt{Operation: op}}
}

func (e *RevokeSetExecutor) prepareSet(request session.RevokeSetRequest) (identity.CommandBinding, identity.Command, kernel.CommandPlan, authorization.DecisionContext, error) {
	fail := func(err error) (identity.CommandBinding, identity.Command, kernel.CommandPlan, authorization.DecisionContext, error) {
		return identity.CommandBinding{}, identity.Command{}, kernel.CommandPlan{}, authorization.DecisionContext{}, err
	}
	native, ok := request.Command()
	set, targeted := native.RevokeSet()
	if !ok || !targeted {
		return fail(session.ErrInvalidSessionCommand)
	}
	b := set.Binding
	if b.PolicyID != e.owned.policyID || b.PolicyVersion != e.owned.policyVersion {
		return fail(identity.ForbiddenError{})
	}
	command, err := MapRevokeSetRequest(request)
	if err != nil {
		return fail(err)
	}
	feature, _ := command.Feature()
	op := feature.Operation
	spec, _ := set.Caller.Bindings()
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return fail(session.ErrUnavailable)
	}
	record, err := builder.Build(audit.RecordInput{OccurredAt: e.owned.clock.Now().UTC().Truncate(time.Microsecond), Action: "identity.session.revoke", Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "session", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.id": b.RecordID, "aggregate.type": "session", "aggregate.before_version": strconv.FormatUint(spec.Version, 10), "aggregate.after_version": strconv.FormatUint(spec.Version+1, 10), "retention.class": "standard"}})
	if err != nil {
		return fail(session.ErrUnavailable)
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, op, "session", record)
	if err != nil {
		return fail(err)
	}
	declaration := kernel.CommandPlan{Contributors: e.owned.registry.Descriptors(), SubjectType: "session", Feature: &kernel.FeatureRegistration{Contributor: e.owned.native.Descriptor(), Operation: op}, Lifecycle: &kernel.LifecyclePlan{EventType: "session.set-revoked.v1", BeforeVersion: spec.Version, AfterVersion: spec.Version + 1}, Audits: []kernel.AuditPlan{{EventType: "identity.session.revoke", SchemaVersion: 1, BindingDigest: digest, RetentionClass: "standard", RetentionPolicyVersion: e.owned.retentionVersion, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}}
	plan, err := e.owned.coordinator.PrepareCommandPlan(b, command, declaration)
	if err != nil {
		return fail(err)
	}
	caller := authorization.DecisionContext{PolicyRevision: authorization.Revision(e.owned.policyVersion), CorrelationID: b.CorrelationID, Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(b.ActorID), Kind: b.ActorKind}, Action: authorization.Action(b.OperationID), Tenant: authorization.TenantID(b.TenantID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}}}
	return b, command, plan, caller, nil
}

type retainedSetResult struct {
	before, after, subject uint64
	count                  uint32
	current                bool
}

// Read only retained evidence after the command owner has proved commitment.
// This is not session authority and cannot reconstruct or execute a mutation.
func (e *RevokeSetExecutor) retainedSet(ctx context.Context, b identity.CommandBinding) (retainedSetResult, error) {
	var out retainedSetResult
	var purpose, user, source, before, after, subject string
	var count int64
	var current bool
	var binding, result []byte
	id, _ := revocationEvidence(b, kernel.LifecyclePlan{})
	read, stop := context.WithTimeout(ctx, e.owned.native.maximumDuration)
	defer stop()
	err := e.owned.native.pool.Raw().QueryRow(read, `SELECT purpose,user_id,source_id,before_version::text,after_version::text,subject_version::text,revoked_count,include_current,binding_digest,result_digest FROM `+e.owned.native.schema+`.set_revocations WHERE tenant_id=$1 AND command_id=$2`, string(b.TenantID), id).Scan(&purpose, &user, &source, &before, &after, &subject, &count, &current, &binding, &result)
	if err != nil {
		return out, readError(read, err)
	}
	parse := func(s string) (uint64, bool) {
		n, e := strconv.ParseUint(s, 10, 64)
		return n, e == nil && n > 0 && strconv.FormatUint(n, 10) == s
	}
	bv, bok := parse(before)
	av, aok := parse(after)
	sv, sok := parse(subject)
	if !bok || !aok || !sok || bv == ^uint64(0) || av != bv+1 || purpose != b.OperationID || user != string(b.UserID) || source != b.RecordID || count < 0 || count > 100000 || current && count == 0 || b.OperationID == session.RevokeOtherOperation().OperationID && current {
		return out, session.ErrUnavailable
	}
	_, bd := revocationEvidence(b, kernel.LifecyclePlan{BeforeVersion: bv, AfterVersion: av})
	rd := setResultDigest(b, bv, av, sv, uint32(count), current)
	if subtle.ConstantTimeCompare(binding, bd[:]) != 1 || subtle.ConstantTimeCompare(result, rd[:]) != 1 {
		return out, session.ErrUnavailable
	}
	if read.Err() != nil {
		return out, readError(read, read.Err())
	}
	return retainedSetResult{bv, av, sv, uint32(count), current}, nil
}

func (e *RevokeSetExecutor) setExecutionMetadata(ctx context.Context, receipt identity.CommandResult) (session.RevokeSetExecutionResult, error) {
	out := session.RevokeSetExecutionResult{Receipt: receipt}
	if receipt.Validate() != nil || receipt.Outcome != identity.CommitOutcomeCommitted || receipt.Feature == nil {
		return out, session.ErrUnavailable
	}
	retained, err := e.retainedSet(ctx, receipt.Binding)
	if err != nil {
		return out, err
	}
	if retained.before != receipt.Feature.BeforeVersion || retained.after != receipt.Feature.AfterVersion {
		return out, session.ErrUnavailable
	}
	out.RevokedCount, out.SubjectVersion, out.CurrentSessionRevoked = retained.count, retained.subject, retained.current
	return out, nil
}

// RevokeSetRecoveryResult is historical scoped command metadata and, only on
// verified committed evidence, retained count/source disposition. It contains
// no credential or permission to execute. An accompanying error leaves count,
// versions and disposition zero while preserving a known command outcome.
type RevokeSetRecoveryResult struct {
	Command                        kernel.CommandRecord
	RevokedCount                   uint32
	SubjectVersion, SessionVersion uint64
	CurrentSessionRevoked          bool
}

// RecoverRevokeSetCommand authorizes current trusted result access and asks the
// existing command owner to reconcile the original scope. It works after process
// restart without bearer or request custody, never reserves missing commands,
// renews admission, reconstructs from live sessions or issues a replacement.
func (e *RevokeSetExecutor) RecoverRevokeSetCommand(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (out RevokeSetRecoveryResult, err error) {
	if ctx == nil || e == nil || e.owned == nil {
		return out, session.ErrInvalidInput
	}
	if q.OperationID != session.RevokeOtherOperation().OperationID && q.OperationID != session.RevokeAllOperation().OperationID || !scopeID(q.RecordID) || q.LinkMode != 0 || q.ActorKind != authorization.SubjectUser || string(q.ActorID) != string(q.UserID) {
		return out, identity.ForbiddenError{}
	}
	bounded, stop := context.WithTimeout(ctx, e.owned.maximumDuration)
	defer stop()
	out.Command, err = e.owned.coordinator.RecoverCommand(bounded, q, caller)
	if out.Command.Binding.CommandID == "" {
		return out, err
	}
	op := session.RevokeOtherOperation()
	if q.OperationID == session.RevokeAllOperation().OperationID {
		op = session.RevokeAllOperation()
	}
	if out.Command.Feature == nil || *out.Command.Feature != op {
		return RevokeSetRecoveryResult{}, session.ErrUnavailable
	}
	if err != nil || out.Command.Outcome != identity.CommitOutcomeCommitted {
		return out, err
	}
	retained, err := e.retainedSet(bounded, out.Command.Binding)
	if err != nil {
		return out, err
	}
	out.RevokedCount, out.SubjectVersion, out.SessionVersion, out.CurrentSessionRevoked = retained.count, retained.subject, retained.after, retained.current
	return out, nil
}

// Format prevents diagnostic traversal of runtime keys and dependencies.
func (RevokeSetExecutor) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.RevokeSetExecutor(redacted)"))
}

// MarshalJSON denies runtime export.
func (RevokeSetExecutor) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// Format redacts execution configuration and reader custody.
func (RevokeSetExecutorConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.RevokeSetExecutorConfig(redacted)"))
}

// MarshalJSON denies configuration export.
func (RevokeSetExecutorConfig) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// Format redacts correlated historical metadata.
func (RevokeSetRecoveryResult) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.RevokeSetRecoveryResult(redacted)"))
}

// MarshalJSON denies implicit historical disclosure; HTTP owns authorized DTOs.
func (RevokeSetRecoveryResult) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
