package postgres

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// RotationExecutorConfig selects the exact trusted reader and existing native
// policy/kernel/audit/outbox composition. Final-signin issuance is not required.
// Install rotation and all prerequisite migrations before execution. Borrowed
// dependencies must outlive calls; construction performs no IO or grants.
type RotationExecutorConfig struct {
	Execution IssueExecutorConfig
	Sessions  *session.SessionService
}

// RotationExecutor owns atomic native rotation and safe historical recovery.
// It accepts no application store, journal or transaction, starts no goroutines,
// and is safe for concurrent calls. Only the core rotator can reveal credentials.
type RotationExecutor struct {
	owned    *IssueExecutor
	sessions *session.SessionService
}

var _ session.RotationExecutor = (*RotationExecutor)(nil)

// NewRotationExecutor validates explicit borrowed composition without IO.
// Sessions must be the authenticating reader that prepared each original request.
func NewRotationExecutor(pool *database.Pool, c RotationExecutorConfig) (*RotationExecutor, error) {
	if c.Sessions == nil {
		return nil, session.ErrInvalidInput
	}
	owned, err := newOwnedSessionExecution(pool, c.Execution, false)
	if err != nil {
		return nil, err
	}
	return &RotationExecutor{owned, c.Sessions}, nil
}

// ExecuteRotation checks original opaque admission and current policy before
// reservation, then locks all native owners and performs one source CAS with
// digest retirement, successor, audit, lifecycle and receipt in the sole Work.
// Original absolute validity bounds both Work and commit; copies never renew it.
// Replays return the exact original outcome, not a second mutation or credential.
// Cancellation, panic and failed commit acknowledgement never prove rollback.
func (e *RotationExecutor) ExecuteRotation(ctx context.Context, request session.RotationRequest) (out session.RotationExecution, err error) {
	entered := false
	var b identity.CommandBinding
	defer func() {
		if recover() != nil {
			err = session.ErrUnavailable
			if entered && out.Receipt.Outcome != identity.CommitOutcomeCommitted {
				out.Receipt = unknownRotation(b)
				err = identity.UnknownCommitError{CommandID: b.CommandID}
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
	bounded, stop := context.WithTimeout(ctx, e.owned.maximumDuration)
	defer stop()
	// Reuse the existing primary-time deadline owner; never add database-read
	// latency to the original absolute admission.
	bounded, stopPrimary, err := (&RevokeOneExecutor{owned: e.owned}).primaryDeadline(bounded, request.ValidUntil())
	if err != nil {
		return out, err
	}
	defer stopPrimary()
	var command identity.Command
	var plan kernel.CommandPlan
	var caller authorization.DecisionContext
	b, command, plan, caller, err = e.prepareRotation(request)
	if err != nil {
		return out, err
	}
	if err = e.owned.allow(bounded, caller); err != nil {
		return out, err
	}
	if err = request.Validate(e.sessions, e.owned.clock.Now()); err != nil {
		return out, err
	}
	entered = true
	reservation, result, err := e.owned.coordinator.ReserveCommand(bounded, b, command, plan)
	if err != nil || reservation == (kernel.Reservation{}) {
		out.Receipt, out.Replayed = result, true
		return e.rotationResult(bounded, request, result, true, err)
	}
	work, err := e.owned.coordinator.Begin(bounded, reservation)
	if err != nil {
		return session.RotationExecution{Receipt: unknownRotation(b)}, err
	}
	defer e.owned.coordinator.Abort(work, identity.UnavailableError{})
	provisional, err := e.owned.coordinator.ApplyFeature(bounded, work, command)
	if err != nil {
		result, err = e.owned.coordinator.Abort(work, err)
		return e.rotationResult(bounded, request, result, false, err)
	}
	if err = request.Validate(e.sessions, e.owned.clock.Now()); err != nil {
		result, err = e.owned.coordinator.Abort(work, identity.ForbiddenError{})
		return e.rotationResult(bounded, request, result, false, err)
	}
	result, err = e.owned.coordinator.Commit(work, provisional)
	out.Receipt = result
	return e.rotationResult(bounded, request, result, false, err)
}

// RecoverRotation returns exact historical metadata under current result-access
// policy even after original admission expiry. It checks the complete retained
// source/successor, deadline and transport intent. It never reserves or replays
// effects, renews authentication, or reveals a bearer. Known commitment survives
// an ancillary evidence error, but no session payload is manufactured on error.
func (e *RotationExecutor) RecoverRotation(ctx context.Context, request session.RotationRequest) (session.RotationExecution, error) {
	if ctx == nil || e == nil || e.owned == nil {
		return session.RotationExecution{}, session.ErrInvalidInput
	}
	mapped, err := MapRotationRequest(request)
	if err != nil {
		return session.RotationExecution{}, err
	}
	spec, _ := mapped.Feature()
	b := spec.Binding
	q := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID, LinkMode: b.LinkMode}
	bounded, stop := context.WithTimeout(ctx, e.owned.maximumDuration)
	defer stop()
	receipt, err := e.owned.coordinator.RecoverFeatureCommand(bounded, q, e.rotationCaller(b))
	return e.rotationResult(bounded, request, receipt, true, err)
}

func unknownRotation(b identity.CommandBinding) identity.CommandResult {
	return identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeUnknown, Feature: &identity.FeatureReceipt{Operation: session.RotateOperation()}}
}

func (e *RotationExecutor) rotationCaller(b identity.CommandBinding) authorization.DecisionContext {
	return authorization.DecisionContext{PolicyRevision: authorization.Revision(e.owned.policyVersion), CorrelationID: b.CorrelationID, Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(b.ActorID), Kind: b.ActorKind}, Action: authorization.Action(b.OperationID), Tenant: authorization.TenantID(b.TenantID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}}}
}

func (e *RotationExecutor) rotationResult(ctx context.Context, request session.RotationRequest, receipt identity.CommandResult, replayed bool, cause error) (session.RotationExecution, error) {
	out := session.RotationExecution{Receipt: receipt, Replayed: replayed}
	if receipt.Outcome != identity.CommitOutcomeCommitted {
		return out, cause
	}
	if receipt.Validate() != nil || receipt.Feature == nil || receipt.Feature.Operation != session.RotateOperation() {
		return out, session.ErrUnavailable
	}
	mapped, err := MapRotationRequest(request)
	if err != nil {
		return out, err
	}
	projection, _ := mapped.Feature()
	if receipt.Binding != projection.Binding {
		return out, identity.ConflictError{CommandID: projection.Binding.CommandID}
	}
	digest, err := rotationIntentDigest(mapped)
	if err != nil {
		return out, err
	}
	native, _, _, _ := nativeRotationIntent(mapped)
	rotation, _ := native.Rotation()
	before, _ := rotation.Source.Bindings()
	after, _ := rotation.Successor.Bindings()
	if receipt.Feature.BeforeVersion != before.Version || receipt.Feature.AfterVersion != after.Version {
		return out, session.ErrUnavailable
	}
	read, stop := context.WithTimeout(ctx, e.owned.native.maximumDuration)
	defer stop()
	retained, err := e.owned.native.readRotation(read, receipt.Binding, kernel.LifecyclePlan{BeforeVersion: before.Version, AfterVersion: after.Version})
	if err != nil {
		return out, err
	}
	if retained.intent != digest {
		return out, identity.ConflictError{CommandID: receipt.Binding.CommandID}
	}
	// A self-consistent retained checksum proves integrity only relative to
	// that payload, not identity with the original command's records.
	expectedSource, _, sourceErr := encodeRecord(rotation.Source)
	expectedNext, _, nextErr := encodeRecord(rotation.Successor)
	actualSource, _, retainedSourceErr := encodeRecord(retained.source)
	actualNext, _, retainedNextErr := encodeRecord(retained.successor)
	if sourceErr != nil || nextErr != nil || retainedSourceErr != nil || retainedNextErr != nil || !bytes.Equal(expectedSource, actualSource) || !bytes.Equal(expectedNext, actualNext) {
		return out, identity.ConflictError{CommandID: receipt.Binding.CommandID}
	}
	out.Session = retained.successor
	return out, cause
}

func (e *RotationExecutor) prepareRotation(request session.RotationRequest) (identity.CommandBinding, identity.Command, kernel.CommandPlan, authorization.DecisionContext, error) {
	fail := func(err error) (identity.CommandBinding, identity.Command, kernel.CommandPlan, authorization.DecisionContext, error) {
		return identity.CommandBinding{}, identity.Command{}, kernel.CommandPlan{}, authorization.DecisionContext{}, err
	}
	command, err := MapRotationRequest(request)
	if err != nil {
		return fail(err)
	}
	native, _, _, err := nativeRotationIntent(command)
	if err != nil {
		return fail(err)
	}
	rotation, _ := native.Rotation()
	b := rotation.Binding
	if b.PolicyID != e.owned.policyID || b.PolicyVersion != e.owned.policyVersion {
		return fail(identity.ForbiddenError{})
	}
	before, _ := rotation.Source.Bindings()
	after, _ := rotation.Successor.Bindings()
	op := session.RotateOperation()
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return fail(session.ErrUnavailable)
	}
	record, err := builder.Build(audit.RecordInput{OccurredAt: e.owned.clock.Now().UTC().Truncate(time.Microsecond), Action: "identity.session.refresh", Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "session", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.id": b.RecordID, "aggregate.type": "session", "aggregate.before_version": strconv.FormatUint(before.Version, 10), "aggregate.after_version": strconv.FormatUint(after.Version, 10), "retention.class": "standard"}})
	if err != nil {
		return fail(err)
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, op, "session", record)
	if err != nil {
		return fail(err)
	}
	declaration := kernel.CommandPlan{Contributors: e.owned.registry.Descriptors(), SubjectType: "session", Feature: &kernel.FeatureRegistration{Contributor: e.owned.native.Descriptor(), Operation: op}, Lifecycle: &kernel.LifecyclePlan{EventType: "session.rotated.v1", BeforeVersion: before.Version, AfterVersion: after.Version}, Audits: []kernel.AuditPlan{{EventType: "identity.session.refresh", SchemaVersion: 1, BindingDigest: digest, RetentionClass: "standard", RetentionPolicyVersion: e.owned.retentionVersion, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}}
	plan, err := e.owned.coordinator.PrepareCommandPlan(b, command, declaration)
	if err != nil {
		return fail(err)
	}
	return b, command, plan, e.rotationCaller(b), nil
}

// Format redacts borrowed dependencies and runtime key/profile configuration.
func (RotationExecutor) Format(s fmt.State, _ rune) {
	s.Write([]byte("postgres.RotationExecutor(redacted)"))
}

// MarshalJSON forbids implicit runtime export.
func (RotationExecutor) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// Format redacts key/profile configuration.
func (RotationExecutorConfig) Format(s fmt.State, _ rune) {
	s.Write([]byte("postgres.RotationExecutorConfig(redacted)"))
}

// MarshalJSON forbids implicit configuration export.
func (RotationExecutorConfig) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
