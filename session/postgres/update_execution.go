package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
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

// UpdateExecutorConfig borrows the exact authenticating reader and existing
// native policy/kernel/audit/outbox composition. Final-signin admission is not
// required for display labels. Install UpdateMigrationSource before use.
type UpdateExecutorConfig struct {
	Execution IssueExecutorConfig
	Sessions  *session.SessionService
}

// UpdateExecutor owns native atomic self-session label CAS and historical
// outcome recovery. It accepts no application store, journal or transaction,
// starts no goroutines and is safe concurrently. Borrowed dependencies/pool
// must outlive calls. Zero is invalid; construction performs no IO.
type UpdateExecutor struct {
	owned    *IssueExecutor
	sessions *session.SessionService
}

var _ session.UpdateExecutor = (*UpdateExecutor)(nil)

// NewUpdateExecutor validates explicit native composition without granting
// permission or beginning a transaction. Sessions must prepare every request.
func NewUpdateExecutor(pool *database.Pool, c UpdateExecutorConfig) (*UpdateExecutor, error) {
	if c.Sessions == nil {
		return nil, session.ErrInvalidInput
	}
	owned, err := newOwnedSessionExecution(pool, c.Execution, false)
	if err != nil {
		return nil, err
	}
	return &UpdateExecutor{owned, c.Sessions}, nil
}

// ExecuteUpdate checks original opaque admission and current exact policy,
// then executes label/session CAS, audit, lifecycle and receipt in the sole
// Work. Original absolute validity bounds the transaction and final commit.
// Exact replays observe history, never reapply. Post-entry ambiguity/panics
// never prove rollback; known commitment survives ancillary metadata errors.
func (e *UpdateExecutor) ExecuteUpdate(ctx context.Context, request session.UpdateCommandRequest) (out session.UpdateExecution, err error) {
	entered := false
	var b identity.CommandBinding
	defer func() {
		if recover() != nil {
			err = session.ErrUnavailable
			if entered && out.Receipt.Outcome != identity.CommitOutcomeCommitted {
				out.Receipt = unknownUpdate(b)
				err = identity.UnknownCommitError{CommandID: b.CommandID}
			}
		}
	}()
	if ctx == nil || e == nil || e.owned == nil || e.sessions == nil {
		return out, session.ErrInvalidInput
	}
	if err = request.Validate(e.sessions, e.owned.clock.Now()); err != nil {
		return out, err
	}
	bounded, stop := context.WithTimeout(ctx, e.owned.maximumDuration)
	defer stop()
	bounded, stopPrimary, err := (&RevokeOneExecutor{owned: e.owned}).primaryDeadline(bounded, request.ValidUntil())
	if err != nil {
		return out, err
	}
	defer stopPrimary()
	var command identity.Command
	var plan kernel.CommandPlan
	var caller authorization.DecisionContext
	b, command, plan, caller, err = e.prepareUpdate(request)
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
		out.Receipt = result
		return e.updateResult(bounded, request, result, true, err)
	}
	work, err := e.owned.coordinator.Begin(bounded, reservation)
	if err != nil {
		return session.UpdateExecution{Receipt: unknownUpdate(b)}, err
	}
	defer e.owned.coordinator.Abort(work, identity.UnavailableError{})
	provisional, err := e.owned.coordinator.ApplyFeature(bounded, work, command)
	if err != nil {
		result, err = e.owned.coordinator.Abort(work, err)
		return e.updateResult(bounded, request, result, false, err)
	}
	if err = request.Validate(e.sessions, e.owned.clock.Now()); err != nil {
		result, err = e.owned.coordinator.Abort(work, identity.ForbiddenError{})
		return e.updateResult(bounded, request, result, false, err)
	}
	result, err = e.owned.coordinator.Commit(work, provisional)
	out.Receipt = result
	return e.updateResult(bounded, request, result, false, err)
}

// RecoverUpdate observes/reconciles exact historical outcome under current
// result-access policy, even after source expiry. Original same-reader custody
// is historical only; no authentication renewal, mutation or label is returned.
func (e *UpdateExecutor) RecoverUpdate(ctx context.Context, request session.UpdateCommandRequest) (identity.CommandResult, error) {
	if ctx == nil || e == nil || e.owned == nil || e.sessions == nil {
		return identity.CommandResult{}, session.ErrInvalidInput
	}
	if err := request.Validate(e.sessions, request.ValidUntil().Add(-time.Nanosecond)); err != nil {
		return identity.CommandResult{}, err
	}
	command, err := MapUpdateRequest(request)
	if err != nil {
		return identity.CommandResult{}, err
	}
	p, _ := command.Feature()
	b := p.Binding
	q := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID, LinkMode: b.LinkMode}
	bounded, stop := context.WithTimeout(ctx, e.owned.maximumDuration)
	defer stop()
	result, err := e.owned.coordinator.RecoverFeatureCommand(bounded, q, e.updateCaller(b))
	if result.Outcome != identity.CommitOutcomeCommitted {
		return result, err
	}
	// Verify exact retained intent as well as the safe receipt scope. Historical
	// evidence failure cannot erase commitment or imply a new live session.
	_, check := e.updateResult(bounded, request, result, true, nil)
	if check != nil {
		return result, check
	}
	return result, err
}

// RecoverUpdateCommand supports restart-safe outcome observation using exact
// original safe scope and trusted current caller context. It never accepts a
// structural session as authentication, renews a lease or reserves missing IDs.
// Current configured access policy governs disclosure; no device/label payload
// is returned. Cancellation and earlier caller deadlines bound the operation.
func (e *UpdateExecutor) RecoverUpdateCommand(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (identity.CommandResult, error) {
	if ctx == nil || e == nil || e.owned == nil {
		return identity.CommandResult{}, session.ErrInvalidInput
	}
	if q.OperationID != session.UpdateOperation().OperationID || !scopeID(q.RecordID) || q.LinkMode != 0 || q.ActorKind != authorization.SubjectUser || string(q.ActorID) != string(q.UserID) {
		return identity.CommandResult{}, identity.ForbiddenError{}
	}
	bounded, stop := context.WithTimeout(ctx, e.owned.maximumDuration)
	defer stop()
	out, err := e.owned.coordinator.RecoverFeatureCommand(bounded, q, caller)
	if out.Binding.CommandID != "" && (out.Feature == nil || out.Feature.Operation != session.UpdateOperation()) {
		return identity.CommandResult{}, session.ErrUnavailable
	}
	return out, err
}

func unknownUpdate(b identity.CommandBinding) identity.CommandResult {
	return identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeUnknown, Feature: &identity.FeatureReceipt{Operation: session.UpdateOperation()}}
}
func (e *UpdateExecutor) updateCaller(b identity.CommandBinding) authorization.DecisionContext {
	return (&RotationExecutor{owned: e.owned}).rotationCaller(b)
}

func (e *UpdateExecutor) updateResult(ctx context.Context, request session.UpdateCommandRequest, receipt identity.CommandResult, replayed bool, cause error) (session.UpdateExecution, error) {
	out := session.UpdateExecution{Receipt: receipt, Replayed: replayed}
	if receipt.Outcome != identity.CommitOutcomeCommitted {
		return out, cause
	}
	if receipt.Validate() != nil || receipt.Feature == nil || receipt.Feature.Operation != session.UpdateOperation() {
		return out, session.ErrUnavailable
	}
	mapped, err := MapUpdateRequest(request)
	if err != nil {
		return out, err
	}
	p, _ := mapped.Feature()
	if receipt.Binding != p.Binding {
		return out, identity.ConflictError{CommandID: p.Binding.CommandID}
	}
	native, _, _, _ := nativeUpdateIntent(mapped)
	u, _ := native.Update()
	before, _ := u.Source.Bindings()
	after, _ := u.Successor.Bindings()
	if receipt.Feature.BeforeVersion != before.Version || receipt.Feature.AfterVersion != after.Version {
		return out, session.ErrUnavailable
	}
	digest, err := updateIntentDigest(mapped)
	if err != nil {
		return out, err
	}
	read, stop := context.WithTimeout(ctx, e.owned.native.maximumDuration)
	defer stop()
	retained, err := e.owned.native.readUpdate(read, receipt.Binding, kernel.LifecyclePlan{BeforeVersion: before.Version, AfterVersion: after.Version})
	if err != nil {
		return out, err
	}
	labelHash := sha256.Sum256([]byte(u.DeviceLabel))
	es, _, _ := encodeRecord(u.Source)
	en, _, _ := encodeRecord(u.Successor)
	as, _, _ := encodeRecord(retained.source)
	an, _, _ := encodeRecord(retained.successor)
	if retained.intent != digest || retained.label != labelHash || !bytes.Equal(es, as) || !bytes.Equal(en, an) {
		return out, identity.ConflictError{CommandID: receipt.Binding.CommandID}
	}
	// Never let an ancillary error carry apparent successful display metadata.
	if cause == nil {
		out.Session, out.DeviceLabel = retained.successor, u.DeviceLabel
	}
	return out, cause
}

func (e *UpdateExecutor) prepareUpdate(request session.UpdateCommandRequest) (identity.CommandBinding, identity.Command, kernel.CommandPlan, authorization.DecisionContext, error) {
	fail := func(err error) (identity.CommandBinding, identity.Command, kernel.CommandPlan, authorization.DecisionContext, error) {
		return identity.CommandBinding{}, identity.Command{}, kernel.CommandPlan{}, authorization.DecisionContext{}, err
	}
	command, err := MapUpdateRequest(request)
	if err != nil {
		return fail(err)
	}
	native, _, _, err := nativeUpdateIntent(command)
	if err != nil {
		return fail(err)
	}
	u, _ := native.Update()
	b := u.Binding
	if b.PolicyID != e.owned.policyID || b.PolicyVersion != e.owned.policyVersion {
		return fail(identity.ForbiddenError{})
	}
	before, _ := u.Source.Bindings()
	after, _ := u.Successor.Bindings()
	op := session.UpdateOperation()
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return fail(session.ErrUnavailable)
	}
	record, err := builder.Build(audit.RecordInput{OccurredAt: e.owned.clock.Now().UTC().Truncate(time.Microsecond), Action: "identity.session.update", Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "session", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.id": b.RecordID, "aggregate.type": "session", "aggregate.before_version": strconv.FormatUint(before.Version, 10), "aggregate.after_version": strconv.FormatUint(after.Version, 10), "retention.class": "standard"}})
	if err != nil {
		return fail(err)
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, op, "session", record)
	if err != nil {
		return fail(err)
	}
	declaration := kernel.CommandPlan{Contributors: e.owned.registry.Descriptors(), SubjectType: "session", Feature: &kernel.FeatureRegistration{Contributor: e.owned.native.Descriptor(), Operation: op}, Lifecycle: &kernel.LifecyclePlan{EventType: "session.updated.v1", BeforeVersion: before.Version, AfterVersion: after.Version}, Audits: []kernel.AuditPlan{{EventType: "identity.session.update", SchemaVersion: 1, BindingDigest: digest, RetentionClass: "standard", RetentionPolicyVersion: e.owned.retentionVersion, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}}
	plan, err := e.owned.coordinator.PrepareCommandPlan(b, command, declaration)
	if err != nil {
		return fail(err)
	}
	return b, command, plan, e.updateCaller(b), nil
}

// Format redacts borrowed dependencies and runtime policy/key configuration.
func (UpdateExecutor) Format(s fmt.State, _ rune) {
	s.Write([]byte("postgres.UpdateExecutor(redacted)"))
}

// MarshalJSON denies implicit executor export.
func (UpdateExecutor) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// Format redacts borrowed dependencies and configuration for every verb.
func (UpdateExecutorConfig) Format(s fmt.State, _ rune) {
	s.Write([]byte("postgres.UpdateExecutorConfig(redacted)"))
}

// MarshalJSON denies implicit runtime configuration export.
func (UpdateExecutorConfig) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }
