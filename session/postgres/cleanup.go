package postgres

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// CleanupCommand selects one exact tenant/user partition and at most Limit
// indexed expiry candidates (1..10000). CommandID is stable across retries;
// changing scope, correlation or limit under that ID conflicts. It carries no
// caller-selected time, authentication proof or bearer. Zero is invalid.
type CleanupCommand struct {
	TenantID      identity.TenantID
	UserID        identity.UserID
	CommandID     identity.CommandID
	CorrelationID string
	Limit         uint32
}

// CleanupResult carries a historical command receipt and, on verified success
// only, its retained deletion count and database-time backlog observation.
// RemainingLag is zero if no expired payload remained at ObservedAt; locked
// candidates remain included. It saturates at 8760 hours, is partition-scoped,
// and is not a claim that a later concurrent refresh/deletion did not change it.
// No result authenticates a user or permits retry of an uncertain command.
type CleanupResult struct {
	Command      identity.CommandResult
	Deleted      uint32
	RemainingLag time.Duration
	ObservedAt   time.Time
}

// CleanupServiceConfig enables native expiry maintenance under current policy
// for a trusted service ActorID, never an input-selected actor. MaximumBatch is
// 1..10000; per-call Limit cannot exceed it. Execution borrows the existing
// native primary/kernel/audit/lifecycle dependencies. Zero is invalid.
type CleanupServiceConfig struct {
	Execution    IssueExecutorConfig
	ActorID      identity.ActorID
	MaximumBatch uint32
}

// CleanupService owns explicit bounded expiry commands, not a scheduler, pool,
// transaction, journal or background goroutine. Calls are concurrency-safe.
// Keep borrowed dependencies alive until all calls finish. Install the complete
// session/rotation and CleanupMigrationSource histories before use.
type CleanupService struct {
	owned *IssueExecutor
	actor identity.ActorID
	batch uint32
}

// NewCleanupService freezes trusted composition without IO. Natural expiry
// prunes live payloads only; it never increments session/family/user authority
// or deletes retained command, proof-use, rotation or revocation evidence.
func NewCleanupService(pool *database.Pool, c CleanupServiceConfig) (*CleanupService, error) {
	if !scopeID(string(c.ActorID)) || c.MaximumBatch < 1 || c.MaximumBatch > 10000 {
		return nil, session.ErrInvalidInput
	}
	owned, err := newOwnedSessionExecutionWithCleanup(pool, c.Execution, false, c.MaximumBatch)
	if err != nil {
		return nil, err
	}
	return &CleanupService{owned, identity.ActorID(strings.Clone(string(c.ActorID))), c.MaximumBatch}, nil
}

func cleanupOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/session", OperationID: "identity.session.expire", SchemaID: "session-expiry-cleanup", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted}
}

func cleanupIntent(b identity.CommandBinding, limit uint32) (identity.Command, error) {
	if limit == 0 || limit > 10000 || b.ActorKind != authorization.SubjectServiceAccount {
		return identity.Command{}, session.ErrInvalidInput
	}
	return identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: cleanupOperation(), Fields: []identity.FeatureField{{Name: "limit", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(limit)}}}})
}

func nativeCleanup(command identity.Command) (identity.CommandBinding, uint32, error) {
	s, ok := command.Feature()
	if !ok || s.Operation != cleanupOperation() || s.Binding.ActorKind != authorization.SubjectServiceAccount || len(s.Fields) != 1 || s.Fields[0].Name != "limit" || s.Fields[0].Value.Kind != identity.FeatureUint64 || s.Fields[0].Value.Uint64 < 1 || s.Fields[0].Value.Uint64 > 10000 {
		return identity.CommandBinding{}, 0, session.ErrInvalidSessionCommand
	}
	return s.Binding, uint32(s.Fields[0].Value.Uint64), nil
}

// CleanupExpired authorizes before reservation and commits one bounded locked
// primary-time cleanup, retained result, required audit and lifecycle together.
// An exact retry observes its original result instead of selecting more rows.
// SKIP LOCKED leaves concurrent refresh/cleanup candidates for a later command.
// Earlier caller deadlines win. Cancellation/panic/failed acknowledgement after
// reservation does not prove rollback; recover the returned safe scope instead.
func (s *CleanupService) CleanupExpired(ctx context.Context, input CleanupCommand) (out CleanupResult, err error) {
	entered := false
	var b identity.CommandBinding
	defer func() {
		if recover() != nil {
			err = session.ErrUnavailable
			if entered && out.Command.Outcome != identity.CommitOutcomeCommitted {
				out = CleanupResult{Command: unknownCleanup(b)}
				err = identity.UnknownCommitError{CommandID: b.CommandID}
			}
		}
	}()
	if ctx == nil || s == nil || s.owned == nil || !scopeID(string(input.TenantID)) || !scopeID(string(input.UserID)) || !scopeID(input.CorrelationID) || input.Limit == 0 || input.Limit > s.batch {
		return out, session.ErrInvalidInput
	}
	op := cleanupOperation()
	b = identity.CommandBinding{CommandID: input.CommandID, TenantID: input.TenantID, UserID: input.UserID, ActorID: s.actor, ActorKind: authorization.SubjectServiceAccount, OperationID: op.OperationID, PolicyID: s.owned.policyID, PolicyVersion: s.owned.policyVersion, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, CorrelationID: input.CorrelationID}
	command, err := cleanupIntent(b, input.Limit)
	if err != nil {
		return out, err
	}
	bounded, stop := context.WithTimeout(ctx, s.owned.maximumDuration)
	defer stop()
	caller := s.cleanupCaller(b)
	if err = s.owned.allow(bounded, caller); err != nil {
		return out, err
	}
	plan, err := s.cleanupPlan(b, command)
	if err != nil {
		return out, err
	}
	entered = true
	reservation, result, err := s.owned.coordinator.ReserveCommand(bounded, b, command, plan)
	if err != nil || reservation == (kernel.Reservation{}) {
		out.Command = result
		return s.cleanupResult(bounded, result, err)
	}
	work, err := s.owned.coordinator.Begin(bounded, reservation)
	if err != nil {
		return CleanupResult{Command: unknownCleanup(b)}, err
	}
	defer s.owned.coordinator.Abort(work, identity.UnavailableError{})
	provisional, err := s.owned.coordinator.ApplyFeature(bounded, work, command)
	if err != nil {
		result, err = s.owned.coordinator.Abort(work, err)
		return s.cleanupResult(bounded, result, err)
	}
	result, err = s.owned.coordinator.Commit(work, provisional)
	out.Command = result
	return s.cleanupResult(bounded, result, err)
}

func unknownCleanup(b identity.CommandBinding) identity.CommandResult {
	return identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeUnknown, Feature: &identity.FeatureReceipt{Operation: cleanupOperation()}}
}

func (s *CleanupService) cleanupCaller(b identity.CommandBinding) authorization.DecisionContext {
	return authorization.DecisionContext{PolicyRevision: authorization.Revision(s.owned.policyVersion), CorrelationID: b.CorrelationID, Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(s.actor), Kind: authorization.SubjectServiceAccount}, Action: authorization.Action(b.OperationID), Tenant: authorization.TenantID(b.TenantID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}}}
}

func (s *CleanupService) cleanupPlan(b identity.CommandBinding, command identity.Command) (kernel.CommandPlan, error) {
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.CommandPlan{}, session.ErrUnavailable
	}
	record, err := builder.Build(audit.RecordInput{OccurredAt: s.owned.clock.Now().UTC().Truncate(time.Microsecond), Action: "identity.session.expire", Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "session_cleanup", ID: string(b.UserID)}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "session_cleanup", "aggregate.id": string(b.UserID), "aggregate.before_version": "0", "aggregate.after_version": "0", "retention.class": "standard"}})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, cleanupOperation(), "session_cleanup", record)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	return s.owned.coordinator.PrepareCommandPlan(b, command, kernel.CommandPlan{Contributors: s.owned.registry.Descriptors(), SubjectType: "session_cleanup", Feature: &kernel.FeatureRegistration{Contributor: s.owned.native.Descriptor(), Operation: cleanupOperation()}, Lifecycle: &kernel.LifecyclePlan{EventType: "session.expired.v1"}, Audits: []kernel.AuditPlan{{EventType: "identity.session.expire", SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionClass: "standard", RetentionPolicyVersion: s.owned.retentionVersion, BindingDigest: digest}}})
}

// RecoverCleanupCommand returns the original historical outcome/count/lag under
// current trusted service access policy, without selecting a new batch. Exact
// tenant/user/actor/operation scope is required; RecordID and LinkMode are empty.
// Missing/denied commands reveal nothing. Live leases are not renewed; expired
// pending reconciles only through the kernel's frozen participant evidence.
func (s *CleanupService) RecoverCleanupCommand(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (CleanupResult, error) {
	if ctx == nil || s == nil || s.owned == nil {
		return CleanupResult{}, session.ErrInvalidInput
	}
	if q.OperationID != cleanupOperation().OperationID || q.ActorKind != authorization.SubjectServiceAccount || q.ActorID != s.actor || q.RecordID != "" || q.LinkMode != 0 {
		return CleanupResult{}, identity.ForbiddenError{}
	}
	bounded, stop := context.WithTimeout(ctx, s.owned.maximumDuration)
	defer stop()
	result, err := s.owned.coordinator.RecoverFeatureCommand(bounded, q, caller)
	return s.cleanupResult(bounded, result, err)
}

// Format redacts runtime policy and service custody.
func (CleanupService) Format(s fmt.State, _ rune) {
	s.Write([]byte("postgres.CleanupService(redacted)"))
}

// Format redacts borrowed configuration.
func (CleanupServiceConfig) Format(s fmt.State, _ rune) {
	s.Write([]byte("postgres.CleanupServiceConfig(redacted)"))
}

// MarshalJSON denies implicit runtime export.
func (CleanupService) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalJSON denies implicit configuration export.
func (CleanupServiceConfig) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }
