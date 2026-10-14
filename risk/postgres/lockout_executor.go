package postgres

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization"
	authority "github.com/faustbrian/go-authorization/postgres"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	database "github.com/faustbrian/go-postgres"
)

// LockoutExecutorConfig selects one verified administrative actor, tenant,
// target user and native start/end operation. Caller is trusted authenticated
// composition, not request JSON. Both separately selected admission and
// historical disclosure policies are required at the caller's current revision.
// Effect adapters must support the existing coordinator recovery contract.
// Pool and callback ownership remains with the caller; construction performs
// no IO. Repository must explicitly select LockoutMutations and its migrations.
type LockoutExecutorConfig ExecutorConfig

// LockoutExecutionRequest identifies one original command and exact mutation
// intent. Request must match the configured authenticated caller and operation.
// A first start may omit RecordID (CommandID is used); subsequent transitions
// must retain the original record ID and exact version. The executor reads the
// existing authorization owner's actor epoch; callers supply no authority row.
// Retain this unchanged for Execute retries or Recover; changing intent cannot
// replay an original success or cause a new effect under the same command ID.
type LockoutExecutionRequest struct {
	CommandID identity.CommandID
	RecordID  string
	Request   risk.LockoutRequest
}

// LockoutSnapshot is the exact original committed post-mutation state, not the
// current restriction or a permission. End preserves StartedAt/ExpiresAt and
// records EndedAt separately. Returned pointers are independently owned; no
// digest, policy permit, counter root or raw network/session input is exposed.
type LockoutSnapshot struct {
	RecordID      string
	Operation     risk.Action
	Version       uint64
	PolicyVersion uint64
	StartedAt     time.Time
	ExpiresAt     time.Time
	EndedAt       *time.Time
}

// LockoutExecution retains the existing coordinator's classified outcome.
// Snapshot is present only after current-policy-authorized primary commitment
// resolution and exact original-intent matching. Unknown or failed execution
// never exposes a provisional snapshot; a committed result is historical only.
type LockoutExecution struct {
	Command  identity.CommandResult
	Snapshot *LockoutSnapshot
}

// LockoutExecutor owns preparation, same-Work mutation, audit/lifecycle and
// authorized original-result recovery through the sole coordinator. It opens
// no private mutation transaction, never retries an unknown effect, and does
// not renew an original decision or recreate a snapshot from latest state.
// Zero is invalid; immutable instances support concurrent independent calls.
type LockoutExecutor struct {
	pool        *database.Pool
	repository  *Repository
	coordinator *identitypostgres.Coordinator
	registry    *identitypostgres.ContributorRegistry
	authority   *authority.AuthorityStore
	caller      authorization.DecisionContext
	retention   uint64
	timeout     time.Duration
}

// Format hides trusted caller and runtime dependency custody.
func (LockoutExecutorConfig) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.LockoutExecutorConfig(redacted)")
}

// MarshalJSON forbids serialization of authenticated runtime configuration.
func (LockoutExecutorConfig) MarshalJSON() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}

// MarshalText forbids serialization of authenticated runtime configuration.
func (LockoutExecutorConfig) MarshalText() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}

// Format redacts correlated actor, subject and transient network facts.
func (LockoutExecutionRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.LockoutExecutionRequest(redacted)")
}

// MarshalJSON forbids exporting trusted internal workflow input.
func (LockoutExecutionRequest) MarshalJSON() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}

// MarshalText forbids exporting trusted internal workflow input.
func (LockoutExecutionRequest) MarshalText() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}

// Format hides caller context and retained runtime custody.
func (LockoutExecutor) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.LockoutExecutor(redacted)")
}

// MarshalJSON forbids exporting runtime workflow custody.
func (LockoutExecutor) MarshalJSON() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }

// MarshalText forbids exporting runtime workflow custody.
func (LockoutExecutor) MarshalText() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }

// NewLockoutExecutor validates and copies one bounded scope without callbacks,
// network activity or resource ownership transfer. Unsupported/incomplete
// composition returns ErrInvalidPolicy; selected schemas fail closed at runtime.
func NewLockoutExecutor(c LockoutExecutorConfig) (*LockoutExecutor, error) {
	if c.Pool == nil || c.Pool.Raw() == nil || c.Repository == nil || c.Repository.lockoutMutation == nil || !boundedLockoutCaller(c.Caller) || c.PolicyID != c.Repository.lockoutMutation.config.PolicyID || c.RetentionPolicyVersion == 0 || c.Coordinator.QueryPolicy == nil || c.Coordinator.AdmissionPolicy == nil || uint64(c.Caller.PolicyRevision) != c.Repository.lockoutMutation.config.PolicyRevision || uint64(c.Caller.PolicyRevision) != c.Coordinator.QueryPolicy.PolicyVersion || uint64(c.Caller.PolicyRevision) != c.Coordinator.AdmissionPolicy.PolicyVersion {
		return nil, risk.ErrInvalidPolicy
	}
	if a := c.Caller.Request.Action; a != authorization.Action(LockoutOperation(risk.StartLockout).OperationID) && a != authorization.Action(LockoutOperation(risk.EndLockout).OperationID) {
		return nil, risk.ErrInvalidPolicy
	}
	kernel, err := identitypostgres.NewRepository(c.Pool, identitypostgres.Config{MaximumDuration: c.Coordinator.MaximumDuration})
	if err != nil {
		return nil, risk.ErrInvalidPolicy
	}
	registry, err := identitypostgres.NewContributorRegistry([]identitypostgres.Contributor{kernel, c.Repository, c.Audit, c.Lifecycle})
	if err != nil {
		return nil, risk.ErrInvalidPolicy
	}
	d := registry.Descriptors()
	if d[2].Owner != "audit/postgres" || d[2].Version != 1 || (d[2].ContractID != "identity.audit" && d[2].ContractID != "identity.security_audit") || d[3] != (identitypostgres.ContributorDescriptor{Owner: "outbox/postgres", ContractID: "identity.lifecycle", Version: 1}) {
		return nil, risk.ErrInvalidPolicy
	}
	if _, ok := c.Audit.(identitypostgres.RecoveryContributor); !ok {
		return nil, risk.ErrInvalidPolicy
	}
	if _, ok := c.Lifecycle.(identitypostgres.RecoveryContributor); !ok {
		return nil, risk.ErrInvalidPolicy
	}
	coord, err := identitypostgres.NewCoordinator(c.Pool, registry, c.Coordinator)
	if err != nil {
		return nil, risk.ErrInvalidPolicy
	}
	actorStore, err := authority.NewAuthorityStore(c.Pool.Raw(), c.Repository.lockoutMutation.config.MaximumDuration)
	if err != nil {
		return nil, risk.ErrInvalidPolicy
	}
	return &LockoutExecutor{pool: c.Pool, repository: c.Repository, coordinator: coord, registry: registry, authority: actorStore, caller: c.Caller.Clone(), retention: c.RetentionPolicyVersion, timeout: c.Coordinator.MaximumDuration}, nil
}

func (e *LockoutExecutor) input(i LockoutExecutionRequest) (LockoutCommandRequest, identity.RecoveryQuery, error) {
	if e == nil || e.coordinator == nil {
		return LockoutCommandRequest{}, identity.RecoveryQuery{}, risk.ErrInvalidCounterCommand
	}
	r := e.caller.Request
	op := LockoutOperation(i.Request.Mode)
	if op.OperationID != string(r.Action) || i.Request.Scope.Tenant != string(r.Tenant) || i.Request.Scope.Attempt != string(i.CommandID) || i.Request.Subject.User != string(r.Resource.ID) || i.Request.Actor != string(r.Subject.ID) || !i.Request.Scope.Now.IsZero() || i.Request.Scope.IndependentFactor || len(i.Request.Subject.Network) > 128 || len(i.Request.Subject.Session) > 128 || i.Request.Subject.Device != "" || i.Request.Subject.IdentifierDigest != "" || i.Request.Subject.Actor != "" || i.Request.Subject.Resource != "" || i.Request.ExpectedVersion == ^uint64(0) || i.Request.Duration < 0 {
		return LockoutCommandRequest{}, identity.RecoveryQuery{}, risk.ErrInvalidCounterCommand
	}
	id := i.RecordID
	if id == "" && i.Request.Mode == risk.StartLockout && i.Request.ExpectedVersion == 0 {
		id = string(i.CommandID)
	}
	b := identity.CommandBinding{CommandID: i.CommandID, TenantID: identity.TenantID(r.Tenant), UserID: identity.UserID(r.Resource.ID), ActorID: identity.ActorID(r.Subject.ID), ActorKind: r.Subject.Kind, RecordID: id, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, PolicyID: e.repository.lockoutMutation.config.PolicyID, PolicyVersion: e.repository.policy, CorrelationID: string(i.CommandID)}
	if b.ValidateFor(op) != nil {
		return LockoutCommandRequest{}, identity.RecoveryQuery{}, risk.ErrInvalidCounterCommand
	}
	if _, err := identity.ParseSubjectID(id); err != nil {
		return LockoutCommandRequest{}, identity.RecoveryQuery{}, risk.ErrInvalidCounterCommand
	}
	dc := e.caller.Clone()
	dc.CorrelationID = b.CorrelationID
	q := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
	return LockoutCommandRequest{Binding: b, Scope: dc, Request: i.Request}, q, nil
}

// Execute performs at most one new mutation. Authorized existing history is
// reconciled instead of preparing a new command or refreshing its freshness.
// Unknown remains bound to this request and must be resolved with Recover;
// earlier caller deadlines win and all policy callbacks run outside Work.
func (e *LockoutExecutor) Execute(ctx context.Context, i LockoutExecutionRequest) (LockoutExecution, error) {
	if ctx == nil {
		return LockoutExecution{}, risk.ErrInvalidCounterCommand
	}
	n, q, err := e.input(i)
	if err != nil {
		return LockoutExecution{}, err
	}
	bounded, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	a, err := e.coordinator.ObserveCommandAdmission(bounded, q, n.Scope)
	if err != nil {
		return LockoutExecution{}, err
	}
	if a.Validate() != nil {
		return LockoutExecution{}, identity.UnavailableError{}
	}
	if !a.Absent {
		return e.recover(bounded, i, q, n.Scope)
	}
	actor, err := e.authority.Get(bounded, authority.AuthorityScope{TenantID: authorization.TenantID(q.TenantID), PolicyNamespace: e.repository.lockoutMutation.config.AuthorityNamespace, SubjectID: authorization.SubjectID(q.ActorID)})
	if err != nil {
		if bounded.Err() != nil {
			return LockoutExecution{}, bounded.Err()
		}
		if errors.Is(err, authority.ErrAuthorityDenied) {
			return LockoutExecution{}, identity.ForbiddenError{}
		}
		return LockoutExecution{}, identity.UnavailableError{}
	}
	n.AuthorityVersion = actor.Version
	var at time.Time
	if err = e.pool.Raw().QueryRow(bounded, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		if bounded.Err() != nil {
			return LockoutExecution{}, bounded.Err()
		}
		return LockoutExecution{}, identity.UnavailableError{}
	}
	c, err := e.repository.PrepareLockoutCommand(bounded, n, at.UTC())
	if err != nil {
		return LockoutExecution{}, err
	}
	p, err := e.plan(n.Binding, c, i.Request.Mode, i.Request.ExpectedVersion, at.UTC())
	if err != nil {
		return LockoutExecution{}, err
	}
	res, result, err := e.coordinator.ReserveCommand(bounded, n.Binding, c, p)
	if result.Outcome == identity.CommitOutcomeUnknown {
		return LockoutExecution{Command: result}, err
	}
	if err != nil || result.Outcome != identity.CommitOutcomeInProgress {
		return e.recover(bounded, i, q, n.Scope)
	}
	w, err := e.coordinator.Begin(bounded, res)
	if err != nil {
		return e.recover(bounded, i, q, n.Scope)
	}
	defer e.coordinator.Abort(w, identity.UnavailableError{})
	result, err = e.coordinator.ApplyFeature(bounded, w, c)
	if err != nil {
		_, _ = e.coordinator.Abort(w, err)
		return e.recover(bounded, i, q, n.Scope)
	}
	result, err = e.coordinator.Commit(w, result)
	if result.Outcome == identity.CommitOutcomeUnknown {
		return LockoutExecution{Command: result}, err
	}
	return e.recover(bounded, i, q, n.Scope)
}

// Recover authorizes historical disclosure through the configured current
// QueryPolicy, reconciles the original command, and reads its immutable domain
// version. It performs no new start/end, intent signing, provider work or retry.
// Missing, denied, malformed and unknown history never returns a snapshot.
func (e *LockoutExecutor) Recover(ctx context.Context, i LockoutExecutionRequest) (LockoutExecution, error) {
	if ctx == nil {
		return LockoutExecution{}, risk.ErrInvalidCounterCommand
	}
	n, q, err := e.input(i)
	if err != nil {
		return LockoutExecution{}, err
	}
	bounded, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	return e.recover(bounded, i, q, n.Scope)
}

func (e *LockoutExecutor) recover(ctx context.Context, i LockoutExecutionRequest, q identity.RecoveryQuery, caller authorization.DecisionContext) (LockoutExecution, error) {
	r, err := e.coordinator.RecoverFeatureCommand(ctx, q, caller)
	result := LockoutExecution{Command: r}
	if err != nil || r.Outcome != identity.CommitOutcomeCommitted {
		return result, err
	}
	if r.Feature == nil || r.Feature.Operation != LockoutOperation(i.Request.Mode) || r.Feature.BeforeVersion != i.Request.ExpectedVersion || r.Feature.AfterVersion != i.Request.ExpectedVersion+1 {
		return LockoutExecution{}, identity.ForbiddenError{}
	}
	raw, err := base64.RawURLEncoding.DecodeString(string(q.CommandID))
	if err != nil || len(raw) != 16 {
		return result, identity.UnavailableError{}
	}
	var snapshot LockoutSnapshot
	var binding, intent []byte
	var version, policy string
	var actorEpoch string
	var signing int64
	err = e.pool.Raw().QueryRow(ctx, `SELECT record_id,operation,after_version::text,policy_version::text,started_at,expires_at,ended_at,binding_digest,intent_digest,signing_version,authority_version::text FROM `+e.repository.schema+`.lockout_transitions WHERE command_id=$1 AND tenant_id=$2 AND command_operation=$3`, raw, string(q.TenantID), q.OperationID).Scan(&snapshot.RecordID, &snapshot.Operation, &version, &policy, &snapshot.StartedAt, &snapshot.ExpiresAt, &snapshot.EndedAt, &binding, &intent, &signing, &actorEpoch)
	if err != nil || ctx.Err() != nil || signing < 1 || signing > 4294967295 || len(binding) != 32 || len(intent) != 32 {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		return result, identity.UnavailableError{}
	}
	snapshot.Version, err = strconv.ParseUint(version, 10, 64)
	snapshot.PolicyVersion, _ = strconv.ParseUint(policy, 10, 64)
	key, ok := e.repository.lockoutMutation.config.SigningKeys[uint32(signing)]
	authorityVersion, ae := strconv.ParseUint(actorEpoch, 10, 64)
	if ae != nil || authorityVersion == 0 {
		return result, identity.UnavailableError{}
	}
	digest := bindingDigest(r.Binding)
	expected := lockoutIntentDigest(key, r.Binding, i.Request, authorityVersion)
	if !ok || !hmac.Equal(binding, digest[:]) || !hmac.Equal(intent, expected[:]) {
		return LockoutExecution{}, identity.ForbiddenError{}
	}
	if err != nil || snapshot.RecordID != q.RecordID || snapshot.Operation != i.Request.Scope.Operation || snapshot.Version != r.Feature.AfterVersion || snapshot.PolicyVersion != r.Binding.PolicyVersion || !lockoutTime(snapshot.StartedAt) || !lockoutTime(snapshot.ExpiresAt) || !snapshot.ExpiresAt.After(snapshot.StartedAt) || snapshot.EndedAt != nil && (!lockoutTime(*snapshot.EndedAt) || snapshot.EndedAt.Before(snapshot.StartedAt)) || (i.Request.Mode == risk.EndLockout) != (snapshot.EndedAt != nil) {
		return result, identity.UnavailableError{}
	}
	snapshot.StartedAt = snapshot.StartedAt.UTC()
	snapshot.ExpiresAt = snapshot.ExpiresAt.UTC()
	if snapshot.EndedAt != nil {
		t := snapshot.EndedAt.UTC()
		snapshot.EndedAt = &t
	}
	result.Snapshot = &snapshot
	return result, nil
}

func (e *LockoutExecutor) plan(b identity.CommandBinding, c identity.Command, mode risk.LockoutMode, before uint64, at time.Time) (identitypostgres.CommandPlan, error) {
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return identitypostgres.CommandPlan{}, err
	}
	action, event := lockoutEvents(mode)
	kind := audit.ActorService
	if b.ActorKind == authorization.SubjectUser {
		kind = audit.ActorHuman
	}
	seed, err := builder.Build(audit.RecordInput{OccurredAt: at, Action: action, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: kind, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "risk_lockout", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "risk_lockout", "aggregate.id": b.RecordID, "aggregate.before_version": strconv.FormatUint(before, 10), "aggregate.after_version": strconv.FormatUint(before+1, 10), "retention.class": "protected"}})
	if err != nil {
		return identitypostgres.CommandPlan{}, err
	}
	op := LockoutOperation(mode)
	digest, err := identitypostgres.FeatureAuditBindingDigest(b, op, "risk_lockout", seed)
	if err != nil {
		return identitypostgres.CommandPlan{}, err
	}
	return e.coordinator.PrepareCommandPlan(b, c, identitypostgres.CommandPlan{Contributors: e.registry.Descriptors(), SubjectType: "risk_lockout", Feature: &identitypostgres.FeatureRegistration{Contributor: e.repository.Descriptor(), Operation: op}, Lifecycle: &identitypostgres.LifecyclePlan{EventType: event, BeforeVersion: before, AfterVersion: before + 1}, Audits: []identitypostgres.AuditPlan{{EventType: action, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: e.retention, RetentionClass: "protected", BindingDigest: digest}}})
}
