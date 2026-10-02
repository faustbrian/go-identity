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
)

// CreationUnitOfWorkConfig fixes the positive audit retention policy revision
// before admission. It is immutable copied configuration, not a callback or
// participant factory. Field-update compositions use the same retention input.
type CreationUnitOfWorkConfig struct{ RetentionPolicyVersion uint64 }

// CreationUnitOfWork is the owned creation-only implementation of the core
// durable command seam. Use it only behind UserCreationService, which supplies
// current authorization, field preparation and output redaction. Direct calls
// do not authorize a caller. The exact Repository must already be enlisted
// with typed audit/outbox adapters in Coordinator. It starts no background work
// and owns no pool; immutable composition supports concurrent service calls.
// Zero is invalid. Creation recovery requires every frozen participant's typed
// recovery phase; other profiles/deadline alerting remain under development.
type CreationUnitOfWork struct {
	coordinator  *Coordinator
	repository   *Repository
	retention    uint64
	contributors []ContributorDescriptor
}

var _ identity.UnitOfWork = (*CreationUnitOfWork)(nil)

// NewCreationUnitOfWork validates exact instance/phase composition without I/O
// or contributor callbacks. Consumers supply owned adapters, not a plan,
// audit builder, transaction, Work or command orchestration implementation.
func NewCreationUnitOfWork(c *Coordinator, r *Repository, config CreationUnitOfWorkConfig) (*CreationUnitOfWork, error) {
	if c == nil || c.pool == nil || c.pool.Raw() == nil || c.registry == nil || c.registry.state == nil || r == nil || r.read == nil || config.RetentionPolicyVersion == 0 {
		return nil, coordinatorError()
	}
	owner := &CreationUnitOfWork{coordinator: c, repository: r, retention: config.RetentionPolicyVersion}
	domain, auditing, lifecycle := 0, 0, 0
	for _, entry := range c.registry.state.entries {
		switch entry.descriptor.Owner {
		case "identity/postgres":
			if entry.contributor != r {
				return nil, coordinatorError()
			}
			domain++
		case "audit/postgres":
			if _, ok := entry.contributor.(AuditContributor); !ok {
				return nil, coordinatorError()
			}
			auditing++
		case "outbox/postgres":
			if _, ok := entry.contributor.(LifecycleContributor); !ok || entry.descriptor.ContractID != "identity.lifecycle" || entry.descriptor.Version != 1 {
				return nil, coordinatorError()
			}
			lifecycle++
		default:
			continue
		}
		owner.contributors = append(owner.contributors, entry.descriptor)
	}
	if domain != 1 || auditing != 1 || lifecycle != 1 {
		return nil, coordinatorError()
	}
	return owner, nil
}

// Format prevents runtime composition or retained dependencies from disclosure.
func (CreationUnitOfWork) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.CreationUnitOfWork(redacted)"))
}

// MarshalJSON rejects serialization of runtime composition.
func (CreationUnitOfWork) MarshalJSON() ([]byte, error) { return nil, coordinatorError() }

// Execute maps the already admitted typed creation to the sole Coordinator.
// Replay preserves original receipts and event IDs. One primary transaction
// owns user/attributes/audit/lifecycle/result. Failure records are built from
// primary time before domain writes and staged only after proven rollback;
// no failed Work is revived. A failed audit commit or ambiguous closure remains
// Unknown. Unsupported commands/actor profiles fail before reservation. This
// trusted adapter seam is not an authenticated application endpoint.
func (o *CreationUnitOfWork) Execute(ctx context.Context, command identity.Command) (result identity.CommandResult, err error) {
	return o.execute(ctx, command, "identity.user.create")
}

// Field-update composition selects an additional command variant, not another
// reservation, transaction or recovery owner.
func (o *CreationUnitOfWork) execute(ctx context.Context, command identity.Command, operation string) (result identity.CommandResult, err error) {
	if o == nil || ctx == nil || o.coordinator == nil || o.repository == nil {
		return result, coordinatorError()
	}
	spec, ok := command.CreateUser()
	profile, updating := command.UpdateProfile()
	admin, administering := command.UpdateUser()
	if operation != "identity.user.create" && operation != "identity.profile.update" && operation != "identity.user.update-admin" || !ok && !updating && !administering || ok && spec.Binding.OperationID != operation || updating && profile.Binding.OperationID != operation || administering && admin.Binding.OperationID != operation {
		return result, identity.InvalidInputError{Field: "creation_command"}
	}
	binding, before := spec.Binding, uint64(0)
	if updating {
		binding, before = profile.Binding, profile.ExpectedVersion
		if _, _, e := o.repository.prepareProfileAttributes(profile); e != nil {
			return result, e
		}
	} else if administering {
		binding, before = admin.Binding, admin.ExpectedVersion
		if _, _, e := o.repository.prepareAdministrativeAttributes(admin); e != nil {
			return result, e
		}
	} else {
		if _, _, e := o.repository.prepareCreationAttributes(spec); e != nil {
			return result, e
		}
	}
	c := o.coordinator
	bounded, cancel := context.WithTimeout(ctx, c.maximumDuration)
	defer cancel()
	seed, e := kernelMutationAudit(bounded, binding, before, time.Now().UTC().Truncate(time.Microsecond), "committed")
	if e != nil {
		return result, e
	}
	digest, e := AuditBindingDigest(binding, seed)
	if e != nil {
		return result, e
	}
	plan, e := c.PrepareCommandPlan(binding, command, CommandPlan{Contributors: o.contributors, Audits: []AuditPlan{{EventType: kernelCommandAudit(binding.OperationID), SchemaVersion: 1, BindingDigest: digest, RetentionPolicyVersion: o.retention, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}, Lifecycle: &LifecyclePlan{EventType: kernelLifecycleEvent(binding.OperationID), BeforeVersion: before, AfterVersion: before + 1}})
	if e != nil {
		return result, e
	}
	reservation, result, err := c.ReserveCommand(bounded, binding, command, plan)
	if err != nil || reservation.state == nil {
		return coreCreationReceipt(result, err)
	}
	result = identity.CommandResult{Binding: binding, Outcome: identity.CommitOutcomeUnknown}
	var work Work
	defer func() {
		panicked := recover() != nil
		if work.state != nil && !work.state.closed {
			result, err = c.Abort(work, identity.UnavailableError{})
		}
		if panicked {
			// Commit's panic cleanup may already have terminalized. Observe the same
			// primary scope without executing or allocating another command.
			cleanup, stop := context.WithTimeout(context.Background(), c.maximumDuration)
			defer stop()
			observed, e := o.recover(cleanup, creationRecoveryQuery(binding), operation)
			if observed.Validate() == nil && observed.Outcome != identity.CommitOutcomeInProgress {
				result, err = observed, e
			} else {
				result = identity.CommandResult{Binding: binding, Outcome: identity.CommitOutcomeUnknown}
				err = identity.UnavailableError{}
			}
		}
		result, err = coreCreationReceipt(result, err)
	}()
	work, err = c.Begin(bounded, reservation)
	if err != nil {
		return result, err
	}
	now, e := work.DatabaseTime(bounded)
	if e != nil {
		return c.Abort(work, e)
	}
	work.state.execution.abortAudits = make(map[string]audit.Record, 5)
	for _, class := range []string{"denied", "conflict", "cancelled", "deadline-exceeded", "dependency-failure"} {
		record, e := kernelMutationAudit(bounded, binding, before, now, class)
		if e != nil {
			return c.Abort(work, e)
		}
		work.state.execution.abortAudits[class] = record
	}
	success, e := kernelMutationAudit(bounded, binding, before, now, "committed")
	if e != nil {
		return c.Abort(work, e)
	}
	var user identity.User
	var updated identity.UserProfile
	if updating {
		updated, e = o.repository.ApplyProfileUpdate(bounded, work, command)
		user = identity.User{ID: binding.UserID, TenantID: binding.TenantID, Status: identity.StatusActive, Version: updated.Version}
	} else if administering {
		user, e = o.repository.ApplyUserUpdate(bounded, work, command)
	} else {
		user, e = o.repository.ApplyUserCreation(bounded, work, command)
	}
	if e != nil {
		r, e := c.Abort(work, e)
		return coreCreationReceipt(r, e)
	}
	if e = work.StageAudit(0, success); e != nil {
		return c.Abort(work, e)
	}
	if e = work.StageLifecycle(0, now); e != nil {
		return c.Abort(work, e)
	}
	result = identity.CommandResult{Binding: binding, Outcome: identity.CommitOutcomeCommitted, User: user, AuditEventID: success.ID()}
	if updating || administering {
		result.ExpectedVersion = before
	}
	if updating {
		result.Profile = &updated
	}
	result, err = c.Commit(work, result)
	return coreCreationReceipt(result, err)
}

// Recover observes historical creation on the primary for the exact original
// scope, without constructing an authenticated DecisionContext from IDs. It
// belongs behind core current authorization/redaction, not a public transport.
// Missing/wrong scope reveals no receipt; live pending is InProgress. Expired
// creation may be aborted only with all frozen participants' negative evidence
// and atomically persisted failure auditing. Missing/unknown evidence stays
// pending. This never infers success from current user state or replays commands.
func (o *CreationUnitOfWork) Recover(ctx context.Context, q identity.RecoveryQuery) (identity.CommandResult, error) {
	return o.recover(ctx, q, "identity.user.create")
}

func (o *CreationUnitOfWork) recover(ctx context.Context, q identity.RecoveryQuery, operation string) (identity.CommandResult, error) {
	if o == nil || o.coordinator == nil || ctx == nil || q.OperationID != operation || operation != "identity.user.create" && operation != "identity.profile.update" && operation != "identity.user.update-admin" {
		return identity.CommandResult{}, coordinatorError()
	}
	if _, e := identity.ParseCommandID(string(q.CommandID)); e != nil {
		return identity.CommandResult{}, identity.InvalidInputError{Field: "command_id"}
	}
	for _, value := range []string{string(q.TenantID), string(q.UserID), string(q.ActorID), string(q.ActorKind), q.OperationID} {
		if !queryScopeText(value) {
			return identity.CommandResult{}, identity.InvalidInputError{Field: "command_query"}
		}
	}
	if q.RecordID != "" || q.LinkMode != 0 {
		return identity.CommandResult{}, identity.ForbiddenError{}
	}
	c := o.coordinator
	bounded, cancel := context.WithTimeout(ctx, c.maximumDuration)
	defer cancel()
	if e := bounded.Err(); e != nil {
		return identity.CommandResult{}, readFailure(bounded, e)
	}
	result, e := c.recoverCommandReceipt(bounded, q)
	return coreCreationReceipt(result, e)
}

func creationRecoveryQuery(b identity.CommandBinding) identity.RecoveryQuery {
	return identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID, LinkMode: b.LinkMode}
}

// Core classifies authoritative closed outcomes itself; infrastructure errors
// must not mask Conflict/InProgress/NotCommitted as an unavailable dependency.
func coreCreationReceipt(r identity.CommandResult, e error) (identity.CommandResult, error) {
	if r.Validate() == nil && (r.Outcome == identity.CommitOutcomeConflict || r.Outcome == identity.CommitOutcomeInProgress || r.Outcome == identity.CommitOutcomeNotCommitted) {
		return r, nil
	}
	return r, e
}

func creationAudit(ctx context.Context, b identity.CommandBinding, now time.Time, class string) (audit.Record, error) {
	return kernelMutationAudit(ctx, b, 0, now, class)
}

func kernelMutationAudit(ctx context.Context, b identity.CommandBinding, before uint64, now time.Time, class string) (audit.Record, error) {
	actorKind := audit.ActorHuman
	switch b.ActorKind {
	case authorization.SubjectUser:
	case authorization.SubjectServiceAccount:
		actorKind = audit.ActorService
	default:
		return audit.Record{}, identity.InvalidInputError{Field: "creation_actor"}
	}
	outcome, reason, changes, after := audit.OutcomeSucceeded, "completed", audit.ChangeSetInput{Redacted: true}, strconv.FormatUint(before+1, 10)
	if class != "committed" {
		changes, after = audit.ChangeSetInput{NoChange: true}, strconv.FormatUint(before, 10)
		switch class {
		case "denied":
			outcome, reason = audit.OutcomeDenied, "not_authorized"
		case "conflict":
			outcome, reason = audit.OutcomeDenied, "conflict"
		case "cancelled":
			outcome, reason = audit.OutcomeFailed, "cancelled"
		case "deadline-exceeded":
			outcome, reason = audit.OutcomeFailed, "timeout"
		case "dependency-failure":
			outcome, reason = audit.OutcomeFailed, "provider_unavailable"
		default:
			return audit.Record{}, invalidAudit()
		}
	}
	builder, e := audit.NewBuilder(audit.BuilderConfig{Limits: securityAuditLimits(), IDGenerator: func() (string, error) { id, e := identity.NewSubjectID(); return string(id), e }})
	if e != nil {
		return audit.Record{}, invalidAudit()
	}
	retention := "standard"
	if b.OperationID == "identity.user.update-admin" {
		retention = "protected"
	}
	target, kind := string(b.UserID), "user"
	if strings.HasPrefix(b.OperationID, "identity.identifier.") {
		target, kind = b.RecordID, "identifier"
	}
	record, e := builder.Build(audit.RecordInput{OccurredAt: now, Action: kernelCommandAudit(b.OperationID), Outcome: outcome, ReasonCode: reason, Actor: audit.ActorInput{Kind: actorKind, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: kind, ID: target}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: changes, Attributes: map[string]string{"identity.profile": "identity.security.v1", "command.id": string(b.CommandID), "retention.class": retention, "aggregate.type": kind, "aggregate.id": target, "aggregate.before_version": strconv.FormatUint(before, 10), "aggregate.after_version": after}})
	if e != nil {
		return audit.Record{}, invalidAudit()
	}
	redactor, e := audit.NewRedactor(audit.RedactionRules{DropDescription: true, DropNetworkOrigin: true, DropUserAgent: true, AllowedAttributes: []string{"identity.profile", "command.id", "retention.class", "aggregate.type", "aggregate.id", "aggregate.before_version", "aggregate.after_version"}})
	if e != nil {
		return audit.Record{}, invalidAudit()
	}
	record, e = redactor.Redact(ctx, record)
	if e != nil {
		return audit.Record{}, readFailure(ctx, e)
	}
	return record, nil
}
