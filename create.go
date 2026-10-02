package identity

import (
	"context"
	"errors"
	"time"

	"github.com/faustbrian/go-authorization"
)

// UnitOfWork is the storage-neutral durable command owner. Execute must enforce
// a global command-ID claim, exact tenant/actor/purpose/canonical-input binding,
// idempotency, user uniqueness including tombstones, and one atomic user/result/
// required audit commit. Recover queries the primary, never a projection/cache.
// Implementations are concurrent-safe and bounded by ctx. They cannot infer
// NotCommitted from cancellation or return Committed without required effects.
// A PostgreSQL adapter alone maps typed commands to its concrete coordinator;
// the core exposes no participant registration, work handle or transaction.
type UnitOfWork interface {
	Execute(context.Context, Command) (CommandResult, error)
	Recover(context.Context, RecoveryQuery) (CommandResult, error)
}

// ConflictError is a stable non-enumerating command, version or uniqueness denial.
type ConflictError struct{ CommandID CommandID }

func (ConflictError) Error() string { return "identity: conflict" }

// UnknownCommitError requires scoped recovery of the same command, not a new ID.
type UnknownCommitError struct{ CommandID CommandID }

func (UnknownCommitError) Error() string { return "identity: unknown commit" }

// NotCommittedError identifies authoritative abort/absence, never inferred rollback.
type NotCommittedError struct{ CommandID CommandID }

func (NotCommittedError) Error() string { return "identity: not committed" }

// InProgressError is a bounded nonterminal observation of the same command.
type InProgressError struct {
	CommandID  CommandID
	RetryAfter time.Duration
}

func (InProgressError) Error() string { return "identity: in progress" }

// UserCreateRequest is the explicit-ID core command boundary. Trusted admission
// preallocates a random CommandID and stable canonical UserID; every retry keeps
// them and the same logical fields. HTTP keyed admission is a separate owned
// transport/adapter concern, not caller-written workflow glue. Fields are at
// most 64 explicit values; defaults may expand the prepared command to 128.
// ActorScope comes from trusted authentication composition, never client JSON.
type UserCreateRequest struct {
	CommandID     CommandID
	TenantID      TenantID
	UserID        UserID
	SchemaVersion uint32
	Fields        []AttributeUpdate
	ActorScope    authorization.DecisionContext
	CorrelationID string
}

// UserCreateRecoveryRequest cannot replace inputs or allocate a new command.
// ActorScope authorizes current creation-result access for the exact target.
type UserCreateRecoveryRequest struct {
	CommandID  CommandID
	TenantID   TenantID
	UserID     UserID
	ActorScope authorization.DecisionContext
}

// UserCreateResult preserves durable outcome even when output is withheld by
// cancellation or current redaction. User is disclosed only on permitted success.
// A committed result is an initial historical snapshot, not current login state.
// CommitOutcomeInvalid means this call made no authoritative outcome observation;
// it never implies that an earlier attempt with this command ID rolled back.
type UserCreateResult struct {
	CommandID     CommandID
	User          User
	CommitOutcome CommitOutcome
}

// UserCreationConfig is explicit immutable composition. Query supplies shared
// current authorization/redaction/time/ID policy. The schema, normalizer and
// validator are the same field-enforcement implementation used by typed writes.
type UserCreationConfig struct {
	Query         UserQueryConfig
	Schema        AttributeSchema
	Normalize     NormalizeAttributeFunc
	ValidateValue ValidateAttributeFunc
}

// UserCreationService owns authorized creation and recovery orchestration. It
// has no stores, goroutines, locks, arbitrary participant callbacks or commits.
// The full identity Service will compose this same implementation and reads.
// Dependencies remain caller-owned and must be concurrent-safe/context-bounded.
type UserCreationService struct {
	uow        UnitOfWork
	policy     *UserQueryService
	attributes *AttributeProcessor
}

// NewUserCreationService validates and freezes composition without I/O.
func NewUserCreationService(uow UnitOfWork, authorize authorization.Service, redact RedactFunc, config UserCreationConfig) (*UserCreationService, error) {
	if nilDependency(uow) {
		return nil, InvalidInputError{Field: "creation_configuration"}
	}
	policy, err := newQueryPolicy(authorize, redact, config.Query)
	if err != nil {
		return nil, err
	}
	attributes, err := NewAttributeProcessor(config.Schema, authorize, config.Normalize, AttributeProcessorConfig{Clock: config.Query.Clock, MaximumDuration: config.Query.MaximumDuration, PolicyVersion: config.Query.PolicyVersion, ValidateCanonicalUserID: config.Query.ValidateCanonicalUserID, ValidateValue: config.ValidateValue})
	if err != nil {
		return nil, err
	}
	return &UserCreationService{uow: uow, policy: policy, attributes: attributes}, nil
}

// UserCreate admits/normalizes/authorizes before the first durable attempt.
// After Execute begins, malformed output, dependency failure or panic is Unknown
// unless a valid authoritative receipt proves another exact outcome. Required
// audit and logical command replay belong to that same adapter commit. Current
// redaction is reapplied after every committed replay; no stale grants survive.
func (s *UserCreationService) UserCreate(ctx context.Context, req UserCreateRequest) (result UserCreateResult, err error) {
	result = UserCreateResult{}
	attempted := false
	defer func() {
		if recover() != nil {
			result.User = User{}
			if attempted && result.CommitOutcome == CommitOutcomeUnknown {
				err = UnknownCommitError{req.CommandID}
			} else {
				err = UnavailableError{}
			}
		}
	}()
	if s == nil || ctx == nil {
		return result, InvalidInputError{Field: "creation_context"}
	}
	if _, valid := decodeID(string(req.CommandID)); !valid || len(req.Fields) > 64 {
		return result, InvalidInputError{Field: "creation_request"}
	}
	result.CommandID = req.CommandID
	if e := validateQueryContext(req.ActorScope, req.TenantID, string(req.UserID), "identity.user.create", "identity.user", s.policy.config.PolicyVersion); e != nil {
		return result, e
	}
	if req.CorrelationID == "" {
		req.CorrelationID = string(req.CommandID)
	}
	if !validDirectoryID(req.CorrelationID) {
		return result, InvalidInputError{Field: "correlation_id"}
	}
	ctx, cancel := context.WithTimeout(ctx, s.policy.config.MaximumDuration)
	defer cancel()
	if e := readContextError(ctx); e != nil {
		return result, e
	}
	now := s.policy.config.Clock.Now()
	if now.IsZero() {
		return result, UnavailableError{}
	}
	dc := req.ActorScope.Clone()
	if dc.Request.Resource.Attributes == nil {
		dc.Request.Resource.Attributes = make(authorization.Attributes)
	}
	dc.Request.Resource.Attributes["identity.user.status"] = authorization.StringValue(string(StatusActive))
	dc.Request.Resource.Attributes["identity.user.version"] = authorization.StringValue("1")
	dc.Request.Resource.Attributes["identity.command.recovery"] = authorization.BoolValue(false)
	dc.Request.Resource.Attributes["identity.command.read-admission"] = authorization.BoolValue(false)
	fields, e := s.attributes.prepare(ctx, AttributePrepareRequest{TenantID: req.TenantID, UserID: req.UserID, SchemaVersion: req.SchemaVersion, Updates: req.Fields, Context: dc}, now)
	if e != nil {
		return result, e
	}
	binding := CommandBinding{CommandID: req.CommandID, TenantID: req.TenantID, UserID: req.UserID, ActorID: ActorID(req.ActorScope.Request.Subject.ID), ActorKind: req.ActorScope.Request.Subject.Kind, OperationID: "identity.user.create", PolicyID: s.policy.config.PolicyID, PolicyVersion: s.policy.config.PolicyVersion, SchemaID: s.attributes.schema.ID, SchemaVersion: req.SchemaVersion, CorrelationID: req.CorrelationID}
	command, e := NewUserCreationCommand(CreateUserCommand{Binding: binding, Status: StatusActive, Attributes: fields})
	if e != nil {
		return result, e
	}
	if e := readContextError(ctx); e != nil {
		return result, e
	}
	attempted = true
	result.CommitOutcome = CommitOutcomeUnknown
	receipt, dependencyErr := s.uow.Execute(ctx, command)
	if !receipt.valid() || receipt.Binding != binding {
		return result, unknownError(ctx, req.CommandID)
	}
	result.CommitOutcome = receipt.Outcome
	return s.finish(ctx, result, receipt, dependencyErr, req.ActorScope)
}

// RecoverUserCreate authorizes current result access before a scoped primary
// lookup. It does not execute, rewrite fields, consume proofs or issue new IDs.
// Historic policy/schema bindings remain intact while current policy controls
// disclosure. Committed recovery does not assert current user status/freshness.
func (s *UserCreationService) RecoverUserCreate(ctx context.Context, req UserCreateRecoveryRequest) (result UserCreateResult, err error) {
	return s.recoverCommand(ctx, req, "identity.user.create")
}

// Shared scoped recovery keeps purpose fencing and known-outcome semantics in
// one implementation as the closed command union gains update variants.
func (s *UserCreationService) recoverCommand(ctx context.Context, req UserCreateRecoveryRequest, operation string) (result UserCreateResult, err error) {
	result = UserCreateResult{}
	attempted := false
	defer func() {
		if recover() != nil {
			result.User = User{}
			if attempted && result.CommitOutcome == CommitOutcomeUnknown {
				err = UnknownCommitError{req.CommandID}
			} else {
				err = UnavailableError{}
			}
		}
	}()
	if s == nil || ctx == nil {
		return result, InvalidInputError{Field: "creation_context"}
	}
	if _, valid := decodeID(string(req.CommandID)); !valid {
		return result, InvalidInputError{Field: "command_id"}
	}
	result.CommandID = req.CommandID
	if e := validateQueryContext(req.ActorScope, req.TenantID, string(req.UserID), operation, "identity.user", s.policy.config.PolicyVersion); e != nil {
		return result, e
	}
	ctx, cancel := context.WithTimeout(ctx, s.policy.config.MaximumDuration)
	defer cancel()
	if e := readContextError(ctx); e != nil {
		return result, e
	}
	if e := s.policy.config.ValidateCanonicalUserID(ctx, req.UserID); e != nil {
		if e := readContextError(ctx); e != nil {
			return result, e
		}
		return result, InvalidInputError{Field: "user_id"}
	}
	if e := readContextError(ctx); e != nil {
		return result, e
	}
	now := s.policy.config.Clock.Now()
	if now.IsZero() {
		return result, UnavailableError{}
	}
	dc := req.ActorScope.Clone()
	dc.Request.Environment.Time = now.UTC()
	if dc.Request.Resource.Attributes == nil {
		dc.Request.Resource.Attributes = make(authorization.Attributes)
	}
	for _, key := range []authorization.AttributeName{"identity.field", "identity.field.write_class", "identity.field.sensitivity", "identity.schema.id", "identity.schema.version", "identity.fields.first", "identity.fields.second", "identity.user.status", "identity.user.version"} {
		delete(dc.Request.Resource.Attributes, key)
	}
	dc.Request.Resource.Attributes["identity.command.recovery"] = authorization.BoolValue(true)
	dc.Request.Resource.Attributes["identity.command.read-admission"] = authorization.BoolValue(false)
	if len(dc.Request.Resource.Attributes) > 128 {
		return result, InvalidInputError{Field: "authorization_attributes"}
	}
	decision, e := s.policy.authorize.Decide(ctx, dc)
	if e := readContextError(ctx); e != nil {
		return result, e
	}
	if e != nil {
		return result, UnavailableError{}
	}
	if decision.Outcome != authorization.Allow || decision.Revision != authorization.Revision(s.policy.config.PolicyVersion) {
		return result, ForbiddenError{}
	}
	q := RecoveryQuery{CommandID: req.CommandID, TenantID: req.TenantID, UserID: req.UserID, ActorID: ActorID(req.ActorScope.Request.Subject.ID), ActorKind: req.ActorScope.Request.Subject.Kind, OperationID: operation}
	attempted = true
	result.CommitOutcome = CommitOutcomeUnknown
	receipt, dependencyErr := s.uow.Recover(ctx, q)
	if !receipt.valid() || receipt.Binding.OperationID != operation || receipt.Binding.CommandID != q.CommandID || receipt.Binding.TenantID != q.TenantID || receipt.Binding.UserID != q.UserID || receipt.Binding.ActorID != q.ActorID || receipt.Binding.ActorKind != q.ActorKind {
		return result, unknownError(ctx, req.CommandID)
	}
	result.CommitOutcome = receipt.Outcome
	return s.finish(ctx, result, receipt, dependencyErr, req.ActorScope)
}

func (s *UserCreationService) finish(ctx context.Context, result UserCreateResult, receipt CommandResult, dependencyErr error, dc authorization.DecisionContext) (UserCreateResult, error) {
	result.CommitOutcome = receipt.Outcome
	if receipt.Outcome == CommitOutcomeUnknown {
		return result, unknownError(ctx, result.CommandID)
	}
	if e := readContextError(ctx); e != nil {
		return result, e
	}
	if dependencyErr != nil {
		return result, UnavailableError{}
	}
	switch receipt.Outcome {
	case CommitOutcomeConflict:
		return result, ConflictError{result.CommandID}
	case CommitOutcomeInProgress:
		return result, InProgressError{result.CommandID, receipt.RetryAfter}
	case CommitOutcomeNotCommitted:
		return result, NotCommittedError{result.CommandID}
	}
	deadline, _ := ctx.Deadline()
	d, err := s.policy.redact(ctx, RedactionPolicyInput{TenantID: receipt.Binding.TenantID, ViewerID: ActorID(dc.Request.Subject.ID), Resource: RedactionResource{Kind: "identity.user", ID: string(receipt.Binding.UserID)}, Fields: userProjectionFields(), OperationID: receipt.Binding.OperationID, PolicyVersion: s.policy.config.PolicyVersion, Deadline: deadline.UTC()})
	if e := readContextError(ctx); e != nil {
		return result, e
	}
	if err != nil || !s.policy.completeUserProjection(d) {
		return result, ForbiddenError{}
	}
	result.User = receipt.User
	return result, nil
}

func unknownError(ctx context.Context, id CommandID) error {
	unknown := UnknownCommitError{id}
	if e := readContextError(ctx); e != nil {
		return errors.Join(unknown, e)
	}
	return unknown
}
