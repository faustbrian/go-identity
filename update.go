package identity

import (
	"context"
	"errors"
	"strconv"

	"github.com/faustbrian/go-authorization"
)

// UpdateUserCommand is a whole-value typed-field update, never a status,
// credential, identifier or role transition. ExpectedVersion is positive and
// below uint64's maximum. The durable owner checks replay before fencing the
// locked current version/status, then atomically persists fields, next aggregate
// version, original command result and required identity.user.update audit.
// Deleted/anonymized users cannot be updated or resurrected. Structural command
// construction alone grants no authorization or schema-validation authority.
type UpdateUserCommand struct {
	Binding         CommandBinding
	ExpectedVersion uint64
	Attributes      []AttributeUpdate
}

// NewUserUpdateCommand validates and privately copies an administrative update.
// It is not an authority issuer; use trusted UserUpdateAdminService composition.
func NewUserUpdateCommand(spec UpdateUserCommand) (Command, error) {
	if !validCommandBinding(spec.Binding) || spec.Binding.OperationID != "identity.user.update-admin" || spec.ExpectedVersion == 0 || spec.ExpectedVersion == ^uint64(0) || len(spec.Attributes) == 0 || len(spec.Attributes) > 64 {
		return Command{}, InvalidInputError{Field: "update_command"}
	}
	total := 0
	for i, u := range spec.Attributes {
		if !validFieldName(u.Name) || reservedFieldName(u.Name) {
			return Command{}, InvalidInputError{Field: "update_command"}
		}
		for _, prior := range spec.Attributes[:i] {
			if prior.Name == u.Name {
				return Command{}, InvalidInputError{Field: "update_command"}
			}
		}
		n, ok := attributeSize(u.Value, u.Value.Kind)
		if !ok || n > attributeBudget-total {
			return Command{}, InvalidInputError{Field: "update_command"}
		}
		total += n
	}
	spec.Attributes = cloneUpdates(spec.Attributes)
	return Command{update: &spec}, nil
}

// UpdateUser returns a private copy, or false for another/invalid command kind.
func (c Command) UpdateUser() (UpdateUserCommand, bool) {
	if c.update == nil || c.create != nil || c.profile != nil || c.status != nil || c.unlink != nil || c.link != nil {
		return UpdateUserCommand{}, false
	}
	spec := *c.update
	spec.Attributes = cloneUpdates(spec.Attributes)
	return spec, true
}

// UserUpdateAdminRequest is the explicit-ID core administrative update boundary.
// Trusted composition supplies the exact upstream ActorScope; role labels grant
// nothing. Retain command ID, target, expected version and logical fields on
// retries. Field schema/write rules apply to 1..64 updates without defaults.
// Keyed HTTP admission remains the platform transport/adapter's pending work.
type UserUpdateAdminRequest struct {
	CommandID       CommandID
	TenantID        TenantID
	UserID          UserID
	ExpectedVersion uint64
	SchemaVersion   uint32
	Fields          []AttributeUpdate
	ActorScope      authorization.DecisionContext
	CorrelationID   string
}

// UserUpdateAdminRecoveryRequest authorizes exact scoped historical result access
// without new fields, command IDs or a second mutation. It is not current state.
type UserUpdateAdminRecoveryRequest struct {
	CommandID  CommandID
	TenantID   TenantID
	UserID     UserID
	ActorScope authorization.DecisionContext
}

// UserUpdateAdminResult separates a durable outcome from current disclosure.
// Version/User are zero on withheld output. Invalid means no authoritative
// command-outcome observation, never evidence that an earlier attempt rolled back.
type UserUpdateAdminResult struct {
	CommandID     CommandID
	User          User
	Version       uint64
	CommitOutcome CommitOutcome
}

// UserUpdateAdminService owns versioned field-update admission. It owns no
// stores, locks, goroutines or transactions. Dependencies must be bounded and
// concurrency-safe. Current row status/version is trusted only after exact
// authorization and scoped authoritative read; the adapter still fences races.
// Core/read/field/outcome enforcement reuses the existing implementations.
type UserUpdateAdminService struct {
	repo     UserQueryRepository
	creation *UserCreationService
}

// NewUserUpdateAdminService freezes existing field and policy composition.
func NewUserUpdateAdminService(repo UserQueryRepository, uow UnitOfWork, authorize authorization.Service, redact RedactFunc, config UserCreationConfig) (*UserUpdateAdminService, error) {
	if nilDependency(repo) {
		return nil, InvalidInputError{Field: "update_configuration"}
	}
	creation, err := NewUserCreationService(uow, authorize, redact, config)
	if err != nil {
		return nil, err
	}
	return &UserUpdateAdminService{repo: repo, creation: creation}, nil
}

// UserUpdateAdmin requires current operation and per-field Allow. A read-admission
// decision precedes state access, then apply decisions see the trusted row's
// status/version. The two phases replace caller metadata; neither implies an
// administrative role. The single clock sample is reused across both phases.
// Execute owns stale-version conflict versus same-command replay. Future
// expected versions are rejected before execution against older policy state.
func (s *UserUpdateAdminService) UserUpdateAdmin(ctx context.Context, req UserUpdateAdminRequest) (result UserUpdateAdminResult, err error) {
	attempted := false
	defer func() {
		if recover() != nil {
			result.User = User{}
			result.Version = 0
			if attempted && result.CommitOutcome == CommitOutcomeUnknown {
				err = UnknownCommitError{req.CommandID}
			} else {
				err = UnavailableError{}
			}
		}
	}()
	if s == nil || ctx == nil {
		return result, InvalidInputError{Field: "update_context"}
	}
	if _, ok := decodeID(string(req.CommandID)); !ok || req.ExpectedVersion == 0 || req.ExpectedVersion == ^uint64(0) || len(req.Fields) == 0 || len(req.Fields) > 64 {
		return result, InvalidInputError{Field: "update_request"}
	}
	result.CommandID = req.CommandID
	policy := s.creation.policy
	if e := validateQueryContext(req.ActorScope, req.TenantID, string(req.UserID), "identity.user.update-admin", "identity.user", policy.config.PolicyVersion); e != nil {
		return result, e
	}
	if req.CorrelationID == "" {
		req.CorrelationID = string(req.CommandID)
	}
	if !validDirectoryID(req.CorrelationID) {
		return result, InvalidInputError{Field: "correlation_id"}
	}
	ctx, cancel := context.WithTimeout(ctx, policy.config.MaximumDuration)
	defer cancel()
	if e := readContextError(ctx); e != nil {
		return result, e
	}
	if e := policy.config.ValidateCanonicalUserID(ctx, req.UserID); e != nil {
		if e := readContextError(ctx); e != nil {
			return result, e
		}
		return result, InvalidInputError{Field: "user_id"}
	}
	if e := readContextError(ctx); e != nil {
		return result, e
	}
	now := policy.config.Clock.Now()
	if now.IsZero() {
		return result, UnavailableError{}
	}
	dc := req.ActorScope.Clone()
	dc.Request.Environment.Time = now.UTC()
	if dc.Request.Resource.Attributes == nil {
		dc.Request.Resource.Attributes = make(authorization.Attributes)
	}
	for _, key := range []authorization.AttributeName{"identity.user.status", "identity.user.version", "identity.field", "identity.field.write_class", "identity.field.sensitivity", "identity.schema.id", "identity.schema.version", "identity.fields.first", "identity.fields.second"} {
		delete(dc.Request.Resource.Attributes, key)
	}
	dc.Request.Resource.Attributes["identity.command.recovery"] = authorization.BoolValue(false)
	dc.Request.Resource.Attributes["identity.command.read-admission"] = authorization.BoolValue(true)
	if e := s.creation.attributes.allow(ctx, dc); e != nil {
		return result, e
	}
	user, dependencyErr := s.repo.Get(ctx, GetUserQuery{TenantID: req.TenantID, UserID: req.UserID, Fields: userProjectionFields()})
	if e := readContextError(ctx); e != nil {
		return result, e
	}
	if dependencyErr != nil {
		if errors.Is(dependencyErr, ErrUserAbsent) {
			return result, ForbiddenError{}
		}
		return result, UnavailableError{}
	}
	if user.Validate(req.TenantID) != nil || user.ID != req.UserID {
		return result, UnavailableError{}
	}
	if user.Status == StatusDeleted || user.Status == StatusAnonymized {
		return result, ForbiddenError{}
	}
	// A future version could become current after this read while policy was
	// evaluated against older status. Reject it before any authoritative attempt.
	// Older versions remain eligible for same-command replay before durable CAS.
	if req.ExpectedVersion > user.Version {
		return result, ConflictError{req.CommandID}
	}
	dc.Request.Resource.Attributes["identity.command.read-admission"] = authorization.BoolValue(false)
	dc.Request.Resource.Attributes["identity.user.status"] = authorization.StringValue(string(user.Status))
	dc.Request.Resource.Attributes["identity.user.version"] = authorization.StringValue(strconv.FormatUint(user.Version, 10))
	fields, e := s.creation.attributes.prepare(ctx, AttributePrepareRequest{TenantID: req.TenantID, UserID: req.UserID, SchemaVersion: req.SchemaVersion, Updates: req.Fields, Context: dc}, now)
	if e != nil {
		return result, e
	}
	binding := CommandBinding{CommandID: req.CommandID, TenantID: req.TenantID, UserID: req.UserID, ActorID: ActorID(req.ActorScope.Request.Subject.ID), ActorKind: req.ActorScope.Request.Subject.Kind, OperationID: "identity.user.update-admin", PolicyID: policy.config.PolicyID, PolicyVersion: policy.config.PolicyVersion, SchemaID: s.creation.attributes.schema.ID, SchemaVersion: req.SchemaVersion, CorrelationID: req.CorrelationID}
	command, e := NewUserUpdateCommand(UpdateUserCommand{Binding: binding, ExpectedVersion: req.ExpectedVersion, Attributes: fields})
	if e != nil {
		return result, e
	}
	if e := readContextError(ctx); e != nil {
		return result, e
	}
	attempted = true
	result.CommitOutcome = CommitOutcomeUnknown
	receipt, dependencyErr := s.creation.uow.Execute(ctx, command)
	if !receipt.valid() || receipt.Binding != binding || (receipt.Outcome == CommitOutcomeCommitted && receipt.ExpectedVersion != req.ExpectedVersion) {
		return result, unknownError(ctx, req.CommandID)
	}
	result.CommitOutcome = receipt.Outcome
	out, e := s.creation.finish(ctx, UserCreateResult{CommandID: req.CommandID, CommitOutcome: receipt.Outcome}, receipt, dependencyErr, req.ActorScope)
	result.User = out.User
	result.Version = out.User.Version
	return result, e
}

// RecoverUserUpdateAdmin is primary scoped recovery with current authorization
// and redaction; it never runs Execute or treats historical state as login state.
func (s *UserUpdateAdminService) RecoverUserUpdateAdmin(ctx context.Context, req UserUpdateAdminRecoveryRequest) (UserUpdateAdminResult, error) {
	if s == nil {
		return UserUpdateAdminResult{}, InvalidInputError{Field: "update_context"}
	}
	result, err := s.creation.recoverCommand(ctx, UserCreateRecoveryRequest{CommandID: req.CommandID, TenantID: req.TenantID, UserID: req.UserID, ActorScope: req.ActorScope}, "identity.user.update-admin")
	return UserUpdateAdminResult{CommandID: result.CommandID, User: result.User, Version: result.User.Version, CommitOutcome: result.CommitOutcome}, err
}
