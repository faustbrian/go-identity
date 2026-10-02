package identity

import (
	"context"
	"crypto/rand"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/faustbrian/go-authorization"
)

// CascadeID is a canonical nonzero 128-bit random cascade identity. It is
// correlation, not authority. Retain it with its generation through cleanup.
type CascadeID string

// ErrCascadeIDEntropy reports cascade generation failure without provider data.
var ErrCascadeIDEntropy = errors.New("identity: cascade ID entropy unavailable")

// NewCascadeID generates a cascade ID without exposing entropy failures.
func NewCascadeID() (CascadeID, error) {
	id, err := newID(rand.Reader, ErrCascadeIDEntropy)
	return CascadeID(id), err
}

// ParseCascadeID accepts only the canonical unpadded 22-byte representation.
func ParseCascadeID(raw string) (CascadeID, error) {
	if _, ok := decodeID(raw); !ok {
		return "", InvalidInputError{Field: "cascade_id"}
	}
	return CascadeID(raw), nil
}

// RevocationStatus separates pending cleanup from closed or unknown cleanup.
// Its zero value is invalid. A committed owner admission is always pending.
type RevocationStatus uint8

const (
	RevocationPending RevocationStatus = iota + 1
	RevocationCompleted
	RevocationUnknown
)

// RevocationOwnerReceipt names one semantic owner, not a storage implementation.
// Pending names a required consumer without asserting its acknowledgement.
type RevocationOwnerReceipt struct {
	Owner  string
	Status RevocationStatus
}

// RevocationOutcome is a historical cascade observation, not current authority.
// Admission returns generation 1, a new random ID, the incremented user authority
// version and Pending. Owners names every required consumer as pending, never
// silently omitting an unavailable consumer or asserting its acknowledgement.
// ExternalLimitations are registered redacted codes, never provider errors.
// Treat slices as immutable; public service results are caller-owned copies.
type RevocationOutcome struct {
	CascadeID           CascadeID
	Generation          uint64
	AuthorityVersion    uint64
	Status              RevocationStatus
	Owners              []RevocationOwnerReceipt
	ExternalLimitations []PolicyReason
}

func (r RevocationOutcome) validAdmission(operation string) bool {
	_, ok := decodeID(string(r.CascadeID))
	if !ok || r.Generation != 1 || r.AuthorityVersion <= 1 || r.Status != RevocationPending || len(r.ExternalLimitations) != 0 {
		return false
	}
	consumers := statusConsumers(operation)
	if len(consumers) == 0 || len(r.Owners) != len(consumers) {
		return false
	}
	for i, owner := range r.Owners {
		if owner.Owner != consumers[i] || owner.Status != RevocationPending {
			return false
		}
	}
	return true
}

// UserStatusRecord is one consistent primary snapshot. AuthorityVersion is
// the user security dimension, not User.Version: profile writes may increment
// the latter alone. Every authority change must also advance User.Version.
type UserStatusRecord struct {
	User             User
	AuthorityVersion uint64
}

// UserStatusQuery is an exact partitioned primary lookup, never a cache read.
type UserStatusQuery struct {
	TenantID TenantID
	UserID   UserID
}

// UserStatusRepository owns consistent bounded primary lifecycle reads. Absence
// returns ErrUserAbsent. The same durable identity owner implements UnitOfWork.
type UserStatusRepository interface {
	GetStatus(context.Context, UserStatusQuery) (UserStatusRecord, error)
}

// UserStatusCommand is immutable lifecycle intent. Both expected versions and
// absolute expiry are stable across retries; replay is checked before locked
// CAS. The owner fences both versions, checks the configured policy version and
// transition, bumps both counters once, and atomically stores status, expiry,
// audit, lifecycle event/outbox, immutable required-consumer snapshot and receipt.
// Suspend/ban emit identity.suspended.v1 and audit identity.user.suspend;
// restore/unban emit identity.restored.v1 and audit identity.user.restore.
// Restore is only from suspended; unban only from banned. Neither revives any
// pre-transition credential. Expiry requires an audited fresh restore command,
// never passive eligibility. Consumer closure is NOT part of admission.
type UserStatusCommand struct {
	Binding                  CommandBinding
	ExpectedVersion          uint64
	ExpectedAuthorityVersion uint64
	StatusPolicyVersion      uint64
	TargetStatus             Status
	Reason                   string
	ExpiresAt                time.Time
}

// RequiredConsumers returns a caller-owned ordered copy of the exact immutable
// identity-lifecycle-consumers-v1 manifest for this operation. Adapters snapshot
// every ID and its public-contract fingerprint at admission; missing consumers
// cannot be omitted merely because they are not running. No acknowledgement is
// granted by this list or command construction.
func (s UserStatusCommand) RequiredConsumers() []string {
	return statusConsumers(s.Binding.OperationID)
}

// NewUserStatusCommand freezes structural lifecycle intent; it grants no
// authorization and does not replace trusted service or locked owner policy.
// Nonzero expiry must be microsecond-exact and within PostgreSQL years 1..9999.
func NewUserStatusCommand(spec UserStatusCommand) (Command, error) {
	target := statusTarget(spec.Binding.OperationID)
	if !validCommandBinding(spec.Binding) || !target.Valid() || spec.TargetStatus != target || spec.ExpectedVersion == 0 || spec.ExpectedVersion == ^uint64(0) || spec.ExpectedAuthorityVersion == 0 || spec.ExpectedAuthorityVersion == ^uint64(0) || spec.StatusPolicyVersion == 0 || spec.Binding.SchemaID != "identity-lifecycle" || spec.Binding.SchemaVersion != 1 {
		return Command{}, InvalidInputError{Field: "status_command"}
	}
	if target == StatusActive {
		if spec.Reason != "" || !spec.ExpiresAt.IsZero() {
			return Command{}, InvalidInputError{Field: "status_command"}
		}
	} else if !validStatusReason(spec.Reason) {
		return Command{}, InvalidInputError{Field: "status_reason"}
	}
	if !spec.ExpiresAt.IsZero() {
		spec.ExpiresAt = spec.ExpiresAt.UTC()
		if spec.ExpiresAt.Year() < 1 || spec.ExpiresAt.Year() > 9999 || spec.ExpiresAt.Nanosecond()%1000 != 0 {
			return Command{}, InvalidInputError{Field: "status_expiry"}
		}
	}
	return Command{status: &spec}, nil
}

// UserStatus returns a value copy, or false for another/invalid command variant.
func (c Command) UserStatus() (UserStatusCommand, bool) {
	if c.status == nil || c.create != nil || c.update != nil || c.profile != nil || c.unlink != nil || c.link != nil {
		return UserStatusCommand{}, false
	}
	return *c.status, true
}

// UserStatusRequest is the explicit-ID core mutation boundary. ActorScope comes
// from trusted authenticated composition, never client JSON. Retain both expected
// versions, command ID, reason and absolute expiry on retries. Suspend/ban require
// a registered reason; restore/unban reject reason/expiry. Zero expiry means
// indefinite. Transport owns session freshness, CSRF and keyed HTTP admission.
type UserStatusRequest struct {
	CommandID                CommandID
	TenantID                 TenantID
	UserID                   UserID
	ExpectedVersion          uint64
	ExpectedAuthorityVersion uint64
	Reason                   string
	ExpiresAt                time.Time
	ActorScope               authorization.DecisionContext
	CorrelationID            string
}

// UserStatusResult separates authoritative command outcome from disclosure.
// Withheld output leaves User/Revocation zero without erasing known commitment.
type UserStatusResult struct {
	CommandID     CommandID
	CommitOutcome CommitOutcome
	User          User
	Revocation    RevocationOutcome
}

// UserStatusRecoveryRequest looks up one original command under current policy.
// ActorScope.Action must name the original literal operation, not a new purpose.
type UserStatusRecoveryRequest struct {
	CommandID  CommandID
	TenantID   TenantID
	UserID     UserID
	ActorScope authorization.DecisionContext
}

// UserStatusConfig is immutable explicit lifecycle composition. Reasons contains
// 1..32 unique registered UTF-8 codes, each at most 512 bytes without whitespace
// or controls. PolicyVersion identifies the frozen transition policy independently
// of authorization revision. No implicit expiry or transition defaults exist.
type UserStatusConfig struct {
	Query         UserQueryConfig
	Policy        StatusPolicy
	PolicyVersion uint64
	Reasons       []string
}

// UserStatusService owns policy and commands, not persistence, cleanup workers,
// transactions or goroutines. Dependencies/callbacks must be concurrency-safe.
type UserStatusService struct {
	repo   UserStatusRepository
	uow    UnitOfWork
	policy *UserQueryService
	config UserStatusConfig
}

// NewUserStatusService validates and copies configuration without I/O.
func NewUserStatusService(repo UserStatusRepository, uow UnitOfWork, authorize authorization.Service, redact RedactFunc, config UserStatusConfig) (*UserStatusService, error) {
	if nilDependency(repo) || nilDependency(uow) || config.PolicyVersion == 0 || config.Policy.Validate() != nil || len(config.Reasons) == 0 || len(config.Reasons) > 32 {
		return nil, InvalidInputError{Field: "status_configuration"}
	}
	for i, reason := range config.Reasons {
		if !validStatusReason(reason) || slices.Contains(config.Reasons[:i], reason) {
			return nil, InvalidInputError{Field: "status_reasons"}
		}
	}
	policy, err := newQueryPolicy(authorize, redact, config.Query)
	if err != nil {
		return nil, err
	}
	config.Policy.AllowedTransitions = slices.Clone(config.Policy.AllowedTransitions)
	config.Reasons = slices.Clone(config.Reasons)
	return &UserStatusService{repo: repo, uow: uow, policy: policy, config: config}, nil
}

// UserSuspend denies new authority and admits pending cleanup under explicit
// identity.user.suspend authorization. Commitment does not certify closure.
func (s *UserStatusService) UserSuspend(ctx context.Context, req UserStatusRequest) (UserStatusResult, error) {
	return s.change(ctx, req, "identity.user.suspend")
}

// UserRestore restores only suspended eligibility with a fresh authority version;
// previously issued credentials never become usable again.
func (s *UserStatusService) UserRestore(ctx context.Context, req UserStatusRequest) (UserStatusResult, error) {
	return s.change(ctx, req, "identity.user.restore")
}

// AdminUserBan requires literal identity.admin.user-ban authorization, not a role
// label. It bumps authority and admits pending cleanup exactly once.
func (s *UserStatusService) AdminUserBan(ctx context.Context, req UserStatusRequest) (UserStatusResult, error) {
	return s.change(ctx, req, "identity.admin.user-ban")
}

// AdminUserUnban restores only banned eligibility, not old credential authority.
func (s *UserStatusService) AdminUserUnban(ctx context.Context, req UserStatusRequest) (UserStatusResult, error) {
	return s.change(ctx, req, "identity.admin.user-unban")
}

func (s *UserStatusService) change(ctx context.Context, req UserStatusRequest, operation string) (result UserStatusResult, err error) {
	attempted := false
	defer func() {
		if recover() != nil {
			result.User = User{}
			result.Revocation = RevocationOutcome{}
			if attempted && result.CommitOutcome == CommitOutcomeUnknown {
				err = UnknownCommitError{req.CommandID}
			} else {
				err = UnavailableError{}
			}
		}
	}()
	if s == nil || ctx == nil {
		return result, InvalidInputError{Field: "status_context"}
	}
	if req.CorrelationID == "" {
		req.CorrelationID = string(req.CommandID)
	}
	binding := CommandBinding{CommandID: req.CommandID, TenantID: req.TenantID, UserID: req.UserID, ActorID: ActorID(req.ActorScope.Request.Subject.ID), ActorKind: req.ActorScope.Request.Subject.Kind, OperationID: operation, PolicyID: s.policy.config.PolicyID, PolicyVersion: s.policy.config.PolicyVersion, SchemaID: "identity-lifecycle", SchemaVersion: 1, CorrelationID: req.CorrelationID}
	command, e := NewUserStatusCommand(UserStatusCommand{Binding: binding, ExpectedVersion: req.ExpectedVersion, ExpectedAuthorityVersion: req.ExpectedAuthorityVersion, StatusPolicyVersion: s.config.PolicyVersion, TargetStatus: statusTarget(operation), Reason: req.Reason, ExpiresAt: req.ExpiresAt})
	if e != nil {
		return result, e
	}
	if req.Reason != "" && !slices.Contains(s.config.Reasons, req.Reason) {
		return result, InvalidInputError{Field: "status_reason"}
	}
	result.CommandID = req.CommandID
	ctx, cancel := context.WithTimeout(ctx, s.policy.config.MaximumDuration)
	defer cancel()
	dc, e := s.admit(ctx, req.TenantID, req.UserID, req.ActorScope, operation, false)
	if e != nil {
		return result, e
	}
	record, dependencyErr := s.repo.GetStatus(ctx, UserStatusQuery{TenantID: req.TenantID, UserID: req.UserID})
	if e := readContextError(ctx); e != nil {
		return result, e
	}
	if dependencyErr != nil {
		if errors.Is(dependencyErr, ErrUserAbsent) {
			return result, ForbiddenError{}
		}
		return result, UnavailableError{}
	}
	if record.User.Validate(req.TenantID) != nil || record.User.ID != req.UserID || record.AuthorityVersion == 0 {
		return result, UnavailableError{}
	}
	if record.User.Status == StatusDeleted || record.User.Status == StatusAnonymized {
		return result, ForbiddenError{}
	}
	if req.ExpectedVersion > record.User.Version || req.ExpectedAuthorityVersion > record.AuthorityVersion {
		return result, ConflictError{req.CommandID}
	}
	if req.ExpectedVersion == record.User.Version {
		if req.ExpectedAuthorityVersion != record.AuthorityVersion {
			return result, ConflictError{req.CommandID}
		}
		if operation == "identity.user.restore" && record.User.Status != StatusSuspended || operation == "identity.admin.user-unban" && record.User.Status != StatusBanned {
			return result, ForbiddenError{}
		}
		duration := time.Duration(0)
		if !req.ExpiresAt.IsZero() {
			now := dc.Request.Environment.Time
			if !req.ExpiresAt.After(now) || req.ExpiresAt.After(now.Add(s.config.Policy.MaximumSuspension)) {
				return result, InvalidInputError{Field: "status_expiry"}
			}
			duration = req.ExpiresAt.Sub(now)
		}
		if e := s.config.Policy.CheckTransition(record.User.Status, statusTarget(operation), req.Reason != "", duration); e != nil {
			return result, e
		}
	}
	dc.Request.Resource.Attributes["identity.command.read-admission"] = authorization.BoolValue(false)
	dc.Request.Resource.Attributes["identity.user.status"] = authorization.StringValue(string(record.User.Status))
	dc.Request.Resource.Attributes["identity.user.version"] = authorization.StringValue(strconv.FormatUint(record.User.Version, 10))
	dc.Request.Resource.Attributes["identity.user.authority-version"] = authorization.StringValue(strconv.FormatUint(record.AuthorityVersion, 10))
	if e := s.allow(ctx, dc); e != nil {
		return result, e
	}
	if e := readContextError(ctx); e != nil {
		return result, e
	}
	attempted = true
	result.CommitOutcome = CommitOutcomeUnknown
	receipt, dependencyErr := s.uow.Execute(ctx, command)
	if !receipt.valid() || receipt.Binding != binding || receipt.Outcome == CommitOutcomeCommitted && (receipt.ExpectedVersion != req.ExpectedVersion || receipt.Revocation.AuthorityVersion != req.ExpectedAuthorityVersion+1) {
		return result, unknownError(ctx, req.CommandID)
	}
	result.CommitOutcome = receipt.Outcome
	return s.finish(ctx, result, receipt, dependencyErr, dc)
}

// RecoverUserStatus performs a primary, exact-scope receipt lookup under current
// authorization, never Execute. The historical status is not current authority.
func (s *UserStatusService) RecoverUserStatus(ctx context.Context, req UserStatusRecoveryRequest) (result UserStatusResult, err error) {
	attempted := false
	defer func() {
		if recover() != nil {
			result.User = User{}
			result.Revocation = RevocationOutcome{}
			if attempted && result.CommitOutcome == CommitOutcomeUnknown {
				err = UnknownCommitError{req.CommandID}
			} else {
				err = UnavailableError{}
			}
		}
	}()
	if s == nil || ctx == nil {
		return result, InvalidInputError{Field: "status_context"}
	}
	if _, ok := decodeID(string(req.CommandID)); !ok {
		return result, InvalidInputError{Field: "command_id"}
	}
	operation := string(req.ActorScope.Request.Action)
	if !statusTarget(operation).Valid() {
		return result, InvalidInputError{Field: "status_operation"}
	}
	result.CommandID = req.CommandID
	ctx, cancel := context.WithTimeout(ctx, s.policy.config.MaximumDuration)
	defer cancel()
	dc, e := s.admit(ctx, req.TenantID, req.UserID, req.ActorScope, operation, true)
	if e != nil {
		return result, e
	}
	attempted = true
	result.CommitOutcome = CommitOutcomeUnknown
	receipt, dependencyErr := s.uow.Recover(ctx, RecoveryQuery{CommandID: req.CommandID, TenantID: req.TenantID, UserID: req.UserID, ActorID: ActorID(dc.Request.Subject.ID), ActorKind: dc.Request.Subject.Kind})
	b := receipt.Binding
	// The receipt retains its original policy identity/version. Current policy
	// above governs disclosure, not the identity of an already committed command.
	if !receipt.valid() || b.CommandID != req.CommandID || b.TenantID != req.TenantID || b.UserID != req.UserID || b.ActorID != ActorID(dc.Request.Subject.ID) || b.ActorKind != dc.Request.Subject.Kind || b.OperationID != operation || b.SchemaID != "identity-lifecycle" || b.SchemaVersion != 1 {
		return result, unknownError(ctx, req.CommandID)
	}
	result.CommitOutcome = receipt.Outcome
	return s.finish(ctx, result, receipt, dependencyErr, dc)
}

func (s *UserStatusService) admit(ctx context.Context, tenant TenantID, user UserID, scope authorization.DecisionContext, operation string, recovery bool) (authorization.DecisionContext, error) {
	if e := validateQueryContext(scope, tenant, string(user), operation, "identity.user", s.policy.config.PolicyVersion); e != nil {
		return authorization.DecisionContext{}, e
	}
	if e := readContextError(ctx); e != nil {
		return authorization.DecisionContext{}, e
	}
	if e := s.policy.config.ValidateCanonicalUserID(ctx, user); e != nil {
		if e := readContextError(ctx); e != nil {
			return authorization.DecisionContext{}, e
		}
		return authorization.DecisionContext{}, InvalidInputError{Field: "user_id"}
	}
	if e := readContextError(ctx); e != nil {
		return authorization.DecisionContext{}, e
	}
	now := s.policy.config.Clock.Now()
	if now.IsZero() {
		return authorization.DecisionContext{}, UnavailableError{}
	}
	dc := scope.Clone()
	dc.Request.Environment.Time = now.UTC()
	if dc.Request.Resource.Attributes == nil {
		dc.Request.Resource.Attributes = make(authorization.Attributes)
	}
	// Policy metadata below is owned by this operation, never caller evidence.
	for key := range dc.Request.Resource.Attributes {
		if strings.HasPrefix(string(key), "identity.user.") || strings.HasPrefix(string(key), "identity.command.") {
			delete(dc.Request.Resource.Attributes, key)
		}
	}
	dc.Request.Resource.Attributes["identity.command.recovery"] = authorization.BoolValue(recovery)
	dc.Request.Resource.Attributes["identity.command.read-admission"] = authorization.BoolValue(!recovery)
	return dc, s.allow(ctx, dc)
}

func (s *UserStatusService) allow(ctx context.Context, dc authorization.DecisionContext) error {
	if len(dc.Request.Resource.Attributes) > 128 {
		return InvalidInputError{Field: "authorization_attributes"}
	}
	d, err := s.policy.authorize.Decide(ctx, dc)
	if e := readContextError(ctx); e != nil {
		return e
	}
	if err != nil {
		return UnavailableError{}
	}
	if d.Outcome != authorization.Allow || d.Revision != authorization.Revision(s.policy.config.PolicyVersion) {
		return ForbiddenError{}
	}
	return nil
}

func (s *UserStatusService) finish(ctx context.Context, result UserStatusResult, receipt CommandResult, dependencyErr error, dc authorization.DecisionContext) (UserStatusResult, error) {
	// Reuse the sole command outcome/redaction implementation; no parallel
	// recovery state machine or rollback inference is introduced here.
	projection := &UserCreationService{policy: s.policy}
	out, err := projection.finish(ctx, UserCreateResult{CommandID: result.CommandID, CommitOutcome: result.CommitOutcome}, receipt, dependencyErr, dc)
	if err != nil {
		return result, err
	}
	result.User = out.User
	result.Revocation = *receipt.Revocation
	result.Revocation.Owners = slices.Clone(receipt.Revocation.Owners)
	result.Revocation.ExternalLimitations = slices.Clone(receipt.Revocation.ExternalLimitations)
	return result, nil
}

func statusTarget(operation string) Status {
	switch operation {
	case "identity.user.suspend":
		return StatusSuspended
	case "identity.admin.user-ban":
		return StatusBanned
	case "identity.user.restore", "identity.admin.user-unban":
		return StatusActive
	default:
		return ""
	}
}

func statusConsumers(operation string) []string {
	switch statusTarget(operation) {
	case StatusSuspended, StatusBanned:
		return []string{"identity/session", "identity/session/valkey", "identity/impersonation", "identity/apikey", "identity/apikey/valkey", "oauth-server", "oauth-server/device", "oauth-server/oidc", "authorization", "authorization/valkey", "identity/risk", "audit"}
	case StatusActive:
		return []string{"identity/session", "identity/session/valkey", "identity/impersonation", "identity/apikey", "identity/apikey/valkey", "oauth-server", "authorization", "authorization/valkey", "audit"}
	default:
		return nil
	}
}

func validStatusReason(reason string) bool {
	if len(reason) == 0 || len(reason) > 512 || !utf8.ValidString(reason) {
		return false
	}
	for _, r := range reason {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
}
