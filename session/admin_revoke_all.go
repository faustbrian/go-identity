package session

import (
	"context"
	"fmt"
	"strings"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// MaxAdminSessionRevokeCount is the complete-set bound from the administrative
// session contract. Exceeding it fails without a partial revocation.
const MaxAdminSessionRevokeCount uint32 = 100000

// AdminSessionRevokeAllRequest selects one authorized user's session set.
// Direct callers supply the actor; trusted transport derives it from the
// original cookie. CommandID identifies the original native command for
// recovery, not a transport idempotency key. Never log or serialize it.
type AdminSessionRevokeAllRequest struct {
	TenantID        identity.TenantID
	ActorID         identity.SubjectID
	TargetSubjectID identity.SubjectID
	CommandID       identity.CommandID
	CorrelationID   string
	Credential      Credential
	CSRF            CSRFToken
}

// AdminSessionRevokeAllResult is a confirmed bulk session invalidation. A
// zero count can still advance SubjectVersion, the positive session-only
// invalidation version. It does not change the user's other authority epochs.
type AdminSessionRevokeAllResult struct {
	RevokedCount   uint32
	SubjectVersion uint64
}

// AdminRevokeAllExecutor is implemented by the owned durable session adapter.
// It fences the original actor and exact target set, including concurrent
// issuance, and commits invalidation, receipt, audit and lifecycle together.
// The adapter must retain the original command for ambiguous-outcome recovery.
type AdminRevokeAllExecutor interface {
	ExecuteAdminSessionRevokeAll(context.Context, AdminSessionRevocation) (AdminSessionRevokeAllResult, error)
}

// AdminRevokeAllService authenticates and authorizes a target-user session
// invalidation without changing other credentials. It owns no storage and
// borrows its immutable, concurrent-safe dependencies for its lifetime.
type AdminRevokeAllService struct {
	sessions *SessionService
	executor AdminRevokeAllExecutor
	config   AdminRevokeConfig
}

// NewAdminRevokeAllService validates explicit composition without IO.
func NewAdminRevokeAllService(sessions *SessionService, executor AdminRevokeAllExecutor, c AdminRevokeConfig) (*AdminRevokeAllService, error) {
	if !sessions.Configured() || issuerNil(executor) || !validAdminRevokeConfig(c) {
		return nil, ErrInvalidInput
	}
	c.PolicyID = strings.Clone(c.PolicyID)
	return &AdminRevokeAllService{sessions: sessions, executor: executor, config: c}, nil
}

// AdminSessionRevokeAll invalidates the target's sessions across audiences
// without affecting other users or the target's other credential types.
func (s *AdminRevokeAllService) AdminSessionRevokeAll(ctx context.Context, r AdminSessionRevokeAllRequest) (AdminSessionRevokeAllResult, error) {
	if r.ActorID == "" {
		return AdminSessionRevokeAllResult{}, ErrInvalidInput
	}
	return s.adminSessionRevokeAll(ctx, r, nil)
}

// AdminSessionRevokeAllWithAdmission calls the trusted transport's quota hook
// once after exact authorization, original credentials and synchronizer have
// been checked. The hook cannot extend original freshness.
func (s *AdminRevokeAllService) AdminSessionRevokeAllWithAdmission(ctx context.Context, r AdminSessionRevokeAllRequest, admit func(context.Context, identity.UserID) error) (AdminSessionRevokeAllResult, error) {
	if admit == nil {
		return AdminSessionRevokeAllResult{}, ErrInvalidInput
	}
	return s.adminSessionRevokeAll(ctx, r, admit)
}

func (s *AdminRevokeAllService) adminSessionRevokeAll(ctx context.Context, r AdminSessionRevokeAllRequest, admit func(context.Context, identity.UserID) error) (AdminSessionRevokeAllResult, error) {
	if s == nil || issuerNil(s.executor) {
		return AdminSessionRevokeAllResult{}, ErrInvalidInput
	}
	op := AdminSessionRevokeAllOperation()
	b := identity.CommandBinding{CommandID: r.CommandID, TenantID: r.TenantID, UserID: identity.UserID(r.TargetSubjectID), ActorID: identity.ActorID(r.ActorID), ActorKind: authorization.SubjectUser, OperationID: op.OperationID, RecordID: string(r.TargetSubjectID), PolicyID: s.config.PolicyID, PolicyVersion: uint64(s.config.PolicyRevision), SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, CorrelationID: r.CorrelationID}
	input := adminRevocationInput{binding: b, operation: op, credential: r.Credential, csrf: r.CSRF}
	return runAdminRevocation(ctx, s.sessions, s.config, input, admit, s.executor.ExecuteAdminSessionRevokeAll, func(result AdminSessionRevokeAllResult) bool {
		return result.SubjectVersion > 0 && result.RevokedCount <= MaxAdminSessionRevokeCount
	})
}

// Format redacts credential custody and identifying scope.
func (AdminSessionRevokeAllRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("session.AdminSessionRevokeAllRequest(redacted)"))
}

// MarshalJSON rejects implicit credential serialization.
func (AdminSessionRevokeAllRequest) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText rejects implicit credential serialization.
func (AdminSessionRevokeAllRequest) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }
