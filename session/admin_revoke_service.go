package session

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// AdminSessionRevokeRequest identifies one exact target and supplies the
// original ordinary administrator cookie and stored synchronizer. Direct
// callers must supply ActorID; the trusted HTTP adapter derives it instead.
// CommandID is server-owned correlation for native outcome recovery, not a
// client idempotency key. Never log or serialize the request.
type AdminSessionRevokeRequest struct {
	TenantID        identity.TenantID
	ActorID         identity.SubjectID
	TargetSubjectID identity.SubjectID
	SessionID       string
	CommandID       identity.CommandID
	CorrelationID   string
	Credential      Credential
	CSRF            CSRFToken
}

// AdminSessionRevokeResult is a confirmed mutation or a non-disclosing no-op.
// Version is positive only on a new transition and zero on no-op: an absent
// session cannot have a post-transition version. A result accompanied by any
// error is not evidence of a confirmed transition or a no-op.
type AdminSessionRevokeResult struct {
	Revoked bool
	Version SessionVersion
}

// AdminRevokeExecutor is satisfied by the owned durable session adapter.
// It must apply current authorization, primary actor and exact-target fences,
// stored CSRF, audit and lifecycle in the native execution path. It must not
// infer rollback from lost acknowledgment. Recovery stays with the original
// command owner and the request's original CommandID.
type AdminRevokeExecutor interface {
	ExecuteAdminSessionRevoke(context.Context, AdminSessionRevocation) (AdminSessionRevokeResult, error)
}

// AdminRevokeConfig selects the exact native policy revision, original
// synchronizer key and a whole-call budget of 1ms..5s. The native executor
// validates against independently configured, matching deployment policy.
type AdminRevokeConfig struct {
	Authorization   authorization.Service
	PolicyID        string
	PolicyRevision  authorization.Revision
	CSRFKey         CSRFKey
	MaximumDuration time.Duration
}

// AdminRevokeService authenticates and authorizes single-session revocation.
// It owns no storage or transaction, starts no goroutines and borrows its
// concurrent-safe dependencies for its lifetime.
type AdminRevokeService struct {
	sessions *SessionService
	executor AdminRevokeExecutor
	config   AdminRevokeConfig
}

// NewAdminRevokeService validates the explicit runtime composition without IO.
func NewAdminRevokeService(sessions *SessionService, executor AdminRevokeExecutor, c AdminRevokeConfig) (*AdminRevokeService, error) {
	if !sessions.Configured() || issuerNil(executor) || issuerNil(c.Authorization) || c.CSRFKey.Version() == 0 || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 5*time.Second {
		return nil, ErrInvalidInput
	}
	// Validate configuration with the shared binding grammar, not a second
	// policy syntax that could disagree with the transactional owner.
	validation := AdminSessionRevokeRequest{TenantID: "validation", TargetSubjectID: "validation", SessionID: "validation", CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", CorrelationID: "validation"}
	if adminRevokeBinding(validation, c, "validation").ValidateFor(AdminSessionRevokeOperation()) != nil {
		return nil, ErrInvalidInput
	}
	c.PolicyID = strings.Clone(c.PolicyID)
	return &AdminRevokeService{sessions: sessions, executor: executor, config: c}, nil
}

// AdminSessionRevoke revokes at most the one authorized session. Neither
// the target's sibling sessions nor its other credentials are changed.
func (s *AdminRevokeService) AdminSessionRevoke(ctx context.Context, r AdminSessionRevokeRequest) (AdminSessionRevokeResult, error) {
	if r.ActorID == "" {
		return AdminSessionRevokeResult{}, ErrInvalidInput
	}
	return s.adminSessionRevoke(ctx, r, nil)
}

// AdminSessionRevokeWithAdmission invokes the trusted transport's quota hook
// once after current authentication, target authorization and CSRF checks.
// The hook receives the derived actor, is never retained, and may deny before
// operation work. It cannot extend the original authentication deadline.
func (s *AdminRevokeService) AdminSessionRevokeWithAdmission(ctx context.Context, r AdminSessionRevokeRequest, admit func(context.Context, identity.UserID) error) (AdminSessionRevokeResult, error) {
	if admit == nil {
		return AdminSessionRevokeResult{}, ErrInvalidInput
	}
	return s.adminSessionRevoke(ctx, r, admit)
}

func (s *AdminRevokeService) adminSessionRevoke(ctx context.Context, r AdminSessionRevokeRequest, admit func(context.Context, identity.UserID) error) (out AdminSessionRevokeResult, err error) {
	entered := false
	defer func() {
		if recover() != nil {
			out, err = AdminSessionRevokeResult{}, ErrUnavailable
			if entered {
				err = identity.UnknownCommitError{CommandID: r.CommandID}
			}
		}
	}()
	if s == nil || !s.sessions.Configured() || ctx == nil || r.Credential.Kind() != CredentialCookie {
		return out, ErrInvalidInput
	}
	actor := r.ActorID
	if actor == "" {
		actor = "validation"
	}
	binding := adminRevokeBinding(r, s.config, actor)
	if binding.ValidateFor(AdminSessionRevokeOperation()) != nil {
		return out, ErrInvalidInput
	}
	bounded, stop := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer stop()
	caller, err := s.sessions.Get(bounded, GetRequest{TenantID: r.TenantID, Credential: r.Credential})
	if err != nil {
		return out, signOutError(err)
	}
	source, err := caller.Session.Bindings()
	if err != nil {
		return out, ErrUnauthenticated
	}
	if r.ActorID == "" {
		binding.ActorID = identity.ActorID(source.UserID)
	}
	prepared, err := s.sessions.PrepareAdminSessionRevoke(caller, binding, r.CSRF, s.config.CSRFKey)
	if err != nil {
		return out, err
	}
	now := s.sessions.config.Clock.Now()
	valid, expire := context.WithTimeout(bounded, prepared.ValidUntil().Sub(now))
	defer expire()
	if err := adminRevokeCurrent(valid, s.sessions, prepared, now); err != nil {
		return out, err
	}
	decision, err := s.config.Authorization.Decide(valid, authorization.DecisionContext{
		PolicyRevision: s.config.PolicyRevision, CorrelationID: binding.CorrelationID,
		Request: authorization.Request{
			Tenant:  authorization.TenantID(binding.TenantID),
			Subject: authorization.Subject{ID: authorization.SubjectID(binding.ActorID), Kind: authorization.SubjectUser},
			Action:  authorization.Action(binding.OperationID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(binding.UserID)},
			Environment: authorization.Environment{Time: now},
		},
	})
	if valid.Err() != nil {
		return out, sessionReadFailure(valid)
	}
	if err != nil {
		return out, ErrUnavailable
	}
	if decision.Outcome != authorization.Allow || decision.Revision != s.config.PolicyRevision {
		return out, identity.ForbiddenError{}
	}
	if err := adminRevokeCurrent(valid, s.sessions, prepared, s.sessions.config.Clock.Now()); err != nil {
		return out, err
	}
	if admit != nil {
		if err := admit(valid, source.UserID); err != nil {
			return out, err
		}
		if err := adminRevokeCurrent(valid, s.sessions, prepared, s.sessions.config.Clock.Now()); err != nil {
			return out, err
		}
	}
	entered = true
	result, err := s.executor.ExecuteAdminSessionRevoke(valid, prepared)
	if err != nil {
		return out, err
	}
	if result.Revoked != (result.Version > 0) {
		return out, identity.UnknownCommitError{CommandID: r.CommandID}
	}
	return result, nil
}

func adminRevokeCurrent(ctx context.Context, sessions *SessionService, r AdminSessionRevocation, now time.Time) error {
	if ctx.Err() != nil {
		return sessionReadFailure(ctx)
	}
	return r.Validate(sessions, now)
}

func adminRevokeBinding(r AdminSessionRevokeRequest, c AdminRevokeConfig, actor identity.SubjectID) identity.CommandBinding {
	op := AdminSessionRevokeOperation()
	return identity.CommandBinding{CommandID: r.CommandID, TenantID: r.TenantID, UserID: identity.UserID(r.TargetSubjectID), ActorID: identity.ActorID(actor), ActorKind: authorization.SubjectUser, OperationID: op.OperationID, RecordID: r.SessionID, PolicyID: c.PolicyID, PolicyVersion: uint64(c.PolicyRevision), SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, CorrelationID: r.CorrelationID}
}

// Format redacts the original credentials and target data.
func (AdminSessionRevokeRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("session.AdminSessionRevokeRequest(redacted)"))
}

// MarshalJSON rejects implicit credential serialization.
func (AdminSessionRevokeRequest) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText rejects implicit credential serialization.
func (AdminSessionRevokeRequest) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }
