package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
)

// RevokeSetExecutor is the owned durable adapter boundary, not an application
// workflow callback. It authorizes before reservation, checks original opaque
// caller custody/freshness and current owners, serializes against issuance, and
// applies the entire bounded set plus source-version transition/audit/lifecycle
// in the sole transaction. It persists exact counts, source disposition and
// command recovery; an unknown outcome never authorizes a replacement mutation.
// Dependencies honor ctx, are concurrency-safe and remain borrowed through calls.
type RevokeSetExecutor interface {
	ExecuteRevokeSet(context.Context, RevokeSetRequest) (RevokeSetExecutionResult, error)
}

// RevokeSetExecutionResult is the owned durable receipt plus retained metadata.
// On committed outcomes, RevokedCount is bounded by the command limit,
// SubjectVersion is the unchanged current user-authority CAS version and
// CurrentSessionRevoked matches the explicit disposition. Receipt versions
// describe the source session's successor, never a new user-wide authority.
// If an error prevents retained metadata retrieval after a known commit, all
// three metadata fields are zero; the exact committed receipt remains intact.
// On other outcomes those metadata fields must all be zero. No credentials or
// refreshed authentication are returned. Treat this as historical metadata only.
type RevokeSetExecutionResult struct {
	Receipt               identity.CommandResult
	RevokedCount          uint32
	SubjectVersion        uint64
	CurrentSessionRevoked bool
}

// SetRevocationConfig selects explicit policy identity/version, all-or-nothing
// active-row bound 1..100000 and a 1ms..30s whole-call budget. Earlier caller,
// original authority and freshness deadlines win. Zero is invalid; configuration
// and borrowed dependencies must remain immutable during concurrent calls.
type SetRevocationConfig struct {
	PolicyID        string
	PolicyVersion   uint64
	MaximumSessions uint32
	MaximumDuration time.Duration
}

// SetRevocationService owns authenticated, fresh self-service revoke-other/all
// composition. It creates no stores, transactions, goroutines, policy engine or
// journal. Native atomic execution/recovery is a separate owned-adapter step;
// installing this service alone is not a complete persisted revocation workflow.
type SetRevocationService struct {
	sessions *SessionService
	executor RevokeSetExecutor
	config   SetRevocationConfig
}

// NewSetRevocationService freezes explicit dependencies without IO. Use the owned
// primary reader and executor configured for that exact reader; caller-selected
// user IDs, structural records or consumer stores cannot replace credentials.
func NewSetRevocationService(sessions *SessionService, executor RevokeSetExecutor, c SetRevocationConfig) (*SetRevocationService, error) {
	if sessions == nil || sessions.reader == nil || issuerNil(executor) || c.MaximumSessions < 1 || c.MaximumSessions > 100000 || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second {
		return nil, ErrInvalidInput
	}
	b := setServiceBinding("validation", "validation", "AQEBAQEBAQEBAQEBAQEBAQ", "validation", c, RevokeOtherOperation())
	if b.ValidateFor(RevokeOtherOperation()) != nil {
		return nil, ErrInvalidInput
	}
	c.PolicyID = strings.Clone(c.PolicyID)
	return &SetRevocationService{sessions, executor, c}, nil
}

// RevokeOtherInput selects actual source credentials and a host-generated
// command/correlation, never user/session targets. Zero credential or malformed
// binding is invalid. HTTP owns canonical parsing and cookie origin/CSRF policy.
type RevokeOtherInput struct {
	TenantID      identity.TenantID
	Credential    Credential
	CommandID     identity.CommandID
	CorrelationID string
}

// RevokeAllInput explicitly selects source disposition and the positive current
// user-authority CAS version. That version must equal the authenticated snapshot;
// it is not a caller-selected invalidation authority. Native execution rechecks
// it under the same primary user lock that serializes issuance/revocation.
type RevokeAllInput struct {
	TenantID               identity.TenantID
	Credential             Credential
	CommandID              identity.CommandID
	CorrelationID          string
	IncludeCurrent         bool
	ExpectedSubjectVersion uint64
}

// RevokeSetResult preserves durable command outcome and scoped recovery. Counts,
// current disposition, SubjectVersion and source SessionVersion are disclosed
// only after consistent committed success inside original authority/freshness
// deadlines. SubjectVersion remains the user's current CAS version, not a new
// epoch. SessionVersion is the source successor, even when it is tombstoned.
// A survivor retains its original bearer, expiry and authentication timestamps;
// HTTP clears only the selected transport when CurrentSessionRevoked is true.
// Retain recovery scope after Unknown/InProgress; do not issue a replacement.
type RevokeSetResult struct {
	CommandID             identity.CommandID
	CommitOutcome         identity.CommitOutcome
	RetryAfter            time.Duration
	Recovery              identity.RecoveryQuery
	RevokedCount          uint32
	SubjectVersion        uint64
	SessionVersion        uint64
	CurrentSessionRevoked bool
}

// RevokeOther freshly authenticates and prepares exact self-owned revocation
// excluding the source, then delegates current policy and atomic persistence
// to the owned executor. No partial count or apparent success is returned for
// denial, outage, malformed receipts, cancellation or an ambiguous outcome.
func (s *SetRevocationService) RevokeOther(ctx context.Context, r RevokeOtherInput) (RevokeSetResult, error) {
	return s.revoke(ctx, r, false, false, 0)
}

// RevokeAll freshly authenticates the source and explicitly preserves or revokes
// it while targeting all user-owned sessions in the tenant, across audiences.
// ExpectedSubjectVersion is positive and exact; mismatch denies before execution.
func (s *SetRevocationService) RevokeAll(ctx context.Context, r RevokeAllInput) (RevokeSetResult, error) {
	return s.revoke(ctx, RevokeOtherInput{r.TenantID, r.Credential, r.CommandID, r.CorrelationID}, true, r.IncludeCurrent, r.ExpectedSubjectVersion)
}

func (s *SetRevocationService) revoke(ctx context.Context, r RevokeOtherInput, all, include bool, expected uint64) (out RevokeSetResult, err error) {
	entered := false
	defer func() {
		if recover() != nil {
			out.RevokedCount, out.SubjectVersion, out.SessionVersion, out.CurrentSessionRevoked = 0, 0, 0, false
			if entered && out.CommitOutcome != identity.CommitOutcomeCommitted {
				out.CommitOutcome = identity.CommitOutcomeUnknown
				err = identity.UnknownCommitError{CommandID: out.CommandID}
			} else {
				err = ErrUnavailable
			}
		}
	}()
	if s == nil || ctx == nil || s.sessions == nil || issuerNil(s.executor) || r.Credential.token.state == nil || (r.Credential.kind != CredentialCookie && r.Credential.kind != CredentialBearer) || all && expected == 0 {
		return out, ErrInvalidInput
	}
	op := RevokeOtherOperation()
	if all {
		op = RevokeAllOperation()
	}
	b := setServiceBinding(r.TenantID, "validation", r.CommandID, r.CorrelationID, s.config, op)
	if b.ValidateFor(op) != nil {
		return out, ErrInvalidInput
	}
	out.CommandID = r.CommandID
	bounded, stop := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer stop()
	if bounded.Err() != nil {
		return out, sessionReadFailure(bounded)
	}
	caller, e := s.sessions.Get(bounded, GetRequest{TenantID: r.TenantID, Credential: r.Credential})
	if e != nil {
		return out, signOutError(e)
	}
	if bounded.Err() != nil {
		return out, sessionReadFailure(bounded)
	}
	if !caller.Authenticated {
		return out, ErrUnauthenticated
	}
	spec, e := caller.Session.Bindings()
	if e != nil {
		return out, ErrUnavailable
	}
	vector, _ := spec.Authority.Bindings()
	if all && expected != vector.User.Version {
		return out, identity.ConflictError{}
	}
	b = setServiceBinding(r.TenantID, spec.UserID, r.CommandID, r.CorrelationID, s.config, op)
	b.RecordID = spec.SessionID
	var command SessionCommand
	if all {
		command, e = NewRevokeAllCommand(b, caller.Session, include, s.config.MaximumSessions)
	} else {
		command, e = NewRevokeOtherCommand(b, caller.Session, s.config.MaximumSessions)
	}
	if e != nil {
		return out, e
	}
	request, e := s.sessions.PrepareRevokeSet(caller, command)
	if e != nil {
		return out, e
	}
	now := s.sessions.config.Clock.Now()
	if e = request.Validate(s.sessions, now); e != nil {
		return out, e
	}
	valid, cancel := context.WithTimeout(bounded, request.ValidUntil().Sub(now))
	defer cancel()
	if valid.Err() != nil {
		return out, sessionReadFailure(valid)
	}
	out.Recovery = identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
	entered = true
	out.CommitOutcome = identity.CommitOutcomeUnknown
	result, dependencyErr := s.executor.ExecuteRevokeSet(valid, request)
	var forbidden identity.ForbiddenError
	if result.Receipt == (identity.CommandResult{}) && dependencyErr != nil && (errors.As(dependencyErr, &forbidden) || errors.Is(dependencyErr, ErrUnauthenticated) || errors.Is(dependencyErr, ErrFreshnessRequired) || errors.Is(dependencyErr, ErrInvalidInput)) {
		out.CommitOutcome = identity.CommitOutcomeInvalid
		return out, setRevocationError(dependencyErr)
	}
	receipt := result.Receipt
	if receipt.Validate() != nil || receipt.Binding != b || receipt.Feature == nil || receipt.Feature.Operation != op {
		return out, identity.UnknownCommitError{CommandID: r.CommandID}
	}
	if receipt.Outcome == identity.CommitOutcomeCommitted {
		if receipt.Feature.BeforeVersion != spec.Version || receipt.Feature.AfterVersion != spec.Version+1 {
			return out, identity.UnknownCommitError{CommandID: r.CommandID}
		}
		// Count retrieval is ancillary to an already proven command commit.
		// Preserve that outcome without inventing unavailable metadata or
		// allowing a malformed/partial projection to become successful output.
		if dependencyErr != nil && result.RevokedCount == 0 && result.SubjectVersion == 0 && !result.CurrentSessionRevoked {
			out.CommitOutcome = identity.CommitOutcomeCommitted
			return out, setRevocationError(dependencyErr)
		}
		if result.RevokedCount > s.config.MaximumSessions || result.SubjectVersion != vector.User.Version || result.CurrentSessionRevoked != include || include && result.RevokedCount == 0 {
			return out, identity.UnknownCommitError{CommandID: r.CommandID}
		}
	} else if result.RevokedCount != 0 || result.SubjectVersion != 0 || result.CurrentSessionRevoked {
		return out, identity.UnknownCommitError{CommandID: r.CommandID}
	}
	out.CommitOutcome, out.RetryAfter = receipt.Outcome, receipt.RetryAfter
	if receipt.Outcome != identity.CommitOutcomeCommitted {
		if dependencyErr != nil {
			redacted := setRevocationError(dependencyErr)
			switch redacted.(type) {
			case identity.CancelledError, identity.DeadlineExceededError:
				return out, redacted
			}
			if errors.Is(redacted, ErrFreshnessRequired) {
				return out, redacted
			}
		}
		// The exact durable receipt owns retry/conflict classification;
		// unrelated dependency text must not override or disclose it.
		switch receipt.Outcome {
		case identity.CommitOutcomeNotCommitted:
			return out, identity.NotCommittedError{}
		case identity.CommitOutcomeConflict:
			return out, identity.ConflictError{}
		case identity.CommitOutcomeInProgress:
			return out, identity.InProgressError{CommandID: r.CommandID, RetryAfter: receipt.RetryAfter}
		default:
			return out, identity.UnknownCommitError{CommandID: r.CommandID}
		}
	}
	if dependencyErr != nil {
		return out, setRevocationError(dependencyErr)
	}
	if valid.Err() != nil {
		return out, sessionReadFailure(valid)
	}
	if e = request.Validate(s.sessions, s.sessions.config.Clock.Now()); e != nil {
		return out, e
	}
	if valid.Err() != nil {
		return out, sessionReadFailure(valid)
	}
	out.RevokedCount, out.SubjectVersion, out.SessionVersion, out.CurrentSessionRevoked = result.RevokedCount, result.SubjectVersion, receipt.Feature.AfterVersion, result.CurrentSessionRevoked
	return out, nil
}

func setRevocationError(err error) error {
	if errors.Is(err, ErrFreshnessRequired) {
		return ErrFreshnessRequired
	}
	return signOutError(err)
}

func setServiceBinding(tenant identity.TenantID, user identity.UserID, command identity.CommandID, correlation string, c SetRevocationConfig, op identity.FeatureOperation) identity.CommandBinding {
	return identity.CommandBinding{CommandID: command, TenantID: tenant, UserID: user, ActorID: identity.ActorID(user), ActorKind: authorization.SubjectUser, OperationID: op.OperationID, RecordID: string(user), SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, PolicyID: c.PolicyID, PolicyVersion: c.PolicyVersion, CorrelationID: correlation}
}

// Format redacts borrowed dependencies and configuration.
func (*SetRevocationService) Format(s fmt.State, _ rune) {
	io.WriteString(s, "session.SetRevocationService(redacted)")
}

// Format redacts policy configuration.
func (SetRevocationConfig) Format(s fmt.State, _ rune) {
	io.WriteString(s, "session.SetRevocationConfig(redacted)")
}

// MarshalJSON denies implicit configuration export.
func (SetRevocationConfig) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// Format redacts correlated credential input.
func (RevokeOtherInput) Format(s fmt.State, _ rune) {
	io.WriteString(s, "session.RevokeOtherInput(redacted)")
}

// MarshalJSON denies implicit credential export.
func (RevokeOtherInput) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// Format redacts correlated credential input.
func (RevokeAllInput) Format(s fmt.State, _ rune) {
	io.WriteString(s, "session.RevokeAllInput(redacted)")
}

// MarshalJSON denies implicit credential export.
func (RevokeAllInput) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// Format redacts correlated durable metadata.
func (RevokeSetResult) Format(s fmt.State, _ rune) {
	io.WriteString(s, "session.RevokeSetResult(redacted)")
}

// MarshalJSON denies implicit output; HTTP owns explicit authorized DTOs.
func (RevokeSetResult) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// Format redacts correlated native receipt metadata.
func (RevokeSetExecutionResult) Format(s fmt.State, _ rune) {
	io.WriteString(s, "session.RevokeSetExecutionResult(redacted)")
}

// MarshalJSON denies implicit durable result export.
func (RevokeSetExecutionResult) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }
