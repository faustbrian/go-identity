package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// UpdateExecutor is implemented by the owned durable adapter, not application
// workflow callbacks or another command journal. ExecuteUpdate authorizes the
// exact current policy, validates original same-reader custody and current
// primary owners, and commits label/session CAS/audit/lifecycle/receipt under
// the sole coordinator. Exact intent replay must not reapply the mutation.
// RecoverUpdate authorizes current exact result access and observes the original
// command only; source expiry must not erase commitment. Neither method returns
// credentials or renewed admission. Methods are concurrent-safe and honor ctx.
// A zero receipt with ForbiddenError, ErrUnauthenticated or ErrInvalidInput and
// absent result metadata/replay is reserved for rejection before reservation
// and effects (Execute) or outcome observation (Recover); it does not classify
// a historical command as rolled back.
type UpdateExecutor interface {
	ExecuteUpdate(context.Context, UpdateCommandRequest) (UpdateExecution, error)
	RecoverUpdate(context.Context, UpdateCommandRequest) (identity.CommandResult, error)
}

// UpdateExecution carries an exact durable receipt and historical successor
// label. Session and DeviceLabel are absent on noncommits. A known commit's
// ancillary read failure may return zero Session/label alongside an error;
// the exact committed receipt remains intact. Replayed describes historical
// observation, not a replacement command or current authority.
type UpdateExecution struct {
	Receipt     identity.CommandResult
	Session     Session
	DeviceLabel string
	Replayed    bool
}

// UpdateConfig requires explicit selected self-policy identity/version and a
// 1ms..30s whole-call budget. Original admission expiry always wins. Zero is
// invalid; the frozen configuration adds no clock, token key or store.
type UpdateConfig struct {
	PolicyID        string
	PolicyVersion   uint64
	MaximumDuration time.Duration
}

// UpdatePreparation identifies the authenticating session and exact expected
// positive session version. CommandID is the stable host-validated identity,
// not a per-attempt random key. DeviceLabel is bounded untrusted display text;
// empty clears it. No owner override, security-field patch or clock is accepted.
// Copies are safe only while caller-owned fields remain immutable.
type UpdatePreparation struct {
	CommandID       identity.CommandID
	CorrelationID   string
	SessionID       string
	ExpectedVersion uint64
	DeviceLabel     string
}

// SessionUpdater owns source-bound label preparation, bounded native execution,
// receipt validation and safe outcome recovery. It creates no store, journal,
// transaction, token, goroutine or competing authority vector. Borrowed reader
// and executor must outlive calls and satisfy their concurrency/budget contracts.
type SessionUpdater struct {
	sessions *SessionService
	executor UpdateExecutor
	config   UpdateConfig
}

// NewSessionUpdater freezes explicit composition without IO. Use the owned
// primary reader and native executor for the exact reader; installing core
// alone does not implement PostgreSQL mutation or permit consumer-written stores.
func NewSessionUpdater(sessions *SessionService, executor UpdateExecutor, c UpdateConfig) (*SessionUpdater, error) {
	if sessions == nil || sessions.reader == nil || issuerNil(executor) || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second {
		return nil, ErrInvalidInput
	}
	b := updateServiceBinding("validation", "validation", "validation", "AQEBAQEBAQEBAQEBAQEBAQ", "validation", c)
	if b.ValidateFor(UpdateOperation()) != nil {
		return nil, ErrInvalidInput
	}
	c.PolicyID = strings.Clone(c.PolicyID)
	return &SessionUpdater{sessions, executor, c}, nil
}

func updateServiceBinding(tenant identity.TenantID, user identity.UserID, record string, command identity.CommandID, correlation string, c UpdateConfig) identity.CommandBinding {
	b := setServiceBinding(tenant, user, command, correlation, SetRevocationConfig{PolicyID: c.PolicyID, PolicyVersion: c.PolicyVersion}, UpdateOperation())
	b.RecordID = record
	return b
}

// Prepare requires unchanged same-reader original Get custody and an exact
// self-session ID/version before constructing a label-only transition. A stale
// expected version returns identity.ConflictError without reserving anything.
// It runs no IO, authorization or mutation; ordinary safe metadata needs no
// fresh login. Retain the returned immutable request for exact scoped recovery.
func (s *SessionUpdater) Prepare(caller GetResult, input UpdatePreparation) (out UpdateCommandRequest, err error) {
	defer func() {
		if recover() != nil {
			out, err = UpdateCommandRequest{}, ErrUnavailable
		}
	}()
	if s == nil || caller.validity == nil || caller.validity.owner != s.sessions {
		return out, ErrUnauthenticated
	}
	if !authorityKey(input.SessionID, 128) || input.ExpectedVersion == 0 || !validListLabel(input.DeviceLabel) {
		return out, ErrInvalidInput
	}
	if err = caller.ValidateAt(s.sessions.config.Clock.Now()); err != nil {
		return out, err
	}
	source, _ := caller.Session.Bindings()
	b := updateServiceBinding(source.TenantID, source.UserID, source.SessionID, input.CommandID, input.CorrelationID, s.config)
	if b.ValidateFor(UpdateOperation()) != nil {
		return out, ErrInvalidInput
	}
	if input.SessionID != source.SessionID {
		return out, ErrUnauthenticated
	}
	if input.ExpectedVersion != source.Version {
		return out, identity.ConflictError{CommandID: input.CommandID}
	}
	command, err := NewUpdateCommand(b, caller.Session, input.DeviceLabel)
	if err != nil {
		return out, err
	}
	return s.sessions.PrepareUpdate(caller, command)
}

// UpdateResult retains exact durable outcome and recovery scope. Session and
// Device appear only after consistent committed success inside the original
// admission/context deadlines. They are historical display data, not new Get
// custody or permission. Recovery returns no Session/Device and never claims
// that a historical command's target remains the current active session.
// Invalid means no authoritative outcome was observed, including cancellation
// before executor entry; it must not be interpreted as original command rollback.
type UpdateResult struct {
	CommandID     identity.CommandID
	CommitOutcome identity.CommitOutcome
	RetryAfter    time.Duration
	Recovery      identity.RecoveryQuery
	Session       Session
	Device        Device
	Replayed      bool
}

func updateResultScope(r UpdateCommandRequest) UpdateResult {
	c, _ := r.Command()
	u, _ := c.Update()
	b := u.Binding
	return UpdateResult{CommandID: b.CommandID, Recovery: identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID, LinkMode: b.LinkMode}}
}

func (s *SessionUpdater) owns(r UpdateCommandRequest) bool {
	if s == nil || r.state == nil || r.state.caller.validity == nil || r.state.caller.validity.owner != s.sessions {
		return false
	}
	c, ok := r.Command()
	u, valid := c.Update()
	return ok && valid && u.Binding.PolicyID == s.config.PolicyID && u.Binding.PolicyVersion == s.config.PolicyVersion
}

// Update makes one bounded exact-intent attempt. The durable coordinator owns
// idempotency across retries and processes. Panic or malformed response after
// executor entry is Unknown, never assumed rollback. A known committed receipt
// survives cancellation, expiry or ancillary read errors without apparent
// metadata success. Recover an ambiguous outcome before changing command intent.
func (s *SessionUpdater) Update(ctx context.Context, r UpdateCommandRequest) (out UpdateResult, err error) {
	entered := false
	defer func() {
		if recover() != nil {
			out.Session, out.Device = Session{}, Device{}
			if entered && out.CommitOutcome != identity.CommitOutcomeCommitted {
				out.CommitOutcome = identity.CommitOutcomeUnknown
				err = identity.UnknownCommitError{CommandID: out.CommandID}
			} else {
				err = ErrUnavailable
			}
		}
	}()
	if ctx == nil || !s.owns(r) {
		return out, ErrInvalidInput
	}
	out = updateResultScope(r)
	out.CommitOutcome = identity.CommitOutcomeInvalid
	now := s.sessions.config.Clock.Now()
	if err = r.Validate(s.sessions, now); err != nil {
		return out, err
	}
	bounded, stop := context.WithTimeout(ctx, min(s.config.MaximumDuration, r.ValidUntil().Sub(now)))
	defer stop()
	if bounded.Err() != nil {
		return out, sessionReadFailure(bounded)
	}
	entered = true
	out.CommitOutcome = identity.CommitOutcomeUnknown
	execution, cause := s.executor.ExecuteUpdate(bounded, r)
	if execution.Receipt == (identity.CommandResult{}) && execution.Session == (Session{}) && execution.DeviceLabel == "" && !execution.Replayed && updateRejected(cause) {
		out.CommitOutcome = identity.CommitOutcomeInvalid
		return out, signOutError(cause)
	}
	out, err = s.receipt(r, execution.Receipt)
	if err != nil {
		if bounded.Err() != nil {
			return out, sessionReadFailure(bounded)
		}
		return out, err
	}
	out.Replayed = execution.Replayed
	if out.CommitOutcome != identity.CommitOutcomeCommitted {
		if execution.Session != (Session{}) || execution.DeviceLabel != "" {
			out.CommitOutcome = identity.CommitOutcomeUnknown
			return out, identity.UnknownCommitError{CommandID: out.CommandID}
		}
		if bounded.Err() != nil {
			return out, sessionReadFailure(bounded)
		}
		if special := updateCause(cause); special != nil {
			return out, special
		}
		return out, updateOutcomeError(out)
	}
	c, _ := r.Command()
	u, _ := c.Update()
	if cause != nil && execution.Session == (Session{}) && execution.DeviceLabel == "" {
		return out, signOutError(cause)
	}
	if !sameIssuedSession(execution.Session, u.Successor) || execution.DeviceLabel != u.DeviceLabel {
		out.CommitOutcome = identity.CommitOutcomeUnknown
		return out, identity.UnknownCommitError{CommandID: out.CommandID}
	}
	if cause != nil {
		return out, signOutError(cause)
	}
	if bounded.Err() != nil {
		return out, sessionReadFailure(bounded)
	}
	now = s.sessions.config.Clock.Now()
	if err = r.Validate(s.sessions, now); err != nil {
		return out, err
	}
	life, err := u.Successor.Lifetime(now)
	if err != nil {
		return out, err
	}
	if bounded.Err() != nil {
		return out, sessionReadFailure(bounded)
	}
	spec, _ := u.Successor.Bindings()
	out.Session = u.Successor
	out.Device = Device{SessionID: spec.SessionID, Label: strings.Clone(execution.DeviceLabel), LastSeenAt: spec.LastActivityAt.UTC(), ExpiresAt: life.ExpiresAt.UTC(), Current: true}
	return out, nil
}

// Recover observes the original exact scoped command under the executor's
// current result-access policy. It does not require an expired original source
// to become valid again, execute a mutation or return session/display metadata.
// Copies preserve original custody and expiry; no recovery grants admission.
func (s *SessionUpdater) Recover(ctx context.Context, r UpdateCommandRequest) (out UpdateResult, err error) {
	entered := false
	defer func() {
		if recover() != nil {
			if entered && out.CommitOutcome != identity.CommitOutcomeCommitted {
				out.CommitOutcome = identity.CommitOutcomeUnknown
				err = identity.UnknownCommitError{CommandID: out.CommandID}
			} else {
				err = ErrUnavailable
			}
		}
	}()
	if ctx == nil || !s.owns(r) {
		return out, ErrInvalidInput
	}
	out = updateResultScope(r)
	out.Replayed = true
	out.CommitOutcome = identity.CommitOutcomeInvalid
	bounded, stop := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer stop()
	if bounded.Err() != nil {
		return out, sessionReadFailure(bounded)
	}
	entered = true
	out.CommitOutcome = identity.CommitOutcomeUnknown
	receipt, cause := s.executor.RecoverUpdate(bounded, r)
	if receipt == (identity.CommandResult{}) && updateRejected(cause) {
		out.CommitOutcome = identity.CommitOutcomeInvalid
		return out, signOutError(cause)
	}
	out, err = s.receipt(r, receipt)
	out.Replayed = true
	if err != nil {
		if bounded.Err() != nil {
			return out, sessionReadFailure(bounded)
		}
		return out, err
	}
	if bounded.Err() != nil {
		return out, sessionReadFailure(bounded)
	}
	if out.CommitOutcome != identity.CommitOutcomeCommitted {
		if special := updateCause(cause); special != nil {
			return out, special
		}
		return out, updateOutcomeError(out)
	}
	if cause != nil {
		return out, signOutError(cause)
	}
	return out, nil
}

func updateRejected(cause error) bool {
	var denied identity.ForbiddenError
	return cause != nil && (errors.As(cause, &denied) || errors.Is(cause, ErrUnauthenticated) || errors.Is(cause, ErrInvalidInput))
}

// Preserve cancellation and explicit denial without letting arbitrary adapter
// diagnostics replace the exact durable retry/conflict outcome.
func updateCause(cause error) error {
	if cause == nil {
		return nil
	}
	redacted := signOutError(cause)
	switch redacted.(type) {
	case identity.ForbiddenError, identity.CancelledError, identity.DeadlineExceededError:
		return redacted
	}
	if errors.Is(redacted, ErrUnauthenticated) || errors.Is(redacted, ErrInvalidInput) {
		return redacted
	}
	return nil
}

func (s *SessionUpdater) receipt(r UpdateCommandRequest, receipt identity.CommandResult) (out UpdateResult, err error) {
	out = updateResultScope(r)
	out.CommitOutcome = identity.CommitOutcomeUnknown
	c, _ := r.Command()
	u, _ := c.Update()
	source, _ := u.Source.Bindings()
	if receipt.Validate() != nil || receipt.Binding != u.Binding || receipt.Feature == nil || receipt.Feature.Operation != UpdateOperation() {
		return out, identity.UnknownCommitError{CommandID: out.CommandID}
	}
	if receipt.Outcome == identity.CommitOutcomeCommitted && (receipt.Feature.BeforeVersion != source.Version || receipt.Feature.AfterVersion != source.Version+1) {
		return out, identity.UnknownCommitError{CommandID: out.CommandID}
	}
	out.CommitOutcome, out.RetryAfter = receipt.Outcome, receipt.RetryAfter
	return out, nil
}

func updateOutcomeError(out UpdateResult) error {
	switch out.CommitOutcome {
	case identity.CommitOutcomeNotCommitted:
		return identity.NotCommittedError{CommandID: out.CommandID}
	case identity.CommitOutcomeConflict:
		return identity.ConflictError{CommandID: out.CommandID}
	case identity.CommitOutcomeInProgress:
		return identity.InProgressError{CommandID: out.CommandID, RetryAfter: out.RetryAfter}
	default:
		return identity.UnknownCommitError{CommandID: out.CommandID}
	}
}

// Format redacts borrowed runtime composition.
func (*SessionUpdater) Format(s fmt.State, _ rune) {
	io.WriteString(s, "session.SessionUpdater(redacted)")
}

// MarshalJSON denies implicit runtime export.
func (*SessionUpdater) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// Format redacts policy configuration.
func (UpdateConfig) Format(s fmt.State, _ rune) { io.WriteString(s, "session.UpdateConfig(redacted)") }

// MarshalJSON denies implicit configuration export.
func (UpdateConfig) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// Format redacts labels and correlated command input.
func (UpdatePreparation) Format(s fmt.State, _ rune) {
	io.WriteString(s, "session.UpdatePreparation(redacted)")
}

// MarshalJSON denies implicit label/command input export.
func (UpdatePreparation) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText denies text and map-key input export.
func (UpdatePreparation) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }

// Format redacts historical native receipt and label.
func (UpdateExecution) Format(s fmt.State, _ rune) {
	io.WriteString(s, "session.UpdateExecution(redacted)")
}

// MarshalJSON denies implicit native receipt/label export.
func (UpdateExecution) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// Format redacts historical scope and safe display metadata.
func (UpdateResult) Format(s fmt.State, _ rune) { io.WriteString(s, "session.UpdateResult(redacted)") }

// MarshalJSON denies implicit display export; HTTP owns explicit authorized DTOs.
func (UpdateResult) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText denies implicit result/map-key export.
func (UpdateResult) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }
