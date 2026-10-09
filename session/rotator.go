package session

import (
	"context"
	"crypto/subtle"
	"fmt"
	identity "github.com/faustbrian/go-identity"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// RotationExecutor is implemented by the owned durable adapter, not an
// application workflow or second journal. It preserves original same-reader
// custody and deadlines, authorizes current policy and compares current owners
// inside atomic digest retirement/successor/audit/lifecycle/command effects.
// ExecuteRotation returns Replayed for historical results. RecoverRotation
// authorizes current exact result access and observes the original command;
// it never executes or reveals. Methods are concurrent-safe and must honor ctx.
type RotationExecutor interface {
	ExecuteRotation(context.Context, RotationRequest) (RotationExecution, error)
	RecoverRotation(context.Context, RotationRequest) (RotationExecution, error)
}

// RotationExecution is a durable receipt and exact historical successor.
// Session is absent on noncommits. Replayed forbids credential delivery. If a
// known commit's ancillary result read fails, Session is absent with an error;
// the exact committed receipt remains valid, without manufactured metadata.
type RotationExecution struct {
	Receipt  identity.CommandResult
	Session  Session
	Replayed bool
}

// RotationConfig selects explicit self-service policy, a 1ms..30s call budget,
// 32..64 token bytes, a lookup key retained by the exact reader, and secure host
// cookie policy. The original transport is preserved: bearer results contain
// no cookie. Configuration is frozen; borrowed dependencies must outlive calls.
type RotationConfig struct {
	PolicyID        string
	PolicyVersion   uint64
	MaximumDuration time.Duration
	LookupKey       DigestKey
	TokenSize       int
	Cookie          CookiePolicy
}

// SessionRotator owns exact successor preparation and commit-gated reveal-once
// delivery, but no store, transaction, journal, goroutine or retained key cache.
// Durable execution is provided only by the separately owned native adapter.
type SessionRotator struct {
	sessions *SessionService
	executor RotationExecutor
	config   RotationConfig
	csrfKey  CSRFKey
}

// NewSessionRotatorWithCSRF selects fresh synchronizer state for cookie
// successors with a dedicated current issuance key. Bearer rotation explicitly
// clears synchronizer state and delivers no CSRF credential or cookie. The
// executor must atomically persist complete source/successor state. Do not use
// legacy lossy adapters. Original credential delivery retains all native gates;
// retrieve CSRF custody from PreparedRotation.CSRFToken after successful Rotate.
func NewSessionRotatorWithCSRF(sessions *SessionService, executor RotationExecutor, c RotationConfig, key CSRFKey) (*SessionRotator, error) {
	if key.key.state == nil {
		return nil, ErrInvalidInput
	}
	s, e := NewSessionRotator(sessions, executor, c)
	if e != nil {
		return nil, e
	}
	s.csrfKey = key
	return s, nil
}

// NewSessionRotator freezes validated composition without IO. The issuance key
// must be retained by the reader with identical bytes/version so delivered
// successors are readable. No profile fallback or independent clock is added.
func NewSessionRotator(sessions *SessionService, executor RotationExecutor, c RotationConfig) (*SessionRotator, error) {
	if sessions == nil || sessions.reader == nil || issuerNil(executor) || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || c.LookupKey.state == nil || c.TokenSize < 32 || c.TokenSize > 64 || c.Cookie.name == "" {
		return nil, ErrInvalidInput
	}
	found := false
	for _, key := range sessions.config.LookupKeys {
		if key.state.version == c.LookupKey.state.version && key.state.size == c.LookupKey.state.size && subtle.ConstantTimeCompare(key.state.material[:], c.LookupKey.state.material[:]) == 1 {
			found = true
		}
	}
	if !found {
		return nil, ErrInvalidInput
	}
	b := rotationBinding("validation", "validation", "validation", "AQEBAQEBAQEBAQEBAQEBAQ", "validation", c)
	if b.ValidateFor(RotateOperation()) != nil {
		return nil, ErrInvalidInput
	}
	c.PolicyID = strings.Clone(c.PolicyID)
	return &SessionRotator{sessions: sessions, executor: executor, config: c}, nil
}
func rotationBinding(tenant identity.TenantID, user identity.UserID, record string, command identity.CommandID, correlation string, c RotationConfig) identity.CommandBinding {
	b := setServiceBinding(tenant, user, command, correlation, SetRevocationConfig{PolicyID: c.PolicyID, PolicyVersion: c.PolicyVersion}, RotateOperation())
	b.RecordID = record
	return b
}

// PreparedRotation privately retains the original successor token, command and
// opaque source custody. Copies share one atomic attempt; the durable owner,
// not this in-memory claim, owns idempotency. Retain Request for safe recovery.
type PreparedRotation struct{ state *preparedRotationState }
type preparedRotationState struct {
	owner     *SessionRotator
	request   RotationRequest
	token     Token
	attempted atomic.Bool
	csrf      CSRFToken
	csrfReady atomic.Bool
}

// CSRFToken returns original reveal-once cookie-CSRF custody only after an
// exact new error-free Rotate within original delivery bounds. Zero, precommit,
// recovery-only, tokenless and bearer paths deny. Copies share reveal permission;
// an earlier successful delivery is not retracted by a later rejected attempt.
// This token never proves current primary authority or renews validity.
func (p PreparedRotation) CSRFToken() (CSRFToken, error) {
	if p.state == nil || !p.state.csrfReady.Load() || p.state.csrf.token.state == nil {
		return CSRFToken{}, ErrInvalidCSRF
	}
	return p.state.csrf, nil
}

// Request returns the original safe immutable request, never the raw successor.
func (p PreparedRotation) Request() (RotationRequest, bool) {
	if p.state == nil {
		return RotationRequest{}, false
	}
	return p.state.request, true
}

// Prepare validates original authenticated custody and refresh eligibility
// before generating a token. It preserves absolute issuance, authentication,
// family, policy and non-session authority; accepted activity and session CAS
// advance exactly once in the frozen candidate. Bounded CSPRNG token generation
// runs, but no durable IO, command reservation or state transition occurs.
func (s *SessionRotator) Prepare(caller GetResult, command identity.CommandID, correlation string) (out PreparedRotation, err error) {
	defer func() {
		if recover() != nil {
			out, err = PreparedRotation{}, ErrUnavailable
		}
	}()
	if s == nil || caller.validity == nil || caller.validity.owner != s.sessions {
		return out, ErrUnauthenticated
	}
	now := s.sessions.config.Clock.Now()
	if err = caller.ValidateAt(now); err != nil {
		return out, err
	}
	old, _ := caller.Session.Bindings()
	if caller.validity.transport == CredentialCookie && caller.Session.CSRFState().state != nil && s.csrfKey.key.state == nil {
		return out, ErrInvalidInput
	}
	b := rotationBinding(old.TenantID, old.UserID, old.SessionID, command, correlation, s.config)
	if b.ValidateFor(RotateOperation()) != nil || old.Version == ^uint64(0) {
		return out, ErrInvalidSessionCommand
	}
	life, err := caller.Session.Lifetime(now)
	if err != nil {
		return out, err
	}
	if !life.RefreshDue {
		return out, ErrRotationDeferred
	}
	token, err := NewToken(s.config.TokenSize)
	if err != nil {
		return out, err
	}
	next := old
	next.Version++
	next.LastActivityAt = now.UTC()
	next.Lookup, err = token.Digest(s.config.LookupKey, string(old.TenantID))
	if err != nil {
		return out, err
	}
	vector, _ := old.Authority.Bindings()
	vector.Session.Version = next.Version
	next.Authority, err = NewAuthoritySnapshot(vector)
	if err != nil {
		return out, err
	}
	successor, err := rebuildSession(next, caller.Session, CSRFState{})
	if err != nil {
		return out, err
	}
	var csrf CSRFToken
	if caller.validity.transport == CredentialCookie && s.csrfKey.key.state != nil {
		csrf, successor, err = prepareCSRFRecord(successor, s.csrfKey)
		if err != nil {
			return out, err
		}
	}
	native, err := NewRotateCommand(b, caller.Session, successor)
	if err != nil {
		return out, err
	}
	request, err := s.sessions.PrepareRotation(caller, native)
	if err != nil {
		return out, err
	}
	return PreparedRotation{state: &preparedRotationState{owner: s, request: request, token: token, csrf: csrf}}, nil
}

// RotationResult retains exact durable outcome/recovery and historical
// successor. Token is present only after a new error-free commit within original
// caller/context/lifetime bounds; its copies share reveal-once custody. Cookie
// Value is empty, and bearer transport never emits cookie attributes. This
// result cannot authenticate or renew authority by itself.
type RotationResult struct {
	CommandID     identity.CommandID
	CommitOutcome identity.CommitOutcome
	RetryAfter    time.Duration
	Recovery      identity.RecoveryQuery
	Session       Session
	Replayed      bool
	Transport     CredentialKind
	Token         Token
	Cookie        http.Cookie
}

// Rotate makes one bounded attempt against the original immutable preparation.
// Panic/malformed response after executor entry is Unknown, never rollback.
// Known receipts preserve their outcome alongside errors, without credentials.
// A repeated preparation attempt requires original scoped recovery, not rerun.
func (s *SessionRotator) Rotate(ctx context.Context, p PreparedRotation) (out RotationResult, err error) {
	entered := false
	defer func() {
		if recover() != nil {
			out.Token = Token{}
			out.Cookie = http.Cookie{}
			if entered && out.CommitOutcome != identity.CommitOutcomeCommitted {
				out.CommitOutcome = identity.CommitOutcomeUnknown
				err = identity.UnknownCommitError{CommandID: out.CommandID}
			} else {
				err = ErrUnavailable
			}
		}
	}()
	if ctx == nil || s == nil || p.state == nil || p.state.owner != s {
		return out, ErrInvalidIssuance
	}
	request := p.state.request
	out = rotationResultScope(request)
	now := s.sessions.config.Clock.Now()
	if err = request.Validate(s.sessions, now); err != nil {
		return out, err
	}
	budget := min(s.config.MaximumDuration, request.ValidUntil().Sub(now))
	bounded, stop := context.WithTimeout(ctx, budget)
	defer stop()
	if bounded.Err() != nil {
		return out, sessionReadFailure(bounded)
	}
	if !p.state.attempted.CompareAndSwap(false, true) {
		return out, ErrIssuanceAlreadyAttempted
	}
	entered = true
	out.CommitOutcome = identity.CommitOutcomeUnknown
	execution, cause := s.executor.ExecuteRotation(bounded, request)
	out, err = s.finish(bounded, request, execution, cause)
	if err != nil || out.CommitOutcome != identity.CommitOutcomeCommitted || out.Replayed {
		return out, err
	}
	now = s.sessions.config.Clock.Now()
	if err = request.Validate(s.sessions, now); err != nil {
		return out, err
	}
	life, err := out.Session.Lifetime(now)
	if err != nil {
		return out, err
	}
	if out.Transport == CredentialCookie {
		spec, _ := out.Session.Bindings()
		cookie, e := s.config.Cookie.Attributes(spec.Remember, now, life.AbsoluteExpiresAt)
		if e != nil {
			return out, e
		}
		out.Cookie = cookie
	}
	if bounded.Err() != nil {
		out.Cookie = http.Cookie{}
		return out, sessionReadFailure(bounded)
	}
	out.Token = p.state.token
	p.state.csrfReady.Store(true)
	return out, nil
}

// Recover makes a bounded historical lookup under the native owner's current
// exact result-access policy. Source expiry does not erase commitment. It never
// executes, regenerates or redelivers a credential, including after restart.
func (s *SessionRotator) Recover(ctx context.Context, r RotationRequest) (out RotationResult, err error) {
	entered := false
	defer func() {
		if recover() != nil {
			out.Token = Token{}
			out.Cookie = http.Cookie{}
			if entered && out.CommitOutcome != identity.CommitOutcomeCommitted {
				out.CommitOutcome = identity.CommitOutcomeUnknown
				err = identity.UnknownCommitError{CommandID: out.CommandID}
			} else {
				err = ErrUnavailable
			}
		}
	}()
	if ctx == nil || s == nil || r.state == nil {
		return out, ErrInvalidInput
	}
	out = rotationResultScope(r)
	bounded, stop := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer stop()
	if bounded.Err() != nil {
		return out, sessionReadFailure(bounded)
	}
	entered = true
	out.CommitOutcome = identity.CommitOutcomeUnknown
	execution, cause := s.executor.RecoverRotation(bounded, r)
	out, err = s.finish(bounded, r, execution, cause)
	out.Replayed = true
	return out, err
}
func rotationResultScope(r RotationRequest) RotationResult {
	command, _ := r.Command()
	spec, _ := command.Rotation()
	b := spec.Binding
	return RotationResult{CommandID: b.CommandID, Transport: r.Transport(), Recovery: identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID, LinkMode: b.LinkMode}}
}
func (s *SessionRotator) finish(ctx context.Context, r RotationRequest, e RotationExecution, cause error) (out RotationResult, err error) {
	out = rotationResultScope(r)
	out.CommitOutcome = identity.CommitOutcomeUnknown
	command, _ := r.Command()
	native, _ := command.Rotation()
	source, _ := native.Source.Bindings()
	receipt := e.Receipt
	if receipt.Validate() != nil || receipt.Binding != native.Binding || receipt.Feature == nil || receipt.Feature.Operation != RotateOperation() {
		return out, identity.UnknownCommitError{CommandID: out.CommandID}
	}
	if receipt.Outcome == identity.CommitOutcomeCommitted {
		if receipt.Feature.BeforeVersion != source.Version || receipt.Feature.AfterVersion != source.Version+1 || (!sameIssuedSession(e.Session, native.Successor) && !(cause != nil && e.Session == (Session{}))) {
			return out, identity.UnknownCommitError{CommandID: out.CommandID}
		}
	} else if e.Session != (Session{}) {
		return out, identity.UnknownCommitError{CommandID: out.CommandID}
	}
	out.CommitOutcome, out.RetryAfter, out.Replayed = receipt.Outcome, receipt.RetryAfter, e.Replayed
	if receipt.Outcome == identity.CommitOutcomeCommitted {
		out.Session = e.Session
		if ctx.Err() != nil {
			return out, sessionReadFailure(ctx)
		}
		if cause != nil {
			return out, signOutError(cause)
		}
		return out, nil
	}
	switch receipt.Outcome {
	case identity.CommitOutcomeNotCommitted:
		return out, identity.NotCommittedError{CommandID: out.CommandID}
	case identity.CommitOutcomeConflict:
		return out, identity.ConflictError{CommandID: out.CommandID}
	case identity.CommitOutcomeInProgress:
		return out, identity.InProgressError{CommandID: out.CommandID, RetryAfter: receipt.RetryAfter}
	default:
		return out, identity.UnknownCommitError{CommandID: out.CommandID}
	}
}

// Format redacts configuration and borrowed runtime dependencies.
func (SessionRotator) Format(s fmt.State, _ rune) {
	io.WriteString(s, "session.SessionRotator(redacted)")
}

// Format redacts policy/key configuration.
func (RotationConfig) Format(s fmt.State, _ rune) {
	io.WriteString(s, "session.RotationConfig(redacted)")
}

// Format redacts original private token custody.
func (PreparedRotation) Format(s fmt.State, _ rune) {
	io.WriteString(s, "session.PreparedRotation(redacted)")
}

// Format redacts historical scope and successor delivery metadata.
func (RotationResult) Format(s fmt.State, _ rune) {
	io.WriteString(s, "session.RotationResult(redacted)")
}

// Format redacts historical receipt and successor.
func (RotationExecution) Format(s fmt.State, _ rune) {
	io.WriteString(s, "session.RotationExecution(redacted)")
}

// MarshalJSON rejects implicit runtime serialization.
func (SessionRotator) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalJSON rejects implicit configuration serialization.
func (RotationConfig) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalJSON rejects implicit bearer custody serialization.
func (PreparedRotation) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalJSON rejects implicit delivery serialization.
func (RotationResult) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalJSON rejects implicit historical linkage serialization.
func (RotationExecution) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }
