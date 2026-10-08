// Package velocity connects the owned risk adapters without sibling imports.
// It retains no journal, epoch, health cache, retry loop or authority graph.
// Only the risk subtree may bind its private adapter functions. Applications
// can pass opaque adapter outputs but cannot implement these connections.
package velocity

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/faustbrian/go-identity/risk"
)

// Journal binds the concrete primary owner, not an application repository.
// Its callbacks must close every transaction before returning. check validates
// current eligibility; record returns only an acknowledged original receipt;
// replay returns authenticated terminal history and never grants resend rights.
type Journal struct{ state *journal }
type journal struct {
	namespace [32]byte
	validate  func(risk.CounterCommand) error
	check     func(context.Context, risk.CounterCommand) error
	record    func(context.Context, risk.CounterCommand) (Attempt, error)
	replay    func(context.Context, risk.CounterCommand) (risk.CounterResult, error)
}

// Native binds the concrete ephemeral owner. check must verify current primary
// eligibility and exact native marker/continuity without counter mutation;
// mutate must independently enforce these at the atomic effect boundary and
// preserve acknowledged outcomes alongside later errors. No exported effect
// method exists on this handle, so an external holder cannot bypass the journal.
type Native struct{ state *native }
type native struct {
	namespace [32]byte
	validate  func(risk.CounterCommand) error
	check     func(context.Context, risk.CounterCommand) error
	mutate    func(context.Context, risk.CounterCommand) (risk.CounterResult, error)
}

// Attempt retains the primary owner's exact receipt through its bound writer.
// It creates no new identity and cannot be reused for another logical command.
type Attempt struct{ state *attempt }
type attempt struct {
	command risk.CounterCommand
	retain  func(context.Context, risk.CounterResult) error
}

// BindJournal is restricted to owned adapters by Go internal visibility. Scope
// and command validation must use their configured authority, not request data.
// Functions must be concurrency-safe, context-bounded and redact all errors.
func BindJournal(namespace [32]byte, validate func(risk.CounterCommand) error, check func(context.Context, risk.CounterCommand) error, record func(context.Context, risk.CounterCommand) (Attempt, error), replay func(context.Context, risk.CounterCommand) (risk.CounterResult, error)) (Journal, error) {
	if namespace == [32]byte{} || validate == nil || check == nil || record == nil || replay == nil {
		return Journal{}, risk.ErrInvalidVelocityRecovery
	}
	return Journal{&journal{namespace, validate, check, record, replay}}, nil
}

// BindNative retains only concrete owned adapter functions. Its namespace must
// be derived from the same retained replay identity as the primary journal.
// Functions must be concurrency-safe, context-bounded and redact all errors.
func BindNative(namespace [32]byte, validate func(risk.CounterCommand) error, check func(context.Context, risk.CounterCommand) error, mutate func(context.Context, risk.CounterCommand) (risk.CounterResult, error)) (Native, error) {
	if namespace == [32]byte{} || validate == nil || check == nil || mutate == nil {
		return Native{}, risk.ErrInvalidVelocityRecovery
	}
	return Native{&native{namespace, validate, check, mutate}}, nil
}

// BindAttempt is called only after the concrete journal acknowledges its
// original intent. retain must authenticate that exact receipt/configuration
// and conserve immutable terminal outcomes; this handle replaces neither check.
func BindAttempt(command risk.CounterCommand, retain func(context.Context, risk.CounterResult) error) (Attempt, error) {
	if _, err := risk.NewCounterResult(command, risk.CounterUnknown, nil); err != nil || retain == nil {
		return Attempt{}, risk.ErrInvalidVelocityRecovery
	}
	return Attempt{&attempt{command, retain}}, nil
}

// Store is the owned composite CounterStore. Configuration is immutable;
// concurrency belongs to the underlying adapter owners. No goroutines, locks,
// clock, resource lifecycle or health state are introduced by this connection.
// Zero is invalid; the concrete native factory retains shutdown ownership.
type Store struct{ state *store }
type store struct {
	journal Journal
	native  Native
	timeout time.Duration
}

// NewStore connects already configured owned handles without IO or activation.
// It cannot select an epoch, forge health or grant retry permission. One outer
// deadline bounds the entire crossing, not a fresh timeout for each stage.
func NewStore(j Journal, n Native, timeout time.Duration) (Store, error) {
	if j.state == nil || n.state == nil || j.state.namespace != n.state.namespace || timeout <= 0 || timeout > time.Minute {
		return Store{}, risk.ErrInvalidVelocityRecovery
	}
	return Store{&store{j, n, timeout}}, nil
}

// Mutate persists intent before one native invocation and conserves its return
// through the original primary receipt. An unacknowledged intent never invokes
// mutate. Only authenticated terminal readback resolves matching retries; pending
// or unknown never authorize dispatch. Known commits survive recording, current
// health or context failures, always accompanied by an error denying admission.
// No SQL transaction/lock is owned here or held across native work. Failed
// recording remains the durable owner's reconciliation obligation, not resend
// permission. The caller must retain the original result when an error returns.
func (s Store) Mutate(ctx context.Context, c risk.CounterCommand) (risk.CounterResult, error) {
	if s.state == nil || ctx == nil {
		return risk.CounterResult{}, risk.ErrInvalidVelocityRecovery
	}
	if err := ctx.Err(); err != nil {
		return risk.CounterResult{}, err
	}
	b := s.state
	if err := b.journal.state.validate(c); err != nil {
		return risk.CounterResult{}, err
	}
	if err := b.native.state.validate(c); err != nil {
		return risk.CounterResult{}, err
	}
	bounded, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()
	if err := b.current(bounded, c); err != nil {
		return risk.CounterResult{}, err
	}
	a, err := b.journal.state.record(bounded, c)
	if err != nil {
		// A failed attempt ACK can mean a committed pending insert. Never call
		// native to resolve it; only the primary's immutable terminal readback
		// may return a known original declaration.
		result, readErr := b.journal.state.replay(bounded, c)
		if readErr != nil {
			return risk.CounterResult{}, err
		}
		if _, _, readErr = result.Declaration(c); readErr != nil {
			return risk.CounterResult{}, readErr
		}
		return result, b.current(bounded, c)
	}
	if a.state == nil || a.state.command.Bindings().Fingerprint != c.Bindings().Fingerprint {
		return risk.CounterResult{}, risk.ErrInvalidVelocityRecovery
	}
	if err := b.current(bounded, c); err != nil {
		return risk.CounterResult{}, err
	}
	result, nativeErr := b.native.state.mutate(bounded, c)
	if _, _, err := result.Declaration(c); err != nil {
		// Invalid/missing attributable output after invocation is ambiguity,
		// not proof of noncommit. Bind it to the existing original intent.
		result, _ = risk.NewCounterResult(c, risk.CounterUnknown, nil)
		if nativeErr == nil {
			nativeErr = err
		}
	}
	retainErr := a.state.retain(bounded, result)
	if err := bounded.Err(); err != nil {
		return result, err
	}
	if nativeErr != nil {
		return result, nativeErr
	}
	if retainErr != nil {
		return result, retainErr
	}
	return result, b.current(bounded, c)
}

func (s *store) current(ctx context.Context, c risk.CounterCommand) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.journal.state.check(ctx, c); err != nil {
		return err
	}
	if err := s.native.state.check(ctx, c); err != nil {
		return err
	}
	return ctx.Err()
}

func redact(s fmt.State)                     { _, _ = io.WriteString(s, "velocity.connection(redacted)") }
func (Journal) Format(s fmt.State, _ rune)   { redact(s) }
func (Native) Format(s fmt.State, _ rune)    { redact(s) }
func (Attempt) Format(s fmt.State, _ rune)   { redact(s) }
func (Store) Format(s fmt.State, _ rune)     { redact(s) }
func (Journal) MarshalJSON() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }
func (Native) MarshalJSON() ([]byte, error)  { return nil, risk.ErrSensitiveSerialization }
func (Attempt) MarshalJSON() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }
func (Store) MarshalJSON() ([]byte, error)   { return nil, risk.ErrSensitiveSerialization }
func (Journal) MarshalText() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }
func (Native) MarshalText() ([]byte, error)  { return nil, risk.ErrSensitiveSerialization }
func (Attempt) MarshalText() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }
func (Store) MarshalText() ([]byte, error)   { return nil, risk.ErrSensitiveSerialization }
