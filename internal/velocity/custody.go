// Package velocity carries private, immutable custody between the owned
// journal, native projection and reference composition. It owns no persistence,
// clock, goroutine, retry, debit or publication state machine. Go internal
// visibility prevents application callers from manufacturing these handles;
// public adapters may expose opaque values but never their secret bindings.
package velocity

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"
)

var (
	ErrInvalid     = errors.New("invalid owned velocity custody")
	ErrUnavailable = errors.New("owned velocity authority unavailable")
	ErrSensitive   = errors.New("owned velocity serialization forbidden")
)

// LeaseBinding is restricted adapter data, not an operator-selectable lease.
type LeaseBinding struct {
	Tenant       string
	Namespace    [32]byte
	Epoch, Owner [16]byte
	Generation   uint64
	ExpiresAt    time.Time
}

type Lease struct{ state *lease }
type lease struct {
	binding LeaseBinding
	check   func(context.Context) error
}

// NewLease is called only by the durable owner after acknowledged acquisition.
// The checker revalidates that exact primary receipt, without retaining an open
// transaction across native IO. It must be concurrent-safe and bounded by ctx.
func NewLease(b LeaseBinding, check func(context.Context) error) (Lease, error) {
	if !scope(b.Tenant) || b.Namespace == [32]byte{} || b.Epoch == [16]byte{} || b.Owner == [16]byte{} || b.Generation == 0 || !wireTime(b.ExpiresAt) || check == nil {
		return Lease{}, ErrInvalid
	}
	return Lease{state: &lease{binding: b, check: check}}, nil
}

// LeaseFacts is intentionally a package function: an external caller obtaining
// an opaque Lease cannot invoke it without importing this internal package.
func LeaseFacts(l Lease) LeaseBinding {
	if l.state == nil {
		return LeaseBinding{}
	}
	return l.state.binding
}

func Check(ctx context.Context, l Lease) error {
	if ctx == nil || l.state == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := l.state.check(ctx); err != nil {
		if errors.Is(err, context.Canceled) {
			return context.Canceled
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return context.DeadlineExceeded
		}
		return ErrUnavailable
	}
	return ctx.Err()
}

type Outcome uint8

const (
	Pending Outcome = iota + 1
	Committed
	NotCommitted
	Unknown
)

type Key struct {
	Version uint32
	Encoded string
}
type Target struct {
	Dimension string
	Keys      []Key
}
type Counter struct {
	Kind                             string
	Value                            uint64
	ObservedAt, StartedAt, ExpiresAt time.Time
}
type HistoryBinding struct {
	ID                            string
	Position                      int64
	Tenant                        string
	Namespace, Attempt            [32]byte
	Fingerprint, Operation, Phase string
	PolicyVersion                 uint64
	PreparedAt, RecordedAt        time.Time
	Window                        time.Duration
	Limit                         uint64
	Outcome                       Outcome
	Targets                       []Target
	Snapshot                      []Counter
}
type History struct{ state *history }
type history struct {
	owner   *lease
	binding HistoryBinding
}

// NewHistory is called only by the durable owner after authenticating original
// records and change positions. No raw attempt or replacement command is used.
// This handle is not permission for a fresh debit or positive risk decision.
func NewHistory(l Lease, b HistoryBinding) (History, error) {
	if l.state == nil || b.Tenant != l.state.binding.Tenant || b.Namespace != l.state.binding.Namespace || !recordID(b.ID) || !hex64(b.Fingerprint) || b.Attempt == [32]byte{} || b.Position <= 0 || !scope(b.Operation) || (b.Phase != "before_credential_or_provider_work" && b.Phase != "before_return") || b.PolicyVersion == 0 || !wireTime(b.PreparedAt) || !wireTime(b.RecordedAt) || b.RecordedAt.Before(b.PreparedAt) || b.Window <= 0 || b.Window > time.Hour || b.Window%time.Microsecond != 0 || b.Limit == 0 || b.Limit > 120 || b.Outcome < Pending || b.Outcome > Unknown || len(b.Targets) < 1 || len(b.Targets) > 4 {
		return History{}, ErrInvalid
	}
	seen := map[string]bool{}
	for _, target := range b.Targets {
		if !scope(target.Dimension) || len(target.Dimension) > 64 || seen[target.Dimension] || len(target.Keys) < 1 || len(target.Keys) > 4 {
			return History{}, ErrInvalid
		}
		seen[target.Dimension] = true
		for i, key := range target.Keys {
			if key.Version == 0 || len(key.Encoded) < 1 || len(key.Encoded) > 64 || i > 0 && target.Keys[i-1].Version <= key.Version {
				return History{}, ErrInvalid
			}
		}
	}
	if b.Outcome == Committed {
		if len(b.Snapshot) != len(b.Targets) {
			return History{}, ErrInvalid
		}
		observed := map[string]bool{}
		for i, c := range b.Snapshot {
			if !seen[c.Kind] || observed[c.Kind] || c.Value == 0 || c.Value > 9007199254740991 || !wireTime(c.ObservedAt) || !wireTime(c.StartedAt) || !wireTime(c.ExpiresAt) || c.ExpiresAt.Sub(c.StartedAt) != b.Window || c.ObservedAt.Before(c.StartedAt) || !c.ObservedAt.Before(c.ExpiresAt) || i > 0 && !c.ObservedAt.Equal(b.Snapshot[0].ObservedAt) {
				return History{}, ErrInvalid
			}
			observed[c.Kind] = true
		}
	} else if len(b.Snapshot) != 0 {
		return History{}, ErrInvalid
	}
	return History{state: &history{owner: l.state, binding: clone(b)}}, nil
}

func HistoryFacts(h History) HistoryBinding {
	if h.state == nil {
		return HistoryBinding{}
	}
	return clone(h.state.binding)
}

func RequireHistory(ctx context.Context, l Lease, h History) error {
	if l.state == nil || h.state == nil || h.state.owner != l.state {
		return ErrInvalid
	}
	return Check(ctx, l)
}

// Acknowledgement is produced only after the native owner receives the exact
// attributable effect acknowledgement. It is not durable applied progress.
type Acknowledgement struct{ state *history }

func Acknowledge(ctx context.Context, l Lease, h History) (Acknowledgement, error) {
	if err := RequireHistory(ctx, l, h); err != nil {
		return Acknowledgement{}, err
	}
	if h.state.binding.Outcome != Committed && h.state.binding.Outcome != NotCommitted {
		return Acknowledgement{}, ErrUnavailable
	}
	return Acknowledgement{state: h.state}, nil
}

// Applied returns original facts only after the durable owner rechecks current
// custody. The caller must still atomically authenticate and persist its owned
// checkpoint; native success or this return alone never establishes health.
func Applied(ctx context.Context, l Lease, a Acknowledgement) (HistoryBinding, error) {
	if err := RequireHistory(ctx, l, History{state: a.state}); err != nil {
		return HistoryBinding{}, err
	}
	return clone(a.state.binding), nil
}

func clone(b HistoryBinding) HistoryBinding {
	b.Targets = slices.Clone(b.Targets)
	for i := range b.Targets {
		b.Targets[i].Keys = slices.Clone(b.Targets[i].Keys)
	}
	b.Snapshot = slices.Clone(b.Snapshot)
	return b
}
func scope(v string) bool {
	if len(v) < 1 || len(v) > 128 {
		return false
	}
	for i := range len(v) {
		if v[i] < '!' || v[i] > '~' {
			return false
		}
	}
	return true
}
func hex64(v string) bool {
	if len(v) != 64 {
		return false
	}
	for i := range len(v) {
		if !(v[i] >= '0' && v[i] <= '9') && !(v[i] >= 'a' && v[i] <= 'f') {
			return false
		}
	}
	return true
}
func recordID(v string) bool {
	if len(v) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(v)
	return err == nil && len(decoded) == 32
}
func wireTime(v time.Time) bool {
	return v.UnixMicro() > 0 && v.UnixMicro() <= 9007199254740991 && v.Equal(time.UnixMicro(v.UnixMicro()))
}

func redacted(s fmt.State)                           { _, _ = io.WriteString(s, "velocity(redacted)") }
func (Lease) Format(s fmt.State, _ rune)             { redacted(s) }
func (LeaseBinding) Format(s fmt.State, _ rune)      { redacted(s) }
func (History) Format(s fmt.State, _ rune)           { redacted(s) }
func (HistoryBinding) Format(s fmt.State, _ rune)    { redacted(s) }
func (Acknowledgement) Format(s fmt.State, _ rune)   { redacted(s) }
func (Lease) MarshalJSON() ([]byte, error)           { return nil, ErrSensitive }
func (LeaseBinding) MarshalJSON() ([]byte, error)    { return nil, ErrSensitive }
func (History) MarshalJSON() ([]byte, error)         { return nil, ErrSensitive }
func (HistoryBinding) MarshalJSON() ([]byte, error)  { return nil, ErrSensitive }
func (Acknowledgement) MarshalJSON() ([]byte, error) { return nil, ErrSensitive }
func (Lease) MarshalText() ([]byte, error)           { return nil, ErrSensitive }
func (LeaseBinding) MarshalText() ([]byte, error)    { return nil, ErrSensitive }
func (History) MarshalText() ([]byte, error)         { return nil, ErrSensitive }
func (HistoryBinding) MarshalText() ([]byte, error)  { return nil, ErrSensitive }
func (Acknowledgement) MarshalText() ([]byte, error) { return nil, ErrSensitive }
