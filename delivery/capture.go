package delivery

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"
)

// CaptureConfig selects one explicit test tenant and fixed memory bounds.
// MaxAttempts is1..1024; MaxBytes is1..4194304 total retained string bytes.
// Metadata/slice storage is additionally bounded by MaxAttempts. There are no
// defaults and no durable, authorization, provider or production profile.
type CaptureConfig struct {
	TenantID    TenantID
	MaxAttempts uint16
	MaxBytes    uint32
}

func (c CaptureConfig) valid() bool {
	return printableASCII(string(c.TenantID), 1, 128) && c.MaxAttempts >= 1 && c.MaxAttempts <= 1024 && c.MaxBytes >= 1 && c.MaxBytes <= 4<<20
}

// CaptureSender is the explicit test-only Sender. It records rendered attempts
// in bounded process memory, reports Accepted (never real provider delivery),
// and owns no queue, dedupe, lease, authority, retry or receipt engine. Compose
// it with the same public Queue/Service contracts used by the owned adapter.
// Production service and worker construction reject it even through Sender.
//
// mu owns attempts, bytes and closed; config is immutable. Calls are safe for
// concurrency, contain only bounded local work, and start no goroutines. Never
// copy a CaptureSender after use. Snapshot copies the attempt slice; callers
// own those explicit sensitive outputs and their retention. Close drops owned
// payload references, not caller snapshots and not cryptographic memory copies.
type CaptureSender struct {
	mu       sync.Mutex
	config   CaptureConfig
	attempts []Attempt
	bytes    uint32
	closed   bool
}

// NewCaptureSender validates a bounded explicit test scope. Zero is invalid.
// Only this test Sender may retain cloned Attempt values for assertions; normal
// provider Senders must not retain plaintext invocation inputs.
func NewCaptureSender(c CaptureConfig) (*CaptureSender, error) {
	if !c.valid() {
		return nil, ErrInvalidInput
	}
	c.TenantID = TenantID(strings.Clone(string(c.TenantID)))
	return &CaptureSender{config: c, attempts: make([]Attempt, 0, int(c.MaxAttempts))}, nil
}

// The package-private marker cannot be accidentally omitted by consumers
// passing this owned implementation through the public Sender interface.
func (*CaptureSender) captureOnly() {}

// Send captures one valid unexpired attempt in the configured exact tenant.
// It makes no external call and deliberately does not deduplicate: a test must
// be able to observe accidental duplicate Sender invocations. Limits and closed
// state return ErrUnavailable without partial retention; cancellation checked
// before and after bounded copying also returns no captured effect.
func (s *CaptureSender) Send(ctx context.Context, a Attempt) (DeliveryResult, error) {
	if s == nil || !s.config.valid() || ctx == nil || a.Validate() != nil {
		return DeliveryResult{}, ErrInvalidInput
	}
	if a.TenantID != s.config.TenantID {
		return DeliveryResult{}, ErrForbidden
	}
	if err := ctx.Err(); err != nil {
		return DeliveryResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return DeliveryResult{}, err
	}
	if s.closed {
		return DeliveryResult{}, ErrUnavailable
	}
	if !a.ValidUntil.After(time.Now()) {
		return DeliveryResult{}, ErrExpired
	}
	// Attempt validation bounds every addend before arithmetic or allocation.
	n := uint32(len(a.TenantID) + len(a.IntentID) + len(a.Recipient) + len(a.Subject) + len(a.Body) + len(a.ContentType) + len(a.IdempotencyKey))
	if len(s.attempts) >= int(s.config.MaxAttempts) || n > s.config.MaxBytes-s.bytes {
		return DeliveryResult{}, ErrUnavailable
	}
	// Clone each string: a tiny substring must not retain an unbounded caller
	// allocation. Snapshots may share these owned immutable bytes, not the slice.
	a.TenantID = TenantID(strings.Clone(string(a.TenantID)))
	a.IntentID = IntentID(strings.Clone(string(a.IntentID)))
	a.Recipient = strings.Clone(a.Recipient)
	a.Subject = strings.Clone(a.Subject)
	a.Body = strings.Clone(a.Body)
	a.ContentType = strings.Clone(a.ContentType)
	a.IdempotencyKey = strings.Clone(a.IdempotencyKey)
	// Preserve the instant without retaining a caller-owned location/zone table.
	a.ValidUntil = a.ValidUntil.UTC()
	if err := ctx.Err(); err != nil {
		return DeliveryResult{}, err
	}
	now := time.Now().UTC()
	if !a.ValidUntil.After(now) {
		return DeliveryResult{}, ErrExpired
	}
	s.attempts = append(s.attempts, a)
	s.bytes += n
	return DeliveryResult{State: StateAccepted, ObservedAt: now}, nil
}

// Snapshot explicitly reveals sensitive test content. It returns a caller-owned
// bounded slice; changing its fields cannot mutate future snapshots. It grants
// no authority and is not durable delivery/status evidence. Cancelled calls
// return no snapshot. Closed captures expose none of their former payloads.
func (s *CaptureSender) Snapshot(ctx context.Context) ([]Attempt, error) {
	if s == nil || !s.config.valid() || ctx == nil {
		return nil, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.closed {
		return nil, ErrUnavailable
	}
	out := slices.Clone(s.attempts)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// Close atomically prevents further captures and clears every owned payload
// reference. It is idempotent for constructed senders, performs no IO, and does
// not revoke or erase caller-owned snapshots or claim secure Go heap erasure.
func (s *CaptureSender) Close() error {
	if s == nil || !s.config.valid() {
		return ErrInvalidInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.attempts)
	s.attempts = nil
	s.bytes = 0
	s.closed = true
	return nil
}

// Format and LogValue never expose the captured memory or configured scope.
func (*CaptureSender) Format(s fmt.State, _ rune) { redact(s) }
func (*CaptureSender) LogValue() slog.Value       { return slog.StringValue("delivery(redacted)") }

// MarshalJSON and MarshalText forbid implicit test-payload serialization.
func (*CaptureSender) MarshalJSON() ([]byte, error) { return nil, ErrSerializationForbidden }
func (*CaptureSender) MarshalText() ([]byte, error) { return nil, ErrSerializationForbidden }

var _ Sender = (*CaptureSender)(nil)
