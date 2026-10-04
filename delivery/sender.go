package delivery

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"time"
)

// ErrOutcomeUnknown means an external effect may have occurred. Recover the
// durable attempt; neither rejection nor automatic resubmission is permitted.
var ErrOutcomeUnknown = errors.New("delivery: outcome unknown")

// ErrExpired prevents invocation of an expired effect before a send begins.
var ErrExpired = errors.New("delivery: expired")

// TenantID is an exact 1..128 printable ASCII namespace, not authorization.
type TenantID string

// IntentID is the queue's stable 16..128 printable ASCII effect identity. It is
// preserved across callback ambiguity; callers must not mint a replacement.
type IntentID string

// DeliveryState separates local queue state from attributable provider outcomes.
// Zero/unknown values are invalid. Accepted is not Delivered. TransientFailure
// is a provider result only; the queue owns retry admission and RetryWait.
type DeliveryState uint8

const (
	StateQueued           DeliveryState = iota + 1 // Local admission, never provider success.
	StateAttempting                                // A fenced durable attempt was recorded before invocation.
	StateAccepted                                  // Provider accepted submission, not confirmed delivery.
	StateDelivered                                 // Attributable provider delivery confirmation.
	StateRejected                                  // Attributable permanent rejection.
	StateBounced                                   // Attributable delivery failure after provider acceptance.
	StateCancelled                                 // Confirmed local prevention or provider cancellation.
	StateOutcomeUnknown                            // Requires authenticated reconciliation.
	StateRetryWait                                 // Queue-owned next-attempt admission after transient evidence.
	StateExpired                                   // Terminal expiry, not provider rejection.
	StateExhausted                                 // Terminal retry exhaustion, not provider rejection.
	StateSuperseded                                // Terminal committed replacement, not provider rejection.
	StateTransientFailure                          // Provider authoritatively reports no successful effect.
)

// Config declares bounded queue/retry and callback policy. Zero is invalid;
// DefaultConfig is explicit. Production forbids test-capture senders and, at
// service composition, must additionally require a named durable Queue.
// BackoffCeilings is caller-owned; constructors copy before retaining it.
type Config struct {
	Attempts          uint8
	SenderTimeout     time.Duration
	SenderConcurrency uint8
	BackoffCeilings   []time.Duration
	DedupeTTL         time.Duration
	Production        bool
}

// DefaultConfig returns a fresh reference profile: five attempts, full-jitter
// ceilings0/1s/5s/30s/2m, callback10s/concurrency8 and dedupe24h. Owning workflows
// must raise dedupe retention to their token lifetime plus24h where necessary.
func DefaultConfig() Config {
	return Config{Attempts: 5, SenderTimeout: 10 * time.Second, SenderConcurrency: 8,
		BackoffCeilings: []time.Duration{0, time.Second, 5 * time.Second, 30 * time.Second, 2 * time.Minute}, DedupeTTL: 24 * time.Hour}
}

// Validate enforces attempts1..10, timeout1..30s, concurrency1..64, dedupe1h..31d
// and exactly one backoff ceiling per attempt. First is0; later ceilings are
// positive, nondecreasing and at most2m. No retry is executed by Sender.
func (c Config) Validate() error {
	if c.Attempts < 1 || c.Attempts > 10 || c.SenderTimeout < time.Second || c.SenderTimeout > 30*time.Second || c.SenderConcurrency < 1 || c.SenderConcurrency > 64 || c.DedupeTTL < time.Hour || c.DedupeTTL > 31*24*time.Hour || len(c.BackoffCeilings) != int(c.Attempts) || c.BackoffCeilings[0] != 0 {
		return ErrInvalidInput
	}
	for i := 1; i < len(c.BackoffCeilings); i++ {
		if c.BackoffCeilings[i] <= 0 || c.BackoffCeilings[i] > 2*time.Minute || c.BackoffCeilings[i] < c.BackoffCeilings[i-1] {
			return ErrInvalidInput
		}
	}
	return nil
}

// Attempt is already rendered sensitive content bound to one durable generation,
// provider idempotency identity and effect expiry. Queue owns/decrypts it only
// for Send; Sender must not retain it, discover recipients or orchestrate retries.
// Validation proves shape only, not a lease, authorization or durable admission.
type Attempt struct {
	TenantID       TenantID
	IntentID       IntentID
	Generation     uint32
	Channel        Channel
	Recipient      string
	Subject        string
	Body           string
	ContentType    string
	IdempotencyKey string
	ValidUntil     time.Time
}

// Validate rejects zero identity/generation, header/address controls, unsupported
// channel/content type, invalid UTC expiry and unbounded transport content.
func (a Attempt) Validate() error {
	if !printableASCII(string(a.TenantID), 1, 128) || !printableASCII(string(a.IntentID), 16, 128) || a.Generation == 0 || !validChannel(a.Channel) || !boundedText(a.Recipient, 1, 320) || !boundedText(a.Subject, 0, 998) || !boundedText(a.Body, 1, 262144) || (a.ContentType != "text/plain" && a.ContentType != "text/html") || a.Channel == ChannelSMS && (a.Subject != "" || a.ContentType != "text/plain") || !printableASCII(a.IdempotencyKey, 16, 128) || !validUTCTime(a.ValidUntil) {
		return ErrInvalidInput
	}
	for _, value := range []string{a.Recipient, a.Subject} {
		for _, ch := range value {
			if ch < 0x20 || ch == 0x7f {
				return ErrInvalidInput
			}
		}
	}
	return nil
}

func validUTCTime(t time.Time) bool {
	_, offset := t.Zone()
	return !t.IsZero() && offset == 0 && t.Year() >= 1 && t.Year() <= 9999
}

// DeliveryResult is attributable normalized evidence, not a retry instruction.
// RetryAfter is a hint only for TransientFailure, bounded0..2m. ProviderReference
// is optional and sensitive, at most256 printable ASCII bytes. ObservedAt is UTC.
// Sender errors, panics, invalid results and late returns lose any success claim.
type DeliveryResult struct {
	State             DeliveryState
	ProviderReference string
	RetryAfter        time.Duration
	ObservedAt        time.Time
}

// Validate accepts only provider classifications, never local queue states.
func (r DeliveryResult) Validate() error {
	switch r.State {
	case StateAccepted, StateDelivered, StateRejected, StateBounced, StateOutcomeUnknown, StateTransientFailure:
	default:
		return ErrInvalidInput
	}
	if (r.ProviderReference != "" && !printableASCII(r.ProviderReference, 1, 256)) || !validUTCTime(r.ObservedAt) || r.RetryAfter < 0 || r.RetryAfter > 2*time.Minute || r.State != StateTransientFailure && r.RetryAfter != 0 {
		return ErrInvalidInput
	}
	return nil
}

// Sender is the bounded application/provider seam. Send must honor its context
// deadline/cancellation, return normalized attributable evidence and never retry,
// acquire recipient authority or own durable queue policy. Production senders
// must not retain Attempt. Only the explicit test-only CaptureSender retains
// bounded cloned inputs for assertions; production construction rejects it.
type Sender interface {
	Send(context.Context, Attempt) (DeliveryResult, error)
}

// OutcomeUnknownError retains only the stable recovery handle; diagnostics are
// always redacted. It matches ErrOutcomeUnknown through errors.Is.
type OutcomeUnknownError struct{ IntentID IntentID }

// Error returns a fixed redacted description without the recovery handle.
func (OutcomeUnknownError) Error() string { return "delivery: outcome unknown" }

// Is preserves stable unknown-outcome classification without an external cause.
func (OutcomeUnknownError) Is(err error) bool { return err == ErrOutcomeUnknown }

// Format redacts every formatting verb, including invalid recovery handles.
func (OutcomeUnknownError) Format(s fmt.State, _ rune) { redact(s) }

type senderExecutor struct {
	sender  Sender
	timeout time.Duration
	slots   chan struct{}
}

func newSenderExecutor(c Config, s Sender) (*senderExecutor, error) {
	if c.Validate() != nil || nilSender(s) {
		return nil, ErrInvalidInput
	}
	if c.Production {
		if _, capture := s.(interface{ captureOnly() }); capture {
			return nil, ErrInvalidInput
		}
	}
	return &senderExecutor{sender: s, timeout: c.SenderTimeout, slots: make(chan struct{}, int(c.SenderConcurrency))}, nil
}

// Reflection is limited to rejecting a typed-nil callback, not discovery/wiring.
func nilSender(s Sender) bool {
	if s == nil {
		return true
	}
	v := reflect.ValueOf(s)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}

// Invocation is synchronous: no detached callback goroutine can survive caller
// cancellation. The trusted Sender must cooperate; arbitrary Go code cannot be
// forcibly stopped safely. No lock/transaction spans the callback, no retries.
func (e *senderExecutor) send(ctx context.Context, a Attempt) (DeliveryResult, error) {
	if ctx == nil || e == nil || e.sender == nil || e.slots == nil || a.Validate() != nil {
		return DeliveryResult{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return DeliveryResult{}, err
	}
	now := time.Now()
	if !a.ValidUntil.After(now) {
		return DeliveryResult{}, ErrExpired
	}
	deadline := now.Add(e.timeout)
	if a.ValidUntil.Before(deadline) {
		deadline = a.ValidUntil
	}
	// Keep effect expiry absolute: converting it to a relative timeout would
	// restart its clock and extend validity by intervening scheduling delay.
	call, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	select {
	case e.slots <- struct{}{}:
		defer func() { <-e.slots }()
	case <-call.Done():
		return DeliveryResult{}, call.Err()
	}
	if err := call.Err(); err != nil {
		return DeliveryResult{}, err
	}
	result, err := invokeSender(call, e.sender, a)
	if err != nil || call.Err() != nil || result.Validate() != nil || result.State == StateOutcomeUnknown {
		return DeliveryResult{State: StateOutcomeUnknown, ObservedAt: time.Now().UTC()}, OutcomeUnknownError{IntentID: a.IntentID}
	}
	return result, nil
}

func invokeSender(ctx context.Context, s Sender, a Attempt) (result DeliveryResult, err error) {
	defer func() {
		if recover() != nil {
			result = DeliveryResult{}
			err = ErrOutcomeUnknown
		}
	}()
	return s.Send(ctx, a)
}

// Format suppresses sensitive callback input and provider evidence for all verbs.
func (Attempt) Format(s fmt.State, _ rune)        { redact(s) }
func (DeliveryResult) Format(s fmt.State, _ rune) { redact(s) }

// LogValue suppresses callback content and provider references in structured logs.
func (Attempt) LogValue() slog.Value        { return slog.StringValue("delivery(redacted)") }
func (DeliveryResult) LogValue() slog.Value { return slog.StringValue("delivery(redacted)") }

// MarshalJSON refuses implicit sensitive persistence; queue custody is explicit.
func (Attempt) MarshalJSON() ([]byte, error)        { return nil, ErrSerializationForbidden }
func (DeliveryResult) MarshalJSON() ([]byte, error) { return nil, ErrSerializationForbidden }

// MarshalText refuses implicit sensitive text serialization.
func (Attempt) MarshalText() ([]byte, error)        { return nil, ErrSerializationForbidden }
func (DeliveryResult) MarshalText() ([]byte, error) { return nil, ErrSerializationForbidden }
