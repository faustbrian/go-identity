package delivery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type senderFunc func(context.Context, Attempt) (DeliveryResult, error)

func (f senderFunc) Send(ctx context.Context, a Attempt) (DeliveryResult, error) { return f(ctx, a) }

func testAttempt() Attempt {
	return Attempt{TenantID: "tenant", IntentID: "synthetic-intent-0001", Generation: 1, Channel: ChannelEmail,
		Recipient: "person@example.invalid", Subject: "Verify", Body: "synthetic-content", ContentType: "text/plain",
		IdempotencyKey: "synthetic-effect-0001", ValidUntil: time.Now().UTC().Add(time.Hour)}
}

func TestSenderExecutesExactlyOneBoundedAttempt(t *testing.T) {
	var calls atomic.Int32
	exec, err := newSenderExecutor(DefaultConfig(), senderFunc(func(ctx context.Context, a Attempt) (DeliveryResult, error) {
		calls.Add(1)
		deadline, ok := ctx.Deadline()
		if !ok || deadline.After(time.Now().Add(11*time.Second)) {
			t.Error("callback lacks bounded deadline")
		}
		if a.ContentType != "text/plain" || a.IdempotencyKey != "synthetic-effect-0001" {
			t.Error("bound attempt changed")
		}
		return DeliveryResult{State: StateAccepted, ObservedAt: time.Now().UTC()}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	result, err := exec.send(context.Background(), testAttempt())
	if err != nil || result.State != StateAccepted || calls.Load() != 1 {
		t.Fatal("bounded callback failed")
	}
}

func TestSenderDeadlineNeverExceedsEffectExpiry(t *testing.T) {
	exec, err := newSenderExecutor(DefaultConfig(), senderFunc(func(ctx context.Context, a Attempt) (DeliveryResult, error) {
		deadline, ok := ctx.Deadline()
		if !ok || deadline.After(a.ValidUntil) {
			t.Fatalf("callback deadline exceeds effect expiry by %s", deadline.Sub(a.ValidUntil))
		}
		return DeliveryResult{State: StateAccepted, ObservedAt: time.Now().UTC()}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	// Repetition exposes sub-clock-resolution drift without sleeps or a timing
	// tolerance that would permit a callback to outlive the authoritative expiry.
	for range 10000 {
		a := testAttempt()
		a.ValidUntil = time.Now().UTC().Add(time.Second)
		if _, err := exec.send(context.Background(), a); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSenderAmbiguityNeverBecomesRejectionOrRetry(t *testing.T) {
	for _, callback := range []senderFunc{
		func(context.Context, Attempt) (DeliveryResult, error) {
			return DeliveryResult{State: StateRejected, ObservedAt: time.Now().UTC()}, errors.New("synthetic-private-error")
		},
		func(context.Context, Attempt) (DeliveryResult, error) { return DeliveryResult{}, nil },
		func(context.Context, Attempt) (DeliveryResult, error) { panic("synthetic-private-panic") },
	} {
		var calls int
		exec, err := newSenderExecutor(DefaultConfig(), senderFunc(func(ctx context.Context, a Attempt) (DeliveryResult, error) { calls++; return callback(ctx, a) }))
		if err != nil {
			t.Fatal(err)
		}
		result, err := exec.send(context.Background(), testAttempt())
		if !errors.Is(err, ErrOutcomeUnknown) || result.State != StateOutcomeUnknown || calls != 1 {
			t.Fatal("ambiguous invocation was retried or misclassified")
		}
		if strings.Contains(fmt.Sprintf("%+v", err), "private") {
			t.Fatal("callback diagnostics leaked")
		}
	}
}

func TestSenderCancelledInvocationAndCapacityWait(t *testing.T) {
	config := DefaultConfig()
	config.SenderConcurrency = 1
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	exec, err := newSenderExecutor(config, senderFunc(func(ctx context.Context, _ Attempt) (DeliveryResult, error) {
		calls.Add(1)
		close(entered)
		select {
		case <-release:
			return DeliveryResult{State: StateDelivered, ObservedAt: time.Now().UTC()}, nil
		case <-ctx.Done():
			return DeliveryResult{}, ctx.Err()
		}
	}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	joined := false
	defer func() {
		cancel()
		close(release)
		if !joined {
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("callback did not join")
			}
		}
	}()
	go func() { _, err := exec.send(ctx, testAttempt()); done <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("callback did not start")
	}
	wait, cancelWait := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancelWait()
	if _, err := exec.send(wait, testAttempt()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("capacity-wait cancellation ignored")
	}
	if calls.Load() != 1 {
		t.Fatal("sender capacity exceeded")
	}
	cancel()
	select {
	case err := <-done:
		joined = true
		if !errors.Is(err, ErrOutcomeUnknown) {
			t.Fatal("cancelled in-flight send became no-effect")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled callback did not return")
	}
}

type nilCallback struct{}

func (*nilCallback) Send(context.Context, Attempt) (DeliveryResult, error) {
	panic("unexpected nil callback")
}

type captureCallback struct{}

func (captureCallback) captureOnly() {}
func (captureCallback) Send(context.Context, Attempt) (DeliveryResult, error) {
	return DeliveryResult{}, nil
}

func TestSenderConstructorAndResultPolicy(t *testing.T) {
	var typedNil *nilCallback
	var functionNil senderFunc
	for _, s := range []Sender{nil, typedNil, functionNil} {
		if _, err := newSenderExecutor(DefaultConfig(), s); !errors.Is(err, ErrInvalidInput) {
			t.Fatal("nil callback accepted")
		}
	}
	c := DefaultConfig()
	c.Production = true
	if _, err := newSenderExecutor(c, captureCallback{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("production capture accepted")
	}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Attempts = 0 }, func(c *Config) { c.Attempts = 11 },
		func(c *Config) { c.SenderTimeout = time.Second - time.Nanosecond }, func(c *Config) { c.SenderTimeout = 30*time.Second + time.Nanosecond },
		func(c *Config) { c.SenderConcurrency = 0 }, func(c *Config) { c.SenderConcurrency = 65 },
		func(c *Config) { c.DedupeTTL = time.Hour - time.Nanosecond }, func(c *Config) { c.DedupeTTL = 31*24*time.Hour + time.Nanosecond },
		func(c *Config) { c.BackoffCeilings = nil }, func(c *Config) { c.BackoffCeilings[0] = time.Second },
		func(c *Config) { c.BackoffCeilings[1] = 0 }, func(c *Config) { c.BackoffCeilings[2] = time.Nanosecond },
	} {
		c := DefaultConfig()
		mutate(&c)
		if c.Validate() == nil {
			t.Fatal("invalid callback policy accepted")
		}
	}
	c = DefaultConfig()
	c.BackoffCeilings[0] = time.Second
	if DefaultConfig().Validate() != nil {
		t.Fatal("default policy shared mutable state")
	}
	for _, state := range []DeliveryState{StateAccepted, StateDelivered, StateRejected, StateBounced, StateTransientFailure} {
		var calls int
		exec, err := newSenderExecutor(DefaultConfig(), senderFunc(func(context.Context, Attempt) (DeliveryResult, error) {
			calls++
			return DeliveryResult{State: state, ObservedAt: time.Now().UTC()}, nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		result, err := exec.send(context.Background(), testAttempt())
		if err != nil || result.State != state || calls != 1 {
			t.Fatal("provider evidence changed or retried")
		}
	}
}

func TestSenderPrivacyAndLateSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	exec, err := newSenderExecutor(DefaultConfig(), senderFunc(func(context.Context, Attempt) (DeliveryResult, error) {
		cancel()
		return DeliveryResult{State: StateDelivered, ObservedAt: time.Now().UTC()}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	result, err := exec.send(ctx, testAttempt())
	var unknown OutcomeUnknownError
	if result.State != StateOutcomeUnknown || !errors.As(err, &unknown) || unknown.IntentID != testAttempt().IntentID {
		t.Fatal("late success lost recovery binding")
	}
	for _, v := range []any{testAttempt(), &Attempt{Body: "synthetic-private-content"}, DeliveryResult{ProviderReference: "synthetic-private-provider"}, validMessage(), validMessage().Recipient, validMessage().Variables[0], plainTemplate(), RenderedMessage{Body: "synthetic-private-content"}} {
		if data, err := json.Marshal(v); !errors.Is(err, ErrSerializationForbidden) || len(data) != 0 {
			t.Fatal("serialization refusal lost stable error or exposed content")
		}
		if strings.Contains(fmt.Sprintf("%#v", v), "private") {
			t.Fatal("private value leaked")
		}
	}
}

func TestSenderValidatesBeforeExternalEffect(t *testing.T) {
	var calls int
	exec, err := newSenderExecutor(DefaultConfig(), senderFunc(func(context.Context, Attempt) (DeliveryResult, error) { calls++; return DeliveryResult{}, nil }))
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Attempt){
		func(a *Attempt) { a.Generation = 0 }, func(a *Attempt) { a.TenantID = "" }, func(a *Attempt) { a.IntentID = "short" },
		func(a *Attempt) { a.Recipient = "x\r\ninjected" }, func(a *Attempt) { a.Subject = "x\ninjected" },
		func(a *Attempt) { a.ContentType = "application/javascript" }, func(a *Attempt) { a.IdempotencyKey = "" },
		func(a *Attempt) { a.ValidUntil = time.Time{} },
	} {
		a := testAttempt()
		change(&a)
		if _, err := exec.send(context.Background(), a); !errors.Is(err, ErrInvalidInput) {
			t.Fatal("invalid attempt admitted")
		}
	}
	a := testAttempt()
	a.ValidUntil = time.Now().UTC().Add(-time.Second)
	if _, err := exec.send(context.Background(), a); !errors.Is(err, ErrExpired) {
		t.Fatal("expired effect sent")
	}
	if calls != 0 {
		t.Fatal("validation caused external effect")
	}
	if strings.Contains(fmt.Sprintf("%+v", testAttempt()), "synthetic-content") {
		t.Fatal("attempt diagnostics leaked")
	}
}
