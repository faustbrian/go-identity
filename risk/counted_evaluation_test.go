package risk

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func countedConfig(t *testing.T, now *time.Time, store CounterStore) EvaluatorConfig {
	t.Helper()
	return countedConfigWithRetryCap(t, now, store, time.Hour)
}

func countedConfigWithRetryCap(t *testing.T, now *time.Time, store CounterStore, maximum time.Duration) EvaluatorConfig {
	t.Helper()
	pc := testPolicyConfig()
	pc.Limits.RetryAfterMax = maximum
	for i := range pc.Profiles {
		pc.Profiles[i].RequiredSignals = []string{"status", "velocity", "captcha"}
	}
	p, err := NewPolicy(pc)
	if err != nil {
		t.Fatal(err)
	}
	key, err := NewCounterDigestKey(7, bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	counter, err := NewCounterCoordinator(CounterCoordinatorConfig{Policy: p, Store: store, Clock: func() time.Time { return *now }, Timeout: time.Second, Keys: []CounterDigestKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	return EvaluatorConfig{Policy: p, Clock: func() time.Time { return *now }, Timeout: 5 * time.Second, Sources: []Source{cleanSource("status"), cleanSource("captcha")}, Counters: &counter}
}

func countedRequest(action Action) EvaluateRequest {
	c := testContext()
	c.Operation = action
	subject := counterSubject()
	if action == "identity.profile.get" {
		subject = Subject{User: "user"}
	}
	return EvaluateRequest{Context: c, Phase: NonIssuing, Subject: subject}
}

func TestCountedEvaluationMutatesAtOwnedPhaseAndUsesPostState(t *testing.T) {
	for _, action := range []Action{"identity.password.signin", "identity.profile.get"} {
		for _, exceeded := range []bool{false, true} {
			now := testContext().Now
			var order []string
			cfg := countedConfig(t, &now, counterStoreFunc(func(ctx context.Context, command CounterCommand) (CounterResult, error) {
				order = append(order, "counter")
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("unbounded mutation")
				}
				b := command.Bindings()
				if b.Operation != action || b.Tenant != testContext().Tenant || b.Attempt != testContext().Attempt {
					t.Fatal("foreign counter binding")
				}
				value := b.Limit
				if exceeded {
					value++
				}
				return NewCounterResult(command, CounterCommitted, snapshotFor(command, value))
			}))
			for i := range cfg.Sources {
				original := cfg.Sources[i]
				cfg.Sources[i].Read = func(ctx context.Context, c Context) (Signal, error) {
					order = append(order, original.Name)
					return original.Read(ctx, c)
				}
			}
			e, err := NewEvaluator(cfg)
			if err != nil {
				t.Fatal(err)
			}
			got, err := e.Evaluate(context.Background(), countedRequest(action))
			want := Allow
			if exceeded {
				want = Throttle
			}
			if err != nil || got.Decision.Action != want || got.counter == nil || got.counter.Outcome != CounterCommitted {
				t.Fatal("post-state decision/outcome", got.Decision, err)
			}
			wantOrder := []string{"counter", "status", "captcha"}
			if action == "identity.profile.get" {
				wantOrder = []string{"status", "captcha", "counter"}
			}
			if !slices.Equal(order, wantOrder) {
				t.Fatal("counter outside canonical phase", order)
			}
		}
	}
}

func TestCountedEvaluationUnavailableNeverAllowsOrRetries(t *testing.T) {
	for _, outcome := range []CounterOutcome{CounterNotCommitted, CounterUnknown, CounterCommitted} {
		now := testContext().Now
		calls := 0
		cfg := countedConfig(t, &now, counterStoreFunc(func(_ context.Context, c CounterCommand) (CounterResult, error) {
			calls++
			var snapshot []Counter
			if outcome == CounterCommitted {
				snapshot = snapshotFor(c, 1)
			}
			r, err := NewCounterResult(c, outcome, snapshot)
			if err != nil {
				t.Fatal(err)
			}
			return r, errors.New("private store failure")
		}))
		e, err := NewEvaluator(cfg)
		if err != nil {
			t.Fatal(err)
		}
		got, err := e.Evaluate(context.Background(), countedRequest("identity.password.signin"))
		if err != nil || got.Decision.Action != Deny || calls != 1 || got.Decision.RetryAfter != 0 || got.counter == nil || got.counter.Outcome != outcome {
			t.Fatal("unknown/failed mutation allowed, retried or erased", err)
		}
	}
}

func TestCountedEvaluationRejectsOwnershipAndScopeBeforeWork(t *testing.T) {
	now := testContext().Now
	store := counterStoreFunc(func(context.Context, CounterCommand) (CounterResult, error) {
		t.Fatal("store accessed before admission")
		return CounterResult{}, nil
	})
	for _, mutate := range []func(*EvaluatorConfig){
		func(c *EvaluatorConfig) { c.Sources = append(c.Sources, cleanSource("velocity")) },
		func(c *EvaluatorConfig) { c.Counters = &CounterCoordinator{} },
		func(c *EvaluatorConfig) { foreign := testCounterCoordinator(t, store); c.Counters = &foreign },
		func(c *EvaluatorConfig) { pc := testPolicyConfig(); p, _ := NewPolicy(pc); c.Policy = p },
	} {
		cfg := countedConfig(t, &now, store)
		mutate(&cfg)
		if _, err := NewEvaluator(cfg); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatal("counter ownership accepted", err)
		}
	}
	cfg := countedConfig(t, &now, store)
	for i := range cfg.Sources {
		cfg.Sources[i].Read = func(context.Context, Context) (Signal, error) {
			t.Fatal("provider accessed before scope/phase admission")
			return Signal{}, nil
		}
	}
	e, err := NewEvaluator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []Action{"signin", "identity.password.change"} {
		r := countedRequest(action)
		_, err := e.Evaluate(context.Background(), r)
		want := ErrInvalidAction
		if action == "identity.password.change" {
			want = ErrUnsupportedCounterPhase
		}
		if !errors.Is(err, want) {
			t.Fatal("unsupported action/phase accepted", err)
		}
	}
	r := countedRequest("identity.password.signin")
	r.Subject.Device = ""
	if _, err := e.Evaluate(context.Background(), r); !errors.Is(err, ErrInvalidCounterCommand) {
		t.Fatal("incomplete counter scope accepted", err)
	}
}

func TestCountedEvaluationRetainsKnownMutationAfterProviderCancellation(t *testing.T) {
	now := testContext().Now
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := countedConfig(t, &now, counterStoreFunc(func(_ context.Context, c CounterCommand) (CounterResult, error) {
		return NewCounterResult(c, CounterCommitted, snapshotFor(c, 1))
	}))
	cfg.Sources[0].Read = func(_ context.Context, c Context) (Signal, error) {
		cancel()
		return testSignal(c, "status", SignalClean), nil
	}
	e, err := NewEvaluator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.Evaluate(ctx, countedRequest("identity.password.signin"))
	if !errors.Is(err, context.Canceled) || got.counter == nil || got.counter.Outcome != CounterCommitted || got.Decision.Action != "" {
		t.Fatal("cancellation lost known attempt mutation", err)
	}
}

func TestCountedEvaluationRechecksOriginalCounterFreshnessAfterProviders(t *testing.T) {
	now := testContext().Now
	cfg := countedConfig(t, &now, counterStoreFunc(func(_ context.Context, c CounterCommand) (CounterResult, error) {
		snapshot := snapshotFor(c, 1)
		for i := range snapshot {
			snapshot[i].ObservedAt = now.Add(-5*time.Minute + time.Second)
		}
		return NewCounterResult(c, CounterCommitted, snapshot)
	}))
	cfg.Sources[1].Read = func(_ context.Context, c Context) (Signal, error) {
		now = now.Add(time.Second)
		c.Now = now
		return testSignal(c, "captcha", SignalClean), nil
	}
	e, err := NewEvaluator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.Evaluate(context.Background(), countedRequest("identity.password.signin"))
	if !errors.Is(err, ErrInvalidSignal) || got.counter == nil || got.counter.Outcome != CounterCommitted || got.Decision.Action != "" {
		t.Fatal("later provider renewed original counter evidence", err)
	}
}

func TestCountedEvaluationOwnsConfigurationAndSeparatesConcurrentAttempts(t *testing.T) {
	now := testContext().Now
	var calls atomic.Int64
	cfg := countedConfig(t, &now, counterStoreFunc(func(_ context.Context, c CounterCommand) (CounterResult, error) {
		calls.Add(1)
		return NewCounterResult(c, CounterCommitted, snapshotFor(c, 1))
	}))
	e, err := NewEvaluator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	*cfg.Counters = CounterCoordinator{}
	cfg.Sources[0].Read = nil
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Go(func() {
			r := countedRequest("identity.password.signin")
			r.Context.Attempt = "attempt-" + strconv.Itoa(i)
			got, err := e.Evaluate(context.Background(), r)
			if err != nil || got.Decision.Action != Allow || got.counter == nil || got.counter.Signal.Attempt != r.Context.Attempt {
				t.Error("cross-attempt/configuration contamination", err)
			}
		})
	}
	wg.Wait()
	if calls.Load() != 16 {
		t.Fatal("missing/duplicate concurrent mutations")
	}
}

func TestCountedEvaluationRetryAfterUsesFinalExceededWindow(t *testing.T) {
	for _, maximum := range []time.Duration{time.Hour, 2 * time.Second} {
		t.Run(maximum.String(), func(t *testing.T) {
			now := testContext().Now
			var windowExpiry time.Time
			cfg := countedConfigWithRetryCap(t, &now, counterStoreFunc(func(_ context.Context, c CounterCommand) (CounterResult, error) {
				snapshot := snapshotFor(c, 1)
				// Only an exceeded counter contributes retry delay. Other counters have
				// much later expiries, but their clean post-state cannot extend it.
				snapshot[0].Value = c.Bindings().Limit + 1
				windowExpiry = now.Add(10 * time.Second)
				snapshot[0].WindowExpiresAt = windowExpiry
				return NewCounterResult(c, CounterCommitted, snapshot)
			}), maximum)
			cfg.Sources[1].Read = func(_ context.Context, c Context) (Signal, error) {
				now = now.Add(500 * time.Millisecond)
				c.Now = now
				return testSignal(c, "captcha", SignalClean), nil
			}
			e, err := NewEvaluator(cfg)
			if err != nil {
				t.Fatal(err)
			}
			got, err := e.Evaluate(context.Background(), countedRequest("identity.password.signin"))
			if err != nil || got.Decision.Action != Throttle {
				t.Fatal("missing throttle", err)
			}
			want := min(windowExpiry.Sub(now), maximum)
			if got.Decision.RetryAfter != want {
				t.Fatalf("retry after includes elapsed work or changes clipping: got %s want %s", got.Decision.RetryAfter, want)
			}
			if got.counter == nil || got.counter.Outcome != CounterCommitted || got.counter.Signal.RetryAfter != min(10*time.Second, maximum) {
				t.Fatal("final decision modified the original attributable counter outcome")
			}
		})
	}
}
