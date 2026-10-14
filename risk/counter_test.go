package risk

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
)

type counterStoreFunc func(context.Context, CounterCommand) (CounterResult, error)

func (f counterStoreFunc) Mutate(c context.Context, command CounterCommand) (CounterResult, error) {
	return f(c, command)
}

func testCounterCoordinator(t *testing.T, store CounterStore) CounterCoordinator {
	t.Helper()
	key, err := NewCounterDigestKey(7, bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewCounterCoordinator(CounterCoordinatorConfig{Policy: testPolicy(t), Keys: []CounterDigestKey{key}, Store: store, Clock: func() time.Time { return testContext().Now }, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func counterSubject() Subject {
	return Subject{Network: "2001:0db8:0:0:0:0:0:1", Device: "device", IdentifierDigest: strings.Repeat("a", 64)}
}

func snapshotFor(command CounterCommand, value uint64) []Counter {
	b := command.Bindings()
	result := make([]Counter, 0, len(b.Targets))
	for _, target := range b.Targets {
		result = append(result, Counter{Kind: string(target.Dimension), Value: value, ObservedAt: b.PreparedAt, WindowStartedAt: b.PreparedAt.Add(-time.Second), WindowExpiresAt: b.PreparedAt.Add(b.Window - time.Second)})
	}
	return result
}

func TestCounterReplayCannotRenewOriginalObservation(t *testing.T) {
	now := testContext().Now
	key, err := NewCounterDigestKey(7, bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	var recorded CounterResult
	c, err := NewCounterCoordinator(CounterCoordinatorConfig{
		Policy: testPolicy(t), Keys: []CounterDigestKey{key}, Timeout: time.Second,
		Clock: func() time.Time { return now },
		Store: counterStoreFunc(func(_ context.Context, command CounterCommand) (CounterResult, error) {
			if recorded.state == nil {
				recorded, err = NewCounterResult(command, CounterCommitted, snapshotFor(command, 1))
			}
			return recorded, err
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := c.Prepare(testContext(), counterSubject(), BeforeCredential)
	if err != nil {
		t.Fatal(err)
	}
	a, err := c.Mutate(context.Background(), first)
	if err != nil || a.Signal.State != SignalClean {
		t.Fatal("first observation unavailable", err)
	}
	now = now.Add(time.Second)
	replay, err := c.Prepare(testContext(), counterSubject(), BeforeCredential)
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Mutate(context.Background(), replay)
	if err != nil || b.Signal.State != SignalClean || !a.Signal.ObservedAt.Equal(b.Signal.ObservedAt) || !a.Signal.ExpiresAt.Equal(b.Signal.ExpiresAt) {
		t.Fatal("replay renewed original counter evidence", err)
	}
	now = a.Signal.ExpiresAt
	replay, err = c.Prepare(testContext(), counterSubject(), BeforeCredential)
	if err != nil {
		t.Fatal(err)
	}
	b, err = c.Mutate(context.Background(), replay)
	if err != nil || b.Outcome != CounterCommitted || b.Signal.State != SignalUnavailable {
		t.Fatal("expired replay admitted or commit classification lost", err)
	}
}

func TestCounterCoordinatorUsesPostMutationSnapshotAndDoesNotRetryUnknown(t *testing.T) {
	for _, outcome := range []CounterOutcome{CounterCommitted, CounterNotCommitted, CounterUnknown} {
		calls := 0
		c := testCounterCoordinator(t, counterStoreFunc(func(ctx context.Context, command CounterCommand) (CounterResult, error) {
			calls++
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("unbounded mutation")
			}
			var snapshot []Counter
			if outcome == CounterCommitted {
				snapshot = snapshotFor(command, 11)
			}
			return NewCounterResult(command, outcome, snapshot)
		}))
		command, err := c.Prepare(testContext(), counterSubject(), BeforeCredential)
		if err != nil {
			t.Fatal(err)
		}
		result, err := c.Mutate(context.Background(), command)
		if err != nil || calls != 1 || result.Outcome != outcome {
			t.Fatal("mutation outcome or automatic retry", err)
		}
		want := SignalUnavailable
		if outcome == CounterCommitted {
			want = SignalThrottle
		}
		if result.Signal.State != want {
			t.Fatal("wrong post-state decision")
		}
		if outcome != CounterCommitted && result.Signal.RetryAfter != 0 {
			t.Fatal("unknown invented retry metadata")
		}
	}
}

func TestCounterPreparationHasExactScopeDimensionsAndKeyedCanonicalNetwork(t *testing.T) {
	c := testCounterCoordinator(t, counterStoreFunc(func(context.Context, CounterCommand) (CounterResult, error) {
		t.Fatal("prepare accessed store")
		return CounterResult{}, nil
	}))
	a, err := c.Prepare(testContext(), counterSubject(), BeforeCredential)
	if err != nil {
		t.Fatal(err)
	}
	subject := counterSubject()
	subject.Network = "2001:db8::1"
	b, err := c.Prepare(testContext(), subject, BeforeCredential)
	if err != nil {
		t.Fatal(err)
	}
	if a.Bindings().Fingerprint != b.Bindings().Fingerprint {
		t.Fatal("alternate address bypass")
	}
	for _, target := range a.Bindings().Targets {
		for _, key := range target.Keys {
			if len(key.Encoded) > 64 || key.Version != 7 || strings.Contains(key.Encoded, "tenant") || strings.Contains(key.Encoded, "db8") || strings.Contains(key.Encoded, "device") {
				t.Fatal("raw or unbounded key")
			}
		}
	}
	foreign := testContext()
	foreign.Tenant = "other"
	b, err = c.Prepare(foreign, subject, BeforeCredential)
	if err != nil {
		t.Fatal(err)
	}
	if a.Bindings().Targets[0].Keys[0].Encoded == b.Bindings().Targets[0].Keys[0].Encoded {
		t.Fatal("cross-tenant key reuse")
	}
	projection := a.Bindings()
	projection.Targets[0].Keys[0].Encoded = "changed"
	if a.Bindings().Targets[0].Keys[0].Encoded == "changed" {
		t.Fatal("mutable command projection")
	}
	for _, value := range []any{a, a.Bindings(), subject} {
		if strings.Contains(fmt.Sprintf("%#v", value), "db8") {
			t.Fatal("raw network diagnostic")
		}
	}
}

func TestCounterPreparationRejectsWrongPhaseExtraAndMissingDimensions(t *testing.T) {
	c := testCounterCoordinator(t, counterStoreFunc(func(context.Context, CounterCommand) (CounterResult, error) {
		t.Fatal("invalid command dispatched")
		return CounterResult{}, nil
	}))
	for _, mutate := range []func(*Subject){
		func(s *Subject) { s.Network = "" }, func(s *Subject) { s.Network = "fe80::1%eth0" },
		func(s *Subject) { s.Device = "" }, func(s *Subject) { s.IdentifierDigest = "plain identifier" },
		func(s *Subject) { s.User = "unused" },
	} {
		s := counterSubject()
		mutate(&s)
		if _, err := c.Prepare(testContext(), s, BeforeCredential); !errors.Is(err, ErrInvalidCounterCommand) {
			t.Fatal("unsafe scope admitted", err)
		}
	}
	for _, phase := range []Phase{"", BeforeReturn, ReserveWithCommand} {
		if _, err := c.Prepare(testContext(), counterSubject(), phase); !errors.Is(err, ErrInvalidCounterCommand) {
			t.Fatal("wrong phase admitted")
		}
	}
	cx := testContext()
	cx.Operation = "identity.password.change"
	if _, err := c.Prepare(cx, Subject{Network: "192.0.2.1", User: "user", Session: "session"}, ReserveWithCommand); !errors.Is(err, ErrUnsupportedCounterPhase) {
		t.Fatal("protected phase bypassed transaction owner")
	}
}

func TestCounterResultRejectsPartialDuplicateForeignAndBadIntervals(t *testing.T) {
	c := testCounterCoordinator(t, counterStoreFunc(func(context.Context, CounterCommand) (CounterResult, error) { return CounterResult{}, nil }))
	command, err := c.Prepare(testContext(), counterSubject(), BeforeCredential)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func([]Counter) []Counter{
		func(s []Counter) []Counter { return s[:3] },
		func(s []Counter) []Counter { s[1].Kind = s[0].Kind; return s },
		func(s []Counter) []Counter { s[0].Kind = "foreign"; return s },
		func(s []Counter) []Counter { s[0].WindowExpiresAt = s[0].WindowStartedAt; return s },
		func(s []Counter) []Counter {
			s[0].WindowExpiresAt = s[0].WindowStartedAt.Add(6 * time.Minute)
			return s
		},
	} {
		if _, err := NewCounterResult(command, CounterCommitted, mutate(snapshotFor(command, 1))); !errors.Is(err, ErrInvalidCounterResult) {
			t.Fatal("invalid post-state admitted")
		}
	}
	if _, err := NewCounterResult(command, CounterUnknown, snapshotFor(command, 1)); !errors.Is(err, ErrInvalidCounterResult) {
		t.Fatal("unknown carried positive state")
	}
}

func TestCounterForeignResultsAndStoreErrorsBecomeUnknownWithoutDisclosure(t *testing.T) {
	var foreign CounterCommand
	c := testCounterCoordinator(t, counterStoreFunc(func(context.Context, CounterCommand) (CounterResult, error) {
		return NewCounterResult(foreign, CounterCommitted, snapshotFor(foreign, 1))
	}))
	fx := testContext()
	fx.Tenant = "foreign"
	var err error
	foreign, err = c.Prepare(fx, counterSubject(), BeforeCredential)
	if err != nil {
		t.Fatal(err)
	}
	command, err := c.Prepare(testContext(), counterSubject(), BeforeCredential)
	if err != nil {
		t.Fatal(err)
	}
	result, err := c.Mutate(context.Background(), command)
	if err != nil || result.Outcome != CounterUnknown || result.Signal.State != SignalUnavailable {
		t.Fatal("foreign result authority")
	}
	c = testCounterCoordinator(t, counterStoreFunc(func(context.Context, CounterCommand) (CounterResult, error) {
		return CounterResult{}, errors.New("private storage secret")
	}))
	command, err = c.Prepare(testContext(), counterSubject(), BeforeCredential)
	if err != nil {
		t.Fatal(err)
	}
	result, err = c.Mutate(context.Background(), command)
	if err != nil || result.Outcome != CounterUnknown || strings.Contains(fmt.Sprintf("%#v", result), "secret") {
		t.Fatal("storage failure disclosure or noncommit fabrication")
	}
}

func TestCounterThresholdUsesExactPostStateWithoutOverflow(t *testing.T) {
	for _, value := range []uint64{0, 1, 10, 11, math.MaxUint64} {
		t.Run(fmt.Sprint(value), func(t *testing.T) {
			c := testCounterCoordinator(t, counterStoreFunc(func(_ context.Context, command CounterCommand) (CounterResult, error) {
				return NewCounterResult(command, CounterCommitted, snapshotFor(command, value))
			}))
			command, err := c.Prepare(testContext(), counterSubject(), BeforeCredential)
			if err != nil {
				t.Fatal(err)
			}
			result, err := c.Mutate(context.Background(), command)
			want := SignalClean
			if value > 10 {
				want = SignalThrottle
			}
			if err != nil || result.Outcome != CounterCommitted || result.Signal.State != want {
				t.Fatal("post-state threshold mismatch", err)
			}
			if want == SignalClean && result.Signal.RetryAfter != 0 {
				t.Fatal("allow exposes retry metadata")
			}
			if want == SignalThrottle && result.Signal.RetryAfter != 5*time.Minute-time.Second {
				t.Fatal("incorrect window retry")
			}
		})
	}
}

func TestCounterLateCancelledAndExpiredResultsRetainCommitButNoFacts(t *testing.T) {
	for _, mode := range []string{"cancelled", "backward", "late", "expired-window", "future-window", "future-observation", "expired-observation"} {
		t.Run(mode, func(t *testing.T) {
			now := testContext().Now
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			key, err := NewCounterDigestKey(7, bytes.Repeat([]byte{0x31}, 32))
			if err != nil {
				t.Fatal(err)
			}
			c, err := NewCounterCoordinator(CounterCoordinatorConfig{
				Policy: testPolicy(t), Keys: []CounterDigestKey{key}, Clock: func() time.Time { return now }, Timeout: time.Second,
				Store: counterStoreFunc(func(_ context.Context, command CounterCommand) (CounterResult, error) {
					snapshot := snapshotFor(command, 1)
					switch mode {
					case "cancelled":
						cancel()
					case "backward":
						now = now.Add(-time.Nanosecond)
					case "late":
						now = now.Add(time.Second)
					case "expired-window":
						snapshot[0].WindowExpiresAt = now
					case "future-window":
						snapshot[0].WindowStartedAt = now.Add(time.Nanosecond)
					case "future-observation":
						snapshot[0].ObservedAt = now.Add(time.Nanosecond)
					case "expired-observation":
						snapshot[0].ObservedAt = now.Add(-5 * time.Minute)
					}
					return NewCounterResult(command, CounterCommitted, snapshot)
				}),
			})
			if err != nil {
				t.Fatal(err)
			}
			command, err := c.Prepare(testContext(), counterSubject(), BeforeCredential)
			if err != nil {
				t.Fatal(err)
			}
			result, err := c.Mutate(ctx, command)
			if err != nil || result.Outcome != CounterCommitted || result.Signal.State != SignalUnavailable || !result.Signal.ObservedAt.IsZero() || !result.Signal.ExpiresAt.IsZero() || result.Signal.RetryAfter != 0 {
				t.Fatal("unusable mutation lost commit or acquired facts", err)
			}
		})
	}
}

func TestCounterCompleteResultWithErrorPreservesOutcomeWithoutUsableFacts(t *testing.T) {
	for _, outcome := range []CounterOutcome{CounterCommitted, CounterNotCommitted, CounterUnknown} {
		for _, failure := range []error{context.Canceled, context.DeadlineExceeded, errors.New("private cleanup failure")} {
			t.Run(fmt.Sprintf("%d/%s", outcome, failure), func(t *testing.T) {
				calls := 0
				c := testCounterCoordinator(t, counterStoreFunc(func(_ context.Context, command CounterCommand) (CounterResult, error) {
					calls++
					var snapshot []Counter
					if outcome == CounterCommitted {
						snapshot = snapshotFor(command, 1)
					}
					result, err := NewCounterResult(command, outcome, snapshot)
					if err != nil {
						t.Fatal(err)
					}
					return result, failure
				}))
				command, err := c.Prepare(testContext(), counterSubject(), BeforeCredential)
				if err != nil {
					t.Fatal(err)
				}
				result, err := c.Mutate(context.Background(), command)
				if err != nil || calls != 1 || result.Outcome != outcome || result.Signal.State != SignalUnavailable || !result.Signal.ObservedAt.IsZero() || !result.Signal.ExpiresAt.IsZero() || result.Signal.RetryAfter != 0 {
					t.Fatal("complete outcome erased or error acquired facts", err)
				}
			})
		}
	}
}

func TestCounterDispatchRejectsZeroForeignExpiredAndCancelledCommands(t *testing.T) {
	calls := 0
	store := counterStoreFunc(func(context.Context, CounterCommand) (CounterResult, error) { calls++; return CounterResult{}, nil })
	c := testCounterCoordinator(t, store)
	other := testCounterCoordinator(t, store)
	foreign, err := other.Prepare(testContext(), counterSubject(), BeforeCredential)
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range []CounterCommand{{}, foreign} {
		if _, err := c.Mutate(context.Background(), command); !errors.Is(err, ErrInvalidCounterCommand) {
			t.Fatal("foreign dispatch accepted")
		}
	}
	command, err := c.Prepare(testContext(), counterSubject(), BeforeCredential)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Mutate(nil, command); !errors.Is(err, ErrInvalidCounterCommand) {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Mutate(ctx, command); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost")
	}
	if calls != 0 {
		t.Fatal("invalid commands dispatched")
	}
	if _, err := (CounterCoordinator{}).Prepare(testContext(), counterSubject(), BeforeCredential); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatal("zero prepare")
	}
	if _, err := (CounterCoordinator{}).Mutate(context.Background(), command); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatal("zero dispatch")
	}
}

func TestCounterRotationKeysAreBoundedOrderedAndIndependentlyOwned(t *testing.T) {
	secret := bytes.Repeat([]byte{0x32}, 32)
	newest, err := NewCounterDigestKey(8, secret)
	if err != nil {
		t.Fatal(err)
	}
	old, err := NewCounterDigestKey(7, bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	store := counterStoreFunc(func(context.Context, CounterCommand) (CounterResult, error) { return CounterResult{}, nil })
	config := CounterCoordinatorConfig{Policy: testPolicy(t), Store: store, Clock: func() time.Time { return testContext().Now }, Timeout: time.Second, Keys: []CounterDigestKey{newest, old}}
	c, err := NewCounterCoordinator(config)
	if err != nil {
		t.Fatal(err)
	}
	a, err := c.Prepare(testContext(), counterSubject(), BeforeCredential)
	if err != nil {
		t.Fatal(err)
	}
	secret[0] = 0
	config.Keys[0] = old
	b, err := c.Prepare(testContext(), counterSubject(), BeforeCredential)
	if err != nil || a.Bindings().Fingerprint != b.Bindings().Fingerprint {
		t.Fatal("caller changed owned rotation key")
	}
	for _, target := range b.Bindings().Targets {
		if len(target.Keys) != 2 || target.Keys[0].Version != 8 || target.Keys[1].Version != 7 || target.Keys[0].Encoded == target.Keys[1].Encoded {
			t.Fatal("rotation aliases lost")
		}
	}
	for _, keys := range [][]CounterDigestKey{nil, {old, newest}, {old, old}, {{}}, {newest, old, old, old, old}} {
		config.Keys = keys
		if _, err := NewCounterCoordinator(config); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatal("invalid keyring accepted")
		}
	}
	for _, length := range []int{0, 31, 129} {
		if _, err := NewCounterDigestKey(1, make([]byte, length)); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatal("key length accepted")
		}
	}
	if _, err := NewCounterDigestKey(0, make([]byte, 32)); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatal("zero version accepted")
	}
}

func TestCounterNeutralReadRequiresExactlyOneSubjectOrNetwork(t *testing.T) {
	c := testCounterCoordinator(t, counterStoreFunc(func(context.Context, CounterCommand) (CounterResult, error) { return CounterResult{}, nil }))
	scope := testContext()
	scope.Operation = "identity.session.get"
	for _, subject := range []Subject{{User: "user"}, {Network: "192.0.2.1"}} {
		command, err := c.Prepare(scope, subject, BeforeReturn)
		if err != nil || len(command.Bindings().Targets) != 2 {
			t.Fatal("neutral read dimension rejected", err)
		}
	}
	for _, subject := range []Subject{{}, {User: "user", Network: "192.0.2.1"}, {User: "user", Device: "extra"}, {Network: "::"}, {Network: "ff02::1"}} {
		if _, err := c.Prepare(scope, subject, BeforeReturn); !errors.Is(err, ErrInvalidCounterCommand) {
			t.Fatal("ambiguous/unsafe neutral dimension", err)
		}
	}
}

func FuzzCounterPreparation(f *testing.F) {
	for _, address := range []string{"192.0.2.1", "::ffff:192.0.2.1", "2001:db8::1", "fe80::1%eth0", "", "bad"} {
		f.Add(address, "device", strings.Repeat("a", 64))
	}
	policy, err := NewPolicy(testPolicyConfig())
	if err != nil {
		f.Fatal(err)
	}
	key, err := NewCounterDigestKey(7, bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		f.Fatal(err)
	}
	c, err := NewCounterCoordinator(CounterCoordinatorConfig{Policy: policy, Keys: []CounterDigestKey{key}, Clock: func() time.Time { return testContext().Now }, Timeout: time.Second,
		Store: counterStoreFunc(func(context.Context, CounterCommand) (CounterResult, error) { panic("preparation dispatched") }),
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, network, device, identifier string) {
		command, err := c.Prepare(testContext(), Subject{Network: network, Device: device, IdentifierDigest: identifier}, BeforeCredential)
		if err != nil {
			if command.state != nil {
				t.Fatal("rejected input retained command")
			}
			return
		}
		binding := command.Bindings()
		if len(binding.Targets) != 4 || len(binding.Fingerprint) != 64 {
			t.Fatal("unbounded prepared command")
		}
		for _, target := range binding.Targets {
			if len(target.Keys) != 1 || len(target.Keys[0].Encoded) > 64 {
				t.Fatal("unbounded scoped key")
			}
		}
	})
}
