package velocity

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/risk"
)

// These doubles are deliberate adapter boundaries. They prove sequencing and
// conservation, not SQL durability, native marker enforcement or interoperability.
type fixture struct {
	mu       sync.Mutex
	command  risk.CounterCommand
	policy   risk.Policy
	keys     []risk.CounterDigestKey
	pending  bool
	retained risk.CounterResult
	writes   int
	healthy  bool
	mode     string
}

type unusedStore struct{}

func (unusedStore) Mutate(context.Context, risk.CounterCommand) (risk.CounterResult, error) {
	panic("preparation dispatched")
}

func newFixture(t *testing.T, mode string, read bool) (*fixture, Store) {
	t.Helper()
	p, err := risk.NewPolicy(risk.PolicyConfig{Version: 3, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}, Profiles: []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: 5 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2, RequiredSignals: []string{"velocity"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	key, err := risk.NewCounterDigestKey(9, bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	old, err := risk.NewCounterDigestKey(8, bytes.Repeat([]byte{8}, 32))
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{policy: p, keys: []risk.CounterDigestKey{key, old}, healthy: true, mode: mode}
	c, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: p, Keys: f.keys, Store: unusedStore{}, Clock: func() time.Time { return time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC) }, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	action, phase, subject := risk.Action("identity.otp.send"), risk.BeforeCredential, risk.Subject{Network: "2001:db8::1", Device: "device", IdentifierDigest: strings.Repeat("a", 64)}
	if read {
		action, phase, subject = "identity.profile.get", risk.BeforeReturn, risk.Subject{User: "user"}
	}
	f.command, err = c.Prepare(risk.Context{Tenant: "tenant", Operation: action, Attempt: "attempt"}, subject, phase)
	if err != nil {
		t.Fatal(err)
	}
	validate := func(c risk.CounterCommand) error { return c.ValidateConfiguration(f.policy, f.keys) }
	check := func(ctx context.Context, c risk.CounterCommand) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if !f.healthy || mode == "health_before" {
			return risk.ErrVelocityRecoveryUnavailable
		}
		return nil
	}
	journal, err := BindJournal([32]byte{1}, validate, check, func(ctx context.Context, c risk.CounterCommand) (Attempt, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if mode == "attempt_rollback" {
			return Attempt{}, risk.ErrVelocityRecoveryUnavailable
		}
		if f.pending {
			return Attempt{}, risk.ErrVelocityRecoveryUnavailable
		}
		f.pending = true
		if mode == "attempt_lost_ack" {
			return Attempt{}, risk.ErrVelocityRecoveryUnavailable
		}
		if mode == "zero_attempt" {
			return Attempt{}, nil
		}
		return BindAttempt(c, func(ctx context.Context, result risk.CounterResult) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if mode == "result_rollback" {
				return risk.ErrVelocityRecoveryUnavailable
			}
			f.retained = result
			if mode == "result_lost_ack" {
				return risk.ErrVelocityRecoveryUnavailable
			}
			return nil
		})
	}, func(ctx context.Context, c risk.CounterCommand) (risk.CounterResult, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if _, _, err := f.retained.Declaration(c); err != nil {
			return risk.CounterResult{}, risk.ErrVelocityRecoveryUnavailable
		}
		return f.retained, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	native, err := BindNative([32]byte{1}, validate, check, func(ctx context.Context, c risk.CounterCommand) (risk.CounterResult, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if !f.pending {
			t.Error("native effect preceded acknowledged durable intent")
		}
		f.writes++
		outcome := risk.CounterCommitted
		if mode == "not_committed" {
			outcome = risk.CounterNotCommitted
		}
		if mode == "unknown" {
			outcome = risk.CounterUnknown
		}
		if mode == "zero_result" {
			return risk.CounterResult{}, risk.ErrVelocityRecoveryUnavailable
		}
		var rows []risk.Counter
		if outcome == risk.CounterCommitted {
			b := c.Bindings()
			for _, target := range b.Targets {
				rows = append(rows, risk.Counter{Kind: string(target.Dimension), Value: 1, ObservedAt: b.PreparedAt, WindowStartedAt: b.PreparedAt, WindowExpiresAt: b.PreparedAt.Add(b.Window)})
			}
		}
		result, err := risk.NewCounterResult(c, outcome, rows)
		if err != nil {
			t.Fatal(err)
		}
		if mode == "commit_then_error" {
			return result, risk.ErrVelocityRecoveryUnavailable
		}
		if mode == "health_after" {
			f.healthy = false
		}
		return result, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(journal, native, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return f, s
}

func TestStoreConservesNativeOutcomesAndOriginalReplay(t *testing.T) {
	for _, read := range []bool{false, true} {
		for _, mode := range []string{"committed", "not_committed", "unknown", "commit_then_error", "health_after", "result_rollback", "result_lost_ack", "zero_result"} {
			t.Run(mode+"/"+map[bool]string{false: "authentication", true: "read"}[read], func(t *testing.T) {
				f, s := newFixture(t, mode, read)
				result, err := s.Mutate(context.Background(), f.command)
				want := risk.CounterCommitted
				if mode == "not_committed" {
					want = risk.CounterNotCommitted
				}
				if mode == "unknown" || mode == "zero_result" {
					want = risk.CounterUnknown
				}
				outcome, rows, projectionErr := result.Declaration(f.command)
				if projectionErr != nil || outcome != want || f.writes != 1 {
					t.Fatal("original native outcome lost", err, projectionErr)
				}
				if (err != nil) != (mode != "committed" && mode != "not_committed" && mode != "unknown") {
					t.Fatal("effect/failure classification changed", err)
				}
				if want == risk.CounterCommitted && len(rows) != len(f.command.Bindings().Targets) {
					t.Fatal("complete original snapshot lost")
				}
				replayed, replayErr := s.Mutate(context.Background(), f.command)
				if f.writes != 1 {
					t.Fatal("matching or unresolved replay resent native effect")
				}
				if mode == "health_after" || mode == "result_rollback" {
					if replayErr == nil {
						t.Fatal("unresolved/unhealthy replay admitted")
					}
					return
				}
				if replayErr != nil {
					t.Fatal(replayErr)
				}
				ro, rr, re := replayed.Declaration(f.command)
				if re != nil || ro != outcome || !reflect.DeepEqual(rows, rr) {
					t.Fatal("replay renewed or changed original declaration", re)
				}
			})
		}
	}
}

func TestStoreNeverDispatchesWithoutAcknowledgedIntent(t *testing.T) {
	for _, mode := range []string{"attempt_rollback", "attempt_lost_ack", "zero_attempt", "health_before"} {
		t.Run(mode, func(t *testing.T) {
			f, s := newFixture(t, mode, false)
			for range 2 {
				if _, err := s.Mutate(context.Background(), f.command); err == nil {
					t.Fatal("unacknowledged intent admitted")
				}
			}
			if f.writes != 0 {
				t.Fatal("failed intent dispatched")
			}
		})
	}
}

func TestStoreConcurrentReplayHasOneNativeEffect(t *testing.T) {
	f, s := newFixture(t, "committed", false)
	var wg sync.WaitGroup
	for range 24 {
		wg.Go(func() { _, _ = s.Mutate(context.Background(), f.command) })
	}
	wg.Wait()
	if f.writes != 1 {
		t.Fatal("concurrent pending/replay double dispatched", f.writes)
	}
	if outcome, _, err := f.retained.Declaration(f.command); err != nil || outcome != risk.CounterCommitted {
		t.Fatal("winner not retained", err)
	}
}

func TestStoreRejectsInvalidAndCanceledInputs(t *testing.T) {
	f, s := newFixture(t, "committed", false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, input := range []struct {
		ctx     context.Context
		command risk.CounterCommand
	}{{nil, f.command}, {ctx, f.command}, {context.Background(), risk.CounterCommand{}}} {
		if _, err := s.Mutate(input.ctx, input.command); err == nil {
			t.Fatal("invalid input admitted")
		}
	}
	if f.writes != 0 || f.pending {
		t.Fatal("invalid input reached adapters")
	}
	if _, err := (Store{}).Mutate(context.Background(), f.command); !errors.Is(err, risk.ErrInvalidVelocityRecovery) {
		t.Fatal("zero store admitted", err)
	}
}

func TestStoreDeadlineAfterCommitPreservesTruth(t *testing.T) {
	f, s := newFixture(t, "committed", false)
	mutate := s.state.native.state.mutate
	s.state.timeout = 20 * time.Millisecond
	s.state.native.state.mutate = func(ctx context.Context, c risk.CounterCommand) (risk.CounterResult, error) {
		result, err := mutate(ctx, c)
		<-ctx.Done()
		return result, err
	}
	result, err := s.Mutate(context.Background(), f.command)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("ignored crossing deadline", err)
	}
	if outcome, _, err := result.Declaration(f.command); err != nil || outcome != risk.CounterCommitted {
		t.Fatal("deadline erased native commit", err)
	}
	if f.writes != 1 {
		t.Fatal("deadline resent effect")
	}
}

func TestStoreInvalidBindingsFailBeforeEffects(t *testing.T) {
	f, s := newFixture(t, "committed", false)
	validate := s.state.native.state.validate
	check := s.state.native.state.check
	record := s.state.journal.state.record
	replay := s.state.journal.state.replay
	mutate := s.state.native.state.mutate
	for _, j := range []Journal{{}, {&journal{namespace: [32]byte{2}}}} {
		if _, err := NewStore(j, s.state.native, time.Second); err == nil {
			t.Fatal("foreign/zero journal accepted")
		}
	}
	for _, bound := range []time.Duration{0, time.Minute + 1} {
		if _, err := NewStore(s.state.journal, s.state.native, bound); err == nil {
			t.Fatal("invalid budget accepted")
		}
	}
	if _, err := NewStore(s.state.journal, Native{}, time.Second); err == nil {
		t.Fatal("zero native accepted")
	}
	for i := range 5 {
		ns, v, ch, r, rp := [32]byte{1}, validate, check, record, replay
		switch i {
		case 0:
			ns = [32]byte{}
		case 1:
			v = nil
		case 2:
			ch = nil
		case 3:
			r = nil
		case 4:
			rp = nil
		}
		if _, err := BindJournal(ns, v, ch, r, rp); err == nil {
			t.Fatal("incomplete journal accepted")
		}
	}
	for i := range 4 {
		ns, v, ch, m := [32]byte{1}, validate, check, mutate
		switch i {
		case 0:
			ns = [32]byte{}
		case 1:
			v = nil
		case 2:
			ch = nil
		case 3:
			m = nil
		}
		if _, err := BindNative(ns, v, ch, m); err == nil {
			t.Fatal("incomplete native accepted")
		}
	}
	if _, err := BindAttempt(risk.CounterCommand{}, func(context.Context, risk.CounterResult) error { return nil }); err == nil {
		t.Fatal("zero command bound")
	}
	if _, err := BindAttempt(f.command, nil); err == nil {
		t.Fatal("missing original receipt writer bound")
	}
	for _, which := range []string{"journal_validate", "native_validate", "native_check", "replay_invalid", "foreign_attempt", "bad_native_result"} {
		t.Run(which, func(t *testing.T) {
			f, s := newFixture(t, "committed", false)
			switch which {
			case "journal_validate":
				s.state.journal.state.validate = func(risk.CounterCommand) error { return risk.ErrInvalidCounterCommand }
			case "native_validate":
				s.state.native.state.validate = func(risk.CounterCommand) error { return risk.ErrInvalidCounterCommand }
			case "native_check":
				s.state.native.state.check = func(context.Context, risk.CounterCommand) error { return risk.ErrVelocityRecoveryUnavailable }
			case "replay_invalid":
				f.pending = true
				s.state.journal.state.replay = func(context.Context, risk.CounterCommand) (risk.CounterResult, error) {
					return risk.CounterResult{}, nil
				}
			case "foreign_attempt":
				s.state.journal.state.record = func(context.Context, risk.CounterCommand) (Attempt, error) { return Attempt{&attempt{}}, nil }
			case "bad_native_result":
				s.state.native.state.mutate = func(context.Context, risk.CounterCommand) (risk.CounterResult, error) {
					return risk.CounterResult{}, nil
				}
			}
			result, err := s.Mutate(context.Background(), f.command)
			if err == nil {
				t.Fatal("invalid owned boundary admitted")
			}
			if which == "bad_native_result" {
				if outcome, _, err := result.Declaration(f.command); err != nil || outcome != risk.CounterUnknown {
					t.Fatal("invalid reply became noncommit", err)
				}
			}
			if f.writes != 0 {
				t.Fatal("invalid boundary wrote native counters")
			}
		})
	}
}

func TestStoreCurrentChecksCannotIgnoreCancellation(t *testing.T) {
	f, s := newFixture(t, "committed", false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.state.native.state.check = func(context.Context, risk.CounterCommand) error { cancel(); return nil }
	if _, err := s.Mutate(ctx, f.command); !errors.Is(err, context.Canceled) {
		t.Fatal("late cancellation admitted", err)
	}
	if f.pending || f.writes != 0 {
		t.Fatal("late cancellation reached mutation")
	}
}

func TestStoreIntentDoesNotFreezeCurrentEligibility(t *testing.T) {
	f, s := newFixture(t, "committed", false)
	record := s.state.journal.state.record
	s.state.journal.state.record = func(ctx context.Context, c risk.CounterCommand) (Attempt, error) {
		a, err := record(ctx, c)
		f.mu.Lock()
		f.healthy = false
		f.mu.Unlock()
		return a, err
	}
	if _, err := s.Mutate(context.Background(), f.command); err == nil {
		t.Fatal("intent admission cached earlier eligibility")
	}
	if !f.pending || f.writes != 0 {
		t.Fatal("later eligibility loss dispatched or erased intent")
	}
	f, s = newFixture(t, "committed", false)
	s.state.timeout = time.Nanosecond
	if _, err := s.Mutate(context.Background(), f.command); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("expired crossing bound admitted", err)
	}
	if f.pending || f.writes != 0 {
		t.Fatal("expired bound reached adapters")
	}
}

func TestStoreConnectionsCannotSerializeOrExposeBindings(t *testing.T) {
	f, s := newFixture(t, "committed", false)
	a, err := BindAttempt(f.command, func(context.Context, risk.CounterResult) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []interface {
		MarshalJSON() ([]byte, error)
		MarshalText() ([]byte, error)
	}{s, s.state.journal, s.state.native, a} {
		if b, e := value.MarshalJSON(); b != nil || !errors.Is(e, risk.ErrSensitiveSerialization) {
			t.Fatal("JSON exported custody", e)
		}
		if b, e := value.MarshalText(); b != nil || !errors.Is(e, risk.ErrSensitiveSerialization) {
			t.Fatal("text exported custody", e)
		}
		if got := fmt.Sprintf("%+v", value); got != "velocity.connection(redacted)" {
			t.Fatal("formatter exposed binding")
		}
	}
}
