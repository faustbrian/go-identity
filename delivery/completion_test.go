package delivery

import (
	"bytes"
	"errors"
	"io"
	"math/big"
	"testing"
	"time"
)

func completionFixture() (completionInput, DeliveryResult) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	return completionInput{State: StateAttempting, Generation: 2, ExpectedGeneration: 2,
			AttemptNumber: 1, Now: now, ValidUntil: now.Add(time.Hour)},
		DeliveryResult{State: StateTransientFailure, ObservedAt: now}
}

func TestCompletionAdmitsOnlyAttributableRetry(t *testing.T) {
	in, result := completionFixture()
	plan, err := planCompletion(DefaultConfig(), in, result, bytes.NewReader(make([]byte, 64)))
	if err != nil || plan.State != StateRetryWait || plan.ErasePayload || plan.NextAttemptAt.Before(in.Now) || plan.NextAttemptAt.After(in.Now.Add(time.Second)) {
		t.Fatal("authoritative transient failure did not admit bounded retry")
	}
	result.RetryAfter = 90 * time.Second
	plan, err = planCompletion(DefaultConfig(), in, result, bytes.NewReader(make([]byte, 64)))
	if err != nil || !plan.NextAttemptAt.Equal(in.Now.Add(90*time.Second)) {
		t.Fatal("provider throttling floor was ignored")
	}
	for _, state := range []DeliveryState{StateOutcomeUnknown, StateAccepted, StateDelivered, StateRejected, StateBounced} {
		result.State, result.RetryAfter = state, 0
		plan, err = planCompletion(DefaultConfig(), in, result, nil)
		if err != nil || plan.State != state || !plan.NextAttemptAt.IsZero() {
			t.Fatal("non-transient evidence was rewritten or retried")
		}
		if plan.ErasePayload != (state == StateDelivered || state == StateRejected || state == StateBounced) {
			t.Fatal("payload erasure disagrees with terminal evidence")
		}
	}
}

func TestCompletionUnknownSurvivesExpiryCancellationAndExhaustion(t *testing.T) {
	in, result := completionFixture()
	in.CancelRequested, in.AttemptNumber, in.ValidUntil = true, 5, in.Now
	result.State = StateOutcomeUnknown
	plan, err := planCompletion(DefaultConfig(), in, result, nil)
	if err != nil || plan.State != StateOutcomeUnknown || !plan.ErasePayload || !plan.NextAttemptAt.IsZero() {
		t.Fatal("ambiguity became local terminal proof")
	}
}

func TestCompletionStopsKnownTransientEffects(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*completionInput, *DeliveryResult)
		want   DeliveryState
	}{
		{"cancel", func(in *completionInput, _ *DeliveryResult) { in.CancelRequested = true }, StateCancelled},
		{"expired", func(in *completionInput, _ *DeliveryResult) { in.ValidUntil = in.Now }, StateExpired},
		{"exhausted", func(in *completionInput, _ *DeliveryResult) { in.AttemptNumber = 5 }, StateExhausted},
		{"expires-before-retry", func(in *completionInput, r *DeliveryResult) {
			in.ValidUntil = in.Now.Add(time.Second)
			r.RetryAfter = time.Second
		}, StateExpired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, result := completionFixture()
			tc.change(&in, &result)
			plan, err := planCompletion(DefaultConfig(), in, result, bytes.NewReader(make([]byte, 64)))
			if err != nil || plan.State != tc.want || !plan.ErasePayload || !plan.NextAttemptAt.IsZero() {
				t.Fatal("known unsuccessful effect did not stop safely")
			}
		})
	}
}

func TestCompletionFencesStaleAndInvalidInputs(t *testing.T) {
	in, result := completionFixture()
	in.ExpectedGeneration++
	if _, err := planCompletion(DefaultConfig(), in, result, nil); !errors.Is(err, ErrConflict) {
		t.Fatal("stale completion was admitted")
	}
	for _, change := range []func(*completionInput){
		func(in *completionInput) { in.Generation = 0 },
		func(in *completionInput) { in.ExpectedGeneration = 0 },
		func(in *completionInput) { in.State = StateOutcomeUnknown },
		func(in *completionInput) { in.State = StateDelivered },
		func(in *completionInput) { in.AttemptNumber = 0 },
		func(in *completionInput) { in.AttemptNumber = 6 },
		func(in *completionInput) { in.Now = time.Time{} },
		func(in *completionInput) { in.ValidUntil = time.Time{} },
	} {
		in, result := completionFixture()
		change(&in)
		if _, err := planCompletion(DefaultConfig(), in, result, nil); !errors.Is(err, ErrInvalidInput) {
			t.Fatal("invalid completion was admitted")
		}
	}
	in, result = completionFixture()
	if _, err := planCompletion(DefaultConfig(), in, result, bytes.NewReader(nil)); !errors.Is(err, ErrUnavailable) {
		t.Fatal("entropy failure produced a retry schedule")
	}
	if _, err := planCompletion(Config{}, in, result, nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("invalid config admitted")
	}
	result.State = StateQueued
	if _, err := planCompletion(DefaultConfig(), in, result, nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("local state used as provider evidence")
	}
}

type countingEntropy struct {
	calls int
	fill  byte
}

type nonProgressEntropy struct{ calls int }

func (r *nonProgressEntropy) Read([]byte) (int, error) {
	r.calls++
	if r.calls == 1000 {
		return 0, io.ErrNoProgress
	}
	return 0, nil
}

func TestCompletionStopsNonProgressEntropyImmediately(t *testing.T) {
	in, result := completionFixture()
	entropy := &nonProgressEntropy{}
	if _, err := planCompletion(DefaultConfig(), in, result, entropy); !errors.Is(err, ErrUnavailable) || entropy.calls != 1 {
		t.Fatalf("non-progress entropy performed %d reads instead of failing closed", entropy.calls)
	}
}

func (r *countingEntropy) Read(p []byte) (int, error) {
	r.calls++
	if r.calls > 16 {
		return 0, io.ErrNoProgress
	}
	for i := range p {
		p[i] = r.fill
	}
	return len(p), nil
}

func TestCompletionUsesNextAttemptCeiling(t *testing.T) {
	for attempt := uint8(1); attempt < 5; attempt++ {
		in, result := completionFixture()
		in.AttemptNumber = attempt
		entropy := &countingEntropy{fill: 1}
		plan, err := planCompletion(DefaultConfig(), in, result, entropy)
		if err != nil || plan.State != StateRetryWait || entropy.calls == 0 || plan.NextAttemptAt.Sub(in.Now) > DefaultConfig().BackoffCeilings[attempt] {
			t.Fatal("retry used the wrong attempt ceiling")
		}
	}
}

func TestCompletionFullJitterEndpointsAndBoundedEntropy(t *testing.T) {
	in, result := completionFixture()
	for _, draw := range []time.Duration{0, time.Second} {
		data := make([]byte, len(big.NewInt(int64(time.Second)).Bytes()))
		big.NewInt(int64(draw)).FillBytes(data)
		plan, err := planCompletion(DefaultConfig(), in, result, bytes.NewReader(data))
		if err != nil || !plan.NextAttemptAt.Equal(in.Now.Add(draw)) {
			t.Fatal("inclusive full-jitter endpoint lost")
		}
	}
	// Rejected all-ones draws must exhaust the bounded reader, not loop forever.
	if _, err := planCompletion(DefaultConfig(), in, result, bytes.NewReader(bytes.Repeat([]byte{255}, 256))); !errors.Is(err, ErrUnavailable) {
		t.Fatal("unusable entropy did not fail closed")
	}
	if _, err := planCompletion(DefaultConfig(), in, result, nil); !errors.Is(err, ErrUnavailable) {
		t.Fatal("missing entropy admitted retry")
	}
	// A cancelled local request cannot rewrite provider acceptance as cancellation.
	in.CancelRequested = true
	result.State = StateAccepted
	plan, err := planCompletion(DefaultConfig(), in, result, nil)
	if err != nil || plan.State != StateAccepted || plan.ErasePayload {
		t.Fatal("cancellation overwrote provider evidence")
	}
}
