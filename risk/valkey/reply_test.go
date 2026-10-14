package valkey

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/risk"
)

func TestMutationReplyPreservesPostStateAndRejectsPartialTruth(t *testing.T) {
	_, _, c := commandFixture(t, 9)
	command := prepareFixture(t, c, "tenant", "attempt", "192.0.2.1")
	b := command.Bindings()
	observed := b.PreparedAt.Add(-time.Second)
	reply := []string{"committed", b.Fingerprint, strconv.FormatInt(observed.UnixMicro(), 10)}
	for _, target := range b.Targets {
		reply = append(reply, string(target.Dimension), "11", strconv.FormatInt(observed.Add(-time.Second).UnixMicro(), 10), strconv.FormatInt(observed.Add(5*time.Minute-time.Second).UnixMicro(), 10))
	}
	_, err := decodeMutationReply(command, reply)
	if err != nil {
		t.Fatal(err)
	}
	// The result is opaque; inspect it through the original coordinator, which
	// grants no signal for a foreign command. Rebuild dispatch with one callback.
	p, keys, _ := commandFixture(t, 9)
	var returned risk.CounterResult
	coordinator, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: p, Keys: keys, Store: replyStoreFunc(func(_ context.Context, c risk.CounterCommand) (risk.CounterResult, error) {
		r := append([]string(nil), reply...)
		r[1] = c.Bindings().Fingerprint
		returned, err = decodeMutationReply(c, r)
		return returned, err
	}), Clock: func() time.Time { return b.PreparedAt }, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	evaluation, err := coordinator.Mutate(context.Background(), prepareFixture(t, coordinator, "tenant", "attempt", "192.0.2.1"))
	if err != nil || evaluation.Outcome != risk.CounterCommitted || evaluation.Signal.State != risk.SignalThrottle || !evaluation.Signal.ObservedAt.Equal(observed) || evaluation.Signal.RetryAfter != 5*time.Minute-2*time.Second {
		t.Fatal("post-state or original observation lost", err)
	}
	for _, change := range []func([]string) []string{
		func(r []string) []string { return r[:len(r)-1] },
		func(r []string) []string { return append(r, "extra") },
		func(r []string) []string { r[1] = strings.Repeat("b", 64); return r },
		func(r []string) []string { r[2] = "01"; return r },
		func(r []string) []string { r[4] = "9007199254740992"; return r },
		func(r []string) []string { r[4] = "-1"; return r },
		func(r []string) []string { r[3] = r[7]; return r },
		func(r []string) []string { r[5] = r[6]; return r },
		func(r []string) []string { r[5] = r[2] + "0"; return r },
		func(r []string) []string { r[0] = "not_committed"; return r },
	} {
		if _, err = decodeMutationReply(command, change(append([]string(nil), reply...))); !errors.Is(err, ErrOutcomeUnknown) {
			t.Fatal("partial or malformed reply accepted")
		}
	}
	for _, status := range []string{"not_committed", "unknown"} {
		_, err = decodeMutationReply(command, []string{status, b.Fingerprint})
		if status == "unknown" && !errors.Is(err, ErrOutcomeUnknown) || status == "not_committed" && err != nil {
			t.Fatal("classification lost")
		}
	}
}

type replyStoreFunc func(context.Context, risk.CounterCommand) (risk.CounterResult, error)

func (f replyStoreFunc) Mutate(ctx context.Context, c risk.CounterCommand) (risk.CounterResult, error) {
	return f(ctx, c)
}

func TestReplyClassificationCannotFabricateCleanAdmission(t *testing.T) {
	for _, tc := range []struct {
		status  string
		extra   bool
		outcome risk.CounterOutcome
	}{
		{"not_committed", false, risk.CounterNotCommitted},
		{"unknown", false, risk.CounterUnknown},
		{"not_committed", true, risk.CounterUnknown},
		{"committed", false, risk.CounterUnknown},
	} {
		t.Run(tc.status+strconv.FormatBool(tc.extra), func(t *testing.T) {
			p, keys, _ := commandFixture(t, 9)
			now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
			c, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: p, Keys: keys, Store: replyStoreFunc(func(_ context.Context, command risk.CounterCommand) (risk.CounterResult, error) {
				reply := []string{tc.status, command.Bindings().Fingerprint}
				if tc.extra {
					reply = append(reply, "unexpected")
				}
				return decodeMutationReply(command, reply)
			}), Clock: func() time.Time { return now }, Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			got, err := c.Mutate(context.Background(), prepareFixture(t, c, "tenant", "attempt", "192.0.2.1"))
			if err != nil || got.Outcome != tc.outcome || got.Signal.State != risk.SignalUnavailable || !got.Signal.ObservedAt.IsZero() || !got.Signal.ExpiresAt.IsZero() || got.Signal.RetryAfter != 0 {
				t.Fatal("unknown/noncommit fabricated admission", err)
			}
		})
	}
}
