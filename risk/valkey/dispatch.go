package valkey

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/faustbrian/go-identity/risk"
)

// This adapter-owned seam is private: callers cannot inject an executor or
// choose an epoch to gain health authority. Public activation will require
// journal-fenced native health admission before entering this dispatch path.
type mutationDispatcher struct {
	layout  commandLayout
	timeout time.Duration
	execute func(context.Context, commandPlan) ([]string, error)
}

func (mutationDispatcher) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "valkey.mutationDispatcher(redacted)")
}
func (mutationDispatcher) MarshalJSON() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }
func (mutationDispatcher) MarshalText() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }

func (d mutationDispatcher) mutate(ctx context.Context, command risk.CounterCommand, epoch [16]byte, expected string) (risk.CounterResult, error) {
	if d.execute == nil || d.timeout < 100*time.Millisecond || d.timeout > 10*time.Second {
		return risk.CounterResult{}, risk.ErrInvalidPolicy
	}
	if ctx == nil {
		return risk.CounterResult{}, risk.ErrInvalidContext
	}
	if err := ctx.Err(); err != nil {
		return risk.CounterResult{}, err
	}
	plan, err := d.layout.prepare(command, epoch)
	if err != nil {
		return risk.CounterResult{}, err
	}
	plan.expected = expected
	if _, err := mutationArguments(plan); err != nil {
		return risk.CounterResult{}, err
	}
	bounded, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	// Cancellation racing preparation still precedes the external boundary.
	if err := bounded.Err(); err != nil {
		return risk.CounterResult{}, err
	}
	reply, err := d.execute(bounded, plan)
	if errors.Is(err, context.Canceled) {
		err = context.Canceled
	} else if errors.Is(err, context.DeadlineExceeded) {
		err = context.DeadlineExceeded
	} else if err != nil && !errors.Is(err, errNativeContinuity) {
		// Any transport error after dispatch can hide a committed mutation. Never
		// retain diagnostics, interpret it as noncommit or automatically resend.
		result, _ := risk.NewCounterResult(command, risk.CounterUnknown, nil)
		return result, ErrOutcomeUnknown
	}
	if len(reply) == 2 && reply[0] == "unavailable" && reply[1] == plan.fingerprint {
		// Only the script's complete no-write health rejection establishes this
		// declaration. Missing marker is not an empty window or clean signal.
		result, resultErr := risk.NewCounterResult(command, risk.CounterNotCommitted, nil)
		if resultErr != nil {
			return risk.CounterResult{}, ErrOutcomeUnknown
		}
		return result, ErrUnavailable
	}
	// Do not erase acknowledged commit truth if cancellation arrives after the
	// reply. The core retains committed outcome but refuses the stale signal.
	result, decodeErr := decodeMutationReply(command, reply)
	if decodeErr != nil {
		return result, decodeErr
	}
	// Native cancellation can be shorter than the outer dispatch deadline.
	// A complete reply still proves its outcome, never timely admission.
	if err != nil {
		return result, err
	}
	// The adapter may have a shorter bound than the coordinator. A late reply
	// proves commit truth, not timely admission, even if the caller is still live.
	if err := bounded.Err(); err != nil {
		return result, err
	}
	return result, nil
}
