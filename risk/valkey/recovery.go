package valkey

import (
	"context"
	_ "embed"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/faustbrian/go-identity/risk"
)

// Recovery effects remain private until the journal-backed core owner can
// provide acknowledged history and complete publication. Fencing alone is
// neither applied progress nor health; it deliberately prevents debit.
//
//go:embed recovery_fence.lua
var recoveryFenceScript string

//go:embed recovery_replay.lua
var recoveryReplayScript string

// This bounded wire projection is private. A matching native marker proves
// only effect fencing; the primary journal must still authorize ownership.
func recoveryFenceFields(value, epoch string) ([]string, bool) {
	if len(value) > 128 {
		return nil, false
	}
	fields := strings.Split(value, "|")
	if len(fields) != 5 || fields[0] != "replaying" || fields[1] != epoch || !lowerHex(fields[1], 32) || fields[1] == strings.Repeat("0", 32) || !lowerHex(fields[3], 32) || fields[3] == strings.Repeat("0", 32) {
		return nil, false
	}
	generation, err := strconv.ParseUint(fields[2], 10, 64)
	if err != nil || generation == 0 || strconv.FormatUint(generation, 10) != fields[2] {
		return nil, false
	}
	expires, ok := parseWireInteger(fields[4])
	return fields, ok && expires > 0
}

func recoveryArguments(p commandPlan, marker string, snapshots []risk.Counter) ([]string, error) {
	if _, err := mutationArguments(p); err != nil {
		return nil, err
	}
	if _, ok := recoveryFenceFields(marker, p.epoch); !ok || len(snapshots) != len(p.targets) || len(snapshots) == 0 {
		return nil, risk.ErrInvalidCounterCommand
	}
	args := []string{marker, p.fingerprint, strconv.FormatInt(p.window.Microseconds(), 10), strconv.Itoa(len(p.targets)), strconv.Itoa(len(p.targets[0].Keys))}
	observed := snapshots[0].ObservedAt
	validTime := func(v time.Time) bool {
		return v.UnixMicro() > 0 && uint64(v.UnixMicro()) <= maximumExactInteger && v.Equal(time.UnixMicro(v.UnixMicro()))
	}
	if !validTime(observed) || uint64(observed.UnixMicro()) > maximumExactInteger-uint64(time.Hour.Microseconds()) {
		return nil, risk.ErrInvalidCounterCommand
	}
	args = append(args, strconv.FormatInt(observed.UnixMicro(), 10))
	for i, s := range snapshots {
		if s.Kind != string(p.targets[i].Dimension) || s.Value == 0 || s.Value > maximumExactInteger || !s.ObservedAt.Equal(observed) || !validTime(s.WindowStartedAt) || !validTime(s.WindowExpiresAt) || observed.Before(s.WindowStartedAt) || !observed.Before(s.WindowExpiresAt) || s.WindowExpiresAt.Sub(s.WindowStartedAt) != p.window {
			return nil, risk.ErrInvalidCounterCommand
		}
		args = append(args, s.Kind, strconv.FormatUint(s.Value, 10), strconv.FormatInt(s.WindowStartedAt.UnixMicro(), 10), strconv.FormatInt(s.WindowExpiresAt.UnixMicro(), 10))
	}
	return args, nil
}

func (t *nativeTransport) recoverFence(ctx context.Context, p commandPlan, previous, current string) error {
	if _, err := mutationArguments(p); err != nil {
		return err
	}
	if _, ok := recoveryFenceFields(current, p.epoch); !ok {
		return risk.ErrInvalidCounterCommand
	}
	if previous != "" {
		if len(previous) > 128 {
			return risk.ErrInvalidCounterCommand
		}
		fields := strings.Split(previous, "|")
		if len(fields) != 5 {
			return risk.ErrInvalidCounterCommand
		}
		if _, ok := recoveryFenceFields(previous, fields[1]); !ok {
			return risk.ErrInvalidCounterCommand
		}
	}
	reply, err := t.executeScript(ctx, recoveryFenceScript, p.keys[:1], []string{previous, current})
	return recoveryAcknowledgement(reply, err, "fenced", current)
}

func (t *nativeTransport) restore(ctx context.Context, p commandPlan, marker string, snapshots []risk.Counter) error {
	args, err := recoveryArguments(p, marker, snapshots)
	if err != nil {
		return err
	}
	reply, err := t.executeScript(ctx, recoveryReplayScript, p.keys, args)
	return recoveryAcknowledgement(reply, err, "restored", p.fingerprint)
}

// No recovery IO error authorizes progress or an automatic resend. Even an
// acknowledged effect arriving after the bound requires owning reconciliation.
func recoveryAcknowledgement(reply []string, err error, kind, binding string) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	if err != nil {
		return ErrOutcomeUnknown
	}
	if len(reply) == 2 && reply[0] == "unavailable" && reply[1] == "" {
		return ErrUnavailable
	}
	if len(reply) != 2 || reply[0] != kind || reply[1] != binding {
		return ErrOutcomeUnknown
	}
	return nil
}
