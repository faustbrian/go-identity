package valkey

import (
	"errors"
	"strconv"
	"time"

	"github.com/faustbrian/go-identity/risk"
)

var (
	// ErrOutcomeUnknown means no complete attributable mutation acknowledgement
	// was received. It grants no retry or clean admission; the owning journal
	// must resolve the original attempt, never allocate a replacement debit.
	ErrOutcomeUnknown = errors.New("risk/valkey: outcome unknown")
	// ErrUnavailable identifies missing or unhealthy ephemeral state. It never
	// means counters were zero or durable lockout state was cleared.
	ErrUnavailable = errors.New("risk/valkey: unavailable")
)

// Lua numeric arithmetic is exact only through this bound. Refusing larger
// values is safer than accepting a rounded count or window as positive proof.
const maximumExactInteger uint64 = 1<<53 - 1

// This wire decoder deliberately samples no clock: replay must retain the
// original observed-at instant. The core separately checks freshness at use.
func decodeMutationReply(command risk.CounterCommand, reply []string) (risk.CounterResult, error) {
	unknown := func() (risk.CounterResult, error) {
		result, _ := risk.NewCounterResult(command, risk.CounterUnknown, nil)
		return result, ErrOutcomeUnknown
	}
	b := command.Bindings()
	if len(b.Targets) == 0 || len(b.Targets) > 4 || len(reply) < 2 || len(reply) > 19 {
		return unknown()
	}
	for _, field := range reply {
		if len(field) > 128 {
			return unknown()
		}
	}
	if reply[1] != b.Fingerprint {
		return unknown()
	}
	switch reply[0] {
	case "not_committed":
		if len(reply) != 2 {
			return unknown()
		}
		result, err := risk.NewCounterResult(command, risk.CounterNotCommitted, nil)
		if err != nil {
			return unknown()
		}
		return result, nil
	case "unknown":
		return unknown()
	case "committed":
		if len(reply) != 3+4*len(b.Targets) {
			return unknown()
		}
	default:
		return unknown()
	}
	observed, ok := parseWireTime(reply[2])
	if !ok {
		return unknown()
	}
	snapshot := make([]risk.Counter, 0, len(b.Targets))
	for i, target := range b.Targets {
		fields := reply[3+i*4 : 7+i*4]
		value, valueOK := parseWireInteger(fields[1])
		start, startOK := parseWireTime(fields[2])
		expires, expiresOK := parseWireTime(fields[3])
		if fields[0] != string(target.Dimension) || !valueOK || value == 0 || !startOK || !expiresOK || observed.Before(start) || !observed.Before(expires) || !expires.After(start) || expires.Sub(start) != b.Window {
			return unknown()
		}
		snapshot = append(snapshot, risk.Counter{Kind: fields[0], Value: value, ObservedAt: observed, WindowStartedAt: start, WindowExpiresAt: expires})
	}
	result, err := risk.NewCounterResult(command, risk.CounterCommitted, snapshot)
	if err != nil {
		return unknown()
	}
	return result, nil
}

func parseWireInteger(value string) (uint64, bool) {
	if len(value) < 1 || len(value) > 16 || len(value) > 1 && value[0] == '0' {
		return 0, false
	}
	for _, b := range []byte(value) {
		if b < '0' || b > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(value, 10, 64)
	return n, err == nil && n <= maximumExactInteger
}

func parseWireTime(value string) (time.Time, bool) {
	n, ok := parseWireInteger(value)
	if !ok {
		return time.Time{}, false
	}
	return time.UnixMicro(int64(n)).UTC(), true
}
