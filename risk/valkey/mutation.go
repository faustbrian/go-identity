package valkey

import (
	_ "embed"
	"strconv"
	"strings"
	"time"

	"github.com/faustbrian/go-identity/risk"
)

// mutationScript runs only on the native server. Tests execute these exact
// bytes in a Lua 5.1 VM with the Redis IO boundary replaced, not another engine.
//
//go:embed mutation.lua
var mutationScriptBody string

var mutationScript = publicationProfileScript + mutationScriptBody

// Fixed tenant/epoch capacity slots have atomic expiry. Probe exhaustion rejects
// before debit; it never saturates logical counts or evicts admissible replay.
const maximumReplayEntries = 4096
const capacityProbeCount = 8

func mutationArguments(p commandPlan) ([]string, error) {
	args, err := commandArguments(p)
	if err != nil {
		return nil, err
	}
	// Only an independently retained exact marker may authorize the atomic
	// engine. Its remaining canonical fields are checked by the server parser.
	if len(p.expected) > 384 || !strings.HasPrefix(p.expected, "confirmed|"+p.epoch+"|") {
		return nil, risk.ErrInvalidCounterCommand
	}
	return append(args, p.expected), nil
}

// Recovery validates the same bounded command layout without granting debit
// authority: its own exact replay fence replaces the healthy admission marker.
func commandArguments(p commandPlan) ([]string, error) {
	if !lowerHex(p.epoch, 32) || !lowerHex(p.fingerprint, 64) || !lowerHex(p.slot, 64) || p.window <= 0 || p.window > time.Hour || p.window%time.Microsecond != 0 || len(p.targets) < 1 || len(p.targets) > 4 {
		return nil, risk.ErrInvalidCounterCommand
	}
	aliases := len(p.targets[0].Keys)
	if aliases < 1 || aliases > 4 || len(p.keys) != 2+capacityProbeCount+len(p.targets)*aliases {
		return nil, risk.ErrInvalidCounterCommand
	}
	seen := map[string]bool{}
	for _, key := range p.keys {
		if len(key) > 256 || !strings.HasPrefix(key, "irv2:{"+p.slot+"}:") || seen[key] {
			return nil, risk.ErrInvalidCounterCommand
		}
		seen[key] = true
	}
	args := []string{p.epoch, p.fingerprint, strconv.FormatInt(p.window.Microseconds(), 10), strconv.Itoa(len(p.targets)), strconv.Itoa(aliases)}
	for _, target := range p.targets {
		if len(target.Keys) != aliases || !boundedScope(string(target.Dimension)) || len(target.Dimension) > 64 || strings.Contains(string(target.Dimension), "|") {
			return nil, risk.ErrInvalidCounterCommand
		}
		args = append(args, string(target.Dimension))
	}
	return args, nil
}
