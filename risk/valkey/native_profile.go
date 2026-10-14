package valkey

import (
	_ "embed"
	"errors"
	"strconv"
	"strings"
)

//go:embed native_profile.lua
var nativeProfileScript string

// This error accompanies an attributable acknowledgement when a subsequent
// read loses continuity. It denies admission without erasing committed truth.
var errNativeContinuity = errors.New("risk/valkey: native continuity unavailable")

// checkProfile reads on the already owned, bounded connection. The transport
// synchronization owner freezes the first eligible boot/eviction tuple; neither
// a reconnect nor a later successful read may replace it. No lock spans IO.
// This is not a proof against selective deletion, flush/fence reinstatement or
// loss between reads. Joint primary eligibility remains required for activation.
func (t *nativeTransport) checkProfile(cell *nativeConnection) error {
	t.mu.Lock()
	lost := t.continuityLost
	t.mu.Unlock()
	if lost {
		return errNativeContinuity
	}
	values, err := cell.eval(nativeProfileScript, nil, nil)
	if err != nil || len(values) != 2 || !lowerHex(values[0], 40) || values[0] == strings.Repeat("0", 40) {
		return t.loseContinuity()
	}
	evictions, err := strconv.ParseUint(values[1], 10, 64)
	if err != nil || strconv.FormatUint(evictions, 10) != values[1] {
		return t.loseContinuity()
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.continuityLost {
		return errNativeContinuity
	}
	if t.boot == "" {
		t.boot, t.evictions = values[0], evictions
	}
	if t.boot != values[0] || t.evictions != evictions {
		t.continuityLost = true
		return errNativeContinuity
	}
	return nil
}

// An uncertain profile after baseline acquisition cannot be healed merely by
// old metadata reappearing: replica/configuration changes can have lost state.
// A new concrete recovery owner is required; this transport never rebinds.
func (t *nativeTransport) loseContinuity() error {
	t.mu.Lock()
	if t.boot != "" {
		t.continuityLost = true
	}
	t.mu.Unlock()
	return errNativeContinuity
}
