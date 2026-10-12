package mfa

import "time"

// totpMatchingStep checks a bounded window without early success or replay exits.
// compare is the native owner's constant-time opaque-code digest comparison;
// candidates are borrowed for that call only and cleared immediately afterward.
// No secret, candidate or callback is retained. The decrypted factor secret is
// borrowed from the native owner's encrypted custody and remains its to clear.
// A matching step is metadata, NOT authentication authority: the owner must
// atomically advance the persisted last step, consume the continuation and
// enforce its shared attempt budget in the protected session transaction.
func totpMatchingStep(secret []byte, algorithm string, digits uint32, period time.Duration, skew uint32, now time.Time, lastStep uint64, hasLastStep bool, compare func([]byte) bool) (uint64, bool) {
	if period < 15*time.Second || period > 120*time.Second || period%time.Second != 0 || skew > 2 || now.IsZero() || now.Unix() < 0 || compare == nil {
		return 0, false
	}
	center := uint64(now.Unix() / int64(period/time.Second))
	lower := uint64(0)
	if center > uint64(skew) {
		lower = center - uint64(skew)
	}
	// center is bounded by nonnegative int64 Unix seconds divided by >=15;
	// adding the at-most-two-step skew cannot overflow uint64.
	upper := center + uint64(skew)
	var selected uint64
	matched, replayed := false, false
	for step := lower; step <= upper; step++ {
		code, valid := totpCode(secret, algorithm, digits, step)
		if !valid {
			return 0, false
		}
		equal := compare(code)
		clear(code)
		if equal {
			if hasLastStep && step <= lastStep {
				replayed = true
			} else if !matched {
				selected, matched = step, true
			}
		}
	}
	// A rare collision must not let a code already used at an earlier step
	// masquerade as a new one elsewhere in the same permitted window.
	if !matched || replayed {
		return 0, false
	}
	return selected, true
}
