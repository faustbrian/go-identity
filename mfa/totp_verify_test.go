package mfa

import (
	"bytes"
	"testing"
	"time"
)

func TestTOTPMatchingStepWindowAndReplay(t *testing.T) {
	key := []byte("12345678901234567890")
	now := time.Unix(1234567890, 0)
	center := uint64(now.Unix() / 30)
	for _, delta := range []int64{-2, -1, 0, 1, 2} {
		want := uint64(int64(center) + delta)
		code, _ := totpCode(key, "SHA1", 8, want)
		calls := 0
		var borrowed [][]byte
		compare := func(candidate []byte) bool {
			calls++
			borrowed = append(borrowed, candidate)
			return bytes.Equal(candidate, code)
		}
		step, ok := totpMatchingStep(key, "SHA1", 8, 30*time.Second, 2, now, 0, false, compare)
		if !ok || step != want || calls != 5 {
			t.Fatal("complete skew window was not verified")
		}
		for _, candidate := range borrowed {
			if !bytes.Equal(candidate, make([]byte, len(candidate))) {
				t.Fatal("transient candidate retained after comparison")
			}
		}
		_, ok = totpMatchingStep(key, "SHA1", 8, 30*time.Second, 2, now, want, true, compare)
		if ok {
			t.Fatal("already used moving factor accepted")
		}
		clear(code)
	}
}

func TestTOTPMatchingStepBounds(t *testing.T) {
	key := []byte("12345678901234567890")
	now := time.Unix(59, 0)
	for _, period := range []time.Duration{0, 14 * time.Second, 121 * time.Second, 30*time.Second + 1} {
		if _, ok := totpMatchingStep(key, "SHA1", 8, period, 0, now, 0, false, func([]byte) bool { t.Fatal("invalid profile compared"); return true }); ok {
			t.Fatal("invalid period accepted")
		}
	}
	for _, n := range []time.Time{time.Time{}, time.Unix(-1, 999999999)} {
		if _, ok := totpMatchingStep(key, "SHA1", 8, 30*time.Second, 0, n, 0, false, func([]byte) bool { t.Fatal("invalid time compared"); return true }); ok {
			t.Fatal("pre-epoch time accepted")
		}
	}
	if _, ok := totpMatchingStep(key, "SHA1", 8, 30*time.Second, 3, now, 0, false, func([]byte) bool { t.Fatal("unbounded skew compared"); return true }); ok {
		t.Fatal("unbounded skew accepted")
	}
	if _, ok := totpMatchingStep(key, "SHA1", 8, 30*time.Second, 0, now, 0, false, nil); ok {
		t.Fatal("missing comparison accepted")
	}
	for _, v := range []struct {
		secret    []byte
		algorithm string
		digits    uint32
	}{{nil, "SHA1", 8}, {make([]byte, 129), "SHA1", 8}, {key, "MD5", 8}, {key, "SHA1", 11}} {
		if _, ok := totpMatchingStep(v.secret, v.algorithm, v.digits, 30*time.Second, 0, now, 0, false, func([]byte) bool { t.Fatal("invalid factor profile compared"); return true }); ok {
			t.Fatal("invalid factor profile accepted")
		}
	}
	// Even the maximum Unix second has a bounded, non-overflowing window.
	callsAtLimit := 0
	if _, ok := totpMatchingStep(key, "SHA1", 8, 15*time.Second, 2, time.Unix(1<<63-1, 0), 0, false, func([]byte) bool { callsAtLimit++; return false }); ok || callsAtLimit != 5 {
		t.Fatal("maximum-time window overflowed or escaped its bound")
	}
	// An epoch counter is usable once; zero must not double as an unset marker.
	for _, used := range []bool{false, true} {
		calls := 0
		step, ok := totpMatchingStep(key, "SHA1", 8, 30*time.Second, 2, time.Unix(0, 0), 0, used, func([]byte) bool { calls++; return calls == 1 })
		if ok == used || step != 0 || calls != 3 {
			t.Fatal("epoch counter or clipped lower window invalid")
		}
	}
}

func TestTOTPMatchingStepDeniesCollisionAndMismatch(t *testing.T) {
	key := []byte("12345678901234567890")
	now := time.Unix(1234567890, 0)
	center := uint64(now.Unix() / 30)
	for _, compare := range []func([]byte) bool{func([]byte) bool { return false }, func([]byte) bool { return true }} {
		if _, ok := totpMatchingStep(key, "SHA1", 8, 30*time.Second, 2, now, center, true, compare); ok {
			t.Fatal("mismatch or collision with replayed counter accepted")
		}
	}
}
