package valkey

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNativeTransportRetainsOriginalBootAndEvictionBaseline(t *testing.T) {
	for _, changed := range []string{"boot", "evictions", "unavailable"} {
		t.Run(changed, func(t *testing.T) {
			plan, _, _ := nativePlan(t)
			transport, fixture := nativeFixture(t, func([]string) string { return nativeArray([]string{"unavailable", plan.fingerprint}) })
			var lost atomic.Bool
			fixture.profileReply = func() string {
				if lost.Load() {
					switch changed {
					case "boot":
						return nativeArray([]string{strings.Repeat("c", 40), "0"})
					case "evictions":
						return nativeArray([]string{strings.Repeat("b", 40), "1"})
					default:
						return nativeArray([]string{"unavailable", ""})
					}
				}
				return nativeArray([]string{strings.Repeat("b", 40), "0"})
			}
			if _, err := transport.execute(context.Background(), plan); err != nil {
				t.Fatal("original native profile denied", err)
			}
			lost.Store(true)
			for range 2 {
				if _, err := transport.execute(context.Background(), plan); err == nil {
					t.Fatal("changed native continuity admitted")
				}
			}
			lost.Store(false)
			if _, err := transport.execute(context.Background(), plan); err == nil {
				t.Fatal("lost continuity resurrected when old metadata returned")
			}
			fixture.mu.Lock()
			defer fixture.mu.Unlock()
			if len(fixture.requests) != 1 {
				t.Fatal("continuity loss reached mutation or rebound baseline")
			}
		})
	}
}

func TestNativeObservedContinuityLossDuringCleanupDeniesEarlierAck(t *testing.T) {
	plan, _, _ := nativePlan(t)
	transport, fixture := nativeFixture(t, func([]string) string { return nativeArray([]string{"committed", plan.fingerprint}) })
	transport.config.timeout = 2 * time.Second
	var lost atomic.Bool
	fixture.profileReply = func() string {
		if lost.Load() {
			return nativeArray([]string{strings.Repeat("c", 40), "0"})
		}
		return nativeArray([]string{strings.Repeat("b", 40), "0"})
	}
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	gate := &firstNativeCleanupGate{Context: transport.lifetime, entered: make(chan struct{}), release: release}
	transport.lifetime = gate
	type result struct {
		reply []string
		err   error
	}
	done := make(chan result, 1)
	go func() { reply, err := transport.execute(context.Background(), plan); done <- result{reply, err} }()
	select {
	case <-gate.entered:
	case <-time.After(time.Second):
		unblock()
		<-done
		t.Fatal("earlier acknowledgement did not reach cleanup")
	}
	lost.Store(true)
	if _, err := transport.execute(context.Background(), plan); err == nil {
		unblock()
		<-done
		t.Fatal("concurrent boot loss admitted")
	}
	unblock()
	r := <-done
	if r.err == nil || len(r.reply) != 2 || r.reply[0] != "committed" {
		t.Fatal("observed loss granted late admission or erased ack", r.err)
	}
}

// Only the first cleanup is gated; independent concurrent operations must still
// be able to publish observed continuity loss and finish their own callbacks.
type firstNativeCleanupGate struct {
	context.Context
	entered chan struct{}
	release <-chan struct{}
	blocked atomic.Bool
}

func (*firstNativeCleanupGate) Value(any) any { return nil }
func (g *firstNativeCleanupGate) AfterFunc(f func()) func() bool {
	stop := context.AfterFunc(g.Context, f)
	return func() bool {
		if g.blocked.CompareAndSwap(false, true) {
			close(g.entered)
			<-g.release
		}
		return stop()
	}
}

func TestNativeProfileScriptClosedServerFacts(t *testing.T) {
	base := "# Server\r\nrun_id:" + strings.Repeat("b", 40) + "\r\n# Memory\r\nmaxmemory_policy:noeviction\r\n# Replication\r\nrole:master\r\nconnected_slaves:0\r\n# Stats\r\nevicted_keys:0\r\n"
	for _, tc := range []struct {
		name, info string
		valid      bool
	}{
		{"valid", base, true},
		{"max_counter", strings.Replace(base, "evicted_keys:0", "evicted_keys:18446744073709551615", 1), true},
		{"evicting", strings.Replace(base, "noeviction", "allkeys-lru", 1), false},
		{"replica", strings.Replace(base, "role:master", "role:slave", 1), false},
		{"replicated", strings.Replace(base, "connected_slaves:0", "connected_slaves:1", 1), false},
		{"missing", strings.Replace(base, "evicted_keys:0\r\n", "", 1), false},
		{"duplicate", base + "run_id:" + strings.Repeat("b", 40) + "\r\n", false},
		{"zero_boot", strings.Replace(base, strings.Repeat("b", 40), strings.Repeat("0", 40), 1), false},
		{"upper_boot", strings.Replace(base, strings.Repeat("b", 40), strings.Repeat("B", 40), 1), false},
		{"leading_zero", strings.Replace(base, "evicted_keys:0", "evicted_keys:00", 1), false},
		{"overflow", strings.Replace(base, "evicted_keys:0", "evicted_keys:18446744073709551616", 1), false},
		{"oversized", base + strings.Repeat("x", 16385), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := newScriptDB()
			db.info = tc.info
			reply := runRecoveryScript(t, db, nativeProfileScript, nil, nil)
			if (reply[0] != "unavailable") != tc.valid || db.writes != 0 {
				t.Fatal("invalid server profile accepted or mutated")
			}
		})
	}
}

func TestNativeProfileDeadlineAfterEffectPreservesContext(t *testing.T) {
	plan, _, _ := nativePlan(t)
	transport, fixture := nativeFixture(t, func([]string) string { return nativeArray([]string{"committed", plan.fingerprint}) })
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	var calls atomic.Int32
	fixture.profileReply = func() string {
		if calls.Add(1) == 2 {
			<-ctx.Done()
			return ""
		}
		return nativeArray([]string{strings.Repeat("b", 40), "0"})
	}
	reply, err := transport.execute(ctx, plan)
	if !errors.Is(err, context.DeadlineExceeded) || len(reply) != 2 || reply[0] != "committed" {
		t.Fatal("post-effect profile deadline erased context or acknowledgement", err)
	}
}
