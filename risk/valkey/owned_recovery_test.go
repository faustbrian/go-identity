package valkey

import (
	"context"
	"errors"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/faustbrian/go-identity/risk"
)

func TestOwnedNativeRecoveryAcknowledgesOnlyExactEffect(t *testing.T) {
	layout, plan, lease, history, _, reader, native, configured := ownedHistoryFixture(t)
	db := newScriptDB()
	facts, err := reader.History(context.Background(), lease, history)
	if err != nil {
		t.Fatal(err)
	}
	db.now = facts.PreparedAt.UnixMicro()
	fail := false
	transport, fixture := nativeFixture(t, func(request []string) string {
		if fail {
			return nativeArray([]string{"unavailable", ""})
		}
		n, err := strconv.Atoi(request[2])
		if err != nil {
			return ""
		}
		reply, err := db.executeScript(request[1], request[3:3+n], request[3+n:])
		if err != nil {
			return "-script failure\r\n"
		}
		return nativeArray(reply)
	})
	owner, err := newOwnedRecovery(layout, transport, native)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, verifier := risk.NewVelocityRecoveryAuthorities()
	ack, err := owner.restore(context.Background(), lease, history, risk.VelocityLease{})
	if err != nil {
		t.Fatal("exact native effect not acknowledged", err)
	}
	if _, err := verifier.Applied(context.Background(), lease, ack); !errors.Is(err, risk.ErrInvalidVelocityRecovery) {
		t.Fatal("foreign graph admitted acknowledgement", err)
	}
	if got, err := configured.Applied(context.Background(), lease, ack); err != nil || got.ID != facts.ID || got.Position != facts.Position {
		t.Fatal("configured native acknowledgement lost original identity", err)
	}
	writes := db.writes
	if _, err := owner.restore(context.Background(), lease, history, risk.VelocityLease{}); err != nil || db.writes != writes {
		t.Fatal("duplicate restoration changed original state", err)
	}
	if _, ok := db.strings[plan.keys[1]]; !ok {
		t.Fatal("original replay not restored")
	}
	fail = true
	if ack, err := owner.restore(context.Background(), lease, history, risk.VelocityLease{}); err == nil || ack != (risk.VelocityAcknowledgement{}) {
		t.Fatal("failed native effect acknowledged")
	}
	fixture.mu.Lock()
	requests := len(fixture.requests)
	fixture.mu.Unlock()
	if requests != 5 {
		t.Fatal("hidden native resend", requests)
	}
}

func TestOwnedNativeRecoveryUnresolvedAndForeignNeverDispatch(t *testing.T) {
	layout, _, lease, history, issuer, reader, native, _ := ownedHistoryFixture(t)
	transport, fixture := nativeFixture(t, func([]string) string { return "" })
	owner, err := newOwnedRecovery(layout, transport, native)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := reader.History(context.Background(), lease, history)
	if err != nil {
		t.Fatal(err)
	}
	for _, outcome := range []risk.VelocityHistoryOutcome{risk.VelocityHistoryPending, risk.VelocityHistoryUnknown} {
		facts.Outcome, facts.Snapshot = outcome, nil
		h, err := issuer.History(lease, facts)
		if err != nil {
			t.Fatal(err)
		}
		if ack, err := owner.restore(context.Background(), lease, h, risk.VelocityLease{}); !errors.Is(err, ErrUnavailable) || ack != (risk.VelocityAcknowledgement{}) {
			t.Fatal("unresolved history dispatched", err)
		}
	}
	_, _, foreign, _ := risk.NewVelocityRecoveryAuthorities()
	wrong, err := newOwnedRecovery(layout, transport, foreign)
	if err != nil {
		t.Fatal(err)
	}
	if ack, err := wrong.restore(context.Background(), lease, history, risk.VelocityLease{}); !errors.Is(err, risk.ErrInvalidVelocityRecovery) || ack != (risk.VelocityAcknowledgement{}) {
		t.Fatal("foreign owner dispatched", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if ack, err := owner.restore(ctx, lease, history, risk.VelocityLease{}); !errors.Is(err, context.Canceled) || ack != (risk.VelocityAcknowledgement{}) {
		t.Fatal("cancelled owner dispatched", err)
	}
	fixture.mu.Lock()
	n := len(fixture.requests)
	fixture.mu.Unlock()
	if n != 0 {
		t.Fatal("rejected custody reached native IO", n)
	}
}

func TestOwnedNativeRecoveryAppliedEffectCannotOverrideFailure(t *testing.T) {
	for _, mode := range []string{"primary_loss", "wrong_ack", "expired"} {
		t.Run(mode, func(t *testing.T) {
			layout, plan, lease, history, issuer, reader, native, _ := ownedHistoryFixture(t)
			facts, err := reader.History(context.Background(), lease, history)
			if err != nil {
				t.Fatal(err)
			}
			lb, err := reader.Lease(lease)
			if err != nil {
				t.Fatal(err)
			}
			var lost atomic.Bool
			lease, err = issuer.Lease(lb, func(context.Context) error {
				if lost.Load() {
					return errors.New("primary unavailable")
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			history, err = issuer.History(lease, facts)
			if err != nil {
				t.Fatal(err)
			}
			db := newScriptDB()
			db.now = facts.PreparedAt.UnixMicro()
			if mode == "expired" {
				db.now = lb.ExpiresAt.UnixMicro()
			}
			transport, fixture := nativeFixture(t, func(request []string) string {
				n, err := strconv.Atoi(request[2])
				if err != nil {
					return ""
				}
				reply, err := db.executeScript(request[1], request[3:3+n], request[3+n:])
				if err != nil {
					return "-failure\r\n"
				}
				if request[1] == recoveryReplayScript {
					if mode == "primary_loss" {
						lost.Store(true)
					}
					if mode == "wrong_ack" {
						return nativeArray([]string{"restored", "wrong binding"})
					}
				}
				return nativeArray(reply)
			})
			owner, err := newOwnedRecovery(layout, transport, native)
			if err != nil {
				t.Fatal(err)
			}
			ack, err := owner.restore(context.Background(), lease, history, risk.VelocityLease{})
			if err == nil || ack != (risk.VelocityAcknowledgement{}) {
				t.Fatal("failed recovery exposed applied custody")
			}
			fixture.mu.Lock()
			n := len(fixture.requests)
			fixture.mu.Unlock()
			want := 2
			if mode == "expired" {
				want = 1
			}
			if n != want {
				t.Fatal("recovery implicitly resent", n)
			}
			_, applied := db.strings[plan.keys[1]]
			if applied != (mode != "expired") {
				t.Fatal("effect truth changed despite admission failure")
			}
		})
	}
}

func TestOwnedNativeNoncommitRejectsConflictingAttempt(t *testing.T) {
	for _, state := range []string{"", "pending", "committed", "corrupt", "probe"} {
		t.Run(state, func(t *testing.T) {
			layout, plan, lease, history, issuer, reader, native, verifier := ownedHistoryFixture(t)
			facts, err := reader.History(context.Background(), lease, history)
			if err != nil {
				t.Fatal(err)
			}
			facts.Outcome, facts.Snapshot = risk.VelocityHistoryNotCommitted, nil
			history, err = issuer.History(lease, facts)
			if err != nil {
				t.Fatal(err)
			}
			db := newScriptDB()
			db.now = facts.PreparedAt.UnixMicro()
			if state == "probe" {
				db.strings[plan.keys[2]] = plan.keys[1] + "|" + plan.fingerprint + "|" + strconv.FormatInt(db.now+1000000, 10)
			} else if state != "" {
				db.strings[plan.keys[1]] = plan.fingerprint + "|" + state
			}
			transport, _ := nativeFixture(t, func(request []string) string {
				n, err := strconv.Atoi(request[2])
				if err != nil {
					return ""
				}
				reply, err := db.executeScript(request[1], request[3:3+n], request[3+n:])
				if err != nil {
					return "-script failure\r\n"
				}
				return nativeArray(reply)
			})
			owner, err := newOwnedRecovery(layout, transport, native)
			if err != nil {
				t.Fatal(err)
			}
			ack, err := owner.restore(context.Background(), lease, history, risk.VelocityLease{})
			if state == "" {
				if err != nil {
					t.Fatal("proved native noncommit unavailable", err)
				}
				got, err := verifier.Applied(context.Background(), lease, ack)
				if err != nil || got.Outcome != risk.VelocityHistoryNotCommitted {
					t.Fatal("noncommit custody lost", err)
				}
			} else if err == nil || ack != (risk.VelocityAcknowledgement{}) {
				t.Fatal("conflicting native attempt acknowledged as noncommit", state)
			}
			for _, key := range plan.keys[10:] {
				if _, ok := db.strings[key]; ok {
					t.Fatal("noncommit debited a counter")
				}
			}
		})
	}
}
