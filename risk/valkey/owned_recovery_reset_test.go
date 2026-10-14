package valkey

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/faustbrian/go-identity/risk"
)

func TestOwnedRecoveryLostLiveFenceCannotResumeOrReinstall(t *testing.T) {
	for _, flush := range []bool{false, true} {
		t.Run(strconv.FormatBool(flush), func(t *testing.T) {
			layout, plan, lease, history, _, reader, native, _ := ownedHistoryFixture(t)
			facts, err := reader.History(context.Background(), lease, history)
			if err != nil {
				t.Fatal(err)
			}
			db := newScriptDB()
			db.now = facts.PreparedAt.UnixMicro()
			transport, _ := nativeFixture(t, func(request []string) string {
				n, err := strconv.Atoi(request[2])
				if err != nil {
					return "-invalid\r\n"
				}
				reply, err := db.executeScript(request[1], request[3:3+n], request[3+n:])
				if err != nil {
					return "-invalid\r\n"
				}
				return nativeArray(reply)
			})
			owner, err := newOwnedRecovery(layout, transport, native)
			if err != nil {
				t.Fatal(err)
			}
			if err := owner.fence(context.Background(), lease, risk.VelocityLease{}); err != nil {
				t.Fatal("initial fence failed", err)
			}
			if _, err := owner.restore(context.Background(), lease, history); err != nil {
				t.Fatal("initial recovery failed", err)
			}
			// An unchanged server boot/profile does not attest this disappeared
			// live fence. Continuing the old traversal could lose earlier counters.
			if flush {
				clear(db.strings)
				clear(db.expiry)
			} else {
				delete(db.strings, plan.keys[0])
				delete(db.expiry, plan.keys[0])
			}
			before, expiry, writes := cloneScriptStrings(db.strings), cloneScriptExpiry(db.expiry), db.writes
			ack, err := owner.restore(context.Background(), lease, history)
			if err == nil || ack != (risk.VelocityAcknowledgement{}) {
				t.Fatal("lost live recovery fence allowed old traversal to continue")
			}
			if db.writes != writes || !reflect.DeepEqual(before, db.strings) || !reflect.DeepEqual(expiry, db.expiry) {
				t.Fatal("lost live recovery fence was repaired or counters changed")
			}
		})
	}
}

func TestOwnedRecoveryFenceRejectsInvalidCustodyBeforeIO(t *testing.T) {
	layout, _, lease, _, journal, reader, native, _ := ownedHistoryFixture(t)
	transport, fixture := nativeFixture(t, func([]string) string { return "-unexpected\r\n" })
	owner, err := newOwnedRecovery(layout, transport, native)
	if err != nil {
		t.Fatal(err)
	}
	lb, err := reader.Lease(lease)
	if err != nil {
		t.Fatal(err)
	}
	foreignIssuer, _, _, _ := risk.NewVelocityRecoveryAuthorities()
	foreign, err := foreignIssuer.Lease(lb, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	lb.Tenant = "another-tenant"
	crossTenant, err := journal.Lease(lb, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	otherNamespace, err := risk.NewVelocityReplayIdentity("another-namespace", layout.secret)
	if err != nil {
		t.Fatal(err)
	}
	wrong := owner
	wrong.layout.replay = otherNamespace
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		owner           ownedRecovery
		ctx             context.Context
		lease, previous risk.VelocityLease
	}{
		{owner, nil, lease, risk.VelocityLease{}},
		{owner, canceled, lease, risk.VelocityLease{}},
		{ownedRecovery{}, context.Background(), lease, risk.VelocityLease{}},
		{owner, context.Background(), risk.VelocityLease{}, risk.VelocityLease{}},
		{owner, context.Background(), foreign, risk.VelocityLease{}},
		{wrong, context.Background(), lease, risk.VelocityLease{}},
		{owner, context.Background(), lease, foreign},
		{owner, context.Background(), lease, crossTenant},
	} {
		if err := tc.owner.fence(tc.ctx, tc.lease, tc.previous); err == nil {
			t.Fatal("invalid fence initialization admitted")
		}
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if len(fixture.requests) != 0 || fixture.dials != 0 {
		t.Fatal("invalid fence initialization reached native IO")
	}
}

func TestOwnedRecoveryFencePostEffectPrimaryLossCannotSucceed(t *testing.T) {
	layout, plan, original, _, journal, reader, native, _ := ownedHistoryFixture(t)
	lb, err := reader.Lease(original)
	if err != nil {
		t.Fatal(err)
	}
	var lost atomic.Bool
	lease, err := journal.Lease(lb, func(context.Context) error {
		if lost.Load() {
			return errors.New("primary authority unavailable")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	db := newScriptDB()
	transport, fixture := nativeFixture(t, func(request []string) string {
		n, err := strconv.Atoi(request[2])
		if err != nil {
			return "-invalid\r\n"
		}
		reply, err := db.executeScript(request[1], request[3:3+n], request[3+n:])
		if err != nil {
			return "-invalid\r\n"
		}
		lost.Store(true)
		return nativeArray(reply)
	})
	owner, err := newOwnedRecovery(layout, transport, native)
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.fence(context.Background(), lease, risk.VelocityLease{}); err == nil {
		t.Fatal("post-effect primary loss granted successful initialization")
	}
	if _, ok := db.strings[plan.keys[0]]; !ok || db.writes != 1 {
		t.Fatal("admission failure erased acknowledged fence effect")
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if len(fixture.requests) != 1 {
		t.Fatal("initialization implicitly retried")
	}
}
