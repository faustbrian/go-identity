package valkey

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/risk"
)

func TestNativeBareEpochCannotAuthorizeDebit(t *testing.T) {
	db := newScriptDB()
	p := scriptPlan(t, "bare-epoch", 9)
	db.strings[p.keys[0]] = p.epoch
	if got := db.run(t, p); got[0] != "unavailable" || db.writes != 0 {
		t.Fatal("bare epoch bypassed paired admission")
	}
}

func TestOwnedNativePublicationExactCutAndNoAdmission(t *testing.T) {
	layout, plan, lease, _, journal, reader, native, verifier := ownedHistoryFixture(t)
	lb, err := reader.Lease(lease)
	if err != nil {
		t.Fatal(err)
	}
	b := risk.VelocityClosureBinding{ID: [32]byte{7}, Position: 1, ReplayThrough: lb.ExpiresAt.Add(-time.Second), MaximumWindow: time.Hour}
	b.ReplayFrom, b.JournalStartedAt = b.ReplayThrough.Add(-time.Hour), b.ReplayThrough.Add(-time.Hour)
	closure, err := journal.Closure(lease, b, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	db := newScriptDB()
	db.now = b.ReplayThrough.UnixMicro() + 1
	marker, err := ownedRecoveryMarker(lb)
	if err != nil {
		t.Fatal(err)
	}
	db.strings[plan.keys[0]] = marker
	db.expiry[plan.keys[0]] = (lb.ExpiresAt.UnixMicro() + 999) / 1000
	db.strings[plan.keys[1]] = "retained original history"
	var scriptMu sync.Mutex
	transport, fixture := nativeFixture(t, func(request []string) string {
		scriptMu.Lock()
		defer scriptMu.Unlock()
		n, err := strconv.Atoi(request[2])
		if err != nil {
			return ""
		}
		reply, err := db.executeScript(request[1], request[3:3+n], request[3+n:])
		if err != nil {
			return "-failure\r\n"
		}
		return nativeArray(reply)
	})
	owner, err := newOwnedRecovery(layout, transport, native)
	if err != nil {
		t.Fatal(err)
	}
	publisher, ok := any(owner).(interface {
		publish(context.Context, risk.VelocityLease, risk.VelocityClosure) (risk.VelocityPublication, error)
	})
	if !ok {
		t.Fatal("native owner cannot publish covered primary cut")
	}
	before, expiry := cloneScriptStrings(db.strings), cloneScriptExpiry(db.expiry)
	ack, err := publisher.publish(context.Background(), lease, closure)
	if err != nil {
		t.Fatal("covered cut not published", err)
	}
	got, err := verifier.Publication(context.Background(), lease, closure, ack)
	if err != nil || got != b {
		t.Fatal("publication lost original cut", err)
	}
	state := db.strings[plan.keys[0]]
	if state == marker || state == plan.epoch || db.expiry[plan.keys[0]] != expiry[plan.keys[0]] || db.strings[plan.keys[1]] != before[plan.keys[1]] {
		t.Fatal("publication reset original fence/history")
	}
	writes := db.writes
	if _, err := publisher.publish(context.Background(), lease, closure); err != nil || db.writes != writes {
		t.Fatal("same cut retry changed native state", err)
	}
	if reply := db.run(t, plan); reply[0] != "unavailable" || db.writes != writes {
		t.Fatal("publication granted debit without primary confirmation")
	}
	results := make(chan error, 8)
	for range 8 {
		go func() {
			ack, err := publisher.publish(context.Background(), lease, closure)
			if err == nil {
				got, checkErr := verifier.Publication(context.Background(), lease, closure, ack)
				if checkErr != nil {
					err = checkErr
				} else if got != b {
					err = errors.New("concurrent publication changed cut")
				}
			}
			results <- err
		}()
	}
	for range 8 {
		if err := <-results; err != nil {
			t.Fatal("concurrent copied publication failed", err)
		}
	}
	if db.writes != writes {
		t.Fatal("concurrent idempotent publication rewrote state")
	}
	foreign, _, _, _ := risk.NewVelocityRecoveryAuthorities()
	fl, err := foreign.Lease(lb, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	fc, err := foreign.Closure(fl, b, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := journal.Lease(lb, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []struct {
		l risk.VelocityLease
		c risk.VelocityClosure
	}{{fl, fc}, {replacement, closure}, {lease, risk.VelocityClosure{}}} {
		if result, err := publisher.publish(context.Background(), bad.l, bad.c); err == nil || result != (risk.VelocityPublication{}) {
			t.Fatal("invalid custody published")
		}
	}
	fixture.mu.Lock()
	requests := len(fixture.requests)
	fixture.mu.Unlock()
	if requests != 10 {
		t.Fatal("invalid custody dispatched or publication resent", requests)
	}
	otherNamespace, err := risk.NewVelocityReplayIdentity("other-native-namespace", layout.secret)
	if err != nil {
		t.Fatal(err)
	}
	wrongOwner := owner
	wrongOwner.layout.replay = otherNamespace
	if ack, err := wrongOwner.publish(context.Background(), lease, closure); err == nil || ack != (risk.VelocityPublication{}) {
		t.Fatal("crossed namespace published")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if ack, err := owner.publish(canceled, lease, closure); !errors.Is(err, context.Canceled) || ack != (risk.VelocityPublication{}) {
		t.Fatal("canceled publication dispatched", err)
	}
	fixture.mu.Lock()
	requests = len(fixture.requests)
	fixture.mu.Unlock()
	if requests != 10 {
		t.Fatal("invalid scope/context reached native IO")
	}
}

func TestNativePublicationScriptBoundsAndOriginalExpiry(t *testing.T) {
	plan := scriptPlan(t, "publication-bounds", 9)
	baseDB := newScriptDB()
	candidate := strings.Replace(confirmedHealthFixture(plan, baseDB.now), "confirmed|", "published|", 1)
	fields := strings.Split(candidate, "|")
	original := "replaying|" + strings.Join(fields[1:5], "|")
	for _, mutate := range []func([]string){
		func(f []string) { f[0] = "confirmed" },
		func(f []string) { f[1] = strings.Repeat("0", 32) },
		func(f []string) { f[2] = "01" },
		func(f []string) { f[2] = "18446744073709551616" },
		func(f []string) { f[3] = strings.Repeat("0", 32) },
		func(f []string) { f[4] = "9007199254740992" },
		func(f []string) { f[5] = strings.Repeat("0", 64) },
		func(f []string) { f[6] = "-1" },
		func(f []string) { f[6] = "9223372036854775808" },
		func(f []string) { f[7] = strconv.FormatInt(baseDB.now-time.Hour.Microseconds(), 10) },
		func(f []string) { f[8] = f[4] },
		func(f []string) { f[9] = "0" },
		func(f []string) { f[10] = "3599999999" },
	} {
		db := newScriptDB()
		db.strings[plan.keys[0]] = original
		bad := append([]string(nil), fields...)
		mutate(bad)
		got := runRecoveryScript(t, db, publicationScript, plan.keys[:1], []string{original, strings.Join(bad, "|")})
		if got[0] != "unavailable" || db.writes != 0 {
			t.Fatal("malformed publication wrote state")
		}
	}
	for _, mode := range []string{"missing", "wrong_fence", "wrong_type", "different_cut", "max_position", "max_generation", "expiry_before", "expiry_equal", "expiry_after"} {
		t.Run(mode, func(t *testing.T) {
			db := newScriptDB()
			f := append([]string(nil), fields...)
			if mode == "max_position" {
				f[6] = "9223372036854775807"
			}
			if mode == "max_generation" {
				f[2] = "18446744073709551615"
			}
			if strings.HasPrefix(mode, "expiry_") {
				f[4] = strconv.FormatInt(db.now+1, 10)
				if mode == "expiry_equal" {
					db.now++
				}
				if mode == "expiry_after" {
					db.now += 2
				}
			}
			old := "replaying|" + strings.Join(f[1:5], "|")
			next := strings.Join(f, "|")
			db.strings[plan.keys[0]] = old
			switch mode {
			case "missing":
				delete(db.strings, plan.keys[0])
			case "wrong_fence":
				db.strings[plan.keys[0]] = original + "x"
			case "wrong_type":
				delete(db.strings, plan.keys[0])
				db.hashes[plan.keys[0]] = map[string]string{}
			case "different_cut":
				db.strings[plan.keys[0]] = strings.Replace(next, f[5], strings.Repeat("c", 64), 1)
			}
			got := runRecoveryScript(t, db, publicationScript, plan.keys[:1], []string{old, next})
			success := mode == "max_position" || mode == "max_generation" || mode == "expiry_before"
			if success {
				if got[0] != "published" || got[1] != f[5] || db.strings[plan.keys[0]] != next || db.writes != 1 {
					t.Fatal("bounded publication changed facts")
				}
			} else if got[0] != "unavailable" || db.writes != 0 {
				t.Fatal("lost/stale native fence published")
			}
		})
	}
	for _, args := range [][]string{nil, {original}, {original, candidate, "extra"}, {original, strings.Repeat("x", 385)}} {
		db := newScriptDB()
		db.strings[plan.keys[0]] = original
		if got := runRecoveryScript(t, db, publicationScript, plan.keys[:1], args); got[0] != "unavailable" || db.writes != 0 {
			t.Fatal("invalid argument shape published")
		}
	}
	db := newScriptDB()
	db.strings[plan.keys[0]] = confirmedHealthFixture(plan, db.now)
	f := strings.Split(db.strings[plan.keys[0]], "|")
	f[4] = strconv.FormatInt(db.now, 10)
	db.strings[plan.keys[0]] = strings.Join(f, "|")
	if got := db.run(t, plan); got[0] != "unavailable" || db.writes != 0 {
		t.Fatal("expired confirmed marker debited")
	}
}

func TestOwnedNativePublicationLatePrimaryLossAndAmbiguity(t *testing.T) {
	for _, mode := range []string{"lease_loss", "closure_loss", "wrong_ack", "socket_loss", "empty_cut"} {
		t.Run(mode, func(t *testing.T) {
			layout, plan, fixtureLease, _, journal, reader, native, _ := ownedHistoryFixture(t)
			lb, err := reader.Lease(fixtureLease)
			if err != nil {
				t.Fatal(err)
			}
			var leaseLost, closureLost atomic.Bool
			lease, err := journal.Lease(lb, func(context.Context) error {
				if leaseLost.Load() {
					return errors.New("primary loss")
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			b := risk.VelocityClosureBinding{ID: [32]byte{8}, Position: 1, ReplayThrough: lb.ExpiresAt.Add(-time.Second), MaximumWindow: time.Hour}
			if mode == "empty_cut" {
				b.Position = 0
			}
			b.ReplayFrom, b.JournalStartedAt = b.ReplayThrough.Add(-time.Hour), b.ReplayThrough.Add(-time.Hour)
			closure, err := journal.Closure(lease, b, func(context.Context) error {
				if closureLost.Load() {
					return errors.New("cut loss")
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			db := newScriptDB()
			db.now = b.ReplayThrough.UnixMicro() + 1
			marker, err := ownedRecoveryMarker(lb)
			if err != nil {
				t.Fatal(err)
			}
			db.strings[plan.keys[0]] = marker
			transport, fixture := nativeFixture(t, func(request []string) string {
				n, _ := strconv.Atoi(request[2])
				reply, err := db.executeScript(request[1], request[3:3+n], request[3+n:])
				if err != nil {
					return "-failure\r\n"
				}
				if mode == "lease_loss" {
					leaseLost.Store(true)
				}
				if mode == "closure_loss" {
					closureLost.Store(true)
				}
				if mode == "wrong_ack" {
					return nativeArray([]string{"published", "wrong cut"})
				}
				if mode == "socket_loss" {
					return ""
				}
				return nativeArray(reply)
			})
			owner, err := newOwnedRecovery(layout, transport, native)
			if err != nil {
				t.Fatal(err)
			}
			publisher, ok := any(owner).(interface {
				publish(context.Context, risk.VelocityLease, risk.VelocityClosure) (risk.VelocityPublication, error)
			})
			if !ok {
				t.Fatal("native owner cannot publish covered primary cut")
			}
			ack, err := publisher.publish(context.Background(), lease, closure)
			if mode == "empty_cut" {
				if err != nil || ack == (risk.VelocityPublication{}) {
					t.Fatal("covered empty cut denied", err)
				}
			} else if err == nil || ack != (risk.VelocityPublication{}) {
				t.Fatal("late/ambiguous effect granted publication", err)
			}
			if db.writes != 1 || db.strings[plan.keys[0]] == marker {
				t.Fatal("failed acknowledgement erased effect truth")
			}
			fixture.mu.Lock()
			requests := len(fixture.requests)
			fixture.mu.Unlock()
			if requests != 1 {
				t.Fatal("publication implicitly resent", requests)
			}
		})
	}
}
