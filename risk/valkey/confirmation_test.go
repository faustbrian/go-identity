package valkey

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/risk"
)

type confirmationFixture struct {
	owner        ownedRecovery
	plan         commandPlan
	lease        risk.VelocityLease
	closure      risk.VelocityClosure
	publication  risk.VelocityPublication
	confirmation risk.VelocityConfirmation
	journal      risk.VelocityJournalIssuer
	native       risk.VelocityNativeIssuer
	binding      risk.VelocityClosureBinding
	db           *scriptDB
	wire         *nativeWireFixture
	lost         [3]atomic.Bool
	mode         atomic.Int32
}

func newConfirmationFixture(t *testing.T, position int64) *confirmationFixture {
	t.Helper()
	layout, plan, original, _, journal, reader, native, _ := ownedHistoryFixture(t)
	f := &confirmationFixture{plan: plan, journal: journal, native: native, db: newScriptDB()}
	lb, err := reader.Lease(original)
	if err != nil {
		t.Fatal(err)
	}
	checker := func(index int) func(context.Context) error {
		return func(context.Context) error {
			if f.lost[index].Load() {
				return errors.New("private primary failure")
			}
			return nil
		}
	}
	f.lease, err = journal.Lease(lb, checker(0))
	if err != nil {
		t.Fatal(err)
	}
	f.binding = risk.VelocityClosureBinding{ID: [32]byte{9}, Position: position, ReplayThrough: lb.ExpiresAt.Add(-time.Second), MaximumWindow: time.Hour}
	f.binding.ReplayFrom, f.binding.JournalStartedAt = f.binding.ReplayThrough.Add(-time.Hour), f.binding.ReplayThrough.Add(-time.Hour)
	f.closure, err = journal.Closure(f.lease, f.binding, checker(1))
	if err != nil {
		t.Fatal(err)
	}
	f.db.now = f.binding.ReplayThrough.UnixMicro() + 1
	marker, err := ownedRecoveryMarker(lb)
	if err != nil {
		t.Fatal(err)
	}
	f.db.strings[plan.keys[0]] = marker
	f.db.expiry[plan.keys[0]] = (lb.ExpiresAt.UnixMicro() + 999) / 1000
	f.db.strings[plan.keys[1]] = "original replay"
	var mu sync.Mutex
	transport, wire := nativeFixture(t, func(request []string) string {
		mu.Lock()
		defer mu.Unlock()
		n, _ := strconv.Atoi(request[2])
		reply, err := f.db.executeScript(request[1], request[3:3+n], request[3+n:])
		if err != nil {
			return "-failure\r\n"
		}
		switch mode := f.mode.Load(); mode {
		case 1, 2, 3:
			f.lost[mode-1].Store(true)
		case 4:
			return nativeArray([]string{"confirmed", "wrong cut"})
		case 5:
			return ""
		case 6:
			return "-MOVED 1 127.0.0.1:1\r\n"
		case 7:
			return "-ASK 1 127.0.0.1:1\r\n"
		case 8:
			return "*2\r\n$9\r\nconfirmed\r\n"
		}
		return nativeArray(reply)
	})
	f.wire = wire
	f.owner, err = newOwnedRecovery(layout, transport, native)
	if err != nil {
		t.Fatal(err)
	}
	f.publication, err = f.owner.publish(context.Background(), f.lease, f.closure)
	if err != nil {
		t.Fatal(err)
	}
	// Primary recording is simulated at its deliberate core boundary. Real PG
	// export is separately tested; this fixture proves the concrete native IO.
	f.confirmation, err = journal.AcknowledgeConfirmation(context.Background(), f.lease, f.closure, f.publication, checker(2))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *confirmationFixture) confirm(t *testing.T, ctx context.Context) error {
	t.Helper()
	owner, ok := any(f.owner).(interface {
		confirm(context.Context, risk.VelocityLease, risk.VelocityClosure, risk.VelocityPublication, risk.VelocityConfirmation) error
	})
	if !ok {
		t.Fatal("native owner cannot confirm recorded primary publication")
	}
	return owner.confirm(ctx, f.lease, f.closure, f.publication, f.confirmation)
}

func TestOwnedNativeConfirmationExactOriginalState(t *testing.T) {
	for _, position := range []int64{0, 1} {
		t.Run(strconv.FormatInt(position, 10), func(t *testing.T) {
			f := newConfirmationFixture(t, position)
			before, expiry := cloneScriptStrings(f.db.strings), cloneScriptExpiry(f.db.expiry)
			writes := f.db.writes
			if err := f.confirm(t, context.Background()); err != nil {
				t.Fatal("exact primary confirmation denied", err)
			}
			expected := strings.Replace(before[f.plan.keys[0]], "published|", "confirmed|", 1)
			if f.db.strings[f.plan.keys[0]] != expected || f.db.writes != writes+1 {
				t.Fatal("confirmation changed original cut")
			}
			for key, value := range before {
				if key != f.plan.keys[0] && f.db.strings[key] != value {
					t.Fatal("confirmation changed counter/replay state")
				}
			}
			for key, value := range expiry {
				if f.db.expiry[key] != value {
					t.Fatal("confirmation renewed expiry")
				}
			}
			writes = f.db.writes
			if err := f.confirm(t, context.Background()); err != nil || f.db.writes != writes {
				t.Fatal("same exact retry rewrote marker", err)
			}
			results := make(chan error, 8)
			for range 8 {
				go func() { results <- f.confirm(t, context.Background()) }()
			}
			for range 8 {
				if err := <-results; err != nil {
					t.Fatal("concurrent confirmation failed", err)
				}
			}
			if f.db.writes != writes {
				t.Fatal("concurrent retry renewed native state")
			}
		})
	}
}

func TestOwnedNativeConfirmationPrimaryLoss(t *testing.T) {
	for index := range 3 {
		for _, after := range []bool{false, true} {
			t.Run(strconv.Itoa(index)+"/"+strconv.FormatBool(after), func(t *testing.T) {
				f := newConfirmationFixture(t, 1)
				before, writes := f.db.strings[f.plan.keys[0]], f.db.writes
				if after {
					f.mode.Store(int32(index + 1))
				} else {
					f.lost[index].Store(true)
				}
				if err := f.confirm(t, context.Background()); err == nil {
					t.Fatal("lost independent primary authority accepted")
				}
				f.wire.mu.Lock()
				requests := len(f.wire.requests)
				f.wire.mu.Unlock()
				if after {
					if requests != 2 || f.db.writes != writes+1 || f.db.strings[f.plan.keys[0]] != strings.Replace(before, "published|", "confirmed|", 1) {
						t.Fatal("post-effect failure lost effect truth or resent")
					}
				} else if requests != 1 || f.db.writes != writes || f.db.strings[f.plan.keys[0]] != before {
					t.Fatal("stale primary authority reached native IO")
				}
			})
		}
	}
}

func TestOwnedNativeConfirmationAmbiguousReply(t *testing.T) {
	for mode := int32(4); mode <= 8; mode++ {
		t.Run(strconv.Itoa(int(mode)), func(t *testing.T) {
			f := newConfirmationFixture(t, 1)
			before, writes := f.db.strings[f.plan.keys[0]], f.db.writes
			f.mode.Store(mode)
			if err := f.confirm(t, context.Background()); err == nil {
				t.Fatal("unattributable reply accepted")
			}
			f.wire.mu.Lock()
			requests := len(f.wire.requests)
			f.wire.mu.Unlock()
			if requests != 2 || f.db.writes != writes+1 || f.db.strings[f.plan.keys[0]] != strings.Replace(before, "published|", "confirmed|", 1) {
				t.Fatal("ambiguous reply caused resend or concealed effect")
			}
			f.mode.Store(0)
			if err := f.confirm(t, context.Background()); err != nil || f.db.writes != writes+1 {
				t.Fatal("explicit exact reconciliation renewed state", err)
			}
		})
	}
}

func TestOwnedNativeConfirmationRejectsMissingOrForeignMarker(t *testing.T) {
	for _, mode := range []string{"missing", "type", "oversized", "replaying", "bare", "foreign-cut", "foreign-confirmed"} {
		t.Run(mode, func(t *testing.T) {
			f := newConfirmationFixture(t, 1)
			key := f.plan.keys[0]
			switch mode {
			case "missing":
				delete(f.db.strings, key)
			case "type":
				delete(f.db.strings, key)
				f.db.hashes[key] = map[string]string{"foreign": "state"}
			case "oversized":
				f.db.strings[key] = strings.Repeat("x", 385)
			case "replaying":
				fields := strings.Split(f.db.strings[key], "|")
				f.db.strings[key] = "replaying|" + strings.Join(fields[1:5], "|")
			case "bare":
				f.db.strings[key] = f.plan.epoch
			default:
				fields := strings.Split(f.db.strings[key], "|")
				fields[5] = strings.Repeat("a", 64)
				if mode == "foreign-confirmed" {
					fields[0] = "confirmed"
				}
				f.db.strings[key] = strings.Join(fields, "|")
			}
			before, expiry, writes := cloneScriptStrings(f.db.strings), cloneScriptExpiry(f.db.expiry), f.db.writes
			if err := f.confirm(t, context.Background()); err == nil || f.db.writes != writes || !reflect.DeepEqual(before, f.db.strings) || !reflect.DeepEqual(expiry, f.db.expiry) {
				t.Fatal("invalid native marker repaired or accepted", err)
			}
		})
	}
}

func TestOwnedNativeConfirmationCanceledBeforeIO(t *testing.T) {
	f := newConfirmationFixture(t, 0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.confirm(t, ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
	f.wire.mu.Lock()
	defer f.wire.mu.Unlock()
	if len(f.wire.requests) != 1 {
		t.Fatal("canceled confirmation dispatched")
	}
}

func TestOwnedNativeConfirmationExactCustodyBeforeIO(t *testing.T) {
	f := newConfirmationFixture(t, 1)
	foreign := newConfirmationFixture(t, 1)
	for _, bad := range []struct {
		lease        risk.VelocityLease
		closure      risk.VelocityClosure
		publication  risk.VelocityPublication
		confirmation risk.VelocityConfirmation
	}{
		{risk.VelocityLease{}, f.closure, f.publication, f.confirmation},
		{f.lease, risk.VelocityClosure{}, f.publication, f.confirmation},
		{f.lease, f.closure, risk.VelocityPublication{}, f.confirmation},
		{f.lease, f.closure, f.publication, risk.VelocityConfirmation{}},
		{foreign.lease, foreign.closure, foreign.publication, foreign.confirmation},
		{f.lease, f.closure, f.publication, foreign.confirmation},
		{f.lease, f.closure, foreign.publication, f.confirmation},
	} {
		if err := f.owner.confirm(context.Background(), bad.lease, bad.closure, bad.publication, bad.confirmation); err == nil {
			t.Fatal("foreign or zero custody accepted")
		}
	}
	wrongOwner := f.owner
	replay, err := risk.NewVelocityReplayIdentity("other-confirmation-namespace", f.owner.layout.secret)
	if err != nil {
		t.Fatal(err)
	}
	wrongOwner.layout.replay = replay
	if err := wrongOwner.confirm(context.Background(), f.lease, f.closure, f.publication, f.confirmation); err == nil {
		t.Fatal("foreign namespace accepted")
	}
	if err := f.confirm(t, nil); err == nil {
		t.Fatal("nil context accepted")
	}
	f.wire.mu.Lock()
	defer f.wire.mu.Unlock()
	if len(f.wire.requests) != 1 {
		t.Fatal("invalid custody dispatched")
	}
}

func TestNativeConfirmationOriginalExpiryBoundary(t *testing.T) {
	for _, delta := range []int64{-1, 0, 1} {
		t.Run(strconv.FormatInt(delta, 10), func(t *testing.T) {
			f := newConfirmationFixture(t, 1)
			key := f.plan.keys[0]
			published := f.db.strings[key]
			confirmed := strings.Replace(published, "published|", "confirmed|", 1)
			fields := strings.Split(published, "|")
			expires, err := strconv.ParseInt(fields[4], 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			f.db.now = expires + delta
			writes := f.db.writes
			reply := runRecoveryScript(t, f.db, confirmationScript, []string{key}, []string{published, confirmed})
			if delta < 0 {
				if reply[0] != "confirmed" || f.db.writes != writes+1 || f.db.expiry[key] != (expires+999)/1000 {
					t.Fatal("original expiry or rounding changed")
				}
			} else if reply[0] != "unavailable" || f.db.writes != writes {
				t.Fatal("expired original lease accepted")
			}
		})
	}
}

func TestNativeConfirmationDoesNotRestoreMissingCounters(t *testing.T) {
	f := newConfirmationFixture(t, 1)
	delete(f.db.strings, f.plan.keys[1])
	delete(f.db.expiry, f.plan.keys[1])
	before, writes := cloneScriptStrings(f.db.strings), f.db.writes
	if err := f.confirm(t, context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, exists := f.db.strings[f.plan.keys[1]]; exists {
		t.Fatal("confirmation repaired absent counter/replay state")
	}
	if len(before) != len(f.db.strings) || f.db.writes != writes+1 {
		t.Fatal("confirmation touched more than the marker")
	}
	// Success attests this exact marker transition only, not eviction freedom or
	// whole-counter continuity. Public healthy activation remains separate.
}
