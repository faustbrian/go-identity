package valkey

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/risk"
	lua "github.com/yuin/gopher-lua"
)

// Only the Redis command boundary is replaced. Every test executes the actual
// production Lua, not a second counter algorithm. This is not topology proof.
type scriptDB struct {
	now             int64
	strings         map[string]string
	hashes          map[string]map[string]string
	expiry          map[string]int64
	writes          int
	failAfterWrites int
}

func newScriptDB() *scriptDB {
	return &scriptDB{now: time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC).UnixMicro(), strings: map[string]string{}, hashes: map[string]map[string]string{}, expiry: map[string]int64{}}
}

func (d *scriptDB) call(l *lua.LState) int {
	command := l.CheckString(1)
	if d.failAfterWrites > 0 && d.writes >= d.failAfterWrites && command == "SET" {
		l.RaiseError("injected native write failure")
		return 0
	}
	key := l.OptString(2, "")
	if at, ok := d.expiry[key]; ok && d.now/1000 >= at {
		delete(d.strings, key)
		delete(d.hashes, key)
		delete(d.expiry, key)
	}
	pushString := func(s string) int { l.Push(lua.LString(s)); return 1 }
	pushNumber := func(n int64) int { l.Push(lua.LNumber(n)); return 1 }
	switch command {
	case "TIME":
		v := l.NewTable()
		v.Append(lua.LString(strconv.FormatInt(d.now/1000000, 10)))
		v.Append(lua.LString(strconv.FormatInt(d.now%1000000, 10)))
		l.Push(v)
		return 1
	case "TYPE":
		kind := "none"
		if _, ok := d.strings[key]; ok {
			kind = "string"
		}
		if _, ok := d.hashes[key]; ok {
			kind = "hash"
		}
		v := l.NewTable()
		v.RawSetString("ok", lua.LString(kind))
		l.Push(v)
		return 1
	case "STRLEN":
		return pushNumber(int64(len(d.strings[key])))
	case "GET":
		if s, ok := d.strings[key]; ok {
			return pushString(s)
		}
		l.Push(lua.LFalse)
		return 1
	case "SET":
		if l.CheckString(4) != "PXAT" {
			l.RaiseError("record lacks atomic expiry")
			return 0
		}
		at, err := strconv.ParseInt(l.CheckString(5), 10, 64)
		if err != nil {
			l.RaiseError("invalid expiry")
			return 0
		}
		d.writes++
		d.strings[key] = l.CheckString(3)
		d.expiry[key] = at
		return pushString("OK")
	default:
		l.RaiseError("unsupported Redis boundary")
		return 0
	}
}

func (d *scriptDB) run(t *testing.T, plan commandPlan) []string {
	t.Helper()
	reply, err := d.execute(plan)
	if err != nil {
		t.Fatal("script execution failed", err)
	}
	return reply
}

func (d *scriptDB) execute(plan commandPlan) ([]string, error) {
	args, err := mutationArguments(plan)
	if err != nil {
		return nil, err
	}
	l := lua.NewState(lua.Options{SkipOpenLibs: true})
	defer l.Close()
	lua.OpenBase(l)
	lua.OpenString(l)
	lua.OpenTable(l)
	lua.OpenMath(l)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	l.SetContext(ctx)
	keys, argv := l.NewTable(), l.NewTable()
	for _, v := range plan.keys {
		keys.Append(lua.LString(v))
	}
	for _, v := range args {
		argv.Append(lua.LString(v))
	}
	l.SetGlobal("KEYS", keys)
	l.SetGlobal("ARGV", argv)
	redis := l.NewTable()
	redis.RawSetString("call", l.NewFunction(d.call))
	l.SetGlobal("redis", redis)
	if err := l.DoString("return (function()\n" + mutationScript + "\nend)()"); err != nil {
		return nil, err
	}
	result, ok := l.Get(-1).(*lua.LTable)
	if !ok {
		return nil, errors.New("script returned non-array")
	}
	reply := make([]string, 0, result.Len())
	for i := 1; i <= result.Len(); i++ {
		v, ok := result.RawGetInt(i).(lua.LString)
		if !ok {
			return nil, errors.New("non-string reply")
		}
		reply = append(reply, string(v))
	}
	return reply, nil
}

func scriptPlan(t *testing.T, attempt string, versions ...uint32) commandPlan {
	t.Helper()
	p, keys, c := commandFixture(t, versions...)
	layout, err := newCommandLayout("native-test", bytes.Repeat([]byte{1}, 32), p, keys)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := layout.prepare(prepareFixture(t, c, "tenant", attempt, "192.0.2.1"), [16]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func TestNativeScriptDebitsAllDimensionsAndConservesReplay(t *testing.T) {
	db := newScriptDB()
	first := scriptPlan(t, "first", 9)
	db.strings[first.keys[0]] = first.epoch
	reply := db.run(t, first)
	if len(reply) != 19 || reply[0] != "committed" || reply[1] != first.fingerprint || reply[2] != strconv.FormatInt(db.now, 10) {
		t.Fatal("missing complete native debit")
	}
	for i, target := range first.targets {
		if reply[3+i*4] != string(target.Dimension) || reply[4+i*4] != "1" {
			t.Fatal("not every logical dimension charged")
		}
	}
	originalExpiry := db.expiry[first.keys[1]]
	db.now += 1000000
	second := scriptPlan(t, "second", 9)
	next := db.run(t, second)
	if next[4] != "2" {
		t.Fatal("counter reset or failed to increment")
	}
	writes := db.writes
	replay := db.run(t, first)
	if !reflect.DeepEqual(reply, replay) || db.writes != writes || db.expiry[first.keys[1]] != originalExpiry {
		t.Fatal("replay debited or refreshed original observation/TTL")
	}
	db.now = time.Date(2026, 10, 7, 12, 5, 0, 0, time.UTC).UnixMicro()
	boundary := db.run(t, scriptPlan(t, "boundary", 9))
	if boundary[4] != "1" || boundary[5] != strconv.FormatInt(db.now, 10) {
		t.Fatal("exclusive expiry did not start a new window")
	}
}

func TestNativeScriptRotationKeepsOneLogicalRoot(t *testing.T) {
	db := newScriptDB()
	old := scriptPlan(t, "old", 8)
	db.strings[old.keys[0]] = old.epoch
	original := db.run(t, old)
	expires := original[6]
	db.now += 1000000
	rotated := scriptPlan(t, "rotated", 9, 8)
	got := db.run(t, rotated)
	for i := range rotated.targets {
		newest, oldest := rotated.keys[2+capacityProbeCount+i*2], rotated.keys[3+capacityProbeCount+i*2]
		if got[4+i*4] != "2" || got[6+i*4] != expires || strings.Split(db.strings[newest], "|")[0] != oldest || strings.Split(db.strings[oldest], "|")[2] != "2" {
			t.Fatal("rotation reset, summed or slid the counter")
		}
	}
	oldWriter := db.run(t, scriptPlan(t, "old-writer", 8))
	if oldWriter[4] != "3" {
		t.Fatal("older retained writer lost shared root")
	}
	newWriter := db.run(t, scriptPlan(t, "new-writer", 9, 8))
	if newWriter[4] != "4" {
		t.Fatal("new writer bypassed old writer debit")
	}
	writes := db.writes
	retired := db.run(t, scriptPlan(t, "unsafe-retirement", 9))
	if retired[0] != "unavailable" || db.writes != writes {
		t.Fatal("unproven root retirement permitted new count")
	}
}

func TestNativeScriptMaximumAliasesAndMicrosecondBoundary(t *testing.T) {
	db := newScriptDB()
	plan := scriptPlan(t, "first", 9, 8, 7, 6)
	plan.window = time.Microsecond
	db.strings[plan.keys[0]] = plan.epoch
	original := db.run(t, plan)
	for i := range plan.targets {
		root := plan.keys[2+capacityProbeCount+i*4+3]
		if original[4+i*4] != "1" || original[6+i*4] != strconv.FormatInt(db.now+1, 10) {
			t.Fatal("maximum alias set changed logical window")
		}
		for j := 0; j < 4; j++ {
			if strings.Split(db.strings[plan.keys[2+capacityProbeCount+i*4+j]], "|")[0] != root {
				t.Fatal("alias owns an independent counter")
			}
		}
	}
	// The physical millisecond TTL has not expired. Logical expiry still wins.
	db.now++
	next := scriptPlan(t, "boundary", 9, 8, 7, 6)
	next.window = time.Microsecond
	result := db.run(t, next)
	if result[4] != "1" || result[5] != strconv.FormatInt(db.now, 10) {
		t.Fatal("physical TTL rounding extended logical window")
	}
}

func TestMutationArgumentsRejectUnboundedOrCrossSlotPlans(t *testing.T) {
	plan := scriptPlan(t, "first", 9, 8, 7, 6)
	args, err := mutationArguments(plan)
	if err != nil || len(args) != 9 || args[0] != plan.epoch || args[1] != plan.fingerprint || args[3] != "4" || args[4] != "4" || len(plan.keys) != 26 {
		t.Fatal("incomplete native arguments", err)
	}
	invalid := []commandPlan{{}, plan, plan, plan, plan, plan, plan, plan}
	invalid[1].window = time.Hour + time.Microsecond
	invalid[2].window = time.Nanosecond
	invalid[3].epoch = "malformed"
	invalid[4].fingerprint = "malformed"
	invalid[5].keys = append([]string(nil), plan.keys...)
	invalid[5].keys[18] = "irv1:{foreign}:counter"
	invalid[6].keys = append([]string(nil), plan.keys...)
	invalid[6].keys[18] = invalid[6].keys[17]
	invalid[7].keys = plan.keys[:18]
	for _, p := range invalid {
		if _, err := mutationArguments(p); !errors.Is(err, risk.ErrInvalidCounterCommand) {
			t.Fatal("invalid native request admitted")
		}
	}
}

func TestNativeScriptRejectsCorruptLateTargetBeforeAnyWrite(t *testing.T) {
	for _, corruption := range []string{"wrong-type", "malformed-count", "overflow", "future-start", "window", "foreign-root"} {
		t.Run(corruption, func(t *testing.T) {
			db := newScriptDB()
			initial := scriptPlan(t, "initial", 9)
			db.strings[initial.keys[0]] = initial.epoch
			db.run(t, initial)
			last := initial.keys[len(initial.keys)-1]
			fields := strings.Split(db.strings[last], "|")
			switch corruption {
			case "wrong-type":
				delete(db.strings, last)
				db.hashes[last] = map[string]string{"invalid": "type"}
			case "malformed-count":
				fields[2] = "01"
			case "overflow":
				fields[2] = "9007199254740991"
			case "future-start":
				fields[1] = strconv.FormatInt(db.now+1, 10)
			case "window":
				fields[3] = "1"
			case "foreign-root":
				fields[0] = "foreign"
			}
			if corruption != "wrong-type" {
				db.strings[last] = strings.Join(fields, "|")
			}
			before := cloneScriptStrings(db.strings)
			expiry := cloneScriptExpiry(db.expiry)
			writes := db.writes
			got := db.run(t, scriptPlan(t, "invalid", 9))
			if got[0] != "unavailable" || db.writes != writes || !reflect.DeepEqual(before, db.strings) || !reflect.DeepEqual(expiry, db.expiry) {
				t.Fatal("late corruption caused partial debit or TTL change")
			}
		})
	}
}

func TestNativeScriptMissingHealthConflictAndPendingNeverDebit(t *testing.T) {
	db := newScriptDB()
	plan := scriptPlan(t, "first", 9)
	for _, health := range []string{"", strings.Repeat("2", 32), "malformed"} {
		if health != "" {
			db.strings[plan.keys[0]] = health
		}
		got := db.run(t, plan)
		if got[0] != "unavailable" || db.writes != 0 {
			t.Fatal("unhealthy epoch debited")
		}
	}
	db.strings[plan.keys[0]] = plan.epoch
	db.run(t, plan)
	writes := db.writes
	conflict := plan
	conflict.fingerprint = strings.Repeat("f", 64)
	if got := db.run(t, conflict); got[0] != "not_committed" || db.writes != writes {
		t.Fatal("changed binding replay debited")
	}
	db.strings[plan.keys[1]] = plan.fingerprint + "|pending"
	if got := db.run(t, plan); got[0] != "unknown" || db.writes != writes {
		t.Fatal("interrupted native execution charged again")
	}
}

func TestNativeScriptReplayCapacityRejectsWithoutDebit(t *testing.T) {
	db := newScriptDB()
	plan := scriptPlan(t, "first", 9)
	db.strings[plan.keys[0]] = plan.epoch
	for i := 0; i < capacityProbeCount; i++ {
		db.strings[plan.keys[2+i]] = "foreign-replay|" + strings.Repeat("f", 64) + "|" + strconv.FormatInt(db.now+3600000000, 10)
		db.expiry[plan.keys[2+i]] = (db.now + 3600000000) / 1000
	}
	got := db.run(t, plan)
	if got[0] != "unavailable" || db.writes != 0 || len(db.hashes) != 0 {
		t.Fatal("full replay capacity debited or evicted active entries")
	}
	db.strings[plan.keys[2]] = "foreign-replay|" + strings.Repeat("f", 64) + "|" + strconv.FormatInt(db.now, 10)
	got = db.run(t, plan)
	if got[0] != "committed" || strings.Split(db.strings[plan.keys[2]], "|")[0] != plan.keys[1] {
		t.Fatal("expired capacity did not admit exactly one bounded replay")
	}
}

func TestNativeScriptCapacityReservationExpiresWithoutReplayRenewal(t *testing.T) {
	db := newScriptDB()
	first := scriptPlan(t, "first", 9)
	db.strings[first.keys[0]] = first.epoch
	db.run(t, first)
	if db.expiry[first.keys[2]] != (db.now+3600000000)/1000 {
		t.Fatal("replay index has no bounded expiry")
	}
	db.now += 1000000
	latest := db.expiry[first.keys[2]]
	db.now += 1000000
	db.run(t, first)
	if db.expiry[first.keys[2]] != latest {
		t.Fatal("duplicate refreshed replay-index retention")
	}
}

func TestNativeScriptWriteFailureRetainsPendingIntent(t *testing.T) {
	db := newScriptDB()
	plan := scriptPlan(t, "first", 9)
	db.strings[plan.keys[0]] = plan.epoch
	// Fail at the second logical dimension, after the first root and its TTL.
	db.failAfterWrites = 3
	if _, err := db.execute(plan); err == nil {
		t.Fatal("injected write failure did not reach script")
	}
	if db.strings[plan.keys[1]] != plan.fingerprint+"|pending" || strings.Split(db.strings[plan.keys[2+capacityProbeCount]], "|")[2] != "1" || db.strings[plan.keys[3+capacityProbeCount]] != "" {
		t.Fatal("fixture did not expose partial effects")
	}
	db.failAfterWrites = 0
	writes := db.writes
	reply := db.run(t, plan)
	if reply[0] != "unknown" || db.writes != writes {
		t.Fatal("partial effects were treated as rollback or another debit")
	}
}

func TestNativeScriptEarlyWriteFailureCannotLeaveImmortalRecords(t *testing.T) {
	for cutoff := 1; cutoff <= 5; cutoff++ {
		t.Run(strconv.Itoa(cutoff), func(t *testing.T) {
			db := newScriptDB()
			plan := scriptPlan(t, "first", 9)
			db.strings[plan.keys[0]] = plan.epoch
			db.failAfterWrites = cutoff
			if _, err := db.execute(plan); err == nil {
				t.Fatal("write failure was not reached")
			}
			for key := range db.hashes {
				if db.expiry[key] <= db.now/1000 {
					t.Fatal("early failure left immortal hash")
				}
			}
			for key := range db.strings {
				if key != plan.keys[0] && db.expiry[key] <= db.now/1000 {
					t.Fatal("early failure left immortal record")
				}
			}
			db.failAfterWrites = 0
			writes := db.writes
			if reply := db.run(t, plan); reply[0] != "unknown" || db.writes != writes {
				t.Fatal("early ambiguity allowed another debit")
			}
		})
	}
}

func TestNativeScriptPostStateDrivesCoreThreshold(t *testing.T) {
	db := newScriptDB()
	p, keys, _ := commandFixture(t, 9)
	layout, err := newCommandLayout("native-test", bytes.Repeat([]byte{1}, 32), p, keys)
	if err != nil {
		t.Fatal(err)
	}
	owner := mutationDispatcher{layout: layout, timeout: time.Second, execute: func(_ context.Context, plan commandPlan) ([]string, error) { return db.run(t, plan), nil }}
	c, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: p, Keys: keys, Store: replyStoreFunc(func(ctx context.Context, command risk.CounterCommand) (risk.CounterResult, error) {
		return owner.mutate(ctx, command, [16]byte{1})
	}), Clock: func() time.Time { return time.UnixMicro(db.now).UTC() }, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 11; i++ {
		command := prepareFixture(t, c, "tenant", strconv.Itoa(i), "192.0.2.1")
		plan, err := layout.prepare(command, [16]byte{1})
		if err != nil {
			t.Fatal(err)
		}
		db.strings[plan.keys[0]] = plan.epoch
		got, err := c.Mutate(context.Background(), command)
		want := risk.SignalClean
		if i == 11 {
			want = risk.SignalThrottle
		}
		if err != nil || got.Outcome != risk.CounterCommitted || got.Signal.State != want {
			t.Fatal("native post-state broke N/N+1 threshold", i, err)
		}
	}
}

func cloneScriptStrings(source map[string]string) map[string]string {
	copy := map[string]string{}
	for key, value := range source {
		copy[key] = value
	}
	return copy
}
func cloneScriptExpiry(source map[string]int64) map[string]int64 {
	copy := map[string]int64{}
	for key, value := range source {
		copy[key] = value
	}
	return copy
}
