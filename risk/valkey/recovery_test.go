package valkey

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/risk"
)

func runRecoveryScript(t *testing.T, db *scriptDB, script string, keys, args []string) []string {
	t.Helper()
	got, err := db.executeScript(script, keys, args)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func recoveryMarker(plan commandPlan, generation, token string, expiry int64) string {
	return "replaying|" + plan.epoch + "|" + generation + "|" + token + "|" + strconv.FormatInt(expiry, 10)
}

func TestNativeRecoveryFenceExpiryTakeoverAndRenewal(t *testing.T) {
	db := newScriptDB()
	plan := scriptPlan(t, "recover", 9)
	key := []string{plan.keys[0]}
	marker := recoveryMarker(plan, "1", strings.Repeat("a", 32), db.now+1234567)
	if got := runRecoveryScript(t, db, recoveryFenceScript, key, []string{"", marker}); !reflect.DeepEqual(got, []string{"fenced", marker}) {
		t.Fatal("no native recovery fence", got)
	}
	writes, expiry := db.writes, db.expiry[key[0]]
	if expiry != (db.now+1234567+999)/1000 {
		t.Fatal("fence expiry not atomic rounded-up original time")
	}
	if got := runRecoveryScript(t, db, recoveryFenceScript, key, []string{"", marker}); got[0] != "fenced" || db.writes != writes || db.expiry[key[0]] != expiry {
		t.Fatal("matching fence replay renewed expiry")
	}
	renewed := recoveryMarker(plan, "1", strings.Repeat("a", 32), db.now+2234567)
	if got := runRecoveryScript(t, db, recoveryFenceScript, key, []string{marker, renewed}); got[0] != "fenced" {
		t.Fatal("exact renewal rejected", got)
	}
	if got := runRecoveryScript(t, db, recoveryFenceScript, key, []string{renewed, marker}); got[0] != "unavailable" {
		t.Fatal("stale renewal shortened fence")
	}
	newOwner := recoveryMarker(plan, "2", strings.Repeat("b", 32), db.now+3234567)
	if got := runRecoveryScript(t, db, recoveryFenceScript, key, []string{renewed, newOwner}); got[0] != "unavailable" {
		t.Fatal("live owner replaced")
	}
	db.now += 2234567
	if got := runRecoveryScript(t, db, recoveryFenceScript, key, []string{renewed, newOwner}); got[0] != "fenced" {
		t.Fatal("expired owner takeover rejected", got)
	}
	writes = db.writes
	if got := runRecoveryScript(t, db, recoveryFenceScript, key, []string{newOwner, marker}); got[0] != "unavailable" || db.writes != writes {
		t.Fatal("old generation resurrected")
	}
	db.now += 1000000
	if got := runRecoveryScript(t, db, recoveryFenceScript, key, []string{newOwner, newOwner}); got[0] != "unavailable" {
		t.Fatal("exact expired fence renewed")
	}
}

func TestNativeRecoveryFenceRejectsInvalidStateBeforeWrite(t *testing.T) {
	for _, kind := range []string{"hash", "oversize", "malformed", "zero-epoch", "zero-owner", "zero-generation", "overflow-generation", "future-expiry", "expired", "leading-zero"} {
		t.Run(kind, func(t *testing.T) {
			db := newScriptDB()
			plan := scriptPlan(t, "recover", 9)
			marker := recoveryMarker(plan, "1", strings.Repeat("a", 32), db.now+1000000)
			switch kind {
			case "hash":
				db.hashes[plan.keys[0]] = map[string]string{"foreign": "state"}
			case "oversize":
				db.strings[plan.keys[0]] = strings.Repeat("x", 129)
			case "malformed":
				db.strings[plan.keys[0]] = "malformed"
			case "zero-epoch":
				marker = strings.Replace(marker, plan.epoch, strings.Repeat("0", 32), 1)
			case "zero-owner":
				marker = strings.Replace(marker, strings.Repeat("a", 32), strings.Repeat("0", 32), 1)
			case "zero-generation":
				marker = recoveryMarker(plan, "0", strings.Repeat("a", 32), db.now+1000000)
			case "overflow-generation":
				marker = recoveryMarker(plan, "18446744073709551616", strings.Repeat("a", 32), db.now+1000000)
			case "future-expiry":
				marker = recoveryMarker(plan, "1", strings.Repeat("a", 32), db.now+60000001)
			case "expired":
				marker = recoveryMarker(plan, "1", strings.Repeat("a", 32), db.now)
			case "leading-zero":
				marker = recoveryMarker(plan, "01", strings.Repeat("a", 32), db.now+1000000)
			}
			if got := runRecoveryScript(t, db, recoveryFenceScript, []string{plan.keys[0]}, []string{"", marker}); got[0] != "unavailable" || db.writes != 0 {
				t.Fatal("invalid fence published", got)
			}
		})
	}
}

func replayArguments(plan commandPlan, marker string, original []string) []string {
	args := []string{marker, plan.fingerprint, strconv.FormatInt(plan.window.Microseconds(), 10), strconv.Itoa(len(plan.targets)), strconv.Itoa(len(plan.targets[0].Keys))}
	return append(args, original[2:]...)
}

func TestNativeRecoveryRestoresOriginalReplayWithoutDebitOrRenewal(t *testing.T) {
	db := newScriptDB()
	plan := scriptPlan(t, "recover", 9, 8)
	db.strings[plan.keys[0]] = plan.epoch
	original := db.run(t, plan)
	originalReplayExpiry := db.expiry[plan.keys[1]]
	db.strings = map[string]string{}
	db.expiry = map[string]int64{}
	db.now += 1000000
	marker := recoveryMarker(plan, "1", strings.Repeat("a", 32), db.now+1000000)
	runRecoveryScript(t, db, recoveryFenceScript, []string{plan.keys[0]}, []string{"", marker})
	args := replayArguments(plan, marker, original)
	if got := runRecoveryScript(t, db, recoveryReplayScript, plan.keys, args); !reflect.DeepEqual(got, []string{"restored", plan.fingerprint}) {
		t.Fatal("known commit not restored", got)
	}
	if db.expiry[plan.keys[1]] != originalReplayExpiry {
		t.Fatal("recovery refreshed original replay retention")
	}
	for i := range plan.targets {
		root := plan.keys[2+capacityProbeCount+i*2+1]
		if db.strings[root] != root+"|"+original[5+i*4]+"|1|"+strconv.FormatInt(plan.window.Microseconds(), 10) {
			t.Fatal("recovery debited or changed original window")
		}
	}
	writes, state, expiry := db.writes, cloneScriptStrings(db.strings), cloneScriptExpiry(db.expiry)
	if got := runRecoveryScript(t, db, recoveryReplayScript, plan.keys, args); got[0] != "restored" || db.writes != writes || !reflect.DeepEqual(state, db.strings) || !reflect.DeepEqual(expiry, db.expiry) {
		t.Fatal("replayed recovery renewed or mutated state")
	}
	// A recovery fence is deliberately not a debit-enabling healthy marker.
	if got := db.run(t, plan); got[0] != "unavailable" {
		t.Fatal("partial recovery enabled fresh mutation")
	}
	db.strings[plan.keys[0]] = plan.epoch
	if got := db.run(t, plan); !reflect.DeepEqual(got, original) {
		t.Fatal("native replay lost original acknowledged observation", got)
	}
}

func TestNativeRecoveryConservesNewerWindowsAndCumulativeSnapshots(t *testing.T) {
	db := newScriptDB()
	older := scriptPlan(t, "older", 8)
	db.strings[older.keys[0]] = older.epoch
	oldReply := db.run(t, older)
	db.now += 1000000
	newer := scriptPlan(t, "newer", 9, 8)
	newReply := db.run(t, newer)
	db.strings = map[string]string{}
	db.expiry = map[string]int64{}
	marker := recoveryMarker(newer, "1", strings.Repeat("a", 32), db.now+1000000)
	runRecoveryScript(t, db, recoveryFenceScript, []string{newer.keys[0]}, []string{"", marker})
	runRecoveryScript(t, db, recoveryReplayScript, newer.keys, replayArguments(newer, marker, newReply))
	runRecoveryScript(t, db, recoveryReplayScript, older.keys, replayArguments(older, marker, oldReply))
	for i := range newer.targets {
		root := newer.keys[2+capacityProbeCount+i*2+1]
		if strings.Split(db.strings[root], "|")[2] != "2" {
			t.Fatal("late original snapshot rolled back or summed cumulative count")
		}
	}
	// The same subject has entered its next window. A late older declaration
	// must neither restore an expired window nor replace the new live one.
	db.now += newer.window.Microseconds()
	marker = recoveryMarker(newer, "2", strings.Repeat("b", 32), db.now+1000000)
	runRecoveryScript(t, db, recoveryFenceScript, []string{newer.keys[0]}, []string{"", marker})
	nextReply := append([]string(nil), newReply...)
	nextReply[2] = strconv.FormatInt(db.now, 10)
	for i := range newer.targets {
		nextReply[4+i*4] = "1"
		nextReply[5+i*4] = nextReply[2]
		nextReply[6+i*4] = strconv.FormatInt(db.now+newer.window.Microseconds(), 10)
	}
	next := scriptPlan(t, "next-window", 9, 8)
	runRecoveryScript(t, db, recoveryReplayScript, next.keys, replayArguments(next, marker, nextReply))
	runRecoveryScript(t, db, recoveryReplayScript, older.keys, replayArguments(older, marker, oldReply))
	for i := range next.targets {
		root := next.keys[2+capacityProbeCount+i*2+1]
		if strings.Split(db.strings[root], "|")[1] != nextReply[2] {
			t.Fatal("expired history replaced current window")
		}
	}
}

func TestNativeRecoveryExpiryAndForeignFenceNeverWrite(t *testing.T) {
	for _, kind := range []string{"lease-expiry", "takeover", "foreign-token", "wrong-type", "snapshot-corrupt", "wrong-dimension", "replay-conflict", "capacity-full"} {
		t.Run(kind, func(t *testing.T) {
			db := newScriptDB()
			plan := scriptPlan(t, "recover", 9)
			db.strings[plan.keys[0]] = plan.epoch
			original := db.run(t, plan)
			db.strings = map[string]string{}
			db.expiry = map[string]int64{}
			marker := recoveryMarker(plan, "1", strings.Repeat("a", 32), db.now+1)
			db.strings[plan.keys[0]] = marker
			args := replayArguments(plan, marker, original)
			switch kind {
			case "lease-expiry":
				db.now++
			case "takeover":
				db.strings[plan.keys[0]] = recoveryMarker(plan, "2", strings.Repeat("b", 32), db.now+1000000)
			case "foreign-token":
				args[0] = recoveryMarker(plan, "1", strings.Repeat("b", 32), db.now+1)
			case "wrong-type":
				db.hashes[plan.keys[len(plan.keys)-1]] = map[string]string{"bad": "type"}
			case "snapshot-corrupt":
				args[len(args)-1] = "01"
			case "wrong-dimension":
				args[6] = "foreign"
			case "replay-conflict":
				db.strings[plan.keys[1]] = strings.Repeat("f", 64) + "|pending"
			case "capacity-full":
				for _, key := range plan.keys[2 : 2+capacityProbeCount] {
					db.strings[key] = "foreign|" + strings.Repeat("f", 64) + "|" + strconv.FormatInt(db.now+3600000000, 10)
				}
			}
			before, writes := cloneScriptStrings(db.strings), db.writes
			if got := runRecoveryScript(t, db, recoveryReplayScript, plan.keys, args); got[0] != "unavailable" || db.writes != writes || !reflect.DeepEqual(before, db.strings) {
				t.Fatal("invalid/stale recovery mutated native state", got)
			}
		})
	}
}

func TestNativeRecoveryPartialWritesAreIdempotentlyRepairable(t *testing.T) {
	for fault := 1; fault <= 10; fault++ {
		t.Run(strconv.Itoa(fault), func(t *testing.T) {
			db := newScriptDB()
			plan := scriptPlan(t, "recover", 9, 8)
			db.strings[plan.keys[0]] = plan.epoch
			original := db.run(t, plan)
			db.strings = map[string]string{}
			db.expiry = map[string]int64{}
			db.writes = 0
			marker := recoveryMarker(plan, "1", strings.Repeat("a", 32), db.now+1000000)
			db.strings[plan.keys[0]] = marker
			db.failAfterWrites = fault
			_, err := db.executeScript(recoveryReplayScript, plan.keys, replayArguments(plan, marker, original))
			if err == nil {
				t.Fatal("fault failed to interrupt restore")
			}
			db.failAfterWrites = 0
			if got := runRecoveryScript(t, db, recoveryReplayScript, plan.keys, replayArguments(plan, marker, original)); got[0] != "restored" {
				t.Fatal("acknowledged committed history could not repair partial replay", got)
			}
			for i := range plan.targets {
				root := plan.keys[2+capacityProbeCount+i*2+1]
				if strings.Split(db.strings[root], "|")[2] != "1" {
					t.Fatal("partial recovery retry debited again")
				}
			}
		})
	}
}

func recoveredSnapshots(t *testing.T, reply []string) []risk.Counter {
	t.Helper()
	observed, ok := parseWireTime(reply[2])
	if !ok {
		t.Fatal("invalid fixture observation")
	}
	var snapshots []risk.Counter
	for i := 3; i < len(reply); i += 4 {
		count, countOK := parseWireInteger(reply[i+1])
		start, startOK := parseWireTime(reply[i+2])
		finish, finishOK := parseWireTime(reply[i+3])
		if !countOK || !startOK || !finishOK {
			t.Fatal("invalid fixture snapshot")
		}
		snapshots = append(snapshots, risk.Counter{Kind: reply[i], Value: count, ObservedAt: observed, WindowStartedAt: start, WindowExpiresAt: finish})
	}
	return snapshots
}

func TestNativeRecoveryTransportUsesExactScriptsAndRetainsUnavailable(t *testing.T) {
	db := newScriptDB()
	plan := scriptPlan(t, "recover", 9, 8, 7, 6)
	db.strings[plan.keys[0]] = plan.epoch
	original := db.run(t, plan)
	db.strings = map[string]string{}
	db.expiry = map[string]int64{}
	transport, fixture := nativeFixture(t, func(request []string) string {
		if len(request) < 3 || request[0] != "EVAL" {
			return ""
		}
		n, err := strconv.Atoi(request[2])
		if err != nil || len(request) < 3+n {
			return ""
		}
		got, err := db.executeScript(request[1], request[3:3+n], request[3+n:])
		if err != nil {
			return "-injected unavailable\r\n"
		}
		return nativeArray(got)
	})
	marker := recoveryMarker(plan, "18446744073709551615", strings.Repeat("a", 32), db.now+1000000)
	if err := transport.recoverFence(context.Background(), plan, "", marker); err != nil {
		t.Fatal("native fenced IO", err)
	}
	if err := transport.restore(context.Background(), plan, marker, recoveredSnapshots(t, original)); err != nil {
		t.Fatal("native applied replay", err)
	}
	fixture.mu.Lock()
	requests := append([][]string(nil), fixture.requests...)
	fixture.mu.Unlock()
	if len(requests) != 2 || requests[0][1] != recoveryFenceScript || requests[1][1] != recoveryReplayScript || requests[0][2] != "1" || requests[1][2] != "26" {
		t.Fatal("recovery used another script, incomplete key set or hidden resend")
	}
	if len(requests[1]) > 64 || db.expiry[plan.keys[1]] != (db.now+time.Hour.Microseconds())/1000 {
		t.Fatal("unbounded native request or refreshed replay")
	}
	// Exact expiration remains logical even while the rounded-up key exists.
	db.now += 1000000
	if err := transport.restore(context.Background(), plan, marker, recoveredSnapshots(t, original)); !errors.Is(err, ErrUnavailable) {
		t.Fatal("expired native fence accepted", err)
	}
}

func TestNativeRecoveryArgumentsRejectBeforeIO(t *testing.T) {
	db := newScriptDB()
	plan := scriptPlan(t, "recover", 9)
	db.strings[plan.keys[0]] = plan.epoch
	original := db.run(t, plan)
	transport, fixture := nativeFixture(t, func([]string) string { return "" })
	marker := recoveryMarker(plan, "1", strings.Repeat("a", 32), db.now+1000000)
	for _, mutate := range []func(*commandPlan, *string, []risk.Counter){
		func(p *commandPlan, _ *string, _ []risk.Counter) { p.epoch = strings.Repeat("2", 32) },
		func(_ *commandPlan, m *string, _ []risk.Counter) { *m = strings.Repeat("x", 129) },
		func(_ *commandPlan, _ *string, s []risk.Counter) { s[0].Value = maximumExactInteger + 1 },
		func(_ *commandPlan, _ *string, s []risk.Counter) {
			s[0].ObservedAt = s[0].ObservedAt.Add(time.Nanosecond)
		},
		func(_ *commandPlan, _ *string, s []risk.Counter) {
			s[1].ObservedAt = s[1].ObservedAt.Add(time.Microsecond)
		},
		func(_ *commandPlan, _ *string, s []risk.Counter) {
			s[0].WindowExpiresAt = s[0].WindowExpiresAt.Add(time.Microsecond)
		},
		func(_ *commandPlan, _ *string, s []risk.Counter) { s[0].Kind = "foreign" },
	} {
		p, m, s := plan, marker, recoveredSnapshots(t, original)
		mutate(&p, &m, s)
		if err := transport.restore(context.Background(), p, m, s); !errors.Is(err, risk.ErrInvalidCounterCommand) {
			t.Fatal("invalid recovery reached transport", err)
		}
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.dials != 0 || len(fixture.requests) != 0 {
		t.Fatal("invalid recovery performed IO")
	}
}

func TestNativeRecoveryLogicalExpiryDoesNotResurrectRoundedKeys(t *testing.T) {
	db := newScriptDB()
	plan := scriptPlan(t, "microsecond", 9, 8)
	plan.window = time.Microsecond
	db.strings[plan.keys[0]] = plan.epoch
	original := db.run(t, plan)
	db.now++
	marker := recoveryMarker(plan, "1", strings.Repeat("a", 32), db.now+1000000)
	db.strings[plan.keys[0]] = marker
	// Old physical keys still exist. The restored next window needs both root
	// and aliases to retain its new ORIGINAL expiry, not the preceding TTL.
	next := scriptPlan(t, "next-microsecond", 9, 8)
	next.window = time.Microsecond
	nextReply := append([]string(nil), original...)
	nextReply[1], nextReply[2] = next.fingerprint, strconv.FormatInt(db.now, 10)
	for i := range next.targets {
		nextReply[5+i*4] = nextReply[2]
		nextReply[6+i*4] = strconv.FormatInt(db.now+1, 10)
	}
	if got := runRecoveryScript(t, db, recoveryReplayScript, next.keys, replayArguments(next, marker, nextReply)); got[0] != "restored" {
		t.Fatal("new original window unavailable", got)
	}
	for _, key := range next.keys[2+capacityProbeCount:] {
		if db.expiry[key] != (db.now+1+999)/1000 {
			t.Fatal("alias retains old window TTL")
		}
	}
	// An expired original record remains a replay classification, not a fresh
	// counter allowance. With empty state it creates no counter at all.
	db.strings = map[string]string{plan.keys[0]: marker}
	db.expiry = map[string]int64{}
	if got := runRecoveryScript(t, db, recoveryReplayScript, plan.keys, replayArguments(plan, marker, original)); got[0] != "restored" {
		t.Fatal("expired original classification lost", got)
	}
	for _, key := range plan.keys[2+capacityProbeCount:] {
		if _, ok := db.strings[key]; ok {
			t.Fatal("expired snapshot resurrected")
		}
	}
}

func TestNativeRecoveryPartialNewWindowRepairsEveryAliasExpiry(t *testing.T) {
	db := newScriptDB()
	db.now += 997
	old := scriptPlan(t, "old-rounded-window", 9, 8)
	old.window = 2 * time.Microsecond
	db.strings[old.keys[0]] = old.epoch
	original := db.run(t, old)
	oldExpiry := db.expiry[old.keys[2+capacityProbeCount]]
	db.now += 2
	next := scriptPlan(t, "new-rounded-window", 9, 8)
	next.window = old.window
	reply := append([]string(nil), original...)
	reply[1], reply[2] = next.fingerprint, strconv.FormatInt(db.now, 10)
	for i := range next.targets {
		reply[5+i*4] = reply[2]
		reply[6+i*4] = strconv.FormatInt(db.now+2, 10)
	}
	marker := recoveryMarker(next, "1", strings.Repeat("a", 32), db.now+1000000)
	db.strings[next.keys[0]] = marker
	db.writes = 0
	db.failAfterWrites = 3
	if _, err := db.executeScript(recoveryReplayScript, next.keys, replayArguments(next, marker, reply)); err == nil {
		t.Fatal("restore was not interrupted between root and alias")
	}
	db.failAfterWrites = 0
	if got := runRecoveryScript(t, db, recoveryReplayScript, next.keys, replayArguments(next, marker, reply)); got[0] != "restored" {
		t.Fatal("partial new window not repaired", got)
	}
	want := (db.now + 2 + 999) / 1000
	if want == oldExpiry {
		t.Fatal("fixture does not distinguish old/new physical expiry")
	}
	for _, key := range next.keys[2+capacityProbeCount:] {
		if db.expiry[key] != want {
			t.Fatal("acknowledged partial restoration retained preceding alias expiry")
		}
	}
	writes := db.writes
	if got := runRecoveryScript(t, db, recoveryReplayScript, next.keys, replayArguments(next, marker, reply)); got[0] != "restored" || db.writes != writes {
		t.Fatal("reconciled snapshot replay debited or renewed")
	}
}

func TestNativeRecoveryTransportLostAcknowledgementNeverResends(t *testing.T) {
	db := newScriptDB()
	plan := scriptPlan(t, "lost-recovery-ack", 9)
	db.strings[plan.keys[0]] = plan.epoch
	original := db.run(t, plan)
	db.strings = map[string]string{}
	db.expiry = map[string]int64{}
	marker := recoveryMarker(plan, "1", strings.Repeat("a", 32), db.now+1000000)
	restored := 0
	transport, fixture := nativeFixture(t, func(request []string) string {
		n, err := strconv.Atoi(request[2])
		if err != nil {
			return ""
		}
		reply, err := db.executeScript(request[1], request[3:3+n], request[3+n:])
		if err != nil {
			return ""
		}
		if request[1] == recoveryReplayScript {
			restored++
			if restored == 1 {
				return ""
			}
		}
		return nativeArray(reply)
	})
	if err := transport.recoverFence(context.Background(), plan, "", marker); err != nil {
		t.Fatal(err)
	}
	if err := transport.restore(context.Background(), plan, marker, recoveredSnapshots(t, original)); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatal("lost ack granted applied progress", err)
	}
	fixture.mu.Lock()
	count := len(fixture.requests)
	fixture.mu.Unlock()
	if count != 2 {
		t.Fatal("ambiguous restore resent itself")
	}
	writes := db.writes
	// The owning recovery process can reconcile the SAME acknowledged history;
	// unlike automatic mutation retry, this cannot debit a second logical attempt.
	if err := transport.restore(context.Background(), plan, marker, recoveredSnapshots(t, original)); err != nil || db.writes != writes {
		t.Fatal("explicit same-history reconciliation changed counters", err)
	}
}

func TestNativeRecoveryFenceGenerationUsesExactUint64Ordering(t *testing.T) {
	db := newScriptDB()
	plan := scriptPlan(t, "generation", 9)
	old := recoveryMarker(plan, "18446744073709551614", strings.Repeat("a", 32), db.now+1)
	runRecoveryScript(t, db, recoveryFenceScript, []string{plan.keys[0]}, []string{"", old})
	db.now++
	current := recoveryMarker(plan, "18446744073709551615", strings.Repeat("b", 32), db.now+1000000)
	if got := runRecoveryScript(t, db, recoveryFenceScript, []string{plan.keys[0]}, []string{old, current}); got[0] != "fenced" {
		t.Fatal("uint64 generations rounded together", got)
	}
	if got := runRecoveryScript(t, db, recoveryFenceScript, []string{plan.keys[0]}, []string{current, old}); got[0] != "unavailable" {
		t.Fatal("generation moved backwards")
	}
}

func TestNativeRecoveryAcknowledgementIsExactRedactedAndNeverRetry(t *testing.T) {
	for _, reply := range [][]string{nil, {"restored"}, {"restored", "foreign"}, {"restored", "binding", "extra"}, {"unavailable", "foreign"}} {
		if err := recoveryAcknowledgement(reply, nil, "restored", "binding"); !errors.Is(err, ErrOutcomeUnknown) {
			t.Fatal("incomplete/foreign acknowledgement accepted", err)
		}
	}
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded, errors.New("provider secret")} {
		got := recoveryAcknowledgement([]string{"restored", "binding"}, cause, "restored", "binding")
		if got == nil || strings.Contains(got.Error(), "provider secret") {
			t.Fatal("late acknowledgement granted progress or leaked diagnostics")
		}
	}
}

func FuzzRecoveryFenceFields(f *testing.F) {
	epoch := strings.Repeat("a", 32)
	for _, seed := range []string{"", "replaying|" + epoch + "|1|" + strings.Repeat("b", 32) + "|1", strings.Repeat("x", 129), "replaying|" + epoch + "|18446744073709551615|" + strings.Repeat("b", 32) + "|9007199254740991"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		fields, ok := recoveryFenceFields(value, epoch)
		if ok && (len(value) > 128 || len(fields) != 5 || strings.Join(fields, "|") != value || fields[1] != epoch) {
			t.Fatal("malformed fence accepted")
		}
	})
}
