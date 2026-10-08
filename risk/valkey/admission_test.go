package valkey

import (
	"context"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/risk"
)

func TestNativeMutationRequiresExactExpectedConfirmation(t *testing.T) {
	for _, changed := range []int{-1, 2, 3, 4, 5, 6, 7, 8, 9} {
		t.Run(strconv.Itoa(changed), func(t *testing.T) {
			db := newScriptDB()
			plan := scriptPlan(t, "expected-confirmation", 9)
			expected := confirmedHealthFixture(plan, db.now)
			plan.expected = expected
			actual := strings.Split(expected, "|")
			switch changed {
			case 2:
				actual[changed] = "2"
			case 3:
				actual[changed] = strings.Repeat("c", 32)
			case 5:
				actual[changed] = strings.Repeat("c", 64)
			case 6:
				actual[changed] = "1"
			case 8:
				actual[changed] = strconv.FormatInt(db.now, 10)
			case 4, 7, 9:
				n, err := strconv.ParseInt(actual[changed], 10, 64)
				if err != nil {
					t.Fatal(err)
				}
				actual[changed] = strconv.FormatInt(n-1, 10)
			}
			db.strings[plan.keys[0]] = strings.Join(actual, "|")
			before, expiry, writes := cloneScriptStrings(db.strings), cloneScriptExpiry(db.expiry), db.writes
			args, err := mutationArguments(plan)
			if err != nil {
				t.Fatal(err)
			}
			// The final wire argument is the exact configured admission marker,
			// independently retained from the marker now present in native storage.
			reply := runRecoveryScript(t, db, mutationScript, plan.keys, args)
			if changed == -1 {
				if reply[0] != "committed" || reply[4] != "1" {
					t.Fatal("exact configured confirmation cannot debit", reply[0])
				}
			} else if reply[0] != "unavailable" || db.writes != writes || !reflect.DeepEqual(before, db.strings) || !reflect.DeepEqual(expiry, db.expiry) {
				t.Fatal("same-epoch different confirmation accepted or mutated")
			}
		})
	}
}

func TestNativeExpectedMarkerDeniesReplayThroughCore(t *testing.T) {
	plan, dispatcher, _ := nativePlan(t)
	db := newScriptDB()
	db.strings[plan.keys[0]] = plan.expected
	transport, fixture := nativeFixture(t, func(request []string) string {
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
	dispatcher.execute = transport.execute
	core, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: dispatcher.layout.policy, Keys: dispatcher.layout.keys, Store: replyStoreFunc(func(ctx context.Context, c risk.CounterCommand) (risk.CounterResult, error) {
		return dispatcher.mutate(ctx, c, [16]byte{1}, plan.expected)
	}), Clock: func() time.Time { return time.UnixMicro(db.now).UTC() }, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	command := prepareFixture(t, core, "tenant", "attempt", "192.0.2.1")
	got, err := core.Mutate(context.Background(), command)
	if err != nil || got.Outcome != risk.CounterCommitted || got.Signal.State != risk.SignalClean {
		t.Fatal("exact native post-state did not reach core", err)
	}
	fields := strings.Split(plan.expected, "|")
	fields[5] = strings.Repeat("c", 64)
	db.strings[plan.keys[0]] = strings.Join(fields, "|")
	before, expiry, writes := cloneScriptStrings(db.strings), cloneScriptExpiry(db.expiry), db.writes
	got, err = core.Mutate(context.Background(), command)
	if err != nil || got.Outcome != risk.CounterNotCommitted || got.Signal.State != risk.SignalUnavailable {
		t.Fatal("old replay bypassed current exact admission", err)
	}
	if !reflect.DeepEqual(before, db.strings) || !reflect.DeepEqual(expiry, db.expiry) || db.writes != writes {
		t.Fatal("denied replay changed original state")
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if len(fixture.requests) != 2 {
		t.Fatal("unexpected mutation resend")
	}
}

func TestNativePostEffectBootLossPreservesCommittedCoreOutcome(t *testing.T) {
	plan, dispatcher, _ := nativePlan(t)
	db := newScriptDB()
	db.strings[plan.keys[0]] = plan.expected
	var lost bool
	transport, fixture := nativeFixture(t, func(request []string) string {
		n, _ := strconv.Atoi(request[2])
		reply, err := db.executeScript(request[1], request[3:3+n], request[3+n:])
		if err != nil {
			return "-invalid\r\n"
		}
		lost = true
		return nativeArray(reply)
	})
	// Both functions run serially on the same fixture connection, not in the
	// caller. Only this operation uses the fixture, so no shared mutable reader.
	fixture.profileReply = func() string {
		boot := strings.Repeat("b", 40)
		if lost {
			boot = strings.Repeat("c", 40)
		}
		return nativeArray([]string{boot, "0"})
	}
	dispatcher.execute = transport.execute
	core, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: dispatcher.layout.policy, Keys: dispatcher.layout.keys, Store: replyStoreFunc(func(ctx context.Context, c risk.CounterCommand) (risk.CounterResult, error) {
		return dispatcher.mutate(ctx, c, [16]byte{1}, plan.expected)
	}), Clock: func() time.Time { return time.UnixMicro(db.now).UTC() }, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	got, err := core.Mutate(context.Background(), prepareFixture(t, core, "tenant", "attempt", "192.0.2.1"))
	if err != nil || got.Outcome != risk.CounterCommitted || got.Signal.State != risk.SignalUnavailable || db.writes == 0 {
		t.Fatal("profile loss erased effect or granted clean admission", err)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if len(fixture.requests) != 1 {
		t.Fatal("post-effect loss resent mutation")
	}
}

func TestNativeMutationRejectsLegacyEpochOnlyAdmission(t *testing.T) {
	db := newScriptDB()
	plan := scriptPlan(t, "legacy-admission", 9)
	db.strings[plan.keys[0]] = confirmedHealthFixture(plan, db.now)
	before, expiry := cloneScriptStrings(db.strings), cloneScriptExpiry(db.expiry)
	// Independent encoding of the historical request without expected custody.
	args := []string{plan.epoch, plan.fingerprint, strconv.FormatInt(plan.window.Microseconds(), 10), strconv.Itoa(len(plan.targets)), strconv.Itoa(len(plan.targets[0].Keys))}
	for _, target := range plan.targets {
		args = append(args, string(target.Dimension))
	}
	reply := runRecoveryScript(t, db, mutationScript, plan.keys, args)
	if reply[0] != "unavailable" || db.writes != 0 || !reflect.DeepEqual(before, db.strings) || !reflect.DeepEqual(expiry, db.expiry) {
		t.Fatal("epoch-only request admitted without exact confirmed custody")
	}
}
