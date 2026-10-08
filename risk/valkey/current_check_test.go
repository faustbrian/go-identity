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

// The production TLS/RESP transport and embedded Lua run against the deliberate
// server boundary. Primary eligibility is simulated; this is not live composition.
func TestOwnedNativeCurrentCheckDoesNotMutate(t *testing.T) {
	for _, mode := range []string{"healthy", "read", "primary_before", "primary_after", "missing", "wrong_type", "oversized", "foreign_cut", "published", "expired", "before_cut", "lost_reply", "changed_boot", "foreign_tenant", "foreign_graph", "foreign_namespace", "wrong_policy", "zero_issuer", "zero_command", "zero_health", "zero_owner", "canceled", "nil_context"} {
		t.Run(mode, func(t *testing.T) {
			f := newConfirmationFixture(t, 1)
			ack, err := f.owner.confirmed(context.Background(), f.lease, f.closure, f.publication, f.confirmation)
			if err != nil {
				t.Fatal(err)
			}
			health, err := f.journal.AcknowledgeEligibility(context.Background(), f.lease, f.closure, f.publication, f.confirmation, ack, func(context.Context) error {
				if (mode == "primary_before" || mode == "primary_after") && f.lost[0].Load() {
					return errors.New("simulated primary unavailable")
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			// All replay-only callbacks are closed. Checking current healthy state
			// must not revive any of them or reconfirm the published marker.
			f.lost[0].Store(true)
			f.lost[1].Store(true)
			f.lost[2].Store(true)
			if mode == "primary_after" {
				f.lost[0].Store(false)
				f.mode.Store(1)
			}
			key := f.plan.keys[0]
			switch mode {
			case "missing":
				delete(f.db.strings, key)
			case "wrong_type":
				delete(f.db.strings, key)
				f.db.hashes[key] = map[string]string{"foreign": "value"}
			case "oversized":
				f.db.strings[key] = strings.Repeat("x", 385)
			case "foreign_cut":
				fields := strings.Split(f.db.strings[key], "|")
				fields[5] = strings.Repeat("a", 64)
				f.db.strings[key] = strings.Join(fields, "|")
			case "published":
				f.db.strings[key] = strings.Replace(f.db.strings[key], "confirmed|", "published|", 1)
			case "expired":
				fields := strings.Split(f.db.strings[key], "|")
				f.db.now, _ = strconv.ParseInt(fields[4], 10, 64)
				// Keep physical storage present to exercise the exclusive logical
				// boundary separately from Redis's lazy expiration on reads.
				f.db.expiry[key] = f.db.now/1000 + 60000
			case "before_cut":
				f.db.now = f.binding.ReplayThrough.UnixMicro() - 1
			case "lost_reply":
				f.mode.Store(5)
			case "changed_boot":
				f.wire.mu.Lock()
				f.wire.profileReply = func() string { return nativeArray([]string{strings.Repeat("c", 40), "0"}) }
				f.wire.mu.Unlock()
			case "zero_health":
				health = risk.VelocityEligibility{}
			}
			coordinator, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: f.owner.layout.policy, Keys: f.owner.layout.keys, Store: replyStoreFunc(func(context.Context, risk.CounterCommand) (risk.CounterResult, error) {
				panic("preparation dispatched")
			}), Clock: func() time.Time { return time.UnixMicro(f.db.now) }, Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			tenant := "tenant"
			if mode == "foreign_tenant" {
				tenant = "other-tenant"
			}
			command := prepareFixture(t, coordinator, tenant, "check-only", "192.0.2.1")
			if mode == "read" {
				command, err = coordinator.Prepare(risk.Context{Tenant: tenant, Operation: "identity.profile.get", Attempt: "check-read"}, risk.Subject{User: "user"}, risk.BeforeReturn)
				if err != nil {
					t.Fatal(err)
				}
			}
			if mode == "zero_command" {
				command = risk.CounterCommand{}
			}
			owner := f.owner
			if mode == "zero_owner" {
				owner = ownedRecovery{}
			}
			switch mode {
			case "zero_issuer":
				owner.issuer = risk.VelocityNativeIssuer{}
			case "foreign_graph":
				_, _, foreign, _ := risk.NewVelocityRecoveryAuthorities()
				owner, err = newOwnedRecovery(owner.layout, owner.transport, foreign)
				if err != nil {
					t.Fatal(err)
				}
			case "foreign_namespace":
				owner.layout.replay, err = risk.NewVelocityReplayIdentity("foreign-check", owner.layout.secret)
				if err != nil {
					t.Fatal(err)
				}
			case "wrong_policy":
				owner.layout.policy, _, _ = commandFixture(t, 9, 8)
			}
			checker, ok := any(owner).(interface {
				checkCurrent(context.Context, risk.CounterCommand, risk.VelocityLease, risk.VelocityClosure, risk.VelocityPublication, risk.VelocityConfirmation, risk.VelocityNativeConfirmation, risk.VelocityEligibility) error
			})
			if !ok {
				t.Fatal("native owner lacks read-only current-marker check")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "canceled" {
				cancel()
			}
			if mode == "nil_context" {
				ctx = nil
			}
			before, expiry, writes := cloneScriptStrings(f.db.strings), cloneScriptExpiry(f.db.expiry), f.db.writes
			err = checker.checkCurrent(ctx, command, f.lease, f.closure, f.publication, f.confirmation, ack, health)
			if mode == "healthy" || mode == "read" {
				if err != nil {
					t.Fatal("current exact marker denied", err)
				}
				if err := checker.checkCurrent(ctx, command, f.lease, f.closure, f.publication, f.confirmation, ack, health); err != nil {
					t.Fatal("read-only retry denied", err)
				}
			} else if err == nil {
				t.Fatal("invalid current custody admitted", mode)
			}
			if mode == "canceled" && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation lost", err)
			}
			if !reflect.DeepEqual(before, f.db.strings) || !reflect.DeepEqual(expiry, f.db.expiry) || f.db.writes != writes {
				t.Fatal("read-only check changed native state", mode)
			}
			// Invalid scope/custody/cancellation and lost primary must not even
			// execute the read script. Setup made exactly two marker requests.
			if mode == "primary_before" || mode == "foreign_tenant" || mode == "foreign_graph" || mode == "foreign_namespace" || mode == "wrong_policy" || mode == "zero_issuer" || mode == "zero_command" || mode == "zero_health" || mode == "zero_owner" || mode == "canceled" || mode == "nil_context" {
				f.wire.mu.Lock()
				requests := len(f.wire.requests)
				f.wire.mu.Unlock()
				if requests != 2 {
					t.Fatal("invalid custody reached native IO", requests)
				}
			}
		})
	}
}

func TestCurrentCheckScriptBoundsAndExclusiveTime(t *testing.T) {
	db := newScriptDB()
	marker := confirmedHealthFixture(commandPlan{epoch: strings.Repeat("1", 32)}, db.now)
	fields := strings.Split(marker, "|")
	expiry, _ := strconv.ParseInt(fields[4], 10, 64)
	through, _ := strconv.ParseInt(fields[8], 10, 64)
	for _, at := range []int64{through - 1, through, expiry - 1, expiry, expiry + 1, -1, 9007199254740991} {
		t.Run(strconv.FormatInt(at, 10), func(t *testing.T) {
			db := newScriptDB()
			db.now = at
			db.strings["health"] = marker
			got, err := db.executeScript(currentCheckScript, []string{"health"}, []string{marker})
			if err != nil {
				t.Fatal(err)
			}
			want := []string{"unavailable", ""}
			if at >= through && at < expiry {
				want = []string{"current", fields[5]}
			}
			if !reflect.DeepEqual(got, want) || db.writes != 0 || db.strings["health"] != marker {
				t.Fatal("exclusive server-time check changed state or admission", got)
			}
		})
	}
	for _, bad := range []struct{ keys, args []string }{
		{nil, []string{marker}}, {[]string{"health", "extra"}, []string{marker}}, {[]string{strings.Repeat("k", 257)}, []string{marker}}, {[]string{"health"}, nil}, {[]string{"health"}, []string{marker, marker}}, {[]string{"health"}, []string{strings.Repeat("x", 385)}},
	} {
		got, err := db.executeScript(currentCheckScript, bad.keys, bad.args)
		if err != nil || !reflect.DeepEqual(got, []string{"unavailable", ""}) || db.writes != 0 {
			t.Fatal("unbounded script request accepted", got, err)
		}
	}
}

func FuzzCurrentCheckReadOnly(f *testing.F) {
	marker := confirmedHealthFixture(commandPlan{epoch: strings.Repeat("1", 32)}, newScriptDB().now)
	for _, seed := range []string{"", marker, strings.Replace(marker, "confirmed|", "published|", 1), strings.Repeat("x", 385), marker + "|extra"} {
		f.Add(seed, marker)
	}
	f.Fuzz(func(t *testing.T, expected, stored string) {
		if len(expected) > 1024 || len(stored) > 1024 {
			t.Skip("bounded marker corpus")
		}
		db := newScriptDB()
		db.strings["health"] = stored
		got, err := db.executeScript(currentCheckScript, []string{"health"}, []string{expected})
		if err != nil || len(got) != 2 {
			t.Fatal("bounded marker caused script failure", err)
		}
		if db.writes != 0 || db.strings["health"] != stored {
			t.Fatal("current read mutated state")
		}
		if got[0] == "current" && (expected != stored || len(expected) > 384 || len(got[1]) != 64) {
			t.Fatal("foreign or oversized marker admitted")
		}
	})
}
