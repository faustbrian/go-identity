package valkey

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/risk/internal/velocity"
)

// Primary eligibility is a deliberate double. Native transport/Lua and public
// health admission are real; joint durable composition is separate evidence.
func TestPublicVelocityCurrentHealthIsReadOnly(t *testing.T) {
	for _, mode := range []string{"healthy", "zero_owner", "zero_journal", "foreign_graph", "foreign_namespace", "nil_context", "canceled", "closed", "primary_before", "primary_after", "missing", "wrong_type", "foreign_cut", "published", "expired", "before_cut", "lost_reply", "changed_boot"} {
		t.Run(mode, func(t *testing.T) {
			f := newConfirmationFixture(t, 1)
			owner := VelocityRecovery{state: &f.owner}
			ack, err := owner.Confirm(t.Context(), f.lease, f.closure, f.publication, f.confirmation)
			if err != nil {
				t.Fatal(err)
			}
			var unavailable atomic.Bool
			eligible, err := f.journal.AcknowledgeEligibility(t.Context(), f.lease, f.closure, f.publication, f.confirmation, ack, func(context.Context) error {
				if unavailable.Load() {
					return errors.New("simulated primary unavailable")
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			journal, err := velocity.BindJournal(f.owner.layout.replay.Namespace(), func(risk.CounterCommand) error { panic("health validated a command") }, func(context.Context, risk.CounterCommand) error { panic("health read command custody") }, func(context.Context, risk.CounterCommand) (velocity.Attempt, error) { panic("health wrote intent") }, func(context.Context, risk.CounterCommand) (risk.CounterResult, error) { panic("health read replay") })
			if err != nil {
				t.Fatal(err)
			}
			verifier, _ := f.native.Verifier()
			journal, err = velocity.BindCurrentJournal(t.Context(), journal, f.owner.reader, verifier, velocity.CurrentChain{Lease: f.lease, Closure: f.closure, Publication: f.publication, Confirmation: f.confirmation, Native: ack, Eligibility: eligible})
			if err != nil {
				t.Fatal(err)
			}
			// Replay-only eligibility must not be revived by health inspection.
			for i := range f.lost {
				f.lost[i].Store(true)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			key := f.plan.keys[0]
			switch mode {
			case "zero_owner":
				owner = VelocityRecovery{}
			case "zero_journal":
				journal = velocity.Journal{}
			case "foreign_graph":
				copy := f.owner
				_, _, copy.issuer, _ = risk.NewVelocityRecoveryAuthorities()
				owner.state = &copy
			case "foreign_namespace":
				copy := f.owner
				copy.layout.replay, err = risk.NewVelocityReplayIdentity("foreign-health", copy.layout.secret)
				if err != nil {
					t.Fatal(err)
				}
				owner.state = &copy
			case "nil_context":
				ctx = nil
			case "canceled":
				cancel()
			case "closed":
				if err := owner.Close(t.Context()); err != nil {
					t.Fatal(err)
				}
			case "primary_before":
				unavailable.Store(true)
			case "primary_after":
				original := f.wire.reply
				f.wire.reply = func(request []string) string {
					response := original(request)
					if len(request) > 1 && request[1] == currentCheckScript {
						unavailable.Store(true)
					}
					return response
				}
			case "missing":
				delete(f.db.strings, key)
			case "wrong_type":
				delete(f.db.strings, key)
				f.db.hashes[key] = map[string]string{"foreign": "value"}
			case "foreign_cut":
				fields := strings.Split(f.db.strings[key], "|")
				fields[5] = strings.Repeat("a", 64)
				f.db.strings[key] = strings.Join(fields, "|")
			case "published":
				f.db.strings[key] = strings.Replace(f.db.strings[key], "confirmed|", "published|", 1)
			case "expired":
				fields := strings.Split(f.db.strings[key], "|")
				f.db.now, _ = strconv.ParseInt(fields[4], 10, 64)
				f.db.expiry[key] = f.db.now/1000 + 60000
			case "before_cut":
				f.db.now = f.binding.ReplayThrough.UnixMicro() - 1
			case "lost_reply":
				f.mode.Store(5)
			case "changed_boot":
				f.wire.mu.Lock()
				f.wire.profileReply = func() string { return nativeArray([]string{strings.Repeat("c", 40), "0"}) }
				f.wire.mu.Unlock()
			}
			checker, ok := any(owner).(interface {
				CheckCurrent(context.Context, velocity.Journal) error
			})
			if !ok {
				t.Fatal("native owner lacks public read-only current health")
			}
			before, expiry, writes := cloneScriptStrings(f.db.strings), cloneScriptExpiry(f.db.expiry), f.db.writes
			err = checker.CheckCurrent(ctx, journal)
			if mode == "healthy" {
				if err != nil {
					t.Fatal("current health denied", err)
				}
				if err := checker.CheckCurrent(ctx, journal); err != nil {
					t.Fatal("health repeat denied", err)
				}
			} else if err == nil {
				t.Fatal("invalid current health admitted", mode)
			}
			if mode == "canceled" && !errors.Is(err, context.Canceled) {
				t.Fatal("health cancellation lost", err)
			}
			if !reflect.DeepEqual(before, f.db.strings) || !reflect.DeepEqual(expiry, f.db.expiry) || writes != f.db.writes {
				t.Fatal("health changed native state or expiry")
			}
		})
	}
}
