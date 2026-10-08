package valkey

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/risk"
)

// Primary checks are simulated at the deliberate owned core boundary. The
// actual native transport and Lua execute; this does not prove live Valkey.
func TestOwnedNativeCurrentAdmission(t *testing.T) {
	for _, mode := range []string{"healthy", "primary_before", "primary_after", "wrong_marker", "missing_marker", "lost_reply", "foreign_tenant", "foreign_graph", "zero", "zero_owner", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			f := newConfirmationFixture(t, 0)
			ack, err := f.owner.confirmed(context.Background(), f.lease, f.closure, f.publication, f.confirmation)
			if err != nil {
				t.Fatal(err)
			}
			health, err := f.journal.AcknowledgeEligibility(context.Background(), f.lease, f.closure, f.publication, f.confirmation, ack, func(context.Context) error {
				if mode != "healthy" && f.lost[0].Load() {
					return errors.New("private primary failure")
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			// Activation must not revive replay-only callbacks. Healthy traffic
			// needs only its distinct current-primary checker and immutable chain.
			f.lost[1].Store(true)
			f.lost[2].Store(true)
			if mode == "healthy" || mode == "primary_before" {
				f.lost[0].Store(true)
			}
			if mode == "primary_after" {
				f.mode.Store(1)
			}
			if mode == "lost_reply" {
				f.mode.Store(5)
			}
			if mode == "wrong_marker" {
				fields := strings.Split(f.db.strings[f.plan.keys[0]], "|")
				fields[5] = strings.Repeat("a", 64)
				f.db.strings[f.plan.keys[0]] = strings.Join(fields, "|")
			}
			if mode == "missing_marker" {
				delete(f.db.strings, f.plan.keys[0])
			}
			if mode == "zero" {
				health = risk.VelocityEligibility{}
			}
			ownerValue := f.owner
			if mode == "zero_owner" {
				ownerValue = ownedRecovery{}
			}
			if mode == "foreign_graph" {
				_, _, foreign, _ := risk.NewVelocityRecoveryAuthorities()
				ownerValue, err = newOwnedRecovery(f.owner.layout, f.owner.transport, foreign)
				if err != nil {
					t.Fatal(err)
				}
			}
			owner, ok := any(ownerValue).(interface {
				mutateCurrent(context.Context, risk.CounterCommand, risk.VelocityLease, risk.VelocityClosure, risk.VelocityPublication, risk.VelocityConfirmation, risk.VelocityNativeConfirmation, risk.VelocityEligibility) (risk.CounterResult, error)
			})
			if !ok {
				t.Fatal("native owner has no current-primary admission boundary")
			}
			c, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{
				Policy: f.owner.layout.policy, Keys: f.owner.layout.keys,
				Clock: func() time.Time { return time.UnixMicro(f.db.now) }, Timeout: time.Second,
				Store: replyStoreFunc(func(ctx context.Context, command risk.CounterCommand) (risk.CounterResult, error) {
					return owner.mutateCurrent(ctx, command, f.lease, f.closure, f.publication, f.confirmation, ack, health)
				}),
			})
			if err != nil {
				t.Fatal(err)
			}
			tenant := "tenant"
			if mode == "foreign_tenant" {
				tenant = "other-tenant"
			}
			command := prepareFixture(t, c, tenant, "new-current-attempt", "192.0.2.1")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "canceled" {
				cancel()
			}
			before, expiry, writes := cloneScriptStrings(f.db.strings), cloneScriptExpiry(f.db.expiry), f.db.writes
			got, err := c.Mutate(ctx, command)
			if mode == "healthy" {
				if err != nil || got.Outcome != risk.CounterCommitted || got.Signal.State != risk.SignalClean {
					t.Fatal("current health did not admit complete native debit", err, got.Outcome)
				}
				if f.db.strings[f.plan.keys[0]] != before[f.plan.keys[0]] || f.db.expiry[f.plan.keys[0]] != expiry[f.plan.keys[0]] {
					t.Fatal("debit renewed health custody")
				}
				post, postExpiry, postWrites := cloneScriptStrings(f.db.strings), cloneScriptExpiry(f.db.expiry), f.db.writes
				f.db.now++
				replayed, err := c.Mutate(ctx, command)
				if err != nil || replayed.Outcome != risk.CounterCommitted || !got.Signal.ObservedAt.Equal(replayed.Signal.ObservedAt) || !got.Signal.ExpiresAt.Equal(replayed.Signal.ExpiresAt) || !reflect.DeepEqual(post, f.db.strings) || !reflect.DeepEqual(postExpiry, f.db.expiry) || postWrites != f.db.writes {
					t.Fatal("same command replay changed original effect", err)
				}
				return
			}
			if mode == "canceled" {
				if !errors.Is(err, context.Canceled) || writes != f.db.writes {
					t.Fatal("canceled command reached native work", err)
				}
				return
			}
			if got.Signal.State != risk.SignalUnavailable {
				t.Fatal("failed current custody granted admission", err, got.Signal.State)
			}
			if mode == "primary_after" {
				if got.Outcome != risk.CounterCommitted || f.db.writes <= writes {
					t.Fatal("later primary loss erased acknowledged native effect", err)
				}
			} else if mode != "lost_reply" && (!reflect.DeepEqual(before, f.db.strings) || !reflect.DeepEqual(expiry, f.db.expiry) || writes != f.db.writes) {
				t.Fatal("denied current custody wrote native state", err)
			}
		})
	}
}
