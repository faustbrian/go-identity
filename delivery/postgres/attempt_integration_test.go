//go:build integration

package postgres

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/delivery"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

type attemptTestSender func(context.Context, delivery.Attempt) (delivery.DeliveryResult, error)

func (s attemptTestSender) Send(ctx context.Context, a delivery.Attempt) (delivery.DeliveryResult, error) {
	return s(ctx, a)
}

func TestDurableAttemptSingleClaimAndCompletionReplay(t *testing.T) {
	ctx, pool := intentDatabase(t)
	if _, err := pool.Exec(ctx, attemptSchemaSQL); err != nil {
		t.Fatal("worker migration failed", err)
	}
	s, prepared := preparedFixture(t, false)
	seedIntentCommand(t, ctx, pool, prepared)
	tx := beginIntentTestTransaction(t, ctx, pool)
	if err := persistInTestTransaction(ctx, s, []preparedIntent{prepared}, tx); err != nil {
		t.Fatal(err)
	}
	if tx.Commit(ctx) != nil {
		t.Fatal("admission commit failed")
	}
	worker, err := newAttemptStore(pool, "test", s.codec, delivery.DefaultConfig(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if c, err := worker.Claim(ctx, delivery.ClaimRequest{TenantID: "tenant-other", WorkerID: "worker-a"}); err != nil || c.Claimed {
		t.Fatal("cross tenant claim", err)
	}
	start := make(chan struct{})
	var group sync.WaitGroup
	var count atomic.Int32
	var winner delivery.ClaimResult
	for range 8 {
		group.Go(func() {
			<-start
			claim, err := worker.Claim(ctx, delivery.ClaimRequest{TenantID: "tenant-a", WorkerID: "worker-a"})
			if err != nil {
				t.Error("claim failed", err)
				return
			}
			if claim.Claimed {
				count.Add(1)
				winner = claim
			}
		})
	}
	close(start)
	group.Wait()
	if count.Load() != 1 || winner.Attempt.Generation != 1 {
		t.Fatal("claim did not fence one original attempt")
	}
	var attempts int
	var state string
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.delivery_attempt_history),state FROM identity.delivery_intents`).Scan(&attempts, &state); err != nil || attempts != 1 || state != "submitted" {
		t.Fatal("attempt was not committed before plaintext handoff", err)
	}
	var sender delivery.Sender = attemptTestSender(func(ctx context.Context, a delivery.Attempt) (delivery.DeliveryResult, error) {
		if pool.Stat().AcquiredConns() != 0 {
			t.Fatal("Sender entered with adapter transaction still acquired")
		}
		check := beginIntentTestTransaction(t, ctx, pool)
		if _, err := check.Exec(ctx, `SELECT effect_id FROM identity.delivery_intents FOR UPDATE NOWAIT`); err != nil {
			t.Fatal("Sender ran under invocation locks", err)
		}
		if check.Rollback(ctx) != nil {
			t.Fatal("sender observation rollback")
		}
		if a.Body == "" || a.Generation != 1 {
			t.Fatal("Sender did not receive original rendered attempt")
		}
		return delivery.DeliveryResult{State: delivery.StateDelivered, ProviderReference: "synthetic-private-provider-reference", ObservedAt: time.Now().UTC()}, nil
	})
	observed, err := sender.Send(ctx, winner.Attempt)
	if err != nil {
		t.Fatal("sender", err)
	}
	request := delivery.CompleteRequest{TenantID: winner.Attempt.TenantID, IntentID: winner.Attempt.IntentID, WorkerID: "worker-a", Generation: 1, Invoked: true, Result: observed}
	result, err := worker.Complete(ctx, request)
	if err != nil || result.Commit != delivery.CommitCommitted || result.State != delivery.StateDelivered {
		t.Fatal("completion failed", err)
	}
	again, err := worker.Complete(ctx, request)
	if err != nil || again != result {
		t.Fatal("completion did not replay", err)
	}
	request.Result.State = delivery.StateRejected
	if _, err := worker.Complete(ctx, request); !errors.Is(err, delivery.ErrConflict) {
		t.Fatal("changed completion replay accepted", err)
	}
	var erased bool
	if err := pool.QueryRow(ctx, `SELECT state,ciphertext IS NULL AND envelope_key_id IS NULL AND payload_erased_at IS NOT NULL FROM identity.delivery_intents`).Scan(&state, &erased); err != nil || state != "confirmed" || !erased {
		t.Fatal("delivery did not erase custody atomically", err)
	}
	if c, err := worker.Claim(ctx, delivery.ClaimRequest{TenantID: "tenant-a", WorkerID: "worker-a"}); err != nil || c.Claimed {
		t.Fatal("terminal intent claimed", err)
	}
}

func TestDurableAttemptMigrationPreservesPopulatedAdmission(t *testing.T) {
	ctx, pool := intentDatabase(t)
	s, p := preparedFixture(t, false)
	seedIntentCommand(t, ctx, pool, p)
	tx := beginIntentTestTransaction(t, ctx, pool)
	if err := persistInTestTransaction(ctx, s, []preparedIntent{p}, tx); err != nil {
		t.Fatal(err)
	}
	if tx.Commit(ctx) != nil {
		t.Fatal("commit")
	}
	history, err := (MigrationSource{Base: identitypostgres.MigrationSource{}, Version: 10, WorkerVersion: 11}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, history[len(history)-1].UpSQL()); err != nil {
		t.Fatal("populated extension", err)
	}
	w, err := newAttemptStore(pool, "test", s.codec, delivery.DefaultConfig(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if c, err := w.Claim(ctx, delivery.ClaimRequest{TenantID: "tenant-a", WorkerID: "worker-a"}); err != nil || !c.Claimed || c.Attempt.IntentID != delivery.IntentID(p.binding.Intent.EffectID) {
		t.Fatal("installed admitted effect lost", err)
	}
}

func TestDurableAttemptCompletionClassificationsRemainDistinct(t *testing.T) {
	for _, test := range []struct {
		name                      string
		input                     delivery.DeliveryState
		invoked, cancelled, erase bool
		want                      delivery.DeliveryState
		durable                   string
	}{
		{"accepted-not-delivered", delivery.StateAccepted, true, false, false, delivery.StateAccepted, "submitted"},
		{"bounced", delivery.StateBounced, true, false, true, delivery.StateBounced, "rejected"},
		{"permanent-rejection", delivery.StateRejected, true, false, true, delivery.StateRejected, "rejected"},
		{"prevented-invocation", 0, false, false, false, delivery.StateRetryWait, "retry-wait"},
		{"cancelled-no-effect", delivery.StateTransientFailure, true, true, true, delivery.StateCancelled, "cancelled"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, pool := intentDatabase(t)
			if _, err := pool.Exec(ctx, attemptSchemaSQL); err != nil {
				t.Fatal(err)
			}
			s, p := preparedFixture(t, false)
			seedIntentCommand(t, ctx, pool, p)
			tx := beginIntentTestTransaction(t, ctx, pool)
			if err := persistInTestTransaction(ctx, s, []preparedIntent{p}, tx); err != nil {
				t.Fatal(err)
			}
			if tx.Commit(ctx) != nil {
				t.Fatal("commit")
			}
			w, err := newAttemptStore(pool, "test", s.codec, delivery.DefaultConfig(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			c, err := w.Claim(ctx, delivery.ClaimRequest{TenantID: "tenant-a", WorkerID: "worker-a"})
			if err != nil || !c.Claimed {
				t.Fatal("claim", err)
			}
			if test.cancelled {
				if _, err := pool.Exec(ctx, `UPDATE identity.delivery_processing SET cancel_requested=true`); err != nil {
					t.Fatal(err)
				}
			}
			r := delivery.CompleteRequest{TenantID: "tenant-a", IntentID: c.Attempt.IntentID, WorkerID: "worker-a", Generation: 1, Invoked: test.invoked}
			if test.invoked {
				r.Result = delivery.DeliveryResult{State: test.input, ObservedAt: time.Now().UTC()}
			}
			foreign := r
			foreign.WorkerID = "worker-other"
			if _, err := w.Complete(ctx, foreign); !errors.Is(err, delivery.ErrConflict) {
				t.Fatal("foreign worker completed", err)
			}
			foreign = r
			foreign.TenantID = "tenant-other"
			if _, err := w.Complete(ctx, foreign); !errors.Is(err, delivery.ErrConflict) {
				t.Fatal("foreign tenant completed", err)
			}
			out, err := w.Complete(ctx, r)
			if err != nil || out.State != test.want || out.Commit != delivery.CommitCommitted {
				t.Fatal("completion classification", err)
			}
			var state string
			var erased bool
			var leased bool
			if err := pool.QueryRow(ctx, `SELECT i.state,i.ciphertext IS NULL,p.lease_owner IS NOT NULL FROM identity.delivery_intents i JOIN identity.delivery_processing p USING(deployment,tenant_id,effect_id)`).Scan(&state, &erased, &leased); err != nil || state != test.durable || erased != test.erase || leased {
				t.Fatal("atomic outcome classification", err)
			}
		})
	}
}

func TestDurableAttemptUnknownAndLeaseLossNeverResubmit(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(map[bool]string{false: "provider-unknown", true: "lost-lease"}[lost], func(t *testing.T) {
			ctx, pool := intentDatabase(t)
			if _, err := pool.Exec(ctx, attemptSchemaSQL); err != nil {
				t.Fatal(err)
			}
			s, p := preparedFixture(t, false)
			seedIntentCommand(t, ctx, pool, p)
			tx := beginIntentTestTransaction(t, ctx, pool)
			if err := persistInTestTransaction(ctx, s, []preparedIntent{p}, tx); err != nil {
				t.Fatal(err)
			}
			if tx.Commit(ctx) != nil {
				t.Fatal("commit")
			}
			worker, err := newAttemptStore(pool, "test", s.codec, delivery.DefaultConfig(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			request := delivery.ClaimRequest{TenantID: "tenant-a", WorkerID: "worker-a"}
			claim, err := worker.Claim(ctx, request)
			if err != nil || !claim.Claimed {
				t.Fatal("claim", err)
			}
			complete := delivery.CompleteRequest{TenantID: "tenant-a", IntentID: claim.Attempt.IntentID, WorkerID: "worker-a", Generation: claim.Attempt.Generation, Invoked: true, Result: delivery.DeliveryResult{State: delivery.StateOutcomeUnknown, ObservedAt: time.Now().UTC()}}
			if lost {
				if _, err := pool.Exec(ctx, `UPDATE identity.delivery_processing SET lease_until=clock_timestamp()-INTERVAL '1 second'`); err != nil {
					t.Fatal(err)
				}
				if _, err := worker.Complete(ctx, complete); !errors.Is(err, delivery.ErrConflict) {
					t.Fatal("expired worker completed", err)
				}
			} else {
				result, err := worker.Complete(ctx, complete)
				if err != nil || result.State != delivery.StateOutcomeUnknown {
					t.Fatal("unknown completion", err)
				}
			}
			for range 2 {
				if c, err := worker.Claim(ctx, request); err != nil || c.Claimed {
					t.Fatal("ambiguous provider work blindly resubmitted", err)
				}
			}
			var state string
			if err := pool.QueryRow(ctx, `SELECT state FROM identity.delivery_intents`).Scan(&state); err != nil || state != "outcome-unknown" {
				t.Fatal("ambiguity not durable", err)
			}
		})
	}
}

func TestDurableAttemptAuthoritativeFailureUsesCorePolicy(t *testing.T) {
	ctx, pool := intentDatabase(t)
	if _, err := pool.Exec(ctx, attemptSchemaSQL); err != nil {
		t.Fatal(err)
	}
	s, p := preparedFixture(t, false)
	seedIntentCommand(t, ctx, pool, p)
	tx := beginIntentTestTransaction(t, ctx, pool)
	if err := persistInTestTransaction(ctx, s, []preparedIntent{p}, tx); err != nil {
		t.Fatal(err)
	}
	if tx.Commit(ctx) != nil {
		t.Fatal("commit")
	}
	config := delivery.DefaultConfig()
	config.Attempts = 2
	config.BackoffCeilings = []time.Duration{0, time.Nanosecond}
	w, err := newAttemptStore(pool, "test", s.codec, config, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	q := delivery.ClaimRequest{TenantID: "tenant-a", WorkerID: "worker-a"}
	first, err := w.Claim(ctx, q)
	if err != nil || !first.Claimed {
		t.Fatal(err)
	}
	r := delivery.CompleteRequest{TenantID: "tenant-a", IntentID: first.Attempt.IntentID, WorkerID: q.WorkerID, Generation: 1, Invoked: true, Result: delivery.DeliveryResult{State: delivery.StateTransientFailure, ObservedAt: time.Now().UTC()}}
	result, err := w.Complete(ctx, r)
	if err != nil || result.State != delivery.StateRetryWait {
		t.Fatal("transient retry", err)
	}
	second, err := w.Claim(ctx, q)
	if err != nil || !second.Claimed || second.Attempt.Generation != 2 || second.Attempt.IdempotencyKey != first.Attempt.IdempotencyKey || second.Attempt.Body != first.Attempt.Body {
		t.Fatal("retry changed original effect", err)
	}
	stale := r
	stale.Result.ObservedAt = time.Now().UTC()
	if _, err := w.Complete(ctx, stale); !errors.Is(err, delivery.ErrConflict) {
		t.Fatal("stale generation rewrote current attempt", err)
	}
	r.Generation = 2
	r.Result.ObservedAt = time.Now().UTC()
	reconfigured, err := newAttemptStore(pool, "test", s.codec, delivery.DefaultConfig(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reconfigured.Complete(ctx, r); !errors.Is(err, delivery.ErrConflict) {
		t.Fatal("restart reinterpreted original retry policy", err)
	}
	result, err = w.Complete(ctx, r)
	if err != nil || result.State != delivery.StateExhausted {
		t.Fatal("attempt bound", err)
	}
	if c, err := w.Claim(ctx, q); err != nil || c.Claimed {
		t.Fatal("exhausted retry", err)
	}
}

func TestDurableAttemptNoOpNeverHandsOffPlaintext(t *testing.T) {
	ctx, pool := intentDatabase(t)
	if _, err := pool.Exec(ctx, attemptSchemaSQL); err != nil {
		t.Fatal(err)
	}
	s, p := preparedFixture(t, true)
	seedIntentCommand(t, ctx, pool, p)
	tx := beginIntentTestTransaction(t, ctx, pool)
	if err := persistInTestTransaction(ctx, s, []preparedIntent{p}, tx); err != nil {
		t.Fatal(err)
	}
	if tx.Commit(ctx) != nil {
		t.Fatal("commit")
	}
	w, err := newAttemptStore(pool, "test", s.codec, delivery.DefaultConfig(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if c, err := w.Claim(ctx, delivery.ClaimRequest{TenantID: "tenant-a", WorkerID: "worker-a"}); err != nil || c.Claimed {
		t.Fatal("no-op custody handed to worker", err)
	}
	// Context cancellation is preserved without inventing a provider result.
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := w.Claim(cancelled, delivery.ClaimRequest{TenantID: "tenant-a", WorkerID: "worker-a"}); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled claim", err)
	}
}

func TestDurableAttemptExpiryErasesWithoutInventingProviderOutcome(t *testing.T) {
	for _, invoked := range []bool{false, true} {
		t.Run(map[bool]string{false: "never-submitted", true: "expired-invocation"}[invoked], func(t *testing.T) {
			ctx, pool := intentDatabase(t)
			if _, err := pool.Exec(ctx, attemptSchemaSQL); err != nil {
				t.Fatal(err)
			}
			s, p := preparedFixtureExpiry(t, false, time.Second)
			seedIntentCommand(t, ctx, pool, p)
			tx := beginIntentTestTransaction(t, ctx, pool)
			if err := persistInTestTransaction(ctx, s, []preparedIntent{p}, tx); err != nil {
				t.Fatal(err)
			}
			if tx.Commit(ctx) != nil {
				t.Fatal("commit")
			}
			w, err := newAttemptStore(pool, "test", s.codec, delivery.DefaultConfig(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			q := delivery.ClaimRequest{TenantID: "tenant-a", WorkerID: "worker-a"}
			if invoked {
				if c, err := w.Claim(ctx, q); err != nil || !c.Claimed {
					t.Fatal("initial claim", err)
				}
			}
			if _, err := pool.Exec(ctx, `SELECT pg_sleep(1.05)`); err != nil {
				t.Fatal("expiry wait", err)
			}
			if c, err := w.Claim(ctx, q); err != nil || c.Claimed {
				t.Fatal("expired effect claimed", err)
			}
			var state string
			var erased bool
			if err := pool.QueryRow(ctx, `SELECT state,ciphertext IS NULL AND envelope_key_id IS NULL AND payload_erased_at IS NOT NULL FROM identity.delivery_intents`).Scan(&state, &erased); err != nil || !erased {
				t.Fatal("expired bearer custody retained", err)
			}
			want := "expired"
			if invoked {
				want = "outcome-unknown"
			}
			if state != want {
				t.Fatal("expiry fabricated provider failure", state)
			}
		})
	}
}
