//go:build integration

package postgres

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/delivery"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

func TestDeliveryStateMigrationPreservesPopulatedHistoryAndOldWriters(t *testing.T) {
	ctx, pool := intentDatabase(t)
	if _, err := pool.Exec(ctx, attemptSchemaSQL); err != nil {
		t.Fatal(err)
	}
	s, prepared := preparedFixture(t, false)
	seedIntentCommand(t, ctx, pool, prepared)
	tx := beginIntentTestTransaction(t, ctx, pool)
	if err := persistInTestTransaction(ctx, s, []preparedIntent{prepared}, tx); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	base := MigrationSource{Base: identitypostgres.MigrationSource{}, Version: 10, WorkerVersion: 11, PolicyVersion: 12, KeyedVersion: 13}
	old, err := base.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	base.StateVersion = 14
	current, err := base.Load(ctx)
	if err != nil || len(current) != len(old)+1 {
		t.Fatal("forward state history", err)
	}
	for n, m := range old {
		if m.Checksum() != current[n].Checksum() {
			t.Fatal("installed history changed")
		}
	}
	if current[len(old)].DownSQL() != "" {
		t.Fatal("state migration exposes destructive rollback")
	}
	if _, err := pool.Exec(ctx, current[len(old)].UpSQL()); err != nil {
		t.Fatal("populated state migration", err)
	}
	var version string
	var unchanged bool
	if err := pool.QueryRow(ctx, `SELECT status_version::text,local_stop_state IS NULL AND local_stop_at IS NULL AND binding_aad=$1 AND intent_digest=$2 AND ciphertext=$3 FROM identity.delivery_intents`, prepared.aad, prepared.binding.Intent.IntentDigest[:], prepared.envelope.Ciphertext).Scan(&version, &unchanged); err != nil || version != "1" || !unchanged {
		t.Fatal("migration reinterpreted existing custody", err)
	}
	worker, err := newAttemptStore(pool, "test", s.codec, delivery.DefaultConfig(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := worker.Claim(ctx, delivery.ClaimRequest{TenantID: "tenant-a", WorkerID: "legacy-worker"})
	if err != nil || !claim.Claimed {
		t.Fatal("legacy worker claim", err)
	}
	if err := pool.QueryRow(ctx, `SELECT status_version::text FROM identity.delivery_intents`).Scan(&version); err != nil || version != "2" {
		t.Fatal("legacy claim lost monotonic version", err)
	}
	if _, err := worker.Complete(ctx, delivery.CompleteRequest{TenantID: "tenant-a", IntentID: claim.Attempt.IntentID, Generation: 1, WorkerID: "legacy-worker", Invoked: true, Result: delivery.DeliveryResult{State: delivery.StateDelivered, ObservedAt: time.Now().UTC()}}); err != nil {
		t.Fatal("legacy completion", err)
	}
	if err := pool.QueryRow(ctx, `SELECT status_version::text,state='confirmed' AND ciphertext IS NULL FROM identity.delivery_intents`).Scan(&version, &unchanged); err != nil || version != "3" || !unchanged {
		t.Fatal("legacy completion lost version/erasure", err)
	}
	for _, sql := range []string{`UPDATE identity.delivery_intents SET status_version=10`, `UPDATE identity.delivery_intents SET local_stop_state='cancelled',local_stop_at=clock_timestamp()`} {
		if _, err := pool.Exec(ctx, sql); err == nil {
			t.Fatal("version or foreign no-op checkpoint was writable")
		}
	}
	start := make(chan struct{})
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			<-start
			if _, err := pool.Exec(ctx, `UPDATE identity.delivery_intents SET state=state`); err != nil {
				t.Error("concurrent metadata write", err)
			}
		})
	}
	close(start)
	group.Wait()
	if err := pool.QueryRow(ctx, `SELECT status_version::text,state='confirmed' AND ciphertext IS NULL FROM identity.delivery_intents`).Scan(&version, &unchanged); err != nil || version != "11" || !unchanged {
		t.Fatal("concurrent writers lost a version or terminal state", err)
	}
}

func TestDeliveryNoOpStopCheckpointSurvivesExpiry(t *testing.T) {
	for _, expiredFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel-before-expiry", true: "expired-first"}[expiredFirst], func(t *testing.T) { testDeliveryNoOpStop(t, expiredFirst) })
	}
}

func testDeliveryNoOpStop(t *testing.T, expiredFirst bool) {
	t.Helper()
	ctx, pool := intentDatabase(t)
	if _, err := pool.Exec(ctx, attemptSchemaSQL+stateSchemaSQL); err != nil {
		t.Fatal(err)
	}
	s, p := preparedFixtureExpiry(t, true, time.Second)
	seedIntentCommand(t, ctx, pool, p)
	tx := beginIntentTestTransaction(t, ctx, pool)
	if err := persistInTestTransaction(ctx, s, []preparedIntent{p}, tx); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	worker, err := newAttemptStore(pool, "test", s.codec, delivery.DefaultConfig(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	q := delivery.CancelRequest{TenantID: "tenant-a", IntentID: delivery.IntentID(p.binding.Intent.EffectID), Reason: "workflow-cancel"}
	want := delivery.CancelResult{State: delivery.StateCancelled, LocalCancelled: true}
	if expiredFirst {
		if _, err := pool.Exec(ctx, `SELECT pg_sleep(GREATEST(EXTRACT(EPOCH FROM($1::timestamptz-clock_timestamp()))+0.002,0))`, p.binding.Intent.ExpiresAt); err != nil {
			t.Fatal(err)
		}
		want = delivery.CancelResult{State: delivery.StateExpired}
	}
	got, err := worker.cancelTracked(ctx, q, "user-a")
	if err != nil || got != want {
		t.Fatal("no-op stop failed", err)
	}
	var version string
	var at time.Time
	if err := pool.QueryRow(ctx, `SELECT status_version::text,local_stop_at FROM identity.delivery_intents`).Scan(&version, &at); err != nil || version != "2" {
		t.Fatal("no-op stop was not durable", err)
	}
	// Expiry comes from database time; the context bounds the test-only wait.
	if _, err := pool.Exec(ctx, `SELECT pg_sleep(GREATEST(EXTRACT(EPOCH FROM($1::timestamptz-clock_timestamp()))+0.002,0))`, p.binding.Intent.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	if got, err := worker.cancelTracked(ctx, q, "user-a"); err != nil || got != want {
		t.Fatal("no-op replay became expiry existence oracle", err)
	}
	var after time.Time
	if err := pool.QueryRow(ctx, `SELECT status_version::text,local_stop_at FROM identity.delivery_intents`).Scan(&version, &after); err != nil || version != "2" || !after.Equal(at) {
		t.Fatal("replay renewed checkpoint", err)
	}
	otherState := "expired"
	if expiredFirst {
		otherState = "cancelled"
	}
	for _, sql := range []string{`UPDATE identity.delivery_intents SET local_stop_state=NULL,local_stop_at=NULL`, "UPDATE identity.delivery_intents SET local_stop_state='" + otherState + "'", `UPDATE identity.delivery_intents SET local_stop_at=clock_timestamp()`} {
		if _, err := pool.Exec(ctx, sql); err == nil {
			t.Fatal("local stop checkpoint rewritten")
		}
	}
	bad := q
	bad.ExpectedGeneration = 1
	if _, err := worker.cancelTracked(ctx, bad, "user-a"); !errors.Is(err, delivery.ErrConflict) {
		t.Fatal("no-op invented an attempt generation", err)
	}
}
