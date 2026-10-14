//go:build integration

package postgres

import (
	"bytes"
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// No Valkey state, fabricated recovery history or caller-provided result is
// involved: the durable adapter must charge and retain its own native outcome.
func TestDurableCounterFreshReplayAndContention(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	dsn := os.Getenv("IDENTITY_RISK_POSTGRES_TEST_DSN")
	c, err := pgx.ParseConfig(dsn)
	if dsn == "" || err != nil || c.Host != "127.0.0.1" || c.Database != "identity_test" {
		t.Fatal("explicit task-owned loopback database required")
	}
	admin, err := pgx.ConnectConfig(ctx, c)
	if err != nil {
		t.Fatal("fixture connection unavailable")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := admin.Close(cleanup); err != nil {
			t.Error("admin cleanup failed")
		}
	})
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	name := "durable_" + strings.ReplaceAll(string(id), "-", "_")
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal("fixture creation unavailable")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
			t.Error("fixture cleanup failed")
		}
	})
	pool, err := database.Connect(ctx, database.Config{DSN: dsn, MaxConns: 8, Configure: func(c *database.PoolConfig) error { c.ConnConfig.Database = name; return nil }})
	if err != nil {
		t.Fatal("fixture pool unavailable")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := pool.Close(cleanup); err != nil {
			t.Error("pool cleanup failed")
		}
	})
	history, err := (DurableCounterMigrationSource{Schema: "risk_store", Version: 1}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range history {
		if _, err := pool.Raw().Exec(ctx, m.UpSQL()); err != nil {
			t.Fatal("native migration unavailable")
		}
	}
	policy := protectedConfig(t).CommandCounters.Policy
	key, _ := risk.NewCounterDigestKey(7, bytes.Repeat([]byte{0x31}, 32))
	config := DurableCounterConfig{Pool: pool, Schema: "risk_store", Namespace: "b1", Policy: policy, Keys: []risk.CounterDigestKey{key}, ReplayKey: bytes.Repeat([]byte{0x54}, 32), Tenants: []string{"tenant"}, MaximumRecords: 1000, Timeout: 2 * time.Second}
	store, err := NewDurableCounterStore(config)
	if err != nil {
		t.Fatal(err)
	}
	prepare := func(attempt string) risk.CounterCommand {
		t.Helper()
		coordinator, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: policy, Keys: config.Keys, Store: store, Clock: time.Now, Timeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		command, err := coordinator.Prepare(risk.Context{Tenant: "tenant", Operation: "identity.password.signin", Attempt: attempt}, risk.Subject{Network: "127.0.0.1", Device: "browser", IdentifierDigest: strings.Repeat("a", 64)}, risk.BeforeCredential)
		if err != nil {
			t.Fatal(err)
		}
		return command
	}
	first := prepare("original")
	result, err := store.Mutate(ctx, first)
	outcome, original, declarationErr := result.Declaration(first)
	if err != nil || declarationErr != nil || outcome != risk.CounterCommitted || len(original) != 4 {
		t.Fatal("fresh durable counter did not commit")
	}
	for _, row := range original {
		if row.Value != 1 {
			t.Fatal("first attempt incorrectly charged")
		}
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			repeated, err := store.Mutate(ctx, first)
			_, snapshot, valid := repeated.Declaration(first)
			if err != nil || valid != nil || !velocitySnapshotsEqual(snapshot, original) {
				t.Error("matching replay changed original charge or freshness")
			}
		})
	}
	wg.Wait()
	second := prepare("next")
	result, err = store.Mutate(ctx, second)
	_, snapshot, valid := result.Declaration(second)
	if err != nil || valid != nil || len(snapshot) != 4 {
		t.Fatal("second charge unavailable")
	}
	for _, row := range snapshot {
		if row.Value != 2 {
			t.Fatal("replay double-debited durable counters")
		}
	}
	// A proved rollback cannot leak a partial window charge or a replay row.
	if _, err := pool.Raw().Exec(ctx, `CREATE FUNCTION risk_store.fail_durable_attempt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic durable rollback'; END $$; CREATE TRIGGER fail_durable_attempt BEFORE INSERT ON risk_store.durable_counter_attempts FOR EACH ROW EXECUTE FUNCTION risk_store.fail_durable_attempt()`); err != nil {
		t.Fatal("rollback injection unavailable")
	}
	third := prepare("rolled-back")
	if _, err := store.Mutate(ctx, third); err == nil {
		t.Fatal("failed outcome granted admission")
	}
	if _, err := pool.Raw().Exec(ctx, `DROP TRIGGER fail_durable_attempt ON risk_store.durable_counter_attempts; DROP FUNCTION risk_store.fail_durable_attempt()`); err != nil {
		t.Fatal("rollback fixture cleanup failed")
	}
	result, err = store.Mutate(ctx, third)
	_, snapshot, valid = result.Declaration(third)
	if err != nil || valid != nil {
		t.Fatal("proved rollback could not retry exact original")
	}
	for _, row := range snapshot {
		if row.Value != 3 {
			t.Fatal("rollback leaked counter charge")
		}
	}
	// Stable replay custody cannot be swapped to reset an existing namespace.
	changed := config
	changed.ReplayKey = bytes.Repeat([]byte{0x55}, 32)
	changedStore, err := NewDurableCounterStore(changed)
	if err != nil {
		t.Fatal(err)
	}
	if err := changedStore.Check(ctx, "tenant"); err == nil {
		t.Fatal("changed stable custody became ready")
	}
	if _, err := changedStore.Mutate(ctx, prepare("changed-custody")); err == nil {
		t.Fatal("changed stable custody reset admission")
	}
	// Capacity denies new work, preserving exact original replay at the bound.
	limited := config
	limited.MaximumRecords = 3
	limitedStore, err := NewDurableCounterStore(limited)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := limitedStore.Mutate(ctx, prepare("capacity")); err == nil {
		t.Fatal("capacity granted a new attempt")
	}
	if err := limitedStore.Check(ctx, "tenant"); err == nil {
		t.Fatal("full scope reported ready")
	}
	if _, err := limitedStore.Mutate(ctx, first); err != nil {
		t.Fatal("capacity erased existing outcome")
	}
	// Rotation must find the original window, not start an empty new-key window.
	newKey, _ := risk.NewCounterDigestKey(8, bytes.Repeat([]byte{0x32}, 32))
	rotatedConfig := config
	rotatedConfig.Keys = []risk.CounterDigestKey{newKey, key}
	rotated, err := NewDurableCounterStore(rotatedConfig)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: policy, Keys: rotatedConfig.Keys, Store: rotated, Clock: time.Now, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	rotatedCommand, err := coordinator.Prepare(risk.Context{Tenant: "tenant", Operation: "identity.password.signin", Attempt: "rotated"}, risk.Subject{Network: "127.0.0.1", Device: "browser", IdentifierDigest: strings.Repeat("a", 64)}, risk.BeforeCredential)
	if err != nil {
		t.Fatal(err)
	}
	result, err = rotated.Mutate(ctx, rotatedCommand)
	_, snapshot, valid = result.Declaration(rotatedCommand)
	if err != nil || valid != nil {
		t.Fatal("retained-key rotation unavailable")
	}
	for _, row := range snapshot {
		if row.Value != 4 {
			t.Fatal("rotation restarted existing window")
		}
	}
	if _, err := store.Mutate(ctx, first); err == nil {
		t.Fatal("old owner replay ignored authoritative rotation")
	}
	removed := rotatedConfig
	removed.Keys = []risk.CounterDigestKey{newKey}
	removedStore, err := NewDurableCounterStore(removed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := removedStore.Mutate(ctx, rotatedCommand); err == nil {
		t.Fatal("removed keys admitted old command")
	}
	if _, err := store.Mutate(ctx, risk.CounterCommand{}); err == nil {
		t.Fatal("zero command admitted")
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if _, err := store.Mutate(cancelled, prepare("cancelled")); err == nil {
		t.Fatal("cancelled counter mutation admitted")
	}
}
