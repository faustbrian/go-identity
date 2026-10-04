//go:build integration

package postgres

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/delivery"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	outboxpostgres "github.com/faustbrian/go-transactional-outbox/v2/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These real-PostgreSQL checks exercise this owner's SQL and outbox bridge.
// They do not claim public Queue, command admission, lease or provider proof.
func intentDatabase(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	config, err := pgxpool.ParseConfig(os.Getenv("IDENTITY_TEST_POSTGRES_DSN"))
	if err != nil || config.ConnConfig.Host != "127.0.0.1" || config.ConnConfig.Database != "identity_test" {
		t.Fatal("task-owned PostgreSQL DSN required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	admin, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal("test cluster connection failed")
	}
	var id [12]byte
	if _, err := rand.Read(id[:]); err != nil {
		admin.Close()
		t.Fatal("test identifier failed")
	}
	name := "delivery_" + hex.EncodeToString(id[:])
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		admin.Close()
		t.Fatal("test database creation failed")
	}
	config.ConnConfig.Database = name
	var pool *pgxpool.Pool
	t.Cleanup(func() {
		if pool != nil {
			pool.Close()
		}
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); err != nil {
			t.Error("test database cleanup failed")
		}
		admin.Close()
	})
	pool, err = pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal("test database connection failed")
	}
	history, err := (identitypostgres.MigrationSource{}).Load(ctx)
	if err != nil {
		t.Fatal("kernel migration load failed")
	}
	for _, m := range history {
		if _, err := pool.Exec(ctx, m.UpSQL()); err != nil {
			t.Fatal("kernel migration install failed")
		}
	}
	data, err := fs.ReadFile(outboxpostgres.Migrations(), "000001_create_outbox.sql")
	if err != nil {
		t.Fatal("outbox migration load failed")
	}
	// Outbox owns this immutable migration. This harness applies its Up section;
	// migration-ledger composition is a separate release acceptance boundary.
	up := strings.Split(string(data), "-- +migrations Down")[0]
	if _, err := pool.Exec(ctx, up); err != nil {
		t.Fatal("outbox migration install failed")
	}
	if _, err := pool.Exec(ctx, intentSchemaSQL); err != nil {
		t.Fatal("delivery migration install failed")
	}
	return ctx, pool
}

func seedIntentCommand(t *testing.T, ctx context.Context, pool *pgxpool.Pool, p preparedIntent) {
	t.Helper()
	b := p.binding.Command
	id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	if _, err := pool.Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,$2,$3,$4,1,$5)`, id, string(b.TenantID), b.OperationID, bytes.Repeat([]byte{1}, 32), []byte{1}); err != nil {
		t.Fatal("original claim fixture failed")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,$2,$3)`, id, string(b.TenantID), b.OperationID); err != nil {
		t.Fatal("original command fixture failed")
	}
}

func persistInTestTransaction(ctx context.Context, s *intentStore, intents []preparedIntent, tx pgx.Tx) error {
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return delivery.ErrUnavailable
	}
	return s.persist(ctx, intents, now, func(ctx context.Context, query string, args ...any) (int64, error) {
		tag, err := tx.Exec(ctx, query, args...)
		return tag.RowsAffected(), err
	}, func(ctx context.Context, query string, args ...any) (retainedIntent, bool, error) {
		var v retainedIntent
		var key int64
		err := tx.QueryRow(ctx, query, args...).Scan(&v.aad, &key, &v.noOp)
		if errors.Is(err, pgx.ErrNoRows) {
			return v, false, nil
		}
		v.key = uint32(key)
		return v, err == nil, err
	})
}

func beginIntentTestTransaction(t *testing.T, ctx context.Context, pool *pgxpool.Pool) pgx.Tx {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal("begin failed")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := tx.Rollback(cleanup); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Error("transaction cleanup failed")
		}
	})
	return tx
}

func TestIntentTransactionCleanupOutlivesCancelledTestContext(t *testing.T) {
	ctx, pool := intentDatabase(t)
	var retained pgx.Tx
	// The regression itself always cleans up, even while proving the helper
	// leaks custody. This avoids turning its expected RED into a pool hang.
	defer func() {
		if retained != nil {
			cleanup, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			_ = retained.Rollback(cleanup)
		}
	}()
	t.Run("cancelled invocation", func(t *testing.T) {
		call, cancel := context.WithCancel(ctx)
		retained = beginIntentTestTransaction(t, call, pool)
		cancel()
	})
	if pool.Stat().AcquiredConns() != 0 {
		t.Fatal("test return retained an open transaction after cancellation")
	}
}

func preparedFixture(t *testing.T, noOp bool) (*intentStore, preparedIntent) {
	return preparedFixtureExpiry(t, noOp, time.Hour)
}

func preparedFixtureExpiry(t *testing.T, noOp bool, remaining time.Duration) (*intentStore, preparedIntent) {
	t.Helper()
	c, b, p := custodyFixture(t)
	b.NoOpEquivalent = noOp
	b.Intent.ExpiresAt = time.Now().UTC().Truncate(time.Microsecond).Add(remaining)
	b.Intent.EffectID = deliveryEffectID(b.Deployment, b.Command, b.Intent.EffectIndex)
	frozen, envelope, err := c.seal(context.Background(), b, p, "envelope-a")
	if err != nil {
		t.Fatal("fixture custody failed")
	}
	s, err := newIntentStore("test", c, map[uint64]providerProfile{1: {name: "test-provider", policyVersion: 1}})
	if err != nil {
		t.Fatal(err)
	}
	plan := identitypostgres.DeliveryPlan{Contributor: s.Descriptor(), Intents: []identitypostgres.DeliveryIntentPlan{frozen.Intent}}
	prepared, err := s.prepare(b.Command, plan, []identitypostgres.DeliveryEnvelope{envelope})
	if err != nil {
		t.Fatal(err)
	}
	return s, prepared[0]
}

func TestIntentExpiredUnknownErasesWithoutFabricatingOutcome(t *testing.T) {
	ctx, pool := intentDatabase(t)
	s, p := preparedFixtureExpiry(t, false, time.Second)
	seedIntentCommand(t, ctx, pool, p)
	tx := beginIntentTestTransaction(t, ctx, pool)
	if err := persistInTestTransaction(ctx, s, []preparedIntent{p}, tx); err != nil {
		t.Fatal(err)
	}
	if tx.Commit(ctx) != nil {
		t.Fatal("commit failed")
	}
	if _, err := pool.Exec(ctx, `UPDATE identity.delivery_intents SET state='submitted'`); err != nil {
		t.Fatal("attempt fixture failed")
	}
	if _, err := pool.Exec(ctx, `UPDATE identity.delivery_intents SET ciphertext=NULL,envelope_key_id=NULL`); err == nil {
		t.Fatal("unexpired custody erased")
	}
	if _, err := pool.Exec(ctx, `SELECT pg_sleep(GREATEST(EXTRACT(EPOCH FROM($1::timestamptz-clock_timestamp()))+0.002,0))`, p.binding.Intent.ExpiresAt); err != nil {
		t.Fatal("expiry fixture failed")
	}
	if _, err := pool.Exec(ctx, `UPDATE identity.delivery_intents SET ciphertext=NULL,envelope_key_id=NULL`); err != nil {
		t.Fatal("expired submitted custody could not erase without terminal claim")
	}
	if _, err := pool.Exec(ctx, `UPDATE identity.delivery_intents SET state='outcome-unknown'`); err != nil {
		t.Fatal("unknown outcome required ciphertext resurrection")
	}
	if _, err := pool.Exec(ctx, `UPDATE identity.delivery_intents SET ciphertext=$1,envelope_key_id='envelope-a'`, p.envelope.Ciphertext); err == nil {
		t.Fatal("expired custody resurrected")
	}
	var state string
	var erased bool
	if pool.QueryRow(ctx, `SELECT state,ciphertext IS NULL FROM identity.delivery_intents`).Scan(&state, &erased) != nil || state != "outcome-unknown" || !erased {
		t.Fatal("expiry fabricated provider outcome")
	}
}

func TestIntentPersistenceAtomicReplayAndErasure(t *testing.T) {
	ctx, pool := intentDatabase(t)
	s, p := preparedFixture(t, false)
	seedIntentCommand(t, ctx, pool, p)
	count := func(intents, outbox int) {
		t.Helper()
		var a, b int
		if pool.QueryRow(ctx, `SELECT count(*) FROM identity.delivery_intents`).Scan(&a) != nil || pool.QueryRow(ctx, `SELECT count(*) FROM outbox_messages`).Scan(&b) != nil || a != intents || b != outbox {
			t.Fatal("non-atomic durable counts", a, b)
		}
	}
	tx := beginIntentTestTransaction(t, ctx, pool)
	if err := persistInTestTransaction(ctx, s, []preparedIntent{p}, tx); err != nil {
		t.Fatal(err)
	}
	if tx.Rollback(ctx) != nil {
		t.Fatal("rollback failed")
	}
	count(0, 0)
	tx = beginIntentTestTransaction(t, ctx, pool)
	if err := persistInTestTransaction(ctx, s, []preparedIntent{p}, tx); err != nil {
		t.Fatal(err)
	}
	if tx.Commit(ctx) != nil {
		t.Fatal("commit failed")
	}
	count(1, 1)
	plain, err := s.codec.open(ctx, p.binding, p.envelope)
	if err != nil {
		t.Fatal("replay preparation failed")
	}
	frozen, randomized, err := s.codec.seal(ctx, p.binding, plain, "envelope-b")
	if err != nil || bytes.Equal(randomized.Ciphertext, p.envelope.Ciphertext) {
		t.Fatal("replay did not randomize custody")
	}
	plan := identitypostgres.DeliveryPlan{Contributor: s.Descriptor(), Intents: []identitypostgres.DeliveryIntentPlan{frozen.Intent}}
	again, err := s.prepare(frozen.Command, plan, []identitypostgres.DeliveryEnvelope{randomized})
	if err != nil {
		t.Fatal("logical replay was not admitted", err)
	}
	tx = beginIntentTestTransaction(t, ctx, pool)
	if err := persistInTestTransaction(ctx, s, again, tx); err != nil {
		t.Fatal("randomized replay failed", err)
	}
	if tx.Commit(ctx) != nil {
		t.Fatal("replay commit failed")
	}
	count(1, 1)
	var ciphertext, handle []byte
	if pool.QueryRow(ctx, `SELECT ciphertext FROM identity.delivery_intents`).Scan(&ciphertext) != nil || !bytes.Equal(ciphertext, p.envelope.Ciphertext) {
		t.Fatal("custody snapshot changed")
	}
	if pool.QueryRow(ctx, `SELECT payload FROM outbox_messages`).Scan(&handle) != nil || string(handle) != p.binding.Intent.EffectID {
		t.Fatal("outbox duplicated sensitive custody")
	}
	// Terminal checkpoint must remove custody in the same statement. Retained
	// replay evidence prevents re-enqueue even after the outbox payload is gone.
	if _, err := pool.Exec(ctx, `UPDATE identity.delivery_intents SET state='cancelled',ciphertext=NULL,envelope_key_id=NULL`); err != nil {
		t.Fatal("terminal erasure failed")
	}
	if _, err := pool.Exec(ctx, `DELETE FROM outbox_messages`); err != nil {
		t.Fatal("outbox pruning failed")
	}
	tx = beginIntentTestTransaction(t, ctx, pool)
	if err := persistInTestTransaction(ctx, s, []preparedIntent{p}, tx); err != nil {
		t.Fatal("matching replay failed", err)
	}
	if tx.Commit(ctx) != nil {
		t.Fatal("replay commit failed")
	}
	count(1, 0)
	changed := p
	changed.aad = bytes.Clone(p.aad)
	changed.aad[len(changed.aad)-1] ^= 1
	tx = beginIntentTestTransaction(t, ctx, pool)
	err = persistInTestTransaction(ctx, s, []preparedIntent{changed}, tx)
	_ = tx.Rollback(ctx)
	if !errors.Is(err, delivery.ErrConflict) {
		t.Fatal("changed original input did not conflict")
	}
	if _, err := pool.Exec(ctx, `UPDATE identity.delivery_intents SET intent_digest=$1`, bytes.Repeat([]byte{9}, 32)); err == nil {
		t.Fatal("immutable replay binding changed")
	}
	if _, err := pool.Exec(ctx, `UPDATE identity.delivery_intents SET state='planned',ciphertext=$1,envelope_key_id='envelope-a'`, p.envelope.Ciphertext); err == nil {
		t.Fatal("terminal custody resurrected")
	}
	count(1, 0)
}

func TestIntentPersistenceConcurrentDuplicatesAndNoOp(t *testing.T) {
	for _, noOp := range []bool{false, true} {
		t.Run(map[bool]string{false: "normal", true: "no-op"}[noOp], func(t *testing.T) {
			ctx, pool := intentDatabase(t)
			s, p := preparedFixture(t, noOp)
			seedIntentCommand(t, ctx, pool, p)
			var wg sync.WaitGroup
			results := make(chan error, 8)
			for range 8 {
				wg.Go(func() {
					tx, err := pool.Begin(ctx)
					if err != nil {
						results <- delivery.ErrUnavailable
						return
					}
					defer func() {
						cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
						defer stop()
						_ = tx.Rollback(cleanup)
					}()
					if err = persistInTestTransaction(ctx, s, []preparedIntent{p}, tx); err == nil {
						err = tx.Commit(ctx)
					}
					results <- err
				})
			}
			wg.Wait()
			close(results)
			for err := range results {
				if err != nil {
					t.Fatal("duplicate did not converge", err)
				}
			}
			var count int
			var erased bool
			var state string
			if pool.QueryRow(ctx, `SELECT count(*) FROM outbox_messages`).Scan(&count) != nil || count != 1 {
				t.Fatal("duplicate outbox admission")
			}
			if pool.QueryRow(ctx, `SELECT state,ciphertext IS NULL AND envelope_key_id IS NULL FROM identity.delivery_intents`).Scan(&state, &erased) != nil || erased != noOp || noOp && state != "cancelled" || !noOp && state != "planned" {
				t.Fatal("admission changed frozen no-op policy")
			}
		})
	}
}

func TestIntentPersistenceRejectsForeignCommandAndRollsBackOutboxFailure(t *testing.T) {
	ctx, pool := intentDatabase(t)
	s, p := preparedFixture(t, false)
	tx := beginIntentTestTransaction(t, ctx, pool)
	if persistInTestTransaction(ctx, s, []preparedIntent{p}, tx) == nil {
		t.Fatal("unowned command admitted")
	}
	_ = tx.Rollback(ctx)
	seedIntentCommand(t, ctx, pool, p)
	if _, err := pool.Exec(ctx, `DROP TABLE outbox_messages`); err != nil {
		t.Fatal("failure fixture failed")
	}
	tx = beginIntentTestTransaction(t, ctx, pool)
	if persistInTestTransaction(ctx, s, []preparedIntent{p}, tx) == nil {
		t.Fatal("missing outbox reported admission")
	}
	_ = tx.Rollback(ctx)
	var count int
	if pool.QueryRow(ctx, `SELECT count(*) FROM identity.delivery_intents`).Scan(&count) != nil || count != 0 {
		t.Fatal("outbox failure left durable intent")
	}
}
