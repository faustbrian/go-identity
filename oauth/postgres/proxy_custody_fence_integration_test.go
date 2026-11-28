//go:build integration

package postgres

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// These SQL fixtures prove the opt-in database boundary, not authenticated
// provider authority, ciphertext validity, or a public sealing operation.
func TestProxyCustodyWriteFenceActivationAndCommitOrdering(t *testing.T) {
	for _, fixture := range proxyCustodyFenceFixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			ctx, db := rpMigrationDatabase(t)
			for _, source := range []migrations.Source{
				MigrationSource{Schema: "oauth_rp", Version: 100}, fixture.source,
			} {
				proxyCustodyFenceApply(t, ctx, db, source)
			}
			activation := ProxyCustodyWriteFenceActivationSource{Schema: "oauth_rp", Version: 103, Kind: fixture.kind}
			history, err := activation.Load(ctx)
			if err != nil || len(history) != 1 {
				t.Fatal("load explicit fence activation", err)
			}
			// PostgreSQL accepts a function referencing absent relations until
			// execution unless activation checks its expansion in the same DDL.
			_, err = db.Exec(ctx, history[0].UpSQL())
			proxyCustodyFenceWantSQLState(t, err, "42703")

			legacy := fixture.row(10, "tenant-a")
			if _, err := db.Exec(ctx, fixture.insert, legacy...); err != nil {
				t.Fatal("insert deployed legacy custody", err)
			}
			var before string
			projection := `SELECT (to_jsonb(c)-ARRAY['fence_provider_id','fence_provider_epoch'])::text FROM oauth_rp.` + fixture.table + ` c WHERE tenant_id=$1 AND ` + fixture.key + `=$2`
			if err := db.QueryRow(ctx, projection, legacy[0], legacy[1]).Scan(&before); err != nil {
				t.Fatal("snapshot deployed custody", err)
			}
			proxyCustodyFenceApply(t, ctx, db, ProxyCustodyWriteFenceMigrationSource{
				Schema: "oauth_rp", Version: 102, Kind: fixture.kind,
			})
			var after string
			if err := db.QueryRow(ctx, projection, legacy[0], legacy[1]).Scan(&after); err != nil || after != before {
				t.Fatal("expansion changed original custody projection", err)
			}
			var unmarked bool
			if err := db.QueryRow(ctx, `SELECT fence_provider_id IS NULL AND fence_provider_epoch IS NULL FROM oauth_rp.`+fixture.table+` WHERE tenant_id=$1 AND `+fixture.key+`=$2`, legacy[0], legacy[1]).Scan(&unmarked); err != nil || !unmarked {
				t.Fatal("expansion fabricated fence provenance", err)
			}

			// An old projection remains usable until the distinct activation.
			oldWriter, err := db.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer oldWriter.Rollback(ctx)
			beforeActivation := fixture.row(20, "tenant-a")
			if _, err := oldWriter.Exec(ctx, fixture.insert, beforeActivation...); err != nil {
				t.Fatal("insert with original projection before activation", err)
			}
			var originalWriterProjection string
			if err := oldWriter.QueryRow(ctx, projection, beforeActivation[0], beforeActivation[1]).Scan(&originalWriterProjection); err != nil {
				t.Fatal("snapshot uncommitted old writer", err)
			}
			sealDB := proxyCustodyFenceConnection(t, ctx, db)
			activationTx, err := sealDB.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer activationTx.Rollback(ctx)
			if _, err := activationTx.Exec(ctx, `SET LOCAL statement_timeout='100ms'`); err != nil {
				t.Fatal(err)
			}
			_, err = activationTx.Exec(ctx, history[0].UpSQL())
			proxyCustodyFenceWantSQLState(t, err, "57014")
			if err := activationTx.Rollback(ctx); err != nil {
				t.Fatal("release timed-out activation", err)
			}
			if err := oldWriter.Commit(ctx); err != nil {
				t.Fatal("old writer must finish before activation can install", err)
			}
			proxyCustodyFenceApply(t, ctx, db, activation)
			for index, row := range [][]any{legacy, beforeActivation} {
				var preservedProjection string
				originalProjection := []string{before, originalWriterProjection}[index]
				if err := db.QueryRow(ctx, projection, row[0], row[1]).Scan(&preservedProjection); err != nil || preservedProjection != originalProjection {
					t.Fatal("activation changed original custody projection", err)
				}
				var preserved bool
				if err := db.QueryRow(ctx, `SELECT fence_provider_id IS NULL AND fence_provider_epoch IS NULL FROM oauth_rp.`+fixture.table+` WHERE tenant_id=$1 AND `+fixture.key+`=$2`, row[0], row[1]).Scan(&preserved); err != nil || !preserved {
					t.Fatal("activation lost pre-existing unmarked custody", err)
				}
				result, err := db.Exec(ctx, `UPDATE oauth_rp.`+fixture.table+` SET binding_ciphertext=$3 WHERE tenant_id=$1 AND `+fixture.key+`=$2`, row[0], row[1], []byte("updated-original-owner-custody"))
				if err != nil || result.RowsAffected() != 1 {
					t.Fatal("insert-only activation blocked ordinary owner update", err)
				}
			}
			for _, test := range []struct {
				name         string
				mark         byte
				tenant       string
				provider     string
				epoch        any
				advance      int
				wantSQLState string
			}{
				{name: "old projection denied only at commit", mark: 30, tenant: "tenant-a", wantSQLState: "23514"},
				{name: "unfenced epoch allowed", mark: 40, tenant: "tenant-a", provider: "provider-a", epoch: 4},
				{name: "equal denied epoch rejected", mark: 50, tenant: "tenant-a", provider: "provider-a", epoch: 4, advance: 4, wantSQLState: "23514"},
				{name: "newly enabled epoch allowed", mark: 60, tenant: "tenant-a", provider: "provider-a", epoch: 5},
				{name: "unrelated provider allowed", mark: 70, tenant: "tenant-a", provider: "provider-b", epoch: 4},
				{name: "unrelated tenant allowed", mark: 80, tenant: "tenant-b", provider: "provider-a", epoch: 4},
				{name: "latest higher denial rejects older epoch", mark: 90, tenant: "tenant-a", provider: "provider-a", epoch: 5, advance: 6, wantSQLState: "23514"},
			} {
				t.Run(test.name, func(t *testing.T) {
					if test.advance != 0 {
						proxyCustodyFenceAdvance(t, ctx, db, fixture, test.tenant, test.provider, test.advance)
					}
					proxyCustodyFenceInsertCommit(t, ctx, db, fixture, test.mark, test.tenant, test.provider, test.epoch, test.wantSQLState)
				})
			}

			observer := proxyCustodyFenceConnection(t, ctx, db)
			t.Run("seal wins before deferred writer", func(t *testing.T) {
				proxyCustodyFenceSealFirst(t, ctx, db, sealDB, observer, fixture)
			})
			t.Run("deferred writer wins before seal", func(t *testing.T) {
				proxyCustodyFenceWriterFirst(t, ctx, db, sealDB, fixture)
			})
		})
	}
}

type proxyCustodyFenceFixture struct {
	name       string
	kind       kernel.OAuthProxyRetirementKind
	source     migrations.Source
	table      string
	key        string
	fenceTable string
	insert     string
	row        func(byte, string) []any
}

func proxyCustodyFenceFixtures() []proxyCustodyFenceFixture {
	issued := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	return []proxyCustodyFenceFixture{
		{
			name: "production", kind: kernel.OAuthProxyRetireProduction,
			source: ProxyTransactionMigrationSource{Schema: "oauth_rp", Version: 101},
			table:  "proxy_transactions", key: "transaction_id", fenceTable: "proxy_production_write_fences",
			insert: `INSERT INTO oauth_rp.proxy_transactions
 (tenant_id,transaction_id,origin_command_id,callback_command_id,production_deployment,
 provider_id,configuration_version,production_callback_uri,state_key_version,state_lookup_digest,
 binding_ciphertext,state_proof_ciphertext,pkce_ciphertext,issued_at,expires_at,version)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
			row: func(mark byte, tenant string) []any {
				return []any{tenant, fmt.Sprintf("production-%d", mark), bytes.Repeat([]byte{mark}, 16),
					bytes.Repeat([]byte{mark + 1}, 16), "production-a", "provider-a", 1,
					"https://identity.example/oauth/proxy/callback", 1, bytes.Repeat([]byte{mark}, 32),
					[]byte("binding-fixture"), []byte("proof-fixture"), []byte("pkce-fixture"),
					issued, issued.Add(5 * time.Minute), 1}
			},
		},
		{
			name: "preview", kind: kernel.OAuthProxyRetirePreview,
			source: ProxyPreviewBindingMigrationSource{Schema: "oauth_rp", Version: 101},
			table:  "proxy_preview_bindings", key: "flow_id", fenceTable: "proxy_preview_write_fences",
			insert: `INSERT INTO oauth_rp.proxy_preview_bindings
 (tenant_id,flow_id,origin_command_id,callback_command_id,issued_at,expires_at,binding_ciphertext,proof_ciphertext,version)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			row: func(mark byte, tenant string) []any {
				return []any{tenant, fmt.Sprintf("preview-%d", mark), bytes.Repeat([]byte{mark}, 16),
					bytes.Repeat([]byte{mark + 1}, 16), issued, issued.Add(5 * time.Minute),
					[]byte("binding-fixture"), []byte("proof-fixture"), 1}
			},
		},
	}
}

func proxyCustodyFenceApply(t *testing.T, ctx context.Context, db *pgx.Conn, source migrations.Source) {
	t.Helper()
	history, err := source.Load(ctx)
	if err != nil || len(history) == 0 {
		t.Fatal("load custody migration", err)
	}
	for _, migration := range history {
		if _, err := db.Exec(ctx, migration.UpSQL()); err != nil {
			t.Fatal("apply custody migration", err)
		}
	}
}

func proxyCustodyFenceConnection(t *testing.T, ctx context.Context, db *pgx.Conn) *pgx.Conn {
	t.Helper()
	connection, err := pgx.ConnectConfig(ctx, db.Config())
	if err != nil {
		t.Fatal("connect independent custody transaction", err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := connection.Close(cleanup); err != nil {
			t.Error("close custody transaction connection", err)
		}
	})
	return connection
}

func proxyCustodyFenceWantSQLState(t *testing.T, err error, code string) {
	t.Helper()
	var failure *pgconn.PgError
	if !errors.As(err, &failure) || failure.Code != code {
		t.Fatalf("wanted PostgreSQL state %s, got %v", code, err)
	}
}

func proxyCustodyFenceMarkedInsert(fixture proxyCustodyFenceFixture, mark byte, tenant, provider string, epoch any) (string, []any) {
	row := fixture.row(mark, tenant)
	statement := fixture.insert
	if provider != "" {
		if fixture.kind == kernel.OAuthProxyRetireProduction {
			row[5] = provider
		}
		// Use an explicit column projection: the legacy INSERT must remain
		// unchanged so omitted markers exercise the real old-binary path.
		columnEnd := bytes.Index([]byte(statement), []byte(")\n VALUES"))
		statement = statement[:columnEnd] + ",fence_provider_id,fence_provider_epoch" + statement[columnEnd:]
		valueEnd := len(statement) - 1
		statement = statement[:valueEnd] + fmt.Sprintf(",$%d,$%d)", len(row)+1, len(row)+2)
		row = append(row, provider, epoch)
	}
	return statement, row
}

func proxyCustodyFenceInsertCommit(t *testing.T, ctx context.Context, db *pgx.Conn, fixture proxyCustodyFenceFixture, mark byte, tenant, provider string, epoch any, wantSQLState string) {
	t.Helper()
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	statement, row := proxyCustodyFenceMarkedInsert(fixture, mark, tenant, provider, epoch)
	if _, err := tx.Exec(ctx, statement, row...); err != nil {
		t.Fatal("custody INSERT must reach deferred fence boundary", err)
	}
	err = tx.Commit(ctx)
	allowed := wantSQLState == ""
	if allowed {
		if err != nil {
			t.Fatal("allowed custody failed at commit", err)
		}
	} else {
		proxyCustodyFenceWantSQLState(t, err, wantSQLState)
	}
	var present bool
	if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT FROM oauth_rp.`+fixture.table+` WHERE tenant_id=$1 AND `+fixture.key+`=$2)`, row[0], row[1]).Scan(&present); err != nil || present != allowed {
		t.Fatal("commit result differs from persisted custody", err)
	}
}

type proxyCustodyFenceExecutor interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func proxyCustodyFenceAdvance(t *testing.T, ctx context.Context, db proxyCustodyFenceExecutor, fixture proxyCustodyFenceFixture, tenant, provider string, epoch int) {
	t.Helper()
	if _, err := db.Exec(ctx, `INSERT INTO oauth_rp.`+fixture.fenceTable+`(tenant_id,provider_id,denied_through) VALUES($1,$2,$3)
 ON CONFLICT(tenant_id,provider_id) DO UPDATE SET denied_through=EXCLUDED.denied_through`, tenant, provider, epoch); err != nil {
		t.Fatal("advance role-local provider fence", err)
	}
}

const proxyCustodyFenceLockKey = `pg_catalog.hashtextextended(pg_catalog.jsonb_build_array('identity.oauth.proxy.custody-fence.v1', $1::text,$2::text,$3::text,$4::text)::text,0)`

func proxyCustodyFenceSealFirst(t *testing.T, ctx context.Context, db, sealDB, observer *pgx.Conn, fixture proxyCustodyFenceFixture) {
	t.Helper()
	writer, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Rollback(ctx)
	statement, row := proxyCustodyFenceMarkedInsert(fixture, 100, "seal-first", "provider-a", 4)
	if _, err := writer.Exec(ctx, statement, row...); err != nil {
		t.Fatal(err)
	}
	seal, err := sealDB.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer seal.Rollback(ctx)
	var acquired bool
	if err := seal.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(`+proxyCustodyFenceLockKey+`)`, "oauth_rp", fixture.table, "seal-first", "provider-a").Scan(&acquired); err != nil || !acquired {
		t.Fatal("writer acquired fence lock before deferred execution", err)
	}
	commitCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	done := make(chan error, 1)
	go func() { done <- writer.Commit(commitCtx) }()
	joined := false
	defer func() {
		seal.Rollback(ctx)
		cancel()
		if !joined {
			<-done
		}
	}()
	waitCtx, stop := context.WithTimeout(ctx, 2*time.Second)
	defer stop()
	for {
		select {
		case err := <-done:
			joined = true
			t.Fatalf("deferred writer did not wait for exclusive seal: %v", err)
		default:
		}
		var blocked bool
		if err := observer.QueryRow(waitCtx, `SELECT $1::integer=ANY(pg_blocking_pids($2::integer))`, int64(sealDB.PgConn().PID()), int64(db.PgConn().PID())).Scan(&blocked); err != nil {
			t.Fatal("observe deferred writer waiting on seal", err)
		}
		if blocked {
			break
		}
	}
	proxyCustodyFenceAdvance(t, ctx, seal, fixture, "seal-first", "provider-a", 4)
	if err := seal.Commit(ctx); err != nil {
		t.Fatal("commit winning seal", err)
	}
	err = <-done
	joined = true
	proxyCustodyFenceWantSQLState(t, err, "23514")
	var present bool
	if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT FROM oauth_rp.`+fixture.table+` WHERE tenant_id=$1 AND `+fixture.key+`=$2)`, row[0], row[1]).Scan(&present); err != nil || present {
		t.Fatal("seal-first writer survived fresh deferred fence read", err)
	}
}

func proxyCustodyFenceWriterFirst(t *testing.T, ctx context.Context, db, sealDB *pgx.Conn, fixture proxyCustodyFenceFixture) {
	t.Helper()
	writer, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Rollback(ctx)
	statement, row := proxyCustodyFenceMarkedInsert(fixture, 110, "writer-first", "provider-a", 4)
	if _, err := writer.Exec(ctx, statement, row...); err != nil {
		t.Fatal(err)
	}
	// Test-only early evaluation holds the same shared transaction lock that
	// a real writer obtains at COMMIT, without introducing a scheduling sleep.
	if _, err := writer.Exec(ctx, `SET CONSTRAINTS oauth_rp.proxy_custody_write_fence IMMEDIATE`); err != nil {
		t.Fatal("evaluate deferred writer guard", err)
	}
	seal, err := sealDB.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer seal.Rollback(ctx)
	var acquired bool
	lock := `SELECT pg_try_advisory_xact_lock(` + proxyCustodyFenceLockKey + `)`
	args := []any{"oauth_rp", fixture.table, "writer-first", "provider-a"}
	if err := seal.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock_shared(`+proxyCustodyFenceLockKey+`)`, args...).Scan(&acquired); err != nil || !acquired {
		t.Fatal("deferred writer used an exclusive rather than shared fence lock", err)
	}
	if err := seal.QueryRow(ctx, lock, args...).Scan(&acquired); err != nil || acquired {
		t.Fatal("seal passed a writer holding the shared fence lock", err)
	}
	if err := writer.Commit(ctx); err != nil {
		t.Fatal("commit winning writer", err)
	}
	if err := seal.QueryRow(ctx, lock, args...).Scan(&acquired); err != nil || !acquired {
		t.Fatal("seal did not acquire exclusive lock after writer commit", err)
	}
	var visible bool
	if err := seal.QueryRow(ctx, `SELECT EXISTS(SELECT FROM oauth_rp.`+fixture.table+` WHERE tenant_id=$1 AND `+fixture.key+`=$2)`, row[0], row[1]).Scan(&visible); err != nil || !visible {
		t.Fatal("writer winning the fence order was not visible to seal", err)
	}
	proxyCustodyFenceAdvance(t, ctx, seal, fixture, "writer-first", "provider-a", 4)
	if err := seal.Commit(ctx); err != nil {
		t.Fatal("commit seal after visible writer", err)
	}
	proxyCustodyFenceInsertCommit(t, ctx, db, fixture, 120, "writer-first", "provider-a", 4, "23514")
}
