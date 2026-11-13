//go:build integration

package postgres

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// These are exact SQL arithmetic/access-path checks, not authentication proof.
// Genuine issued-key authority and transaction composition are exercised by the
// external consumer tests. Only this isolated quota relation is populated here.
func quotaSQLDatabase(t *testing.T) (context.Context, *pgx.Conn) {
	t.Helper()
	config, err := pgx.ParseConfig(os.Getenv("GOLIB_APIKEY_TEST_POSTGRES_DSN"))
	if err != nil || config.Host != "127.0.0.1" {
		t.Fatal("explicit task-owned loopback PostgreSQL required")
	}
	ctx, stop := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(stop)
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	name := "quota_sql_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		_ = admin.Close(ctx)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+quoted); err != nil {
			t.Error("quota SQL database cleanup", err)
		}
		_ = admin.Close(cleanup)
	})
	config.Database = name
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if conn.Close(cleanup) != nil {
			t.Error("quota SQL connection cleanup")
		}
	})
	if _, err := conn.Exec(ctx, `CREATE SCHEMA identity; CREATE DOMAIN identity.directory_id AS text; CREATE SCHEMA identity_api_keys;`+quotaSQL); err != nil {
		t.Fatal(err)
	}
	return ctx, conn
}

func TestQuotaSQLExactFractionalRefillAndMaximumBounds(t *testing.T) {
	ctx, conn := quotaSQLDatabase(t)
	at := time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)
	if _, err := conn.Exec(ctx, initializeQuotaSQL, "tenant", "configuration", "fraction", "2", "3", at); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `UPDATE identity_api_keys.quotas SET balance=0`); err != nil {
		t.Fatal(err)
	}
	var debit bool
	var remaining int64
	args := []any{"tenant", "configuration", "fraction", "2", "3", "1", "1", at.Add(2 * time.Microsecond)}
	if err := conn.QueryRow(ctx, debitQuotaSQL, args...).Scan(&debit, &remaining); err != nil || debit || remaining != 0 {
		t.Fatal("fractional refill fabricated whole token", err)
	}
	args[7] = at.Add(3 * time.Microsecond)
	if err := conn.QueryRow(ctx, debitQuotaSQL, args...).Scan(&debit, &remaining); err != nil || !debit || remaining != 0 {
		t.Fatal("fractional refill was discarded", err)
	}
	args[7] = at
	if err := conn.QueryRow(ctx, debitQuotaSQL, args...).Scan(&debit, &remaining); err != pgx.ErrNoRows {
		t.Fatal("backward time was rounded/accepted", err)
	}
	start := time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := conn.Exec(ctx, initializeQuotaSQL, "tenant", "configuration", "maximum", "1000000", "9223372036854775", start); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `UPDATE identity_api_keys.quotas SET balance=0 WHERE key_id='maximum'`); err != nil {
		t.Fatal(err)
	}
	args = []any{"tenant", "configuration", "maximum", "1000000", "9223372036854775", "18446744073709551615", "1", time.Date(9999, 12, 31, 23, 59, 59, 999999000, time.UTC)}
	if err := conn.QueryRow(ctx, debitQuotaSQL, args...).Scan(&debit, &remaining); err != nil || !debit || remaining != 999999 {
		t.Fatal("maximum exact refill overflowed or exceeded capacity", err)
	}
}

func TestQuotaSQLBoundedAccessPath(t *testing.T) {
	ctx, conn := quotaSQLDatabase(t)
	// One heavily populated tenant/configuration plus a tenant skew. Both quota
	// statements must still address only the exact composite primary-key tuple.
	if _, err := conn.Exec(ctx, `INSERT INTO identity_api_keys.quotas SELECT CASE WHEN i%10=0 THEN 'other' ELSE 'tenant' END,'configuration','key-'||i,1000,1000,clock_timestamp() FROM generate_series(1,100000) i; ANALYZE identity_api_keys.quotas; SET statement_timeout='1s'`); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Truncate(time.Microsecond)
	var version string
	if err := conn.QueryRow(ctx, `SHOW server_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	t.Log("engine", version, "rows=100000; composite primary key; 90% one tenant; exact production SQL/string numeric bindings; 1s statement deadline; EXPLAIN ANALYZE mutates disposable state")
	for i := 0; i < 3; i++ {
		for _, statement := range []struct {
			name, sql string
			args      []any
		}{
			{"initialize-conflict", initializeQuotaSQL, []any{"tenant", "configuration", "key-1", "1000", "1", at}},
			{"initialize-new", initializeQuotaSQL, []any{"tenant", "configuration", "new-key-" + strconv.Itoa(i), "1000", "1", at}},
			{"debit-existing", debitQuotaSQL, []any{"tenant", "configuration", "key-1", "1000", "1", "1", "1", at}},
			{"debit-absent", debitQuotaSQL, []any{"tenant", "configuration", "absent-key", "1000", "1", "1", "1", at}},
		} {
			rows, err := conn.Query(ctx, "EXPLAIN (ANALYZE, BUFFERS, WAL, FORMAT TEXT) "+statement.sql, statement.args...)
			if err != nil {
				t.Fatal(err)
			}
			var plan strings.Builder
			for rows.Next() {
				var line string
				if rows.Scan(&line) != nil {
					rows.Close()
					t.Fatal("query plan decoding")
				}
				plan.WriteString(line + "\n")
			}
			err = rows.Err()
			rows.Close()
			if err != nil || strings.Contains(plan.String(), "Seq Scan") || !strings.Contains(plan.String(), "quotas_pkey") {
				t.Fatal("quota operation lost its exact tuple access path", err, plan.String())
			}
			t.Logf("sample=%d operation=%s\n%s", i+1, statement.name, plan.String())
		}
	}
}
