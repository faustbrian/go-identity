//go:build integration && queryperformance

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// This measures the native statements and the local application operations
// independently; neither result represents production latency or contention.
func TestProviderAuthorityQueriesStayPointBounded(t *testing.T) {
	_, pool, authority, operator, key := providerAuthorityFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	connection, err := pool.Raw().Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Release()
	db := connection.Conn()
	const seedCommand = "AAAAAAAAAAAAAAAAAAAAAQ"
	if _, err := db.Exec(ctx, `INSERT INTO `+authority.table+`
 (tenant_id,provider_id,version,profile_version,enabled,previous_version,command_id,command_actor)
 SELECT CASE WHEN n<=24000 THEN $1::text ELSE 'sparse-provider-'||((n-24001)/100)::text END,
 'provider-'||n::text,7,3,true,6,$2,$3 FROM generate_series(1,30000) n`,
		string(key.TenantID), seedCommand, string(oneTapStartActor)); err != nil {
		t.Fatal("seed representative provider authorities", err)
	}
	if _, err := db.Exec(ctx, `ANALYZE `+authority.table); err != nil {
		t.Fatal("analyze representative provider authorities", err)
	}
	var engine string
	var total, dense, tenants, smallest, largest int
	var heapBytes, indexBytes int64
	if err := db.QueryRow(ctx, `SELECT version()`).Scan(&engine); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE tenant_id=$1),count(DISTINCT tenant_id),
 pg_relation_size($2::regclass),pg_indexes_size($2::regclass) FROM `+authority.table,
		string(key.TenantID), authority.table).Scan(&total, &dense, &tenants, &heapBytes, &indexBytes); err != nil || total != 30000 || dense != 24000 || tenants != 61 {
		t.Fatal("provider authority volume/skew differs", total, dense, tenants, err)
	}
	if err := db.QueryRow(ctx, `SELECT min(n),max(n) FROM
 (SELECT count(*) n FROM `+authority.table+` WHERE tenant_id<>$1 GROUP BY tenant_id) sparse`,
		string(key.TenantID)).Scan(&smallest, &largest); err != nil || smallest != 100 || largest != 100 {
		t.Fatal("sparse provider tenant distribution differs", smallest, largest, err)
	}
	t.Logf("engine=%s; synthetic_rows=%d dense_tenant_rows=%d sparse_tenants=60 rows_each=100 heap_bytes=%d index_bytes=%d; isolated fixture, one acquired connection, sequential warm samples, no competing fixture workload; not production scale, cold-cache or contention evidence", engine, total, dense, heapBytes, indexBytes)
	for _, statement := range []string{
		`SELECT column_name||'='||udt_schema||'.'||udt_name FROM information_schema.columns WHERE table_schema='onetap_oauth' AND table_name='provider_authorities' ORDER BY ordinal_position`,
		`SELECT indexdef FROM pg_indexes WHERE schemaname='onetap_oauth' AND tablename='provider_authorities' ORDER BY indexname`,
	} {
		rows, err := db.Query(ctx, statement)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var metadata string
			if err := rows.Scan(&metadata); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			t.Log(metadata)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
	}

	for _, selection := range []struct {
		name, tenant, provider string
		wantRows               int
	}{
		{"dense-hit", string(key.TenantID), "provider-1", 1},
		{"sparse-hit", "sparse-provider-0", "provider-24001", 1},
		{"dense-miss", string(key.TenantID), "provider-missing", 0},
		{"sparse-miss", "sparse-provider-0", "provider-missing", 0},
		{"foreign-tenant", "missing-provider-tenant", "provider-1", 0},
	} {
		for _, projection := range []string{"current", "replay"} {
			t.Run(projection+"/"+selection.name, func(t *testing.T) {
				statement := authority.currentQuery()
				if projection == "replay" {
					statement = authority.replayQuery()
				}
				scan := func(row pgx.Row) error {
					var version, profile, previous, command, actor string
					var enabled bool
					var err error
					if projection == "current" {
						err = row.Scan(&version, &profile, &enabled)
					} else {
						err = row.Scan(&previous, &version, &enabled, &command, &actor, &profile)
					}
					if err != nil {
						return err
					}
					if version != "7" || profile != "3" || !enabled {
						return fmt.Errorf("provider state projection differs")
					}
					if projection == "replay" && (previous != "6" || command != seedCommand || actor != string(oneTapStartActor)) {
						return fmt.Errorf("provider replay projection differs")
					}
					return nil
				}
				providerAuthorityMeasureQuery(t, ctx, db, statement, []any{selection.tenant, selection.provider}, selection.wantRows, scan)
			})
		}
	}

	for _, selection := range []struct{ name, tenant, provider string }{
		{"dense", string(key.TenantID), "provider-1"},
		{"sparse", "sparse-provider-0", "provider-24001"},
	} {
		for _, operation := range []string{"advance", "stale", "register", "conflict"} {
			t.Run(operation+"/"+selection.name, func(t *testing.T) {
				statement, expected, provider, wantRows := authority.advanceQuery(), uint64(7), selection.provider, 1
				if operation == "stale" {
					expected, wantRows = 6, 0
				}
				if operation == "register" || operation == "conflict" {
					statement, expected = authority.registerQuery(), 0
					if operation == "register" {
						provider = "provider-new"
					} else {
						wantRows = 0
					}
				}
				args := []any{selection.tenant, provider, providerAuthorityVersion(8), true,
					providerAuthorityVersion(expected), string(providerAuthorityCommand(t)), string(oneTapStartActor), providerAuthorityVersion(3)}
				scan := func(row pgx.Row) error {
					var acceptedAt time.Time
					if err := row.Scan(&acceptedAt); err != nil {
						return err
					}
					if acceptedAt.IsZero() {
						return fmt.Errorf("provider write returned no acceptance time")
					}
					return nil
				}
				providerAuthorityMeasureQuery(t, ctx, db, statement, args, wantRows, scan)
			})
		}
	}
	var remaining, changed int
	if err := db.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE version<>7 OR previous_version<>6 OR profile_version<>3 OR NOT enabled OR command_id<>$1) FROM `+authority.table,
		seedCommand).Scan(&remaining, &changed); err != nil || remaining != total || changed != 0 {
		t.Fatal("rolled-back query samples retained a provider change", remaining, changed, err)
	}
	key.ProviderID = "provider-1"
	var applies, reads []time.Duration
	for version := uint64(8); version <= 20; version++ {
		next := ProviderAuthorityState{Version: version, ProfileVersion: 3, Enabled: version%2 != 0}
		change := ProviderAuthorityChange{Key: key, ExpectedVersion: version - 1, Next: next, CommandID: providerAuthorityCommand(t)}
		start := time.Now()
		got, err := operator.Apply(ctx, change)
		applyTime := time.Since(start)
		if err != nil || got != next {
			t.Fatal("populated owner Apply did not commit the selected epoch", err)
		}
		start = time.Now()
		got, err = authority.Current(ctx, key)
		readTime := time.Since(start)
		if err != nil || got != next {
			t.Fatal("populated owner Current missed the committed epoch", err)
		}
		if version > 8 {
			applies, reads = append(applies, applyTime), append(reads, readTime)
		}
	}
	slices.Sort(applies)
	slices.Sort(reads)
	t.Logf("dense tenant full local owner operation: 12 warm samples; Apply including audit, outbox and commit median=%s range=%s..%s; Current median=%s range=%s..%s; no contention or production latency claim",
		applies[6], applies[0], applies[11], reads[6], reads[0], reads[11])
}

func providerAuthorityMeasureQuery(t *testing.T, ctx context.Context, db *pgx.Conn, statement string, args []any, wantRows int, scan func(pgx.Row) error) {
	t.Helper()
	bindings := make([]string, len(args))
	for index, arg := range args {
		bindings[index] = fmt.Sprintf("$%d=%T", index+1, arg)
	}
	t.Logf("native SQL=%s; bindings=%s", statement, strings.Join(bindings, ", "))
	const sampleCount = 12
	var samples []time.Duration
	for sample := range sampleCount + 2 {
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		func() {
			defer func() {
				cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				if err := tx.Rollback(cleanup); err != nil {
					t.Error("rollback provider query evidence", err)
				}
			}()
			if _, err := tx.Exec(ctx, `SET LOCAL statement_timeout='2s'; SET LOCAL lock_timeout='1s'`); err != nil {
				t.Fatal(err)
			}
			if sample == 0 {
				var raw []byte
				if err := tx.QueryRow(ctx, "EXPLAIN (ANALYZE,BUFFERS,WAL,FORMAT JSON) "+statement, args...).Scan(&raw); err != nil {
					t.Fatal("explain native provider query", err)
				}
				var plans []struct{ Plan providerAuthorityQueryPlan }
				if err := json.Unmarshal(raw, &plans); err != nil || len(plans) != 1 || !plans[0].Plan.bounded(wantRows) {
					t.Fatalf("provider query lost scoped single-row work bound: %v\n%s", err, raw)
				}
				t.Logf("default-planner instrumented execution=%s", raw)
				return
			}
			start := time.Now()
			err := scan(tx.QueryRow(ctx, statement, args...))
			elapsed := time.Since(start)
			if wantRows == 0 {
				if !errors.Is(err, pgx.ErrNoRows) {
					t.Fatal("provider no-match query returned data or failed", err)
				}
			} else if err != nil {
				t.Fatal("provider single-row query failed", err)
			}
			if sample > 1 {
				samples = append(samples, elapsed)
			}
		}()
	}
	slices.Sort(samples)
	t.Logf("returned_rows=%d warm_samples=%d client_median=%s min=%s max=%s; statement round trip/typed scan included, acquisition/BEGIN/setup/ROLLBACK excluded; writes rollback but can generate local WAL/dead tuples; no commit, full-operation, throughput or production claim", wantRows, sampleCount, samples[len(samples)/2], samples[0], samples[len(samples)-1])
}

type providerAuthorityQueryPlan struct {
	Kind      string                       `json:"Node Type"`
	Relation  string                       `json:"Relation Name"`
	Index     string                       `json:"Index Name"`
	Condition string                       `json:"Index Cond"`
	Operation string                       `json:"Operation"`
	Rows      float64                      `json:"Actual Rows"`
	Loops     float64                      `json:"Actual Loops"`
	Filtered  float64                      `json:"Rows Removed by Filter"`
	Inserted  float64                      `json:"Tuples Inserted"`
	Conflicts float64                      `json:"Conflicting Tuples"`
	Arbiters  []string                     `json:"Conflict Arbiter Indexes"`
	Plans     []providerAuthorityQueryPlan `json:"Plans"`
}

func (p providerAuthorityQueryPlan) bounded(wantRows int) bool {
	if p.Loops != 1 || p.Rows != float64(wantRows) {
		return false
	}
	if p.Kind == "ModifyTable" {
		if p.Relation != "provider_authorities" || len(p.Plans) != 1 {
			return false
		}
		if p.Operation == "Insert" {
			input := p.Plans[0]
			return p.Inserted == float64(wantRows) && p.Conflicts == float64(1-wantRows) &&
				slices.Equal(p.Arbiters, []string{"provider_authorities_pkey"}) &&
				input.Kind == "Result" && input.Rows == 1 && input.Loops == 1 && len(input.Plans) == 0
		}
		return p.Operation == "Update" && p.Plans[0].bounded(wantRows)
	}
	return (p.Kind == "Index Scan" || p.Kind == "Index Only Scan") && p.Relation == "provider_authorities" &&
		p.Index == "provider_authorities_pkey" && strings.Contains(p.Condition, "tenant_id") && strings.Contains(p.Condition, "provider_id") &&
		p.Filtered >= 0 && p.Rows+p.Filtered <= 1 && len(p.Plans) == 0
}
