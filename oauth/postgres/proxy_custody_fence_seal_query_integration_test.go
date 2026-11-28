//go:build integration && queryperformance

package postgres

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// This isolates native seal statements in rollback-only samples. Advisory-lock
// contention, authoritative disable reads and full seal commits are not timed.
func TestProxyCustodyFenceSealQueriesStayPointBounded(t *testing.T) {
	ctx, db := rpMigrationDatabase(t)
	fixture, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer proxyRetirementQueryRollback(t, fixture)
	install := func(source migrations.Source) {
		t.Helper()
		history, err := source.Load(ctx)
		if err != nil {
			t.Fatal("load actual fence history", err)
		}
		for _, migration := range history {
			if _, err := fixture.Exec(ctx, migration.UpSQL()); err != nil {
				t.Fatal("install actual fence history", err)
			}
		}
	}
	const schema = "oauth_rp"
	install(MigrationSource{Schema: schema, Version: 100})
	for _, role := range []struct {
		name, custody, fence string
		kind                 kernel.OAuthProxyRetirementKind
		base                 migrations.Source
		version              migrations.Version
	}{
		{"production", "proxy_transactions", "proxy_production_write_fences", kernel.OAuthProxyRetireProduction,
			ProxyTransactionMigrationSource{Schema: schema, Version: 101}, 102},
		{"preview", "proxy_preview_bindings", "proxy_preview_write_fences", kernel.OAuthProxyRetirePreview,
			ProxyPreviewBindingMigrationSource{Schema: schema, Version: 104}, 105},
	} {
		t.Run(role.name, func(t *testing.T) {
			install(role.base)
			install(ProxyCustodyWriteFenceMigrationSource{Schema: schema, Version: role.version, Kind: role.kind})
			install(ProxyCustodyWriteFenceActivationSource{Schema: schema, Version: role.version + 1, Kind: role.kind})
			table := rpQuotedSchema(schema) + "." + role.fence
			if _, err := fixture.Exec(ctx, `INSERT INTO `+table+`(tenant_id,provider_id,denied_through)
 SELECT CASE WHEN n<=16000 THEN 'tenant-dense' ELSE 'tenant-sparse-'||((n-16001)/100)::text END,
 'provider-'||n,7 FROM generate_series(1,20000) n`); err != nil {
				t.Fatal("seed 20k scoped seal floors", err)
			}
			if _, err := fixture.Exec(ctx, "ANALYZE "+table); err != nil {
				t.Fatal(err)
			}
			var engine, columns, indexes string
			var total, dense, tenants int
			if err := fixture.QueryRow(ctx, `SELECT current_setting('server_version'),
 (SELECT string_agg(column_name||':'||coalesce(domain_schema||'.'||domain_name,udt_schema||'.'||udt_name),', ' ORDER BY ordinal_position)
 FROM information_schema.columns WHERE table_schema=$1 AND table_name=$2),
 (SELECT string_agg(indexdef,E'\n' ORDER BY indexname) FROM pg_indexes WHERE schemaname=$1 AND tablename=$2)`, schema, role.fence).
				Scan(&engine, &columns, &indexes); err != nil {
				t.Fatal("inspect actual seal schema/indexes", err)
			}
			if err := fixture.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE tenant_id='tenant-dense'),count(DISTINCT tenant_id) FROM `+table).
				Scan(&total, &dense, &tenants); err != nil || total != 20000 || dense != 16000 || tenants != 41 {
				t.Fatal("seal population/skew differs", total, dense, tenants, err)
			}
			t.Logf("PostgreSQL %s; columns=%s; indexes=%s; 20k floors at epoch 7: 16k dense tenant, 40 sparse tenants of 100; isolated sequential warm samples, no competing fixture load", engine, columns, indexes)
			for _, tenant := range []struct{ name, id, provider string }{
				{"dense", "tenant-dense", "provider-1"}, {"sparse", "tenant-sparse-0", "provider-16001"},
			} {
				for _, operation := range []struct {
					name, provider                      string
					epoch                               uint64
					want, inserted, conflicts, filtered int
				}{
					{"insert", "provider-new", 8, 1, 1, 0, 0},
					{"advance", tenant.provider, 8, 1, 0, 1, 0},
					{"maximum-advance", tenant.provider, ^uint64(0), 1, 0, 1, 0},
					{"earlier-replay", tenant.provider, 6, 0, 0, 1, 1},
					{"exact-replay", tenant.provider, 7, 0, 0, 1, 1},
					{"floor-hit", tenant.provider, 0, 1, 0, 0, 0},
					{"floor-miss", "provider-missing", 0, 0, 0, 0, 0},
				} {
					t.Run(tenant.name+"/"+operation.name, func(t *testing.T) {
						statement := proxyCustodyFenceFloorSQL(table)
						args := []any{tenant.id, operation.provider}
						bindings := "string,string"
						if operation.epoch != 0 {
							statement = proxyCustodyFenceAdvanceSQL(table)
							args = append(args, providerAuthorityVersion(operation.epoch))
							bindings += ",pgtype.Numeric (runtime providerAuthorityVersion)"
						}
						t.Logf("exact SQL=%s; native pgx bindings=%s", statement, bindings)
						const samples = 8
						var elapsed []time.Duration
						for sample := range samples + 2 {
							tx, err := fixture.Begin(ctx)
							if err != nil {
								t.Fatal(err)
							}
							func() {
								defer proxyRetirementQueryRollback(t, tx)
								if _, err := tx.Exec(ctx, `SET LOCAL statement_timeout='2s'; SET LOCAL lock_timeout='1s'`); err != nil {
									t.Fatal(err)
								}
								if sample == 0 {
									var raw []byte
									if err := tx.QueryRow(ctx, "EXPLAIN (ANALYZE,BUFFERS,WAL,FORMAT JSON) "+statement, args...).Scan(&raw); err != nil {
										t.Fatal("explain native seal statement", err)
									}
									var plans []struct {
										Plan struct {
											providerAuthorityQueryPlan
											ConflictFiltered float64 `json:"Rows Removed by Conflict Filter"`
										}
									}
									if err := json.Unmarshal(raw, &plans); err != nil || len(plans) != 1 {
										t.Fatal("decode seal plan", err)
									}
									p := plans[0].Plan
									bounded := p.Relation == role.fence && p.Loops == 1 && p.Rows == float64(operation.want)
									if operation.epoch != 0 {
										bounded = bounded && p.Kind == "ModifyTable" && p.Operation == "Insert" &&
											p.Inserted == float64(operation.inserted) && p.Conflicts == float64(operation.conflicts) &&
											p.ConflictFiltered == float64(operation.filtered) && slices.Equal(p.Arbiters, []string{role.fence + "_pkey"}) && len(p.Plans) == 1
										if bounded {
											input := p.Plans[0]
											bounded = input.Kind == "Result" && input.Rows == 1 && input.Loops == 1 && len(input.Plans) == 0
										}
									} else {
										bounded = bounded && (p.Kind == "Index Scan" || p.Kind == "Index Only Scan") && p.Index == role.fence+"_pkey" &&
											strings.Contains(p.Condition, "tenant_id") && strings.Contains(p.Condition, "provider_id") && p.Filtered == 0 && len(p.Plans) == 0
									}
									if !bounded {
										t.Fatalf("seal statement lost default-planner one-row bound: %s", raw)
									}
									t.Logf("default-planner instrumented execution/buffers/WAL=%s", raw)
									return
								}
								var floor string
								start := time.Now()
								err := tx.QueryRow(ctx, statement, args...).Scan(&floor)
								duration := time.Since(start)
								if operation.want == 0 {
									if !errors.Is(err, pgx.ErrNoRows) {
										t.Fatal("no-op or absent floor returned data or failed", floor, err)
									}
								} else {
									wantFloor := "7"
									if operation.epoch != 0 {
										wantFloor = fmt.Sprint(operation.epoch)
									}
									if err != nil || floor != wantFloor {
										t.Fatal("unexpected seal floor", floor, err)
									}
								}
								if sample > 1 {
									elapsed = append(elapsed, duration)
								}
							}()
						}
						slices.Sort(elapsed)
						t.Logf("returned/changed=%d; %d warm samples median=%s min=%s max=%s; native encode/round trip/scan included, savepoint/setup/rollback/assertions excluded; no-op conflicts can still lock rows and emit WAL; no full commit, contention, throughput or production claim", operation.want, samples, elapsed[samples/2], elapsed[0], elapsed[samples-1])
					})
				}
			}
			var remaining, changed int
			if err := fixture.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE denied_through<>7) FROM `+table).
				Scan(&remaining, &changed); err != nil || remaining != 20000 || changed != 0 {
				t.Fatal("rollback-only seal samples retained a write", remaining, changed, err)
			}
			var triggers, functions, relations int
			if err := fixture.QueryRow(ctx, `SELECT (SELECT count(*) FROM pg_catalog.pg_trigger),
 (SELECT count(*) FROM pg_catalog.pg_proc),(SELECT count(*) FROM pg_catalog.pg_class)`).Scan(&triggers, &functions, &relations); err != nil {
				t.Fatal("inspect local catalog scale", err)
			}
			t.Logf("activation-gate scale assumptions: catalog triggers=%d functions=%d relations=%d; one named hook per measured custody table; not a large-catalog or full seal operation benchmark", triggers, functions, relations)
			t.Log("local seal query bound: one activation probe, one scoped advisory-lock statement, one advance, plus at most one retry floor read; authoritative source-read evidence is separate; advisory wait and commit cost are not measured")
			for _, suffix := range []string{"", "_missing"} {
				args := []any{rpQuotedSchema(schema) + "." + role.custody, "enforce_proxy_" + role.name + "_write_fence" + suffix}
				var raw []byte
				if err := fixture.QueryRow(ctx, "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) "+proxyCustodyFenceActiveSQL, args...).Scan(&raw); err != nil {
					t.Fatal("explain catalog-only activation gate", err)
				}
				t.Logf("exact catalog gate SQL=%s; bindings=string,string; plan=%s; catalog cardinality and installed hooks are local-fixture assumptions, not production catalog scale", proxyCustodyFenceActiveSQL, raw)
				var elapsed []time.Duration
				for sample := range 9 {
					var active bool
					start := time.Now()
					err := fixture.QueryRow(ctx, proxyCustodyFenceActiveSQL, args...).Scan(&active)
					duration := time.Since(start)
					if err != nil || active != (suffix == "") {
						t.Fatal("activation gate projection differs", active, err)
					}
					if sample > 0 {
						elapsed = append(elapsed, duration)
					}
				}
				slices.Sort(elapsed)
				t.Logf("activation gate eight warm samples median=%s min=%s max=%s; no user history scan, full-operation or production timing claim", elapsed[4], elapsed[0], elapsed[7])
			}
		})
	}
}
