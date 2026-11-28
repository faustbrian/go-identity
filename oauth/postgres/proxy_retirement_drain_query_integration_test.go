//go:build integration && queryperformance

package postgres

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// Synthetic checkpoints measure exact local statements, not discovery,
// cryptographic retirement, replay recovery or a complete committing drain.
func TestProxyRetirementDrainQueriesStayPointBounded(t *testing.T) {
	ctx, db := rpMigrationDatabase(t)
	fixture, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer proxyRetirementQueryRollback(t, fixture)
	const schema, table = "oauth_rp", "oauth_rp.proxy_retirement_drains"
	for _, source := range []migrations.Source{
		MigrationSource{Schema: schema, Version: 100},
		ProxyRetirementDrainMigrationSource{Schema: schema, Version: 101},
	} {
		history, err := source.Load(ctx)
		if err != nil {
			t.Fatal("load actual drain migration", err)
		}
		for _, migration := range history {
			if _, err := fixture.Exec(ctx, migration.UpSQL()); err != nil {
				t.Fatal("install actual drain migration", err)
			}
		}
	}
	id := func(number uint64) string {
		var raw [16]byte
		binary.BigEndian.PutUint64(raw[8:], number)
		return base64.RawURLEncoding.EncodeToString(raw[:])
	}
	type target struct {
		Flow    string `json:"flow"`
		Origin  string `json:"origin"`
		Command string `json:"command"`
	}
	targets := make([]target, 32)
	for n := range targets {
		targets[n] = target{id(uint64(100001 + n)), id(uint64(200001 + n)), id(uint64(300001 + n))}
	}
	slices.SortFunc(targets, func(a, b target) int { return strings.Compare(a.Flow, b.Flow) })
	page, err := json.Marshal(struct {
		Next    string   `json:"next"`
		Targets []target `json:"targets"`
	}{Next: targets[len(targets)-1].Flow, Targets: targets})
	if err != nil {
		t.Fatal(err)
	}
	var runtimePage proxyRetirementDrainPage
	if err := json.Unmarshal(page, &runtimePage); err != nil || !runtimePage.valid(identity.PreAuthTransactionID(id(1))) {
		t.Fatal("representative pending page violates the runtime checkpoint contract", err)
	}
	var canonicalPage string
	if err := fixture.QueryRow(ctx, `SELECT $1::jsonb::text`, page).Scan(&canonicalPage); err != nil {
		t.Fatal("normalize expected checkpoint JSON", err)
	}
	if _, err := fixture.Exec(ctx, `INSERT INTO `+table+`
 (tenant_id,cascade_id,generation,role,deployment,source_command_id,provider_id,source_version,
 revision,after_flow_id,pending_page,confirmed,retired,exhausted)
 SELECT CASE WHEN n<=16000 THEN 'tenant-dense' ELSE 'tenant-sparse-'||((n-16001)/100)::text END,
 translate(rtrim(encode(decode(lpad(to_hex(n),32,'0'),'hex'),'base64'),'='),'+/','-_'),1,
 CASE WHEN n%2=1 THEN 1 ELSE 2 END,CASE WHEN n%2=1 THEN 'production-a' ELSE 'preview-a' END,
 translate(rtrim(encode(decode(lpad(to_hex(n+20000),32,'0'),'hex'),'base64'),'='),'+/','-_'),
 'provider-'||n,8,1,'',CASE WHEN n%3=0 THEN $1::jsonb END,0,0,false FROM generate_series(1,20000) n`, page); err != nil {
		t.Fatal("seed 20k skewed drain checkpoints", err)
	}
	if _, err := fixture.Exec(ctx, "ANALYZE "+table); err != nil {
		t.Fatal(err)
	}
	var engine, columns, indexes string
	var total, dense, tenants, pending int
	if err := fixture.QueryRow(ctx, `SELECT current_setting('server_version'),
 (SELECT string_agg(column_name||':'||coalesce(domain_schema||'.'||domain_name,udt_schema||'.'||udt_name),', ' ORDER BY ordinal_position)
 FROM information_schema.columns WHERE table_schema=$1 AND table_name='proxy_retirement_drains'),
 (SELECT string_agg(indexdef,E'\n' ORDER BY indexname) FROM pg_indexes WHERE schemaname=$1 AND tablename='proxy_retirement_drains')`, schema).
		Scan(&engine, &columns, &indexes); err != nil {
		t.Fatal("inspect actual drain column types/indexes", err)
	}
	if err := fixture.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE tenant_id='tenant-dense'),count(DISTINCT tenant_id),
 count(*) FILTER(WHERE pending_page IS NOT NULL) FROM `+table).Scan(&total, &dense, &tenants, &pending); err != nil || total != 20000 || dense != 16000 || tenants != 41 || pending != 6666 {
		t.Fatal("drain fixture volume/skew differs", total, dense, tenants, pending, err)
	}
	t.Logf("PostgreSQL %s; columns=%s; indexes=%s; 20k rows, 16k dense tenant plus 40 tenants of 100; both roles/deployments, 6666 pending 32-target pages (%d JSON bytes), others NULL; sequential warm fixture, no competing load", engine, columns, indexes, len(page))
	type checkpoint struct {
		source, provider, version, after string
		revision, retired                int64
		page                             []byte
		confirmed                        int16
		exhausted                        bool
	}
	read := func(tx pgx.Tx, args []any) (checkpoint, error) {
		var state checkpoint
		err := tx.QueryRow(ctx, proxyRetirementDrainReadSQL(table), args...).Scan(&state.source, &state.provider,
			&state.version, &state.revision, &state.after, &state.page, &state.confirmed, &state.retired, &state.exhausted)
		return state, err
	}
	for _, scope := range []struct {
		name, tenant, deployment string
		number                   uint64
		role                     int16
	}{
		{"dense-production", "tenant-dense", "production-a", 3, 1},
		{"dense-preview", "tenant-dense", "preview-a", 2, 2},
		{"sparse-production", "tenant-sparse-0", "production-a", 16001, 1},
		{"sparse-preview", "tenant-sparse-0", "preview-a", 16002, 2},
	} {
		for _, operation := range []struct {
			name string
			want int
		}{
			{"read", 1}, {"missing", 0}, {"insert", 1}, {"conflict", 0},
			{"current-cas", 1}, {"stale-cas", 0}, {"exhaust-cas", 1},
		} {
			t.Run(scope.name+"/"+operation.name, func(t *testing.T) {
				number := scope.number
				if operation.name == "missing" || operation.name == "insert" {
					number += 30000
				}
				key := []any{scope.tenant, id(number), int64(1), scope.role, scope.deployment}
				source, provider := id(number+20000), fmt.Sprintf("provider-%d", number)
				statement, args := proxyRetirementDrainReadSQL(table), slices.Clone(key)
				isInsert := operation.name == "insert" || operation.name == "conflict"
				isUpdate := strings.HasSuffix(operation.name, "-cas")
				after, confirmed, retired, exhausted := id(1), int16(1), int64(1), false
				var nextPage any = page
				if operation.name == "exhaust-cas" {
					nextPage, confirmed, exhausted = nil, 0, true
				}
				if isInsert || isUpdate {
					args = append(args, source, provider, providerAuthorityVersion(8))
					if isInsert {
						statement = proxyRetirementDrainInsertSQL(table)
					} else {
						statement = proxyRetirementDrainUpdateSQL(table)
						revision := int64(1)
						if operation.name == "stale-cas" {
							revision = 2
						}
						args = append(args, revision)
					}
					args = append(args, after, nextPage, confirmed, retired, exhausted)
				}
				bindings := make([]string, len(args))
				for n, arg := range args {
					bindings[n] = fmt.Sprintf("$%d=%T", n+1, arg)
				}
				t.Logf("exact SQL=%s; native pgx bindings=%s", statement, strings.Join(bindings, ", "))
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
								t.Fatal("explain exact drain statement", err)
							}
							var plans []struct{ Plan providerAuthorityQueryPlan }
							if err := json.Unmarshal(raw, &plans); err != nil || len(plans) != 1 {
								t.Fatal("decode drain plan", err)
							}
							p := plans[0].Plan
							bounded := p.Relation == "proxy_retirement_drains" && p.Loops == 1
							if isInsert {
								bounded = bounded && p.Kind == "ModifyTable" && p.Operation == "Insert" && p.Rows == 0 &&
									p.Inserted == float64(operation.want) && p.Conflicts == float64(1-operation.want) &&
									len(p.Arbiters) == 0 && len(p.Plans) == 1
								if bounded {
									input := p.Plans[0]
									bounded = input.Kind == "Result" && input.Rows == 1 && input.Loops == 1 && len(input.Plans) == 0
								}
							} else {
								if isUpdate {
									bounded = bounded && p.Kind == "ModifyTable" && p.Operation == "Update" && p.Rows == 0 && len(p.Plans) == 1
									if bounded {
										p = p.Plans[0]
									}
								}
								bounded = bounded && (p.Kind == "Index Scan" || p.Kind == "Index Only Scan") && p.Index == "proxy_retirement_drains_pkey" &&
									p.Rows == float64(operation.want) && p.Loops == 1 && p.Rows+p.Filtered <= 1 && len(p.Plans) == 0
								for _, keyColumn := range []string{"tenant_id", "cascade_id", "generation", "role", "deployment"} {
									bounded = bounded && strings.Contains(p.Condition, keyColumn)
								}
							}
							if !bounded {
								t.Fatalf("drain statement lost default-planner exact-PK work bound: %s", raw)
							}
							t.Logf("default-planner instrumented execution/buffers/WAL=%s", raw)
							return
						}
						var duration time.Duration
						if isInsert || isUpdate {
							start := time.Now()
							tag, err := tx.Exec(ctx, statement, args...)
							duration = time.Since(start)
							if err != nil || tag.RowsAffected() != int64(operation.want) {
								t.Fatal("drain mutation affected unexpected rows", tag.RowsAffected(), err)
							}
						} else {
							start := time.Now()
							_, err := read(tx, key)
							duration = time.Since(start)
							if operation.want == 0 && !errors.Is(err, pgx.ErrNoRows) || operation.want == 1 && err != nil {
								t.Fatal("drain read returned unexpected result", err)
							}
						}
						if operation.name != "missing" {
							state, err := read(tx, key)
							wantRevision, wantAfter, wantPage, wantConfirmed, wantRetired, wantExhausted := int64(1), "", "", int16(0), int64(0), false
							if number%3 == 0 {
								wantPage = canonicalPage
							}
							if (isInsert || isUpdate) && operation.want == 1 {
								wantAfter, wantPage, wantConfirmed, wantRetired, wantExhausted = after, canonicalPage, confirmed, retired, exhausted
								if nextPage == nil {
									wantPage = ""
								}
								if isUpdate {
									wantRevision = 2
								}
							}
							if err != nil || state.source != source || state.provider != provider || state.version != "8" || state.revision != wantRevision ||
								state.after != wantAfter || string(state.page) != wantPage || state.confirmed != wantConfirmed || state.retired != wantRetired || state.exhausted != wantExhausted {
								t.Fatal("drain checkpoint projection/CAS differs", state.revision, err)
							}
						}
						if sample > 1 {
							elapsed = append(elapsed, duration)
						}
					}()
				}
				slices.Sort(elapsed)
				t.Logf("returned/affected=%d; %d warm samples median=%s min=%s max=%s; native round trip/encode/scan included, savepoint/setup/rollback/assertions/readback excluded; per-statement only, writes can emit WAL/dead tuples; no full drain, commit, cold-cache, contention, throughput or production claim", operation.want, samples, elapsed[samples/2], elapsed[0], elapsed[samples-1])
			})
		}
	}
	var remaining, changed int
	if err := fixture.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE revision<>1 OR after_flow_id<>'' OR confirmed<>0 OR retired<>0 OR exhausted) FROM `+table).
		Scan(&remaining, &changed); err != nil || remaining != 20000 || changed != 0 {
		t.Fatal("rollback-only drain samples retained a checkpoint mutation", remaining, changed, err)
	}
}
