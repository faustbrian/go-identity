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

	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// Synthetic pending cascades measure exact admission/replay statements, not
// authenticated disable admission, consumer cleanup or production performance.
func TestProviderDisableCascadeQueriesStayPointBounded(t *testing.T) {
	ctx, db := rpMigrationDatabase(t)
	const schema, table = "oauth_rp", "oauth_rp.provider_disable_cascades"
	consumers := providerDisableCascadeConsumers()
	contracts, err := json.Marshal(consumers)
	if err != nil {
		t.Fatal(err)
	}
	admitted := time.Now().UTC().Truncate(time.Second)
	deadline := admitted.Add(24 * time.Hour)
	id := func(number uint64) string {
		var raw [16]byte
		binary.BigEndian.PutUint64(raw[8:], number)
		return base64.RawURLEncoding.EncodeToString(raw[:])
	}
	setup, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer setup.Rollback(ctx)
	for _, source := range []migrations.Source{
		MigrationSource{Schema: schema, Version: 100},
		ProviderAuthorityMigrationSource{Schema: schema, Version: 101},
		ProviderDisableCascadeMigrationSource{Schema: schema, Version: 102},
	} {
		history, err := source.Load(ctx)
		if err != nil {
			t.Fatal("load actual cascade migration history", err)
		}
		for _, migration := range history {
			if _, err := setup.Exec(ctx, migration.UpSQL()); err != nil {
				t.Fatal("install actual cascade migration history", err)
			}
		}
	}
	if _, err := setup.Exec(ctx, `INSERT INTO `+table+`
 (tenant_id,source_command_id,provider_id,actor_id,previous_version,disabled_version,profile_version,
 cascade_id,generation,manifest_version,event_topic,event_version,consumer_contracts,status,legal_hold_state,admitted_at,deadline_at)
 SELECT CASE WHEN n<=16000 THEN 'tenant-dense' ELSE 'tenant-sparse-'||((n-16001)/100)::text END,
 translate(rtrim(encode(decode(lpad(to_hex(n),32,'0'),'hex'),'base64'),'='),'+/','-_'),
 'provider-'||n,$1,6,7,3,
 translate(rtrim(encode(decode(lpad(to_hex(n+20000),32,'0'),'hex'),'base64'),'='),'+/','-_'),
 1,$2,$3,1,$4::jsonb,1,'not_applicable',$5::timestamptz,$6::timestamptz
 FROM generate_series(1,20000) n`, string(oneTapStartActor), providerDisableCascadeManifest,
		providerDisableCascadeTopic, contracts, admitted, deadline); err != nil {
		t.Fatal("seed 20k skewed pending cascades", err)
	}
	if _, err := setup.Exec(ctx, "ANALYZE "+table); err != nil {
		t.Fatal(err)
	}
	if err := setup.Commit(ctx); err != nil {
		t.Fatal("commit representative cascade fixture", err)
	}
	var engine, columns, indexes string
	var total, dense, tenants int
	var heapBytes, indexBytes int64
	if err := db.QueryRow(ctx, `SELECT current_setting('server_version'),
 (SELECT string_agg(column_name||':'||coalesce(domain_schema||'.'||domain_name,udt_schema||'.'||udt_name),', ' ORDER BY ordinal_position)
 FROM information_schema.columns WHERE table_schema=$1 AND table_name='provider_disable_cascades'),
 (SELECT string_agg(indexdef,E'\n' ORDER BY indexname) FROM pg_indexes WHERE schemaname=$1 AND tablename='provider_disable_cascades')`, schema).
		Scan(&engine, &columns, &indexes); err != nil {
		t.Fatal("inspect actual cascade column types and indexes", err)
	}
	if err := db.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE tenant_id='tenant-dense'),count(DISTINCT tenant_id),
 pg_relation_size($1::regclass),pg_indexes_size($1::regclass) FROM `+table, table).
		Scan(&total, &dense, &tenants, &heapBytes, &indexBytes); err != nil || total != 20000 || dense != 16000 || tenants != 41 {
		t.Fatal("cascade fixture volume/skew differs", total, dense, tenants, err)
	}
	t.Logf("PostgreSQL %s; columns=%s; indexes=%s; 20k synthetic pending rows, dense tenant=16k, 40 sparse tenants of 100; heap_bytes=%d index_bytes=%d; sequential warm connection, no competing fixture workload", engine, columns, indexes, heapBytes, indexBytes)
	for _, selection := range []struct {
		name, tenant string
		number       uint64
		insert       bool
		want         int
	}{
		{"dense-replay-hit", "tenant-dense", 1, false, 1},
		{"sparse-replay-hit", "tenant-sparse-0", 16001, false, 1},
		{"dense-replay-miss", "tenant-dense", 30001, false, 0},
		{"sparse-replay-miss", "tenant-sparse-0", 30001, false, 0},
		{"foreign-tenant", "tenant-missing", 1, false, 0},
		{"dense-insert", "tenant-dense", 30001, true, 1},
		{"sparse-insert", "tenant-sparse-0", 30002, true, 1},
	} {
		t.Run(selection.name, func(t *testing.T) {
			statement := providerDisableCascadeReadSQL(table)
			args := []any{selection.tenant, id(selection.number)}
			provider, cascade := fmt.Sprintf("provider-%d", selection.number), id(selection.number+20000)
			if selection.insert {
				statement = providerDisableCascadeInsertSQL(table)
				args = []any{selection.tenant, id(selection.number), provider, string(oneTapStartActor),
					providerAuthorityVersion(6), providerAuthorityVersion(7), providerAuthorityVersion(3), cascade,
					providerDisableCascadeManifest, providerDisableCascadeTopic, contracts, admitted, deadline}
			}
			bindings := make([]string, len(args))
			for n, arg := range args {
				bindings[n] = fmt.Sprintf("$%d=%T", n+1, arg)
			}
			t.Logf("exact SQL=%s; native bindings=%s", statement, strings.Join(bindings, ", "))
			const samples = 8
			var elapsed []time.Duration
			for sample := range samples + 2 {
				tx, err := db.Begin(ctx)
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
							t.Fatal("explain exact cascade statement", err)
						}
						var plans []struct{ Plan providerAuthorityQueryPlan }
						if err := json.Unmarshal(raw, &plans); err != nil || len(plans) != 1 {
							t.Fatalf("decode cascade plan: %v\n%s", err, raw)
						}
						p := plans[0].Plan
						bounded := p.Relation == "provider_disable_cascades" && p.Loops == 1
						if selection.insert {
							bounded = bounded && p.Kind == "ModifyTable" && p.Operation == "Insert" && p.Rows == 0 && len(p.Plans) == 1
							if bounded {
								input := p.Plans[0]
								bounded = input.Kind == "Result" && input.Rows == 1 && input.Loops == 1 && len(input.Plans) == 0
							}
						} else {
							bounded = bounded && (p.Kind == "Index Scan" || p.Kind == "Index Only Scan") && p.Index == "provider_disable_cascades_pkey" &&
								strings.Contains(p.Condition, "tenant_id") && strings.Contains(p.Condition, "source_command_id") &&
								p.Rows == float64(selection.want) && p.Filtered == 0 && len(p.Plans) == 0
						}
						if !bounded {
							t.Fatalf("cascade statement lost default-planner one-row bound: %s", raw)
						}
						t.Logf("default-planner instrumented execution/buffers/WAL, not client latency=%s", raw)
						return
					}
					var duration time.Duration
					if selection.insert {
						start := time.Now()
						tag, err := tx.Exec(ctx, statement, args...)
						duration = time.Since(start)
						if err != nil || tag.RowsAffected() != 1 {
							t.Fatal("exact cascade insert did not admit one row", tag.RowsAffected(), err)
						}
					} else {
						var gotProvider, actor, previous, disabled, profile, gotCascade, manifest, topic, hold string
						var generation int64
						var eventVersion, status int16
						var gotContracts []byte
						var gotAdmitted, gotDeadline time.Time
						start := time.Now()
						err := tx.QueryRow(ctx, statement, args...).Scan(&gotProvider, &actor, &previous, &disabled, &profile,
							&gotCascade, &generation, &manifest, &topic, &eventVersion, &gotContracts, &status, &hold, &gotAdmitted, &gotDeadline)
						duration = time.Since(start)
						if selection.want == 0 {
							if !errors.Is(err, pgx.ErrNoRows) {
								t.Fatal("cascade replay miss returned data or failed", err)
							}
						} else {
							var gotConsumers []ProviderDisableConsumer
							if err != nil || json.Unmarshal(gotContracts, &gotConsumers) != nil || !slices.Equal(gotConsumers, consumers) ||
								gotProvider != provider || actor != string(oneTapStartActor) || previous != "6" || disabled != "7" || profile != "3" ||
								gotCascade != cascade || generation != 1 || manifest != providerDisableCascadeManifest || topic != providerDisableCascadeTopic ||
								eventVersion != 1 || status != 1 || hold != "not_applicable" || !gotAdmitted.Equal(admitted) || !gotDeadline.Equal(deadline) {
								t.Fatal("cascade replay changed the admitted receipt projection", err)
							}
						}
					}
					if sample > 1 {
						elapsed = append(elapsed, duration)
					}
				}()
			}
			slices.Sort(elapsed)
			t.Logf("returned/affected=%d; %d warm samples median=%s min=%s max=%s; one warmup; native encode/round trip/scan included, acquisition/BEGIN/setup/ROLLBACK/assertions excluded; writes rollback but produce local WAL/dead tuples; no commit, full admission, consumer, cold-cache, contention, throughput or production claim", selection.want, samples, elapsed[samples/2], elapsed[0], elapsed[samples-1])
		})
	}
	var remaining int
	if err := db.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&remaining); err != nil || remaining != total {
		t.Fatal("rollback-only cascade insert samples persisted admission rows", remaining, total, err)
	}
}
