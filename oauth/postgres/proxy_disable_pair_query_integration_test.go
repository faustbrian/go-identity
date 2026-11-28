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
	"github.com/jackc/pgx/v5/pgconn"
)

// Only the new primary pair-store statements are measured. Local fence and
// checkpoint reads, authenticated source recovery and full acknowledgement
// commits have separate evidence; these samples never commit pair writes.
func TestProxyDisablePairQueriesStayPointBounded(t *testing.T) {
	ctx, db := rpMigrationDatabase(t)
	fixture, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer proxyRetirementQueryRollback(t, fixture)
	const schema, relation, table = "oauth_rp", "provider_disable_proxy_pairs", "oauth_rp.provider_disable_proxy_pairs"
	for _, source := range []migrations.Source{
		MigrationSource{Schema: schema, Version: 100},
		ProviderAuthorityMigrationSource{Schema: schema, Version: 101},
		ProviderDisableCascadeMigrationSource{Schema: schema, Version: 102},
		ProxyDisablePairMigrationSource{Schema: schema, Version: 103},
	} {
		history, err := source.Load(ctx)
		if err != nil {
			t.Fatal("load actual pair-store migration history", err)
		}
		for _, migration := range history {
			if _, err := fixture.Exec(ctx, migration.UpSQL()); err != nil {
				t.Fatal("install actual pair-store migration history", err)
			}
		}
	}
	id := func(number uint64) string {
		var raw [16]byte
		binary.BigEndian.PutUint64(raw[8:], number)
		return base64.RawURLEncoding.EncodeToString(raw[:])
	}
	admitted := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	settled := admitted.Add(time.Second)
	scope := proxyDisablePairScope{productionSchema: "oauth_production", productionDeployment: "production-a",
		previewSchema: "oauth_preview", previewDeployment: "preview-a"}
	if _, err := fixture.Exec(ctx, `INSERT INTO `+table+`
 (tenant_id,source_command_id,cascade_id,generation,production_schema,production_deployment,
 preview_schema,preview_deployment,acknowledged_at)
 SELECT CASE WHEN n<=16000 THEN 'tenant-dense' ELSE 'tenant-sparse-'||((n-16001)/100)::text END,
 translate(rtrim(encode(decode(lpad(to_hex(n),32,'0'),'hex'),'base64'),'='),'+/','-_'),
 translate(rtrim(encode(decode(lpad(to_hex(n+20000),32,'0'),'hex'),'base64'),'='),'+/','-_'),
 7,$1,$2,$3,$4,CASE WHEN n%2=0 THEN $5::timestamptz END
 FROM generate_series(1,20000) n`, scope.productionSchema, scope.productionDeployment,
		scope.previewSchema, scope.previewDeployment, settled); err != nil {
		t.Fatal("seed 20k skewed pending and settled pair rows", err)
	}
	if _, err := fixture.Exec(ctx, "ANALYZE "+table); err != nil {
		t.Fatal(err)
	}
	var engine, columns, indexes string
	var total, dense, tenants, acknowledged int
	var heapBytes, indexBytes int64
	if err := fixture.QueryRow(ctx, `SELECT current_setting('server_version'),
 (SELECT string_agg(column_name||':'||coalesce(domain_schema||'.'||domain_name,udt_schema||'.'||udt_name),', ' ORDER BY ordinal_position)
 FROM information_schema.columns WHERE table_schema=$1 AND table_name=$2),
 (SELECT string_agg(indexdef,E'\n' ORDER BY indexname) FROM pg_indexes WHERE schemaname=$1 AND tablename=$2)`, schema, relation).
		Scan(&engine, &columns, &indexes); err != nil {
		t.Fatal("inspect actual pair-store columns and indexes", err)
	}
	if err := fixture.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE tenant_id='tenant-dense'),
 count(DISTINCT tenant_id),count(acknowledged_at),pg_relation_size($1::regclass),pg_indexes_size($1::regclass)
 FROM `+table, table).Scan(&total, &dense, &tenants, &acknowledged, &heapBytes, &indexBytes); err != nil || total != 20000 || dense != 16000 || tenants != 41 || acknowledged != 10000 {
		t.Fatal("pair-store population/skew differs", total, dense, tenants, acknowledged, err)
	}
	t.Logf("PostgreSQL %s; pgx mode=%v; columns=%s; indexes=%s; synthetic rows=20k, dense tenant=16k, 40 sparse tenants of 100, half pending/half settled; heap_bytes=%d index_bytes=%d; one connection, sequential warm samples, no competing fixture load", engine, db.Config().DefaultQueryExecMode, columns, indexes, heapBytes, indexBytes)

	for _, tenant := range []struct {
		name, id string
		first    uint64
	}{
		{"dense", "tenant-dense", 1}, {"sparse", "tenant-sparse-0", 16001},
	} {
		for _, selection := range []struct {
			name    string
			change  func(*ProviderDisableAdmission, *proxyDisablePairScope)
			found   bool
			exact   bool
			settled bool
		}{
			{name: "pending", found: true, exact: true},
			{name: "settled", found: true, exact: true, settled: true},
			{name: "wrong-generation", found: true, change: func(a *ProviderDisableAdmission, _ *proxyDisablePairScope) { a.Generation++ }},
			{name: "wrong-cascade", found: true, change: func(a *ProviderDisableAdmission, _ *proxyDisablePairScope) {
				a.CascadeID = identity.CascadeID(id(50000))
			}},
			{name: "wrong-production-schema", found: true, change: func(_ *ProviderDisableAdmission, s *proxyDisablePairScope) { s.productionSchema = "other_production" }},
			{name: "wrong-production-deployment", found: true, change: func(_ *ProviderDisableAdmission, s *proxyDisablePairScope) {
				s.productionDeployment = "other-production"
			}},
			{name: "wrong-preview-schema", found: true, change: func(_ *ProviderDisableAdmission, s *proxyDisablePairScope) { s.previewSchema = "other_preview" }},
			{name: "wrong-preview-deployment", found: true, change: func(_ *ProviderDisableAdmission, s *proxyDisablePairScope) { s.previewDeployment = "other-preview" }},
			{name: "missing-command", exact: true, change: func(a *ProviderDisableAdmission, _ *proxyDisablePairScope) {
				a.Disable.CommandID = identity.CommandID(id(30001))
			}},
			{name: "foreign-tenant", exact: true, change: func(a *ProviderDisableAdmission, _ *proxyDisablePairScope) { a.Disable.Key.TenantID = "tenant-missing" }},
		} {
			number := tenant.first
			if selection.settled {
				number++
			}
			admission := ProviderDisableAdmission{CascadeID: identity.CascadeID(id(number + 20000)), Generation: 7,
				Disable:    ProviderAuthorityChange{Key: ProviderAuthorityKey{TenantID: identity.TenantID(tenant.id)}, CommandID: identity.CommandID(id(number))},
				AdmittedAt: admitted}
			selectedScope := scope
			if selection.change != nil {
				selection.change(&admission, &selectedScope)
			}
			for _, operation := range []string{"read", "confirm"} {
				t.Run(tenant.name+"/"+selection.name+"/"+operation, func(t *testing.T) {
					statement := proxyDisablePairReadSQL(table)
					args := []any{string(admission.Disable.Key.TenantID), string(admission.Disable.CommandID)}
					wantRows, filtered := 0, 0
					if selection.found {
						wantRows = 1
					}
					if operation == "confirm" {
						statement = proxyDisablePairConfirmSQL(table)
						args = append(proxyDisablePairArgs(admission, selectedScope), admission.AdmittedAt)
						if selection.found && (!selection.exact || selection.settled) {
							wantRows, filtered = 0, 1
						}
					}
					bindings := make([]string, len(args))
					for index, arg := range args {
						bindings[index] = fmt.Sprintf("$%d=%T", index+1, arg)
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
									t.Fatal("explain exact pair-store statement", err)
								}
								var plans []struct{ Plan providerAuthorityQueryPlan }
								if err := json.Unmarshal(raw, &plans); err != nil || len(plans) != 1 {
									t.Fatalf("decode pair-store plan: %v\n%s", err, raw)
								}
								p := plans[0].Plan
								if operation == "confirm" {
									if p.Kind != "ModifyTable" || p.Operation != "Update" || p.Relation != relation || p.Loops != 1 || p.Rows != float64(wantRows) || len(p.Plans) != 1 {
										t.Fatalf("pair confirmation lost one-row update shape: %s", raw)
									}
									p = p.Plans[0]
								}
								if (p.Kind != "Index Scan" && p.Kind != "Index Only Scan") || p.Relation != relation || p.Index != relation+"_pkey" ||
									!strings.Contains(p.Condition, "tenant_id") || !strings.Contains(p.Condition, "source_command_id") ||
									p.Loops != 1 || p.Rows != float64(wantRows) || p.Filtered != float64(filtered) || len(p.Plans) != 0 {
									t.Fatalf("pair query lost exact PK lookup and bounded CAS filtering: %s", raw)
								}
								t.Logf("default-planner execution/buffers/WAL=%s", raw)
								return
							}
							var duration time.Duration
							if operation == "read" {
								start := time.Now()
								at, err := readProxyDisablePair(ctx, tx, table, admission, selectedScope)
								duration = time.Since(start)
								if !selection.found || !selection.exact {
									var forbidden identity.ForbiddenError
									if !errors.As(err, &forbidden) || !at.IsZero() {
										t.Fatal("absent or mismatched pair was not forbidden", at, err)
									}
								} else if err != nil || (selection.settled && !at.Equal(settled)) || (!selection.settled && !at.IsZero()) {
									t.Fatal("exact pending/settled pair projection differs", at, err)
								}
							} else {
								var at time.Time
								start := time.Now()
								err := tx.QueryRow(ctx, statement, args...).Scan(&at)
								duration = time.Since(start)
								if wantRows == 0 {
									if !errors.Is(err, pgx.ErrNoRows) {
										t.Fatal("non-exact or settled pair confirmation returned data or failed", at, err)
									}
								} else {
									if err != nil || at.IsZero() || at.Before(admitted) {
										t.Fatal("exact pending pair did not acknowledge", at, err)
									}
									retained, err := readProxyDisablePair(ctx, tx, table, admission, selectedScope)
									if err != nil || !retained.Equal(at) {
										t.Fatal("confirmation changed the pair scope or failed to retain its timestamp", retained, err)
									}
								}
							}
							if sample > 1 {
								elapsed = append(elapsed, duration)
							}
						}()
					}
					slices.Sort(elapsed)
					t.Logf("SQL rows=%d CAS filtered=%d; eight warm samples median=%s min=%s max=%s; one warmup; native encoding/round trip/typed scan included, read scope validation included, setup/savepoint/rollback/assertions excluded; no commit, full acknowledgement, contention, cold-cache, throughput or production claim", wantRows, filtered, elapsed[samples/2], elapsed[0], elapsed[samples-1])
				})
			}
		}
	}

	t.Run("insert", func(t *testing.T) {
		admission := ProviderDisableAdmission{CascadeID: identity.CascadeID(id(50001)), Generation: 7,
			Disable:    ProviderAuthorityChange{Key: ProviderAuthorityKey{TenantID: "tenant-dense"}, CommandID: identity.CommandID(id(30001))},
			AdmittedAt: admitted}
		statement, args := proxyDisablePairInsertSQL(table), proxyDisablePairArgs(admission, scope)
		bindings := make([]string, len(args))
		for index, arg := range args {
			bindings[index] = fmt.Sprintf("$%d=%T", index+1, arg)
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
						t.Fatal("explain actual pair insert", err)
					}
					var plans []struct{ Plan providerAuthorityQueryPlan }
					if err := json.Unmarshal(raw, &plans); err != nil || len(plans) != 1 {
						t.Fatalf("decode pair insert plan: %v\n%s", err, raw)
					}
					p := plans[0].Plan
					if p.Kind != "ModifyTable" || p.Operation != "Insert" || p.Relation != relation || p.Rows != 0 || p.Loops != 1 || len(p.Plans) != 1 {
						t.Fatalf("pair insert lost single tuple shape: %s", raw)
					}
					input := p.Plans[0]
					if input.Kind != "Result" || input.Rows != 1 || input.Loops != 1 || len(input.Plans) != 0 {
						t.Fatalf("pair insert unexpectedly scans history: %s", raw)
					}
					t.Logf("default-planner insert execution/buffers/WAL=%s", raw)
					return
				}
				start := time.Now()
				err := stageProxyDisablePair(ctx, tx, table, admission, scope)
				duration := time.Since(start)
				if err != nil {
					t.Fatal("actual stage did not insert one pair", err)
				}
				if at, err := readProxyDisablePair(ctx, tx, table, admission, scope); err != nil || !at.IsZero() {
					t.Fatal("staged pair did not preserve exact pending projection", at, err)
				}
				if sample > 1 {
					elapsed = append(elapsed, duration)
				}
			}()
		}
		slices.Sort(elapsed)
		t.Logf("inserted=1; eight warm samples median=%s min=%s max=%s; one warmup; native stage encoding/round trip included, readback/setup/savepoint/rollback excluded; PK uniqueness checks are not a history scan; writes can produce local WAL/dead tuples; no commit or full admission claim", elapsed[samples/2], elapsed[0], elapsed[samples-1])
		tx, err := fixture.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer proxyRetirementQueryRollback(t, tx)
		args[1] = id(1)
		_, err = tx.Exec(ctx, statement, args...)
		var duplicate *pgconn.PgError
		if !errors.As(err, &duplicate) || duplicate.Code != "23505" || duplicate.ConstraintName != relation+"_pkey" {
			t.Fatal("exact pair key did not enforce unique insert", err)
		}
	})
	var remaining, changed, stillAcknowledged int
	if err := fixture.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE acknowledged_at IS NOT NULL AND acknowledged_at<>$1),count(acknowledged_at)
 FROM `+table, settled).Scan(&remaining, &changed, &stillAcknowledged); err != nil || remaining != total || changed != 0 || stillAcknowledged != acknowledged {
		t.Fatal("rollback-only pair samples retained inserts or acknowledgements", remaining, changed, stillAcknowledged, err)
	}
}
