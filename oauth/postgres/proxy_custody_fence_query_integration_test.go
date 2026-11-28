//go:build integration && queryperformance

package postgres

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Expansion-only measurements isolate the trigger's exact point predicate and
// marked writer INSERT. Deferred trigger/lock/commit cost is not measured here.
func TestProxyCustodyFenceQueriesStayPointBounded(t *testing.T) {
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
			t.Fatal("load actual custody/fence migration", err)
		}
		for _, migration := range history {
			if _, err := fixture.Exec(ctx, migration.UpSQL()); err != nil {
				t.Fatal("install actual custody/fence migration", err)
			}
		}
	}
	const schema = "oauth_rp"
	install(MigrationSource{Schema: schema, Version: 100})
	issued := time.Now().UTC().Truncate(time.Second)
	binding := make([]byte, 2048)
	if _, err := rand.Read(binding); err != nil {
		t.Fatal(err)
	}
	// Match Work's fixed binary profile: uint64 is numeric, uint32 is int8,
	// and the added canonical epoch string remains text with SQL's explicit cast.
	codecs := pgtype.NewMap()
	nativeRows := func(t *testing.T, tx pgx.Tx, statement string, args []any, oids []uint32) pgx.Rows {
		t.Helper()
		values, formats := make([][]byte, len(args)), make([]int16, len(args))
		for n, arg := range args {
			formats[n] = pgtype.BinaryFormatCode
			var err error
			values[n], err = codecs.Encode(oids[n], formats[n], arg, make([]byte, 0))
			if err != nil {
				t.Fatal("encode fixed Work scalar profile", n, err)
			}
		}
		return pgx.RowsFromResultReader(codecs, tx.Conn().PgConn().ExecParams(ctx, statement, values, oids, formats, nil))
	}
	for _, role := range []struct {
		name, custody, fence, seed string
		kind                       kernel.OAuthProxyRetirementKind
		source                     migrations.Source
		version                    migrations.Version
		insert                     func(string, bool) string
		args                       []any
		oids                       []uint32
	}{
		{
			name: "production", custody: "proxy_transactions", fence: "proxy_production_write_fences",
			kind: kernel.OAuthProxyRetireProduction, source: ProxyTransactionMigrationSource{Schema: schema, Version: 101}, version: 102,
			insert: proxyStartInsertSQL,
			args: []any{"tenant-dense", "flow-new", bytes.Repeat([]byte{251}, 16), bytes.Repeat([]byte{252}, 16),
				"production-a", "provider-1", providerAuthorityVersion(^uint64(0)), "https://identity.example/callback", int64(4294967295),
				bytes.Repeat([]byte{253}, 32), binding, []byte{1}, []byte{2}, issued, issued.Add(5 * time.Minute), "provider-1", "8"},
			oids: []uint32{25, 25, 17, 17, 25, 25, 1700, 25, 20, 17, 17, 17, 17, 1184, 1184, 25, 25},
			seed: `INSERT INTO oauth_rp.proxy_transactions
 (tenant_id,transaction_id,origin_command_id,callback_command_id,production_deployment,provider_id,configuration_version,
 production_callback_uri,state_key_version,state_lookup_digest,binding_ciphertext,state_proof_ciphertext,pkce_ciphertext,issued_at,expires_at,version)
 SELECT CASE WHEN n<=16000 THEN 'tenant-dense' ELSE 'tenant-sparse-'||((n-16001)/100)::text END,
 'flow-'||n,decode(md5('origin-'||n),'hex'),decode(md5('callback-'||n),'hex'),'production-a','provider-'||n,7,
 'https://identity.example/callback',1,decode(md5('state-'||n)||md5('lookup-'||n),'hex'),
 decode(repeat(md5('binding-'||n),16),'hex'),decode('01','hex'),decode('02','hex'),$1::timestamptz,$2::timestamptz,1
 FROM generate_series(1,20000) n`,
		},
		{
			name: "preview", custody: "proxy_preview_bindings", fence: "proxy_preview_write_fences",
			kind: kernel.OAuthProxyRetirePreview, source: ProxyPreviewBindingMigrationSource{Schema: schema, Version: 104}, version: 105,
			insert: proxyPreviewInsertSQL,
			args: []any{"tenant-dense", "flow-new", bytes.Repeat([]byte{251}, 16), bytes.Repeat([]byte{252}, 16),
				issued, issued.Add(5 * time.Minute), binding, []byte{1}, "provider-1", "8"},
			oids: []uint32{25, 25, 17, 17, 1184, 1184, 17, 17, 25, 25},
			seed: `INSERT INTO oauth_rp.proxy_preview_bindings
 (tenant_id,flow_id,origin_command_id,callback_command_id,issued_at,expires_at,binding_ciphertext,proof_ciphertext,version)
 SELECT CASE WHEN n<=16000 THEN 'tenant-dense' ELSE 'tenant-sparse-'||((n-16001)/100)::text END,
 'flow-'||n,decode(md5('origin-'||n),'hex'),decode(md5('callback-'||n),'hex'),$1::timestamptz,$2::timestamptz,
 decode(repeat(md5('binding-'||n),16),'hex'),decode('01','hex'),1 FROM generate_series(1,20000) n`,
		},
	} {
		t.Run(role.name, func(t *testing.T) {
			install(role.source)
			install(ProxyCustodyWriteFenceMigrationSource{Schema: schema, Version: role.version, Kind: role.kind})
			if _, err := fixture.Exec(ctx, role.seed, issued, issued.Add(5*time.Minute)); err != nil {
				t.Fatal("seed 20k original custody rows", err)
			}
			table := rpQuotedSchema(schema) + "." + role.fence
			if _, err := fixture.Exec(ctx, `INSERT INTO `+table+`(tenant_id,provider_id,denied_through)
 SELECT CASE WHEN n<=16000 THEN 'tenant-dense' ELSE 'tenant-sparse-'||((n-16001)/100)::text END,
 'provider-'||n,7 FROM generate_series(1,20000) n`); err != nil {
				t.Fatal("seed 20k scoped fences", err)
			}
			for _, relation := range []string{table, rpQuotedSchema(schema) + "." + role.custody} {
				if _, err := fixture.Exec(ctx, "ANALYZE "+relation); err != nil {
					t.Fatal(err)
				}
			}
			var engine, columns, indexes string
			var total, dense, tenants int
			if err := fixture.QueryRow(ctx, `SELECT current_setting('server_version'),
 (SELECT string_agg(column_name||':'||coalesce(domain_schema||'.'||domain_name,udt_schema||'.'||udt_name),', ' ORDER BY ordinal_position)
 FROM information_schema.columns WHERE table_schema=$1 AND table_name=$2),
 (SELECT string_agg(indexdef,E'\n' ORDER BY indexname) FROM pg_indexes WHERE schemaname=$1 AND tablename=$2)`, schema, role.fence).
				Scan(&engine, &columns, &indexes); err != nil {
				t.Fatal("inspect actual fence schema/indexes", err)
			}
			if err := fixture.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE tenant_id='tenant-dense'),count(DISTINCT tenant_id) FROM `+table).
				Scan(&total, &dense, &tenants); err != nil || total != 20000 || dense != 16000 || tenants != 41 {
				t.Fatal("fence population/skew differs", total, dense, tenants, err)
			}
			t.Logf("PostgreSQL %s; fence columns=%s; indexes=%s; 20k fence and 20k open custody rows per role, 16k dense and 40 sparse tenants of 100; synthetic custody bodies=512 bytes, measured INSERT binding=2048 incompressible bytes; sequential warm fixture, no competing load", engine, columns, indexes)
			for _, selection := range []struct {
				name, tenant, provider string
				insert                 bool
				want                   int
			}{
				{"dense-hit", "tenant-dense", "provider-1", false, 1},
				{"sparse-hit", "tenant-sparse-0", "provider-16001", false, 1},
				{"dense-miss", "tenant-dense", "provider-missing", false, 0},
				{"sparse-miss", "tenant-sparse-0", "provider-missing", false, 0},
				{"foreign-tenant", "tenant-sparse-0", "provider-1", false, 0},
				{"marked-insert", "tenant-dense", "provider-1", true, 1},
			} {
				t.Run(selection.name, func(t *testing.T) {
					statement := `SELECT f.denied_through FROM ` + table + ` f WHERE f.tenant_id=$1 AND f.provider_id=$2`
					args, oids := []any{selection.tenant, selection.provider}, []uint32{25, 25}
					if selection.insert {
						statement, args, oids = role.insert(schema, true), role.args, role.oids
					}
					t.Logf("exact SQL=%s; fixed binary parameter_oids=%v; lookup adapts only trigger INTO/NEW references; marked INSERT uses runtime Work scalar wire types, epoch text→numeric", statement, oids)
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
								rows := nativeRows(t, tx, "EXPLAIN (ANALYZE,BUFFERS,WAL,FORMAT JSON) "+statement, args, oids)
								var raw []byte
								if !rows.Next() || rows.Scan(&raw) != nil {
									rows.Close()
									t.Fatal("explain native fence statement", rows.Err())
								}
								rows.Close()
								var plans []struct{ Plan providerAuthorityQueryPlan }
								if err := json.Unmarshal(raw, &plans); err != nil || rows.Err() != nil || len(plans) != 1 {
									t.Fatal("decode fence plan", err, rows.Err())
								}
								p := plans[0].Plan
								bounded := p.Loops == 1
								if selection.insert {
									bounded = bounded && p.Kind == "ModifyTable" && p.Operation == "Insert" && p.Relation == role.custody && p.Rows == 0 && len(p.Plans) == 1
									if bounded {
										input := p.Plans[0]
										bounded = input.Kind == "Result" && input.Rows == 1 && input.Loops == 1 && len(input.Plans) == 0
									}
								} else {
									bounded = bounded && (p.Kind == "Index Scan" || p.Kind == "Index Only Scan") && p.Relation == role.fence && p.Index == role.fence+"_pkey" &&
										strings.Contains(p.Condition, "tenant_id") && strings.Contains(p.Condition, "provider_id") && p.Rows == float64(selection.want) && p.Filtered == 0 && len(p.Plans) == 0
								}
								if !bounded {
									t.Fatalf("default fence plan lost one-row bound: %s", raw)
								}
								t.Logf("default-planner instrumented execution/buffers/WAL=%s", raw)
								return
							}
							start := time.Now()
							rows := nativeRows(t, tx, statement, args, oids)
							count := 0
							var denied pgtype.Numeric
							for rows.Next() {
								count++
								if err := rows.Scan(&denied); err != nil {
									rows.Close()
									t.Fatal(err)
								}
							}
							rows.Close()
							duration := time.Since(start)
							if selection.insert {
								count = int(rows.CommandTag().RowsAffected())
							}
							if rows.Err() != nil || count != selection.want || !selection.insert && count == 1 && (!denied.Valid || denied.Int == nil || denied.Int.String() != "7" || denied.Exp != 0) {
								t.Fatal("native fence statement returned/affected unexpected rows", count, rows.Err())
							}
							if sample > 1 {
								elapsed = append(elapsed, duration)
							}
						}()
					}
					slices.Sort(elapsed)
					t.Logf("returned/affected=%d; %d warm samples median=%s min=%s max=%s; native encode/round trip/drain/scan included; acquisition/savepoint/setup/rollback/assertions excluded; expansion only, deferred trigger/lock/commit execution NOT measured; rollback writes may emit WAL/dead tuples; not consumer acceptance, cold-cache, contention, throughput or production evidence", selection.want, samples, elapsed[samples/2], elapsed[0], elapsed[samples-1])
				})
			}
			var custodyRows int
			if err := fixture.QueryRow(ctx, "SELECT count(*) FROM "+rpQuotedSchema(schema)+"."+role.custody).Scan(&custodyRows); err != nil || custodyRows != 20000 {
				t.Fatal("sample marked INSERT survived rollback", custodyRows, err)
			}
		})
	}
}
