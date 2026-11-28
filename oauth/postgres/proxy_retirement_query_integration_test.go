//go:build integration && queryperformance

package postgres

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Synthetic custody proves the native statement's work bound, not authenticated
// retirement, AEAD, grant revocation, or the complete committing operation.
func TestProxyRetirementCustodyQueriesStayBounded(t *testing.T) {
	ctx, db := rpMigrationDatabase(t)
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer proxyRetirementQueryRollback(t, tx)
	install := func(t *testing.T, source migrations.Source) {
		t.Helper()
		history, err := source.Load(ctx)
		if err != nil {
			t.Fatal("load actual custody migration", err)
		}
		for _, migration := range history {
			if _, err := tx.Exec(ctx, migration.UpSQL()); err != nil {
				t.Fatal("apply actual custody migration", err)
			}
		}
	}
	install(t, MigrationSource{Schema: "oauth_rp", Version: 100})
	issued := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	for _, role := range []struct {
		name, table, key, seed string
		kind                   kernel.OAuthProxyRetirementKind
		source                 migrations.Source
		read, erase            func(string) string
	}{
		{
			name: "production", table: "proxy_transactions", key: "transaction_id",
			kind:   kernel.OAuthProxyRetireProduction,
			source: ProxyTransactionMigrationSource{Schema: "oauth_rp", Version: 101},
			read:   productionRetirementQuery, erase: productionRetirementMutation,
			seed: `INSERT INTO oauth_rp.proxy_transactions
 (tenant_id,transaction_id,origin_command_id,callback_command_id,production_deployment,provider_id,
 configuration_version,production_callback_uri,state_key_version,state_lookup_digest,binding_ciphertext,
 state_proof_ciphertext,pkce_ciphertext,issued_at,expires_at,version,outcome,handoff_ciphertext,settled_at)
 SELECT CASE WHEN n<=16000 THEN 'tenant-dense' ELSE 'tenant-sparse-'||((n-16001)/100)::text END,
 'flow-'||n,decode(md5('origin-'||n),'hex'),decode(md5('callback-'||n),'hex'),
 'production-a','provider-a',18446744073709551615,'https://identity.example/callback',4294967295,
 decode(md5('state-'||n)||md5('lookup-'||n),'hex'),decode(repeat(md5('binding-'||n),16),'hex'),
 CASE WHEN n%2=1 THEN decode(repeat(md5('proof-'||n),16),'hex') END,
 CASE WHEN n%2=1 THEN decode(md5('pkce-'||n),'hex') END,$1::timestamptz,$2::timestamptz,
 CASE WHEN n%2=1 THEN 1 ELSE 2 END,CASE WHEN n%2=0 THEN 1 END,
 CASE WHEN n%2=0 THEN decode(repeat(md5('handoff-'||n),16),'hex') END,
 CASE WHEN n%2=0 THEN $1::timestamptz+interval '1 second' END FROM generate_series(1,20000) n`,
		},
		{
			name: "preview", table: "proxy_preview_bindings", key: "flow_id",
			kind:   kernel.OAuthProxyRetirePreview,
			source: ProxyPreviewBindingMigrationSource{Schema: "oauth_rp", Version: 104},
			read:   previewRetirementQuery, erase: previewRetirementMutation,
			seed: `INSERT INTO oauth_rp.proxy_preview_bindings
 (tenant_id,flow_id,origin_command_id,callback_command_id,issued_at,expires_at,
 binding_ciphertext,proof_ciphertext,version,settled_at)
 SELECT CASE WHEN n<=16000 THEN 'tenant-dense' ELSE 'tenant-sparse-'||((n-16001)/100)::text END,
 'flow-'||n,decode(md5('origin-'||n),'hex'),decode(md5('callback-'||n),'hex'),$1::timestamptz,$2::timestamptz,
 decode(repeat(md5('binding-'||n),16),'hex'),
 CASE WHEN n%2=1 THEN decode(repeat(md5('proof-'||n),16),'hex') END,
 CASE WHEN n%2=1 THEN 1 ELSE 2 END,
 CASE WHEN n%2=0 THEN $1::timestamptz+interval '1 second' END FROM generate_series(1,20000) n`,
		},
	} {
		t.Run(role.name, func(t *testing.T) {
			install(t, role.source)
			if _, err := tx.Exec(ctx, role.seed, issued, issued.Add(5*time.Minute)); err != nil {
				t.Fatal("seed 20k skewed open/settled originals", err)
			}
			// Install the actual expansion and validation on populated custody.
			version := migrations.Version(102)
			if role.kind == kernel.OAuthProxyRetirePreview {
				version = 105
			}
			install(t, ProxyRetirementMigrationSource{Schema: "oauth_rp", Version: version, Kind: role.kind})
			table := "oauth_rp." + role.table
			var engine, columns, indexes string
			if err := tx.QueryRow(ctx, `SELECT current_setting('server_version'),
 (SELECT string_agg(column_name||':'||coalesce(domain_schema||'.'||domain_name,udt_schema||'.'||udt_name),', ' ORDER BY ordinal_position)
 FROM information_schema.columns WHERE table_schema='oauth_rp' AND table_name=$1),
 (SELECT string_agg(indexdef,E'\n' ORDER BY indexname) FROM pg_indexes WHERE schemaname='oauth_rp' AND tablename=$1)`,
				role.table).Scan(&engine, &columns, &indexes); err != nil {
				t.Fatal("inspect actual column and index definitions", err)
			}
			var total, dense, tenants, open, settled int
			if err := tx.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE tenant_id='tenant-dense'),count(DISTINCT tenant_id),
 count(*) FILTER(WHERE version=1),count(*) FILTER(WHERE version=2) FROM `+table).
				Scan(&total, &dense, &tenants, &open, &settled); err != nil || total != 20000 || dense != 16000 || tenants != 41 || open != 10000 || settled != 10000 {
				t.Fatal("custody volume or skew differs", total, dense, tenants, open, settled, err)
			}
			t.Logf("PostgreSQL %s; columns=%s; indexes=%s; 20k synthetic rows, 16k dense tenant plus 40 tenants of 100 rows; half open, half settled; no competing fixture load", engine, columns, indexes)
			for _, selection := range []struct {
				name, tenant string
				number       int
			}{
				{"dense-open", "tenant-dense", 1}, {"dense-settled", "tenant-dense", 2},
				{"sparse-open", "tenant-sparse-0", 16001}, {"sparse-settled", "tenant-sparse-0", 16002},
			} {
				var origin, callback, digest []byte
				projection := "origin_command_id,callback_command_id,NULL::bytea"
				if role.kind == kernel.OAuthProxyRetireProduction {
					projection = "origin_command_id,callback_command_id,state_lookup_digest"
				}
				if err := tx.QueryRow(ctx, `SELECT `+projection+` FROM `+table+` WHERE tenant_id=$1 AND `+role.key+`=$2`,
					selection.tenant, fmt.Sprintf("flow-%d", selection.number)).
					Scan(&origin, &callback, &digest); err != nil {
					t.Fatal("read selected synthetic locator", err)
				}
				binding := make([]byte, 2048)
				if _, err := rand.Read(binding); err != nil {
					t.Fatal(err)
				}
				if _, err := tx.Exec(ctx, `UPDATE `+table+` SET binding_ciphertext=$3 WHERE tenant_id=$1 AND `+role.key+`=$2`,
					selection.tenant, fmt.Sprintf("flow-%d", selection.number), binding); err != nil {
					t.Fatal("install incompressible measured binding", err)
				}
				readArgs := []any{selection.tenant, fmt.Sprintf("flow-%d", selection.number), origin}
				if role.kind == kernel.OAuthProxyRetireProduction {
					readArgs = append(readArgs, "production-a", "provider-a")
				}
				eraseArgs := append(slices.Clone(readArgs), callback)
				if role.kind == kernel.OAuthProxyRetireProduction {
					eraseArgs = append(eraseArgs, "https://identity.example/callback", "18446744073709551615", int64(4294967295), digest)
				}
				eraseArgs = append(eraseArgs, issued, issued.Add(5*time.Minute), binding, bytes.Repeat([]byte{251}, 16), "18446744073709551615")
				if _, err := tx.Exec(ctx, "ANALYZE "+table); err != nil {
					t.Fatal(err)
				}
				for _, variant := range []string{"eligible", "missing-flow", "stale-origin", "stale-binding"} {
					t.Run(selection.name+"/"+variant, func(t *testing.T) {
						queryArgs, mutationArgs := slices.Clone(readArgs), slices.Clone(eraseArgs)
						want := 1
						if variant != "eligible" {
							want = 0
						}
						switch variant {
						case "missing-flow":
							queryArgs[1], mutationArgs[1] = "missing-flow", "missing-flow"
						case "stale-origin":
							queryArgs[2], mutationArgs[2] = bytes.Repeat([]byte{250}, 16), bytes.Repeat([]byte{250}, 16)
						case "stale-binding":
							mutationArgs[len(mutationArgs)-3] = []byte("stale-binding")
						}
						if variant != "stale-binding" {
							proxyRetirementMeasureStatement(t, ctx, tx, role.read(table), queryArgs, role.table, role.key, false, want, callback, binding)
						}
						proxyRetirementMeasureStatement(t, ctx, tx, role.erase(table), mutationArgs, role.table, role.key, true, want, callback, binding)
					})
				}
			}
			var unchanged bool
			if err := tx.QueryRow(ctx, `SELECT count(*)=20000 AND count(*) FILTER(WHERE version=1)=10000
 AND count(*) FILTER(WHERE version=2)=10000 AND bool_and(retired_at IS NULL AND retirement_source_command_id IS NULL
 AND retirement_source_version IS NULL) FROM `+table).Scan(&unchanged); err != nil || !unchanged {
				t.Fatal("sample retirement survived rollback", err)
			}
		})
	}
}

func proxyRetirementMeasureStatement(t *testing.T, ctx context.Context, fixture pgx.Tx, statement string, args []any, table, key string, mutation bool, want int, callback, binding []byte) {
	t.Helper()
	bindings := make([]string, len(args))
	for i, arg := range args {
		bindings[i] = fmt.Sprintf("$%d=%T", i+1, arg)
	}
	t.Logf("native SQL=%s; Work scalar bindings=%s; decimal versions are text→numeric, state key is int8", statement, strings.Join(bindings, ", "))
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
				rows := proxyRetirementNativeRows(t, ctx, tx, "EXPLAIN (ANALYZE,BUFFERS,WAL,FORMAT JSON) "+statement, args)
				var raw []byte
				if !rows.Next() {
					t.Fatal("explain did not return a plan", rows.Err())
				}
				if err := rows.Scan(&raw); err != nil {
					rows.Close()
					t.Fatal(err)
				}
				rows.Close()
				if err := rows.Err(); err != nil {
					t.Fatal(err)
				}
				var plans []struct{ Plan proxyRetirementEvidencePlan }
				if err := json.Unmarshal(raw, &plans); err != nil || len(plans) != 1 || !plans[0].Plan.pointBounded(table, key, mutation, want) {
					t.Fatalf("default planner lost exact existing-index point bound: %v\n%s", err, raw)
				}
				t.Logf("default planner, instrumented buffers/WAL (not wall latency)=%s", raw)
				return
			}
			start := time.Now()
			rows := proxyRetirementNativeRows(t, ctx, tx, statement, args)
			count := 0
			for rows.Next() {
				count++
				var gotCallback, gotBinding, digest []byte
				var uri, profile string
				var stateKey int64
				var issued, expires time.Time
				var err error
				if table == "proxy_transactions" {
					err = rows.Scan(&gotCallback, &uri, &profile, &stateKey, &digest, &issued, &expires, &gotBinding)
				} else {
					err = rows.Scan(&gotCallback, &issued, &expires, &gotBinding)
				}
				if err != nil || !bytes.Equal(gotCallback, callback) || !bytes.Equal(gotBinding, binding) {
					rows.Close()
					t.Fatal("read returned a different custody projection", err)
				}
			}
			rows.Close()
			duration := time.Since(start)
			if err := rows.Err(); err != nil {
				t.Fatal("native retirement execution", err)
			}
			if mutation {
				count = int(rows.CommandTag().RowsAffected())
			}
			if count != want {
				t.Fatalf("returned/affected rows=%d, want %d", count, want)
			}
			if sample > 1 {
				elapsed = append(elapsed, duration)
			}
		}()
	}
	slices.Sort(elapsed)
	t.Logf("returned/affected_rows=%d; %d warm sequential samples, median=%s min=%s max=%s; includes native encode, round trip and drain/scan; excludes acquisition, savepoint, rollback and setup; fixture writes rollback, but WAL/dead tuples may occur; synthetic size/skew only, not cold-cache, contention, throughput, full-operation or production evidence", want, samples, elapsed[samples/2], elapsed[0], elapsed[samples-1])
}

// Match kernel.Work's fixed scalar OIDs and binary encodings rather than letting
// pgx infer numeric parameters from SQL. No raw connection escapes the fixture.
func proxyRetirementNativeRows(t *testing.T, ctx context.Context, tx pgx.Tx, statement string, args []any) pgx.Rows {
	t.Helper()
	codecs := pgtype.NewMap()
	values, oids, formats := make([][]byte, len(args)), make([]uint32, len(args)), make([]int16, len(args))
	for i, arg := range args {
		switch arg.(type) {
		case string:
			oids[i] = pgtype.TextOID
		case []byte:
			oids[i] = pgtype.ByteaOID
		case int64:
			oids[i] = pgtype.Int8OID
		case time.Time:
			oids[i] = pgtype.TimestamptzOID
		default:
			t.Fatalf("unexpected Work binding type %T", arg)
		}
		formats[i] = pgtype.BinaryFormatCode
		var err error
		values[i], err = codecs.Encode(oids[i], formats[i], arg, make([]byte, 0))
		if err != nil {
			t.Fatal("encode native Work scalar", err)
		}
	}
	return pgx.RowsFromResultReader(codecs, tx.Conn().PgConn().ExecParams(ctx, statement, values, oids, formats, nil))
}

func proxyRetirementQueryRollback(t *testing.T, tx pgx.Tx) {
	t.Helper()
	cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := tx.Rollback(cleanup); err != nil {
		t.Error("rollback retirement query fixture/sample", err)
	}
}

type proxyRetirementEvidencePlan struct {
	Kind      string                        `json:"Node Type"`
	Operation string                        `json:"Operation"`
	Relation  string                        `json:"Relation Name"`
	Index     string                        `json:"Index Name"`
	Condition string                        `json:"Index Cond"`
	Rows      float64                       `json:"Actual Rows"`
	Loops     float64                       `json:"Actual Loops"`
	Filtered  float64                       `json:"Rows Removed by Filter"`
	Plans     []proxyRetirementEvidencePlan `json:"Plans"`
}

func (p proxyRetirementEvidencePlan) pointBounded(table, key string, mutation bool, want int) bool {
	if mutation {
		// UPDATE without RETURNING reports zero output rows; its child reports
		// matched rows. A normal sample checks the command's affected-row tag.
		return p.Kind == "ModifyTable" && p.Operation == "Update" && p.Relation == table && p.Loops == 1 && p.Rows == 0 &&
			len(p.Plans) == 1 && p.Plans[0].pointBounded(table, key, false, want)
	}
	exactKey := map[string]string{
		table + "_pkey": key,
		table + "_tenant_id_origin_command_id_key":   "origin_command_id",
		table + "_tenant_id_callback_command_id_key": "callback_command_id",
	}[p.Index]
	return (p.Kind == "Index Scan" || p.Kind == "Index Only Scan") && p.Relation == table && exactKey != "" &&
		strings.Contains(p.Condition, "tenant_id") && strings.Contains(p.Condition, exactKey) &&
		p.Loops == 1 && p.Rows == float64(want) && p.Filtered >= 0 && p.Rows+p.Filtered <= 1 && len(p.Plans) == 0
}
