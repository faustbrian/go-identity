//go:build integration && queryperformance

package postgres

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// Synthetic custody measures discovery's actual SQL and native pgx bindings;
// authenticated eligibility and the retiring consumer have separate coverage.
func TestProxyRetirementDiscoveryQueryIsKeysetBounded(t *testing.T) {
	ctx, db := rpMigrationDatabase(t)
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer proxyRetirementQueryRollback(t, tx)
	install := func(source migrations.Source) {
		t.Helper()
		history, err := source.Load(ctx)
		if err != nil {
			t.Fatal("load discovery's actual custody migrations", err)
		}
		for _, migration := range history {
			if _, err := tx.Exec(ctx, migration.UpSQL()); err != nil {
				t.Fatal("apply discovery's actual custody migrations", err)
			}
		}
	}
	install(MigrationSource{Schema: "oauth_rp", Version: 100})
	issued := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	for _, role := range []struct {
		name, table, key, seed, erase string
		kind                          kernel.OAuthProxyRetirementKind
		source                        migrations.Source
		query                         func(string) string
	}{
		{
			name: "production", table: "proxy_transactions", key: "transaction_id",
			kind:   kernel.OAuthProxyRetireProduction,
			source: ProxyTransactionMigrationSource{Schema: "oauth_rp", Version: 101},
			query:  productionRetirementDiscoverySQL,
			seed: `INSERT INTO oauth_rp.proxy_transactions
 (tenant_id,transaction_id,origin_command_id,callback_command_id,production_deployment,provider_id,
 configuration_version,production_callback_uri,state_key_version,state_lookup_digest,binding_ciphertext,
 state_proof_ciphertext,pkce_ciphertext,issued_at,expires_at,version,outcome,handoff_ciphertext,settled_at)
 SELECT CASE WHEN n<=16000 THEN 'tenant-dense' ELSE 'tenant-sparse-'||((n-16001)/100)::text END,
 'flow-'||lpad(n::text,6,'0'),decode(md5('origin-'||n),'hex'),decode(md5('callback-'||n),'hex'),
 'production-a','provider-a',18446744073709551615,'https://identity.example/callback',4294967295,
 decode(md5('state-'||n)||md5('lookup-'||n),'hex'),decode(repeat(md5('binding-'||n),16),'hex'),
 CASE WHEN n%2=1 THEN decode(md5('proof-'||n),'hex') END,
 CASE WHEN n%2=1 THEN decode(md5('pkce-'||n),'hex') END,$1::timestamptz,$2::timestamptz,
 CASE WHEN n%2=1 THEN 1 ELSE 2 END,CASE WHEN n%2=0 THEN 1 END,
 CASE WHEN n%2=0 THEN decode(md5('handoff-'||n),'hex') END,
 CASE WHEN n%2=0 THEN $1::timestamptz+interval '1 second' END FROM generate_series(1,20000) n`,
			erase: `,state_proof_ciphertext=NULL,pkce_ciphertext=NULL,handoff_ciphertext=NULL`,
		},
		{
			name: "preview", table: "proxy_preview_bindings", key: "flow_id",
			kind:   kernel.OAuthProxyRetirePreview,
			source: ProxyPreviewBindingMigrationSource{Schema: "oauth_rp", Version: 104},
			query:  previewRetirementDiscoverySQL,
			seed: `INSERT INTO oauth_rp.proxy_preview_bindings
 (tenant_id,flow_id,origin_command_id,callback_command_id,issued_at,expires_at,
 binding_ciphertext,proof_ciphertext,version,settled_at)
 SELECT CASE WHEN n<=16000 THEN 'tenant-dense' ELSE 'tenant-sparse-'||((n-16001)/100)::text END,
 'flow-'||lpad(n::text,6,'0'),decode(md5('origin-'||n),'hex'),decode(md5('callback-'||n),'hex'),
 $1::timestamptz,$2::timestamptz,decode(repeat(md5('binding-'||n),16),'hex'),
 CASE WHEN n%2=1 THEN decode(md5('proof-'||n),'hex') END,CASE WHEN n%2=1 THEN 1 ELSE 2 END,
 CASE WHEN n%2=0 THEN $1::timestamptz+interval '1 second' END FROM generate_series(1,20000) n`,
			erase: `,proof_ciphertext=NULL`,
		},
	} {
		t.Run(role.name, func(t *testing.T) {
			install(role.source)
			if _, err := tx.Exec(ctx, role.seed, issued, issued.Add(5*time.Minute)); err != nil {
				t.Fatal("seed 20k skewed original custody rows", err)
			}
			version := migrations.Version(102)
			if role.kind == kernel.OAuthProxyRetirePreview {
				version = 105
			}
			install(ProxyRetirementMigrationSource{Schema: "oauth_rp", Version: version, Kind: role.kind})
			table := "oauth_rp." + role.table
			// Two complete middle pages are retired: application-side rejection
			// must not turn the SQL into an unbounded search for eligible rows.
			if _, err := tx.Exec(ctx, `UPDATE `+table+` SET version=3,
 retirement_source_command_id=decode(md5('retire-'||`+role.key+`),'hex'),retirement_source_version=7,
 retired_at=issued_at+interval '2 seconds'`+role.erase+`
 WHERE right(`+role.key+`,6)::int%5=0 OR right(`+role.key+`,6)::int BETWEEN 8001 AND 8065`); err != nil {
				t.Fatal("install retired custody including rejected middle pages", err)
			}
			if _, err := tx.Exec(ctx, "ANALYZE "+table); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, `SET LOCAL statement_timeout='2s'; SET LOCAL lock_timeout='1s'`); err != nil {
				t.Fatal(err)
			}
			var engine, columns, indexes string
			if err := tx.QueryRow(ctx, `SELECT current_setting('server_version'),
 (SELECT string_agg(column_name||':'||coalesce(domain_schema||'.'||domain_name,udt_schema||'.'||udt_name),', ' ORDER BY ordinal_position)
 FROM information_schema.columns WHERE table_schema='oauth_rp' AND table_name=$1),
 (SELECT string_agg(indexdef,E'\n' ORDER BY indexname) FROM pg_indexes WHERE schemaname='oauth_rp' AND tablename=$1)`, role.table).
				Scan(&engine, &columns, &indexes); err != nil {
				t.Fatal("inspect actual discovery schema and indexes", err)
			}
			var total, dense, tenants, retired int
			if err := tx.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE tenant_id='tenant-dense'),
 count(DISTINCT tenant_id),count(*) FILTER(WHERE version=3) FROM `+table).
				Scan(&total, &dense, &tenants, &retired); err != nil || total != 20000 || dense != 16000 || tenants != 41 || retired != 4052 {
				t.Fatal("unexpected discovery volume/skew/retired population", total, dense, tenants, retired, err)
			}
			t.Logf("PostgreSQL %s; pgx mode=%v; columns=%s; indexes=%s; 20k synthetic rows, 16k dense tenant, 40 tenants of 100, 4052 retired, mixed open/settled; no competing fixture load", engine, db.Config().DefaultQueryExecMode, columns, indexes)
			for _, selection := range []struct {
				name, tenant        string
				after, first, count int
			}{
				{"dense-first", "tenant-dense", 0, 1, 33},
				{"dense-middle-all-retired", "tenant-dense", 8000, 8001, 33},
				{"dense-next-all-retired", "tenant-dense", 8032, 8033, 33},
				{"dense-end", "tenant-dense", 15992, 15993, 8},
				{"dense-no-match", "tenant-dense", 16000, 0, 0},
				{"sparse-first", "tenant-sparse-0", 0, 16001, 33},
				{"sparse-middle", "tenant-sparse-0", 16050, 16051, 33},
				{"sparse-end", "tenant-sparse-0", 16092, 16093, 8},
				{"sparse-no-match", "tenant-sparse-0", 16100, 0, 0},
				{"missing-tenant", "tenant-missing", 0, 0, 0},
			} {
				t.Run(selection.name, func(t *testing.T) {
					after := ""
					if selection.after > 0 {
						after = fmt.Sprintf("flow-%06d", selection.after)
					}
					proxyRetirementMeasureDiscovery(t, ctx, tx, role.query(table), role.table, role.key,
						selection.tenant, after, selection.first, selection.count, issued)
				})
			}
		})
	}
}

func proxyRetirementMeasureDiscovery(t *testing.T, ctx context.Context, tx pgx.Tx, statement, table, key, tenant, after string, first, want int, issued time.Time) {
	t.Helper()
	const pageSize, samples = 32, 8
	args := []any{tenant, after, pageSize + 1}
	t.Logf("actual discovery SQL=%s; native pgx Query bindings: $1=%T(%q), $2=%T(%q), $3=%T(%d); page=%d plus one continuation row", statement, args[0], tenant, args[1], after, args[2], pageSize+1, pageSize)
	var elapsed []time.Duration
	for sample := range samples + 1 {
		if sample == 0 || sample == samples {
			var raw []byte
			if err := tx.QueryRow(ctx, "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) "+statement, args...).Scan(&raw); err != nil {
				t.Fatal("explain actual discovery with native bindings", err)
			}
			var plans []struct{ Plan proxyRetirementDiscoveryPlan }
			if err := json.Unmarshal(raw, &plans); err != nil || len(plans) != 1 || !plans[0].Plan.keysetBounded(table, key, want, pageSize+1) {
				t.Fatalf("default planner lost existing primary-key bounded discovery: %v\n%s", err, raw)
			}
			t.Logf("default plan sample=%d, instrumented execution/buffers, not client wall latency=%s", sample, raw)
		}
		start := time.Now()
		rows, err := tx.Query(ctx, statement, args...)
		if err != nil {
			t.Fatal("execute actual discovery query", err)
		}
		page := make([]proxyRetirementDiscoveryQueryRow, 0, pageSize+1)
		for rows.Next() {
			var row proxyRetirementDiscoveryQueryRow
			destinations := []any{&row.flow, &row.version, &row.origin, &row.callback, &row.issued, &row.expires, &row.binding}
			if table == "proxy_transactions" {
				destinations = []any{&row.flow, &row.version, &row.origin, &row.callback, &row.production, &row.provider, &row.uri,
					&row.configuration, &row.stateKey, &row.digest, &row.issued, &row.expires, &row.binding}
			}
			if err := rows.Scan(destinations...); err != nil {
				rows.Close()
				t.Fatal("scan approved discovery projection", err)
			}
			page = append(page, row)
			if len(page) > pageSize+1 {
				rows.Close()
				t.Fatal("discovery exceeded page plus continuation bound")
			}
		}
		rows.Close()
		duration := time.Since(start)
		if err := rows.Err(); err != nil || len(page) != want {
			t.Fatal("unexpected bounded discovery result", len(page), want, err)
		}
		for count, row := range page {
			number, err := strconv.Atoi(strings.TrimPrefix(row.flow, "flow-"))
			if err != nil || number != first+count || row.flow != fmt.Sprintf("flow-%06d", first+count) {
				t.Fatal("discovery omitted, reordered or crossed the tenant's keyset", row.flow, count, err)
			}
			wantVersion := "2"
			if number%2 == 1 {
				wantVersion = "1"
			}
			retired := number%5 == 0 || number >= 8001 && number <= 8065
			if retired {
				wantVersion = "3"
			}
			originDigest := md5.Sum([]byte(fmt.Sprintf("origin-%d", number)))
			callbackDigest := md5.Sum([]byte(fmt.Sprintf("callback-%d", number)))
			bindingDigest := md5.Sum([]byte(fmt.Sprintf("binding-%d", number)))
			wantBinding := bytes.Repeat(bindingDigest[:], 16)
			if retired {
				wantBinding = nil
			}
			if row.version != wantVersion || !bytes.Equal(row.origin, originDigest[:]) || !bytes.Equal(row.callback, callbackDigest[:]) ||
				!row.issued.Equal(issued) || !row.expires.Equal(issued.Add(5*time.Minute)) || !bytes.Equal(row.binding, wantBinding) {
				t.Fatal("discovery changed original metadata or exposed retired ciphertext", row.flow, row.version)
			}
			if table == "proxy_transactions" {
				stateDigest := md5.Sum([]byte(fmt.Sprintf("state-%d", number)))
				lookupDigest := md5.Sum([]byte(fmt.Sprintf("lookup-%d", number)))
				wantDigest := append(stateDigest[:], lookupDigest[:]...)
				if row.production != "production-a" || row.provider != "provider-a" || row.uri != "https://identity.example/callback" ||
					row.configuration != "18446744073709551615" || row.stateKey != 4294967295 || !bytes.Equal(row.digest, wantDigest) {
					t.Fatal("discovery changed approved production locator metadata", row.flow)
				}
			}
		}
		if sample > 0 {
			elapsed = append(elapsed, duration)
		}
	}
	slices.Sort(elapsed)
	t.Logf("returned=%d, scan bound=%d, %d warm sequential native Query+scan samples: median=%s min=%s max=%s; one warmup plus two instrumented plans, no cache flush or forced planner; includes round trip/drain/scan, excludes acquisition/setup/assertions; runtime is one query per page of at most 33 rows, not an eligibility search; synthetic scale/skew only, not cold-cache, contention, throughput, full-operation, cryptographic eligibility or production proof", want, pageSize+1, samples, elapsed[samples/2], elapsed[0], elapsed[samples-1])
}

type proxyRetirementDiscoveryQueryRow struct {
	flow, version, production, provider, uri, configuration string
	origin, callback, digest, binding                       []byte
	stateKey                                                int64
	issued, expires                                         time.Time
}

type proxyRetirementDiscoveryPlan struct {
	Kind      string                         `json:"Node Type"`
	Relation  string                         `json:"Relation Name"`
	Index     string                         `json:"Index Name"`
	Condition string                         `json:"Index Cond"`
	Rows      float64                        `json:"Actual Rows"`
	Loops     float64                        `json:"Actual Loops"`
	Filtered  float64                        `json:"Rows Removed by Filter"`
	Plans     []proxyRetirementDiscoveryPlan `json:"Plans"`
}

func (p proxyRetirementDiscoveryPlan) keysetBounded(table, key string, want, limit int) bool {
	if p.Kind != "Limit" || p.Rows != float64(want) || p.Loops != 1 || p.Filtered != 0 || len(p.Plans) != 1 {
		return false
	}
	scan := p.Plans[0]
	return (scan.Kind == "Index Scan" || scan.Kind == "Index Only Scan") && scan.Relation == table &&
		scan.Index == table+"_pkey" && strings.Contains(scan.Condition, "tenant_id") && strings.Contains(scan.Condition, key) &&
		strings.Contains(scan.Condition, ">") && scan.Rows == float64(want) && scan.Loops == 1 &&
		scan.Filtered == 0 && scan.Rows <= float64(limit) && len(scan.Plans) == 0
}
