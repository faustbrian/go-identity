//go:build integration

package postgres

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func TestProxyLookupSelectsOriginalAcrossRetainedKeys(t *testing.T) {
	ctx, db := rpMigrationDatabase(t)
	prior, err := (MigrationSource{Schema: "oauth_rp", Version: 100}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, prior[0].UpSQL()); err != nil {
		t.Fatal(err)
	}
	history, err := (ProxyTransactionMigrationSource{Schema: "oauth_rp", Version: 101}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, history[0].UpSQL()); err != nil {
		t.Fatal(err)
	}
	// At 80 initial rows/sec, the five-minute admission window contains
	// about 24k rows. Keep the selected provider deliberately dense and the
	// tenants skewed; the result still requires an exact random-key point read.
	const seed = `INSERT INTO oauth_rp.proxy_transactions(tenant_id,transaction_id,origin_command_id,callback_command_id,
production_deployment,provider_id,configuration_version,production_callback_uri,state_key_version,state_lookup_digest,
binding_ciphertext,state_proof_ciphertext,pkce_ciphertext,issued_at,expires_at,version)
SELECT CASE WHEN g%10=0 THEN 'tenant-small' ELSE 'tenant-dense' END, 'proxy-'||g,
decode(md5('origin-'||g),'hex'),decode(md5('callback-'||g),'hex'),'production-a',
CASE WHEN g%10=0 THEN 'provider-b' ELSE 'provider-a' END,1,'https://identity.example/callback',1,
decode(md5('state-'||g)||md5('fixture-'||g),'hex'),decode('01','hex'),decode('02','hex'),decode('03','hex'),
statement_timestamp()-interval '1 minute',statement_timestamp()+interval '1 minute',1
FROM generate_series(1,24000) g`
	if _, err := db.Exec(ctx, seed); err != nil {
		t.Fatal(err)
	}
	keys := make(map[uint32][32]byte, 32)
	for version := range uint32(32) {
		keys[version+1] = [32]byte{byte(version + 1)}
	}
	selection := proxyLookupSelection{"production-a", "provider-a", "https://identity.example/callback", 1, [32]byte{42}}
	private := proxyLookupDigest(keys[9], 9, selection.production, selection.provider, selection.providerVersion, selection.state)
	if _, err := db.Exec(ctx, `UPDATE oauth_rp.proxy_transactions SET state_key_version=9,state_lookup_digest=$1 WHERE tenant_id='tenant-dense' AND transaction_id='proxy-123'`, private[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `ANALYZE oauth_rp.proxy_transactions`); err != nil {
		t.Fatal(err)
	}
	row, err := readProxyLookup(ctx, db, "oauth_rp", keys, selection)
	if err != nil || row.tenant != "tenant-dense" || row.transaction != "proxy-123" || row.stateKey != 9 || len(row.proof) != 1 {
		t.Fatal("retained key did not select exact durable custody", err)
	}
	row.clear()
	for name, changed := range map[string]proxyLookupSelection{
		"foreign deployment":     {"production-b", selection.provider, selection.callback, 1, selection.state},
		"other provider version": {selection.production, selection.provider, selection.callback, 2, selection.state},
		"other callback":         {selection.production, selection.provider, selection.callback + "/foreign", 1, selection.state},
		"missing state":          {selection.production, selection.provider, selection.callback, 1, [32]byte{43}},
	} {
		bad, err := readProxyLookup(ctx, db, "oauth_rp", keys, changed)
		if !errors.Is(err, identity.ForbiddenError{}) || len(bad.proof) > 0 {
			t.Fatalf("%s exposed custody: %v", name, err)
		}
	}
	t.Run("typed indexed point lookup", func(t *testing.T) {
		versions := make([]int64, 32)
		digests := make([][]byte, 32)
		for i := range versions {
			versions[i] = int64(i + 1)
			d := proxyLookupDigest(keys[uint32(i+1)], uint32(i+1), selection.production, selection.provider, 1, selection.state)
			digests[i] = d[:]
		}
		for _, miss := range []bool{false, true} {
			if miss {
				digests[8] = make([]byte, 32)
			}
			var raw []byte
			err := db.QueryRow(ctx, "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) "+proxyLookupSQL("oauth_rp"), selection.production, selection.provider, selection.providerVersion, selection.callback, versions, digests).Scan(&raw)
			var plan []struct{ Plan proxyLookupPlan }
			if err != nil || json.Unmarshal(raw, &plan) != nil || len(plan) != 1 || !plan[0].Plan.boundedStateScan() {
				t.Fatalf("lookup must use an indexed state equality on dense data; miss=%v: %v\n%s", miss, err, raw)
			}
		}
		measure := func(ctx context.Context, lookup proxyLookupSelection, shouldMatch bool) time.Duration {
			start := time.Now()
			for range 25 {
				r, err := readProxyLookup(ctx, db, "oauth_rp", keys, lookup)
				if shouldMatch && err != nil || !shouldMatch && !errors.Is(err, identity.ForbiddenError{}) {
					t.Fatal("lookup verification failed during sample", err)
				}
				r.clear()
			}
			return time.Since(start) / 25
		}
		matched := measure(ctx, selection, true)
		selection.state[0]++
		missed := measure(ctx, selection, false)
		selection.state[0]--
		t.Logf("24k warm isolated rows, 32 retained keys, 25 samples each: hit mean %s; miss mean %s (includes Go and driver)", matched, missed)
	})
	t.Run("bounded native Start insert", func(t *testing.T) {
		var version, columns, indexes string
		if err := db.QueryRow(ctx, `SELECT current_setting('server_version'),
(SELECT string_agg(column_name||':'||coalesce(domain_schema||'.'||domain_name,udt_schema||'.'||udt_name), ', ' ORDER BY ordinal_position)
 FROM information_schema.columns WHERE table_schema='oauth_rp' AND table_name='proxy_transactions'),
(SELECT string_agg(indexdef, E'\n' ORDER BY indexname) FROM pg_indexes WHERE schemaname='oauth_rp' AND tablename='proxy_transactions')`).Scan(&version, &columns, &indexes); err != nil {
			t.Fatal("inspect isolated insert schema", err)
		}
		t.Logf("PostgreSQL %s; isolated analyzed 24k rows, 90%% tenant-dense/provider-a and 10%% tenant-small/provider-b; sequential warmed rollback-only samples, no concurrent load or production extrapolation; ciphertext-shaped bytes do not exercise encryption", version)
		t.Logf("actual columns: %s\nactual indexes maintained by each insert:\n%s", columns, indexes)
		for _, test := range []struct {
			name, tenant, provider string
			providerVersion        uint64
			stateKeyVersion        uint32
		}{
			{"dense", "tenant-dense", "provider-a", 1, 1},
			{"sparse", "tenant-small", "provider-b", 1, 1},
			{"full-width versions", "tenant-dense", "provider-a", math.MaxUint64, math.MaxUint32},
		} {
			t.Run(test.name, func(t *testing.T) {
				issued := time.Now().UTC().Truncate(time.Second)
				binding, proof, pkce := make([]byte, 2048), make([]byte, 2048), make([]byte, 128)
				for _, ciphertext := range [][]byte{binding, proof, pkce} {
					if _, err := rand.Read(ciphertext); err != nil {
						t.Fatal("generate incompressible ciphertext-shaped fixture", err)
					}
				}
				args := []any{test.tenant, "proxy-insert-sample", bytes.Repeat([]byte{201}, 16), bytes.Repeat([]byte{202}, 16),
					"production-a", test.provider, test.providerVersion, "https://identity.example/callback", test.stateKeyVersion,
					bytes.Repeat([]byte{203}, 32), binding, proof, pkce,
					issued, issued.Add(5 * time.Minute)}
				bindings := make([]string, len(args))
				for i, arg := range args {
					bindings[i] = fmt.Sprintf("$%d=%T", i+1, arg)
				}
				t.Logf("ApplyFeature native Go/pgx bindings: %s; provider version=%d; state key version=%d; binding/proof/PKCE bytes=2048/2048/128", strings.Join(bindings, ", "), test.providerVersion, test.stateKeyVersion)
				const samples = 25
				var elapsed, fastest, slowest time.Duration
				for i := range samples + 1 {
					tx, err := db.Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					func() {
						defer func() {
							cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
							defer cancel()
							if err := tx.Rollback(cleanup); err != nil {
								t.Error("rollback native Start sample", err)
							}
						}()
						if _, err := tx.Exec(ctx, `SET LOCAL statement_timeout='2s'; SET LOCAL lock_timeout='1s'`); err != nil {
							t.Fatal("bound insert sample", err)
						}
						if i == 0 {
							var raw []byte
							err := tx.QueryRow(ctx, "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) "+insertProxyStartSQL("oauth_rp"), args...).Scan(&raw)
							var plan []struct{ Plan proxyLookupPlan }
							if err != nil || json.Unmarshal(raw, &plan) != nil || len(plan) != 1 || !plan[0].Plan.boundedStartInsert() {
								t.Fatalf("native Start must insert a single Result row without scans: %v\n%s", err, raw)
							}
							t.Logf("warmup instrumented insert plan (includes buffer work, not normal latency): %s", raw)
							return
						}
						start := time.Now()
						tag, err := tx.Exec(ctx, insertProxyStartSQL("oauth_rp"), args...)
						duration := time.Since(start)
						if err != nil || tag.RowsAffected() != 1 {
							t.Fatal("native Start insert must affect exactly one row", err)
						}
						elapsed += duration
						if fastest == 0 || duration < fastest {
							fastest = duration
						}
						if duration > slowest {
							slowest = duration
						}
						var stored bool
						if err := tx.QueryRow(ctx, `SELECT configuration_version=$3 AND state_key_version=$4 AND version=1 AND outcome IS NULL
AND binding_ciphertext=$5 AND state_proof_ciphertext=$6 AND pkce_ciphertext=$7
FROM oauth_rp.proxy_transactions WHERE tenant_id=$1 AND transaction_id=$2`, args[0], args[1], args[6], args[8], args[10], args[11], args[12]).Scan(&stored); err != nil || !stored {
							t.Fatal("insert did not preserve native versions and open custody", err)
						}
					}()
				}
				var retained int
				if err := db.QueryRow(ctx, `SELECT count(*) FROM oauth_rp.proxy_transactions WHERE tenant_id=$1 AND transaction_id=$2`, args[0], args[1]).Scan(&retained); err != nil || retained != 0 {
					t.Fatal("rolled-back insert retained custody", err)
				}
				t.Logf("%d warmed insert samples: mean %s; min %s; max %s; includes Go/pgx and statement round trip, excludes BEGIN, timeout setup, correctness read and ROLLBACK; no latency threshold or commit/durability/complete Start claim", samples, elapsed/samples, fastest, slowest)
			})
		}
	})
	t.Run("indexed original lock and settlement", func(t *testing.T) {
		var command []byte
		var now time.Time
		if err := db.QueryRow(ctx, `SELECT callback_command_id,clock_timestamp() FROM oauth_rp.proxy_transactions
WHERE tenant_id='tenant-dense' AND transaction_id='proxy-123'`).Scan(&command, &now); err != nil {
			t.Fatal(err)
		}
		args := []any{"tenant-dense", "proxy-123", command}
		samples := func(query string, args []any) time.Duration {
			start := time.Now()
			for i := range 26 {
				tx, err := db.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if i == 0 {
					var raw []byte
					err := tx.QueryRow(ctx, "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) "+query, args...).Scan(&raw)
					var plan []struct{ Plan proxyLookupPlan }
					if err != nil || json.Unmarshal(raw, &plan) != nil || len(plan) != 1 || !plan[0].Plan.boundedOriginalScan() {
						_ = tx.Rollback(ctx)
						t.Fatalf("original operation must perform one indexed locator probe: %v\n%s", err, raw)
					}
					start = time.Now()
				} else if tag, err := tx.Exec(ctx, query, args...); err != nil || tag.RowsAffected() != 1 {
					_ = tx.Rollback(ctx)
					t.Fatal("original operation did not affect the one selected row", err)
				}
				if err := tx.Rollback(ctx); err != nil {
					t.Fatal(err)
				}
			}
			return time.Since(start) / 25
		}
		locked := samples(lockProxyForwardSQL("oauth_rp"), append(args, uint64(1), []byte{1}))
		settled := samples(settleProxyForwardSQL("oauth_rp"), append(args, int16(2), []byte(nil), now))
		t.Logf("24k warm isolated rows, 25 samples each with transaction and rollback: lock mean %s; settlement mean %s", locked, settled)
	})
	t.Run("full-width provider version", func(t *testing.T) {
		full := selection
		full.providerVersion = math.MaxUint64
		digest := proxyLookupDigest(keys[9], 9, full.production, full.provider, full.providerVersion, full.state)
		if _, err := db.Exec(ctx, `UPDATE oauth_rp.proxy_transactions SET configuration_version=$1::text::numeric,state_key_version=9,state_lookup_digest=$2
WHERE tenant_id='tenant-dense' AND transaction_id='proxy-125'`, strconv.FormatUint(full.providerVersion, 10), digest[:]); err != nil {
			t.Fatal("could not install supported full-width provider version", err)
		}
		row, err := readProxyLookup(ctx, db, "oauth_rp", keys, full)
		defer row.clear()
		if err != nil || row.tenant != "tenant-dense" || row.transaction != "proxy-125" || row.stateKey != 9 {
			t.Fatal("did not select exact full-width provider version", err)
		}
	})
	duplicate := proxyLookupDigest(keys[3], 3, selection.production, selection.provider, selection.providerVersion, selection.state)
	if _, err := db.Exec(ctx, `UPDATE oauth_rp.proxy_transactions SET state_key_version=3,state_lookup_digest=$1 WHERE tenant_id='tenant-dense' AND transaction_id='proxy-124'`, duplicate[:]); err != nil {
		t.Fatal(err)
	}
	ambiguous, err := readProxyLookup(ctx, db, "oauth_rp", keys, selection)
	if !errors.Is(err, identity.UnavailableError{}) || len(ambiguous.binding) != 0 {
		t.Fatal("multiple retained keys silently selected one of two native rows", err)
	}
}

type proxyLookupPlan struct {
	Kind        string `json:"Node Type"`
	Operation   string
	Relation    string  `json:"Relation Name"`
	Condition   string  `json:"Index Cond"`
	ActualRows  float64 `json:"Actual Rows"`
	ActualLoops int     `json:"Actual Loops"`
	Plans       []proxyLookupPlan
}

func (p proxyLookupPlan) boundedStartInsert() bool {
	if p.Kind != "ModifyTable" || p.Operation != "Insert" || p.Relation != "proxy_transactions" || p.ActualLoops != 1 || len(p.Plans) != 1 {
		return false
	}
	result := p.Plans[0]
	return result.Kind == "Result" && result.ActualRows == 1 && result.ActualLoops == 1 && len(result.Plans) == 0
}

func (p proxyLookupPlan) boundedStateScan() bool {
	if p.Relation == "proxy_transactions" {
		return p.Kind == "Index Scan" && strings.Contains(p.Condition, "state_lookup_digest =") && p.ActualLoops > 0 && p.ActualLoops <= 32
	}
	for _, child := range p.Plans {
		if child.boundedStateScan() {
			return true
		}
	}
	return false
}

func (p proxyLookupPlan) boundedOriginalScan() bool {
	if p.Relation == "proxy_transactions" && p.Kind == "Index Scan" && p.ActualLoops == 1 &&
		strings.Contains(p.Condition, "tenant_id") && (strings.Contains(p.Condition, "transaction_id") || strings.Contains(p.Condition, "callback_command_id")) {
		return true
	}
	for _, child := range p.Plans {
		if child.boundedOriginalScan() {
			return true
		}
	}
	return false
}
