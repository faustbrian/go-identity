//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"errors"
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
	Relation    string `json:"Relation Name"`
	Condition   string `json:"Index Cond"`
	ActualLoops int    `json:"Actual Loops"`
	Plans       []proxyLookupPlan
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
