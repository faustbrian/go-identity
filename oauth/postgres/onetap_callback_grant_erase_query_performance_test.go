//go:build integration && queryperformance

package postgres

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// Measures the one added exact-custody UPDATE, not callback acceptance or
// production throughput. Actual callback atomicity is the native owner's test.
func TestOneTapCallbackGrantErasureQueryStaysPointBounded(t *testing.T) {
	_, pool, config, _ := oneTapStartIntegrationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	connection, err := pool.Raw().Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Release()
	db := connection.Conn()
	body := make([]byte, 65536)
	for offset := 0; offset < len(body); offset += sha256.Size {
		block := sha256.Sum256([]byte(fmt.Sprintf("onetap-erase-query-block:%d", offset)))
		copy(body[offset:], block[:])
	}
	digest := sha256.Sum256(body[:2048])
	maximumDigest := sha256.Sum256(body)
	issued := time.Now().UTC().Truncate(time.Second).Add(-time.Second)
	expires := issued.Add(5 * time.Minute)
	for _, seed := range []struct {
		sql  string
		args []any
	}{
		{`CREATE TEMP TABLE onetap_erase_query_seed AS SELECT n,
 CASE WHEN n<=90000 THEN $1::text ELSE 'cold-onetap-'||(n%100)::text END AS tenant,
 decode(md5('onetap-erase-command:'||n::text),'hex') AS command,
 decode(md5('onetap-erase-flow:'||n::text),'hex') AS flow,
 decode(md5('onetap-erase-fingerprint-a:'||n::text)||md5('onetap-erase-fingerprint-b:'||n::text),'hex') AS fingerprint
 FROM generate_series(1,100000) n`, []any{string(config.TenantID)}},
		{`INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields)
 SELECT command,tenant,'identity.oauth.onetap-start',fingerprint,1,decode('01','hex') FROM onetap_erase_query_seed`, nil},
		{`INSERT INTO identity.commands(command_id,tenant_id,purpose)
 SELECT command,tenant,'identity.oauth.onetap-start' FROM onetap_erase_query_seed`, nil},
		{`INSERT INTO ` + rpQuotedSchema(config.Schema) + `.onetap_callback_grants
 (tenant_id,flow_id,origin_command_id,origin_operation,issued_at,expires_at,proof_ciphertext)
 SELECT tenant,flow,command,'identity.oauth.onetap-start',$1,$2,$3 FROM onetap_erase_query_seed`, []any{issued, expires, body[:2048]}},
		{`ANALYZE ` + rpQuotedSchema(config.Schema) + `.onetap_callback_grants`, nil},
	} {
		if _, err := db.Exec(ctx, seed.sql, seed.args...); err != nil {
			t.Fatal("representative erasure seed", err)
		}
	}
	var engine string
	var total, hot int
	var heapBytes, indexBytes int64
	if err := db.QueryRow(ctx, `SELECT version()`).Scan(&engine); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE tenant_id=$1),pg_relation_size($2::regclass),pg_indexes_size($2::regclass) FROM `+rpQuotedSchema(config.Schema)+`.onetap_callback_grants`, string(config.TenantID), config.Schema+".onetap_callback_grants").Scan(&total, &hot, &heapBytes, &indexBytes); err != nil || total != 100000 || hot != 90000 {
		t.Fatal("representative erasure corpus", total, hot, err)
	}
	t.Logf("engine=%s; rows=%d hot_tenant=%d cold_tenants=100 rows_per_cold_tenant=100 heap_bytes=%d index_bytes=%d; isolated fixture database, one acquired loopback connection, warm samples, no competing workload; no production-scale or cold-disk claim", engine, total, hot, heapBytes, indexBytes)
	for _, sql := range []string{
		`SELECT column_name||'='||udt_schema||'.'||udt_name FROM information_schema.columns WHERE table_schema=$1 AND table_name='onetap_callback_grants' ORDER BY ordinal_position`,
		`SELECT indexdef FROM pg_indexes WHERE schemaname=$1 AND tablename='onetap_callback_grants' ORDER BY indexname`,
	} {
		rows, err := db.Query(ctx, sql, config.Schema)
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
	sql := oneTapCallbackGrantEraseSQL(config.Schema)
	description, err := db.Prepare(ctx, "onetap_callback_grant_erase", sql)
	if err != nil {
		t.Fatal("prepare exact production erasure", err)
	}
	var directoryOID, directoryBaseOID uint32
	if err := db.QueryRow(ctx, `SELECT oid,typbasetype FROM pg_type WHERE oid='identity.directory_id'::regtype`).Scan(&directoryOID, &directoryBaseOID); err != nil {
		t.Fatal(err)
	}
	oids := slices.Clone(description.ParamOIDs)
	if len(oids) > 0 && oids[0] == directoryOID {
		oids[0] = directoryBaseOID
	}
	if !reflect.DeepEqual(oids, []uint32{directoryBaseOID, 17, 17, 25, 1184, 1184, 17}) {
		t.Fatal("production erasure bindings changed", description.ParamOIDs)
	}
	t.Logf("exact production SQL=%s; Go bindings=string,[]byte(16),[]byte(16),string,time.Time(UTC),time.Time(UTC),[]byte(32); server_parameter_oids=%v", sql, description.ParamOIDs)
	flow := func(n int) []byte { sum := md5.Sum([]byte(fmt.Sprintf("onetap-erase-flow:%d", n))); return sum[:] }
	command := func(n int) []byte { sum := md5.Sum([]byte(fmt.Sprintf("onetap-erase-command:%d", n))); return sum[:] }
	for _, test := range []struct {
		name, tenant, preparation string
		flowNumber, commandNumber int
		operation                 string
		issued, expires           time.Time
		digest                    [32]byte
		wantRows                  int64
	}{
		{"hot-live", string(config.TenantID), "", 1, 1, oneTapStartOperationID, issued, expires, digest, 1},
		{"cold-live", "cold-onetap-1", "", 90001, 90001, oneTapStartOperationID, issued, expires, digest, 1},
		{"maximum-body", string(config.TenantID), "maximum", 1, 1, oneTapStartOperationID, issued, expires, maximumDigest, 1},
		{"missing-flow", string(config.TenantID), "", 200001, 1, oneTapStartOperationID, issued, expires, digest, 0},
		{"foreign-tenant", "cold-onetap-1", "", 1, 1, oneTapStartOperationID, issued, expires, digest, 0},
		{"wrong-command", string(config.TenantID), "", 1, 2, oneTapStartOperationID, issued, expires, digest, 0},
		{"wrong-operation", string(config.TenantID), "", 1, 1, "identity.oauth.signin-start", issued, expires, digest, 0},
		{"changed-issued", string(config.TenantID), "", 1, 1, oneTapStartOperationID, issued.Add(-time.Second), expires, digest, 0},
		{"changed-expiry", string(config.TenantID), "", 1, 1, oneTapStartOperationID, issued, expires.Add(-time.Second), digest, 0},
		{"stale-body", string(config.TenantID), "", 1, 1, oneTapStartOperationID, issued, expires, maximumDigest, 0},
		{"replaced-body", string(config.TenantID), "maximum", 1, 1, oneTapStartOperationID, issued, expires, digest, 0},
		{"already-erased", string(config.TenantID), "erased", 1, 1, oneTapStartOperationID, issued, expires, digest, 0},
		{"expired", string(config.TenantID), "expired", 1, 1, oneTapStartOperationID, issued.Add(-10 * time.Minute), expires.Add(-10 * time.Minute), digest, 0},
		{"not-yet-issued", string(config.TenantID), "future", 1, 1, oneTapStartOperationID, issued.Add(10 * time.Minute), expires.Add(10 * time.Minute), digest, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			tx, err := db.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
				defer stop()
				if err := tx.Rollback(cleanup); err != nil {
					t.Error("rollback erasure experiment", err)
				}
			}()
			var preparation string
			var preparationArgs []any
			switch test.preparation {
			case "maximum":
				preparation = `proof_ciphertext=$3`
				preparationArgs = []any{string(config.TenantID), flow(1), body}
			case "erased":
				preparation = `proof_ciphertext=NULL,erased_at=pg_catalog.clock_timestamp()`
				preparationArgs = []any{string(config.TenantID), flow(1)}
			case "expired", "future":
				preparation = `issued_at=$3,expires_at=$4`
				preparationArgs = []any{string(config.TenantID), flow(1), test.issued, test.expires}
			}
			if preparation != "" {
				tag, err := tx.Exec(ctx, `UPDATE `+rpQuotedSchema(config.Schema)+`.onetap_callback_grants SET `+preparation+` WHERE tenant_id=$1 AND flow_id=$2`, preparationArgs...)
				if err != nil || tag.RowsAffected() != 1 {
					t.Fatal("prepare exact erasure partition", err)
				}
			}
			args := []any{test.tenant, flow(test.flowNumber), command(test.commandNumber), test.operation, test.issued, test.expires, test.digest[:]}
			var samples []time.Duration
			for iteration := 0; iteration < 31; iteration++ {
				if _, err := tx.Exec(ctx, `SAVEPOINT erasure_sample`); err != nil {
					t.Fatal(err)
				}
				start := time.Now()
				tag, writeErr := tx.Exec(ctx, sql, args...)
				elapsed := time.Since(start)
				_, rollbackErr := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT erasure_sample`)
				if writeErr != nil || rollbackErr != nil || tag.RowsAffected() != test.wantRows {
					t.Fatal("exact erasure result or rollback changed", tag.RowsAffected(), writeErr, rollbackErr)
				}
				if _, err := tx.Exec(ctx, `RELEASE SAVEPOINT erasure_sample`); err != nil {
					t.Fatal(err)
				}
				if iteration > 0 {
					samples = append(samples, elapsed)
				}
			}
			var raw []byte
			if err := tx.QueryRow(ctx, "EXPLAIN (ANALYZE, BUFFERS, WAL, FORMAT JSON) "+sql, args...).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			var plans []oneTapCustodyQueryPlan
			if err := json.Unmarshal(raw, &plans); err != nil || len(plans) != 1 || plans[0].Plan.Operation != "Update" {
				t.Fatal("exact erasure write plan unavailable", err)
			}
			var index *oneTapCustodyPlanNode
			for _, child := range plans[0].Plan.Plans {
				if found := oneTapCustodyPointIndex(t, child); found != nil {
					index = found
				}
			}
			if index == nil {
				t.Fatal("erasure has no scoped point index")
			}
			tenantKey := strings.Contains(index.IndexCond, "tenant_id")
			flowKey := strings.Contains(index.IndexCond, "flow_id")
			t.Logf("erasure access node=%s index=%s rows=%g filtered=%g loops=%g tenant_key=%t flow_key=%t", index.NodeType, index.IndexName, index.Rows, index.Filtered, index.Loops, tenantKey, flowKey)
			// The expiry index also contains the complete primary-key tuple.
			// Exact expiry plus tenant/flow is equally point-bounded; planner
			// preference between these two indexes is not a behavioral contract.
			pointIndex := index.IndexName == "onetap_callback_grants_pkey" || index.IndexName == "onetap_callback_grants_expiry"
			if !pointIndex || index.Rows != float64(test.wantRows) || index.Loops != 1 || !tenantKey || !flowKey ||
				index.Filtered < 0 || index.Rows+index.Filtered > 1 {
				t.Fatal("erasure no longer bounds work to one tenant/flow row")
			}
			if test.wantRows == 1 {
				var erased, bodyAbsent, withinLifetime bool
				if err := tx.QueryRow(ctx, `SELECT erased_at IS NOT NULL,proof_ciphertext IS NULL,erased_at>=issued_at AND erased_at<expires_at FROM `+rpQuotedSchema(config.Schema)+`.onetap_callback_grants WHERE tenant_id=$1 AND flow_id=$2`, test.tenant, flow(test.flowNumber)).Scan(&erased, &bodyAbsent, &withinLifetime); err != nil || !erased || !bodyAbsent || !withinLifetime {
					t.Fatal("successful exact erasure did not clear custody within its original lifetime", err)
				}
			}
			slices.Sort(samples)
			t.Logf("updated_rows=%d warm_n=30 median=%s min=%s max=%s; exact single statement/client roundtrip included; setup/savepoint/rollback excluded; body hash is bounded to 65536 bytes on at most one row; rollback generates local WAL/dead tuples, not durable throughput proof", test.wantRows, samples[15], samples[0], samples[29])
			t.Logf("exact-binding erasure plan=%s", raw)
		})
	}
	var erased int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM `+rpQuotedSchema(config.Schema)+`.onetap_callback_grants WHERE erased_at IS NOT NULL`).Scan(&erased); err != nil || erased != 0 {
		t.Fatal("erasure experiment retained changes", erased, err)
	}
}
