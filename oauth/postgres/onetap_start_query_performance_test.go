//go:build integration && queryperformance

package postgres

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// A local incremental-cost experiment for callback-custody statements in
// onetap_start_output.go and onetap_callback_grant.go, not production throughput
// or callback acceptance.
// The owner fixture installs actual DDL; the synthetic 2KiB custody bodies are
// planner data, not signed grants. Hot/cold means tenant skew, not disk caches.
func TestOneTapStartCallbackCustodyQueriesStayPointBounded(t *testing.T) {
	_, pool, config, _ := oneTapStartIntegrationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	connection, err := pool.Raw().Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Release()
	db := connection.Conn()
	ciphertext := make([]byte, 2048)
	for offset := 0; offset < len(ciphertext); offset += sha256.Size {
		block := sha256.Sum256([]byte(fmt.Sprintf("onetap-custody-planner-block:%d", offset)))
		copy(ciphertext[offset:], block[:])
	}

	// Keep temporary seed state on this one acquired connection. The fixture
	// owns the database; no production or shared database is accessed.
	for _, statement := range []string{
		`CREATE TEMP TABLE onetap_query_seed AS SELECT n,
 CASE WHEN n<=90000 OR n=100001 THEN $1::text ELSE 'cold-onetap-'||(n%100)::text END AS tenant,
 decode(md5('onetap-command:'||n::text),'hex') AS command,
 decode(md5('onetap-flow:'||n::text),'hex') AS flow,
 decode(md5('onetap-fingerprint-a:'||n::text)||md5('onetap-fingerprint-b:'||n::text),'hex') AS fingerprint
 FROM generate_series(1,100002) n`,
		`INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields)
 SELECT command,tenant,'identity.oauth.onetap-start',fingerprint,1,decode('01','hex') FROM onetap_query_seed`,
		`INSERT INTO identity.commands(command_id,tenant_id,purpose)
 SELECT command,tenant,'identity.oauth.onetap-start' FROM onetap_query_seed`,
		`INSERT INTO ` + rpQuotedSchema(config.Schema) + `.onetap_callback_grants
 (tenant_id,flow_id,origin_command_id,origin_operation,issued_at,expires_at,proof_ciphertext)
 SELECT tenant,flow,command,'identity.oauth.onetap-start',statement_timestamp(),statement_timestamp()+interval '5 minutes',$1::bytea
 FROM onetap_query_seed WHERE n<=100000`,
		`ANALYZE identity.commands`,
		`ANALYZE ` + rpQuotedSchema(config.Schema) + `.onetap_callback_grants`,
	} {
		var args []any
		if strings.Contains(statement, "generate_series") {
			args = []any{string(config.TenantID)}
		} else if strings.Contains(statement, "proof_ciphertext)") {
			args = []any{ciphertext}
		}
		if _, err := db.Exec(ctx, statement, args...); err != nil {
			t.Fatal("representative callback custody seed", err)
		}
	}
	var engine string
	var total, hot int
	var heapBytes, indexBytes int64
	if err := db.QueryRow(ctx, `SELECT version()`).Scan(&engine); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE tenant_id=$1),pg_relation_size('onetap_oauth.onetap_callback_grants'),pg_indexes_size('onetap_oauth.onetap_callback_grants') FROM `+rpQuotedSchema(config.Schema)+`.onetap_callback_grants`, string(config.TenantID)).Scan(&total, &hot, &heapBytes, &indexBytes); err != nil || total != 100000 || hot != 90000 {
		t.Fatal("representative callback custody cardinality/skew", total, hot, err)
	}
	t.Logf("engine=%s; rows=%d hot_tenant=%d cold_tenants=100 rows_per_cold_tenant=100 custody_bytes=2048 heap_bytes=%d index_bytes=%d; isolated loopback, one acquired connection, warm sequential samples, no competing fixture workload; no production-scale or cold-disk claim", engine, total, hot, heapBytes, indexBytes)
	for _, statement := range []string{
		`SELECT column_name||'='||udt_schema||'.'||udt_name FROM information_schema.columns WHERE table_schema=$1 AND table_name='onetap_callback_grants' ORDER BY ordinal_position`,
		`SELECT indexdef FROM pg_indexes WHERE schemaname=$1 AND tablename='onetap_callback_grants' ORDER BY indexname`,
	} {
		rows, err := db.Query(ctx, statement, config.Schema)
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

	// These are the complete production statements, including the boolean
	// projection used by RecoverParticipant and every stageCallbackGrant column.
	selectSQL := `SELECT origin_command_id=$3 FROM ` + rpQuotedSchema(config.Schema) + `.onetap_callback_grants WHERE tenant_id=$1 AND flow_id=$2`
	insertSQL := `INSERT INTO ` + rpQuotedSchema(config.Schema) + `.onetap_callback_grants
	 (tenant_id,flow_id,origin_command_id,origin_operation,issued_at,expires_at,proof_ciphertext) VALUES($1,$2,$3,$4,$5,$6,$7)`
	t.Logf("exact recovery SQL=%s; bindings: string, []byte(16), []byte(16)", selectSQL)
	t.Logf("exact stage SQL=%s; bindings: string, []byte(16), []byte(16), string, time.Time(UTC), time.Time(UTC), []byte(2048)", insertSQL)
	selectDescription, err := db.Prepare(ctx, "onetap_custody_select", selectSQL)
	if err != nil {
		t.Fatal("prepare exact point query", err)
	}
	insertDescription, err := db.Prepare(ctx, "onetap_custody_insert", insertSQL)
	if err != nil {
		t.Fatal("prepare exact constrained insert", err)
	}
	var directoryOID, directoryBaseOID uint32
	if err := db.QueryRow(ctx, `SELECT oid,typbasetype FROM pg_type WHERE oid='identity.directory_id'::regtype`).Scan(&directoryOID, &directoryBaseOID); err != nil {
		t.Fatal(err)
	}
	for label, description := range map[string]*pgconn.StatementDescription{"select": selectDescription, "insert": insertDescription} {
		want := []uint32{directoryBaseOID, 17, 17}
		if label == "insert" {
			want = append(want, 25, 1184, 1184, 17)
		}
		actual := slices.Clone(description.ParamOIDs)
		if len(actual) > 0 && actual[0] == directoryOID {
			actual[0] = directoryBaseOID
		}
		if !reflect.DeepEqual(actual, want) {
			t.Fatal("production binding/column compatibility changed", label, description.ParamOIDs)
		}
		t.Logf("%s server_parameter_oids=%v; tenant is native directory domain or its text base", label, description.ParamOIDs)
	}

	flow := func(n int) []byte { sum := md5.Sum([]byte(fmt.Sprintf("onetap-flow:%d", n))); return sum[:] }
	command := func(n int) []byte { sum := md5.Sum([]byte(fmt.Sprintf("onetap-command:%d", n))); return sum[:] }
	for _, test := range []struct {
		name, tenant  string
		flow, command []byte
		wantRows      int
		wantOriginal  bool
	}{
		{"hot-match", string(config.TenantID), flow(1), command(1), 1, true},
		{"cold-match", "cold-onetap-1", flow(90001), command(90001), 1, true},
		{"hot-wrong-command", string(config.TenantID), flow(1), command(2), 1, false},
		{"foreign-tenant", "cold-onetap-1", flow(1), command(1), 0, false},
		{"hot-missing-flow", string(config.TenantID), flow(200001), command(1), 0, false},
		{"cold-missing-flow", "cold-onetap-1", flow(200001), command(90001), 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			args := []any{test.tenant, test.flow, test.command}
			var samples []time.Duration
			for iteration := 0; iteration < 31; iteration++ {
				start := time.Now()
				var original bool
				err := db.QueryRow(ctx, selectSQL, args...).Scan(&original)
				elapsed := time.Since(start)
				if test.wantRows == 0 {
					if !errors.Is(err, pgx.ErrNoRows) {
						t.Fatal("missing scoped custody matched", err)
					}
				} else if err != nil || original != test.wantOriginal {
					t.Fatal("original command projection changed", original, err)
				}
				if iteration > 0 {
					samples = append(samples, elapsed)
				}
			}
			var raw []byte
			if err := db.QueryRow(ctx, "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) "+selectSQL, args...).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			var plans []oneTapCustodyQueryPlan
			if err := json.Unmarshal(raw, &plans); err != nil || len(plans) != 1 {
				t.Fatal("point plan unavailable", err)
			}
			index := oneTapCustodyPointIndex(t, plans[0].Plan)
			if index == nil || index.Rows != float64(test.wantRows) || index.Loops != 1 || !strings.Contains(index.IndexCond, "tenant_id") || !strings.Contains(index.IndexCond, "flow_id") || index.Filtered != 0 && index.Filtered != 1 {
				t.Fatal("custody lookup no longer uses exact scoped primary key")
			}
			slices.Sort(samples)
			t.Logf("rows=%d warm_n=30 median=%s min=%s max=%s; one statement per call, acquired-connection roundtrip/scan included; setup/pool acquisition excluded; no wall-clock pass threshold", test.wantRows, samples[len(samples)/2], samples[0], samples[len(samples)-1])
			t.Logf("exact-binding plan=%s", raw)
		})
	}

	t.Run("callback-proof-projection", func(t *testing.T) {
		// This is loadOneTapCallbackGrant's full point projection, not the
		// narrower recovery boolean. The copied ciphertext incurs row/TOAST
		// retrieval and client transfer that an EXPLAIN alone does not measure.
		fullSQL := `SELECT origin_command_id,origin_operation,issued_at,expires_at,proof_ciphertext,erased_at IS NOT NULL
	 FROM ` + rpQuotedSchema(config.Schema) + `.onetap_callback_grants WHERE tenant_id=$1 AND flow_id=$2`
		description, err := db.Prepare(ctx, "onetap_callback_proof_select", fullSQL)
		if err != nil || !reflect.DeepEqual(description.ParamOIDs, []uint32{directoryBaseOID, 17}) {
			t.Fatal("full callback projection binding/column compatibility", err)
		}
		t.Logf("exact callback SQL=%s; Go bindings=string,[]byte(16); server_parameter_oids=%v", fullSQL, description.ParamOIDs)
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			if err := tx.Rollback(cleanup); err != nil {
				t.Error("rollback erased-row query fixture", err)
			}
		}()
		var seedIssued, seedExpires time.Time
		var storedBytes, payloadBytes int
		var toastBytes int64
		if err := tx.QueryRow(ctx, `SELECT g.issued_at,g.expires_at,pg_column_size(g.proof_ciphertext),octet_length(g.proof_ciphertext),pg_total_relation_size(c.reltoastrelid)
 FROM `+rpQuotedSchema(config.Schema)+`.onetap_callback_grants g JOIN pg_class c ON c.oid=$3::regclass WHERE g.tenant_id=$1 AND g.flow_id=$2`, string(config.TenantID), flow(1), config.Schema+".onetap_callback_grants").Scan(&seedIssued, &seedExpires, &storedBytes, &payloadBytes, &toastBytes); err != nil || payloadBytes != len(ciphertext) {
			t.Fatal("full projection storage context", err)
		}
		t.Logf("body_payload_bytes=%d stored_body_bytes=%d table_toast_bytes=%d; receipt transfers one boolean, full point read scans command/operation/timestamps/body/erasure; EXPLAIN buffer work and paired client samples are separate observations", payloadBytes, storedBytes, toastBytes)
		tag, err := tx.Exec(ctx, `UPDATE `+rpQuotedSchema(config.Schema)+`.onetap_callback_grants SET proof_ciphertext=NULL,erased_at=issued_at+interval '1 second' WHERE tenant_id=$1 AND flow_id=$2`, string(config.TenantID), flow(2))
		if err != nil || tag.RowsAffected() != 1 {
			t.Fatal("prepare one constraint-valid erased custody row", err)
		}
		for _, test := range []struct {
			name, tenant string
			n            int
			wantRows     int
			erased       bool
		}{
			{"hot-original", string(config.TenantID), 1, 1, false},
			{"cold-original", "cold-onetap-1", 90001, 1, false},
			{"hot-erased", string(config.TenantID), 2, 1, true},
			{"foreign-tenant", "cold-onetap-1", 1, 0, false},
			{"missing-flow", string(config.TenantID), 200001, 0, false},
		} {
			t.Run(test.name, func(t *testing.T) {
				flowKey, commandID := flow(test.n), command(test.n)
				var fullSamples, receiptSamples []time.Duration
				for iteration := 0; iteration < 31; iteration++ {
					// Alternate order within every pair; neither projection gets
					// a systematically colder first read. The first pair warms up.
					for pass := 0; pass < 2; pass++ {
						full := (iteration+pass)%2 == 0
						start := time.Now()
						if full {
							var original, body []byte
							var operation string
							var issued, expires time.Time
							var erased bool
							readErr := tx.QueryRow(ctx, fullSQL, test.tenant, flowKey).Scan(&original, &operation, &issued, &expires, &body, &erased)
							elapsed := time.Since(start)
							if test.wantRows == 0 {
								if !errors.Is(readErr, pgx.ErrNoRows) {
									t.Fatal("full projection disclosed foreign/missing flow", readErr)
								}
							} else {
								if readErr != nil {
									t.Fatal("full callback custody projection failed", readErr)
								}
								metadataMatches := bytes.Equal(original, commandID) && operation == oneTapStartOperationID && issued.Equal(seedIssued) && expires.Equal(seedExpires)
								bodyMatches := test.erased && body == nil || !test.erased && bytes.Equal(body, ciphertext)
								if !metadataMatches || erased != test.erased || !bodyMatches {
									t.Fatal("full callback custody projection changed")
								}
							}
							clear(body)
							if iteration > 0 {
								fullSamples = append(fullSamples, elapsed)
							}
						} else {
							var original bool
							readErr := tx.QueryRow(ctx, selectSQL, test.tenant, flowKey, commandID).Scan(&original)
							elapsed := time.Since(start)
							if test.wantRows == 0 {
								if !errors.Is(readErr, pgx.ErrNoRows) {
									t.Fatal("receipt comparison disclosed foreign/missing flow", readErr)
								}
							} else if readErr != nil || !original {
								t.Fatal("receipt projection comparison changed", readErr)
							}
							if iteration > 0 {
								receiptSamples = append(receiptSamples, elapsed)
							}
						}
					}
				}
				var raw []byte
				if err := tx.QueryRow(ctx, "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) "+fullSQL, test.tenant, flowKey).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				var plans []oneTapCustodyQueryPlan
				if err := json.Unmarshal(raw, &plans); err != nil || len(plans) != 1 {
					t.Fatal("full callback point plan unavailable", err)
				}
				index := oneTapCustodyPointIndex(t, plans[0].Plan)
				if index == nil || index.IndexName != "onetap_callback_grants_pkey" || index.Rows != float64(test.wantRows) || index.Loops != 1 || !strings.Contains(index.IndexCond, "tenant_id") || !strings.Contains(index.IndexCond, "flow_id") || index.Filtered != 0 && index.Filtered != 1 {
					t.Fatal("full callback projection lost original scoped primary-key bound")
				}
				slices.Sort(fullSamples)
				slices.Sort(receiptSamples)
				t.Logf("rows=%d erased=%t paired_warm_n=30 full_median=%s full_min=%s full_max=%s receipt_median=%s receipt_min=%s receipt_max=%s; client roundtrip/scan/body transfer included, setup/acquisition/AEAD excluded; no production latency or speedup claim", test.wantRows, test.erased, fullSamples[15], fullSamples[0], fullSamples[29], receiptSamples[15], receiptSamples[0], receiptSamples[29])
				t.Logf("full-projection exact-binding plan=%s", raw)
			})
		}
	})

	issued := time.Now().UTC().Truncate(time.Second)
	for _, test := range []struct {
		name, tenant  string
		command, flow []byte
	}{
		{"hot-insert", string(config.TenantID), command(100001), flow(100001)},
		{"cold-insert", "cold-onetap-2", command(100002), flow(100002)},
	} {
		t.Run(test.name, func(t *testing.T) {
			args := []any{test.tenant, test.flow, test.command, "identity.oauth.onetap-start", issued, issued.Add(5 * time.Minute), ciphertext}
			var samples []time.Duration
			for iteration := 0; iteration < 31; iteration++ {
				tx, err := db.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				start := time.Now()
				tag, writeErr := tx.Exec(ctx, insertSQL, args...)
				elapsed := time.Since(start)
				rollbackErr := tx.Rollback(ctx)
				if writeErr != nil || rollbackErr != nil || tag.RowsAffected() != 1 {
					t.Fatal("constrained single-row insert/rollback failed", writeErr, rollbackErr)
				}
				if iteration > 0 {
					samples = append(samples, elapsed)
				}
			}
			tx, err := db.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			var raw []byte
			explainErr := tx.QueryRow(ctx, "EXPLAIN (ANALYZE, BUFFERS, WAL, FORMAT JSON) "+insertSQL, args...).Scan(&raw)
			rollbackErr := tx.Rollback(ctx)
			if explainErr != nil || rollbackErr != nil {
				t.Fatal("instrumented insert must roll back", explainErr, rollbackErr)
			}
			var plans []oneTapCustodyQueryPlan
			if err := json.Unmarshal(raw, &plans); err != nil || len(plans) != 1 || plans[0].Plan.Operation != "Insert" || len(plans[0].Triggers) != 1 || plans[0].Triggers[0].Calls != 1 {
				t.Fatal("insert lost its single scoped-command FK trigger", err)
			}
			slices.Sort(samples)
			t.Logf("inserted_rows=1 rollback_only=true fk_trigger_calls=1 warm_n=30 median=%s min=%s max=%s; single statement client time excludes BEGIN/ROLLBACK; rollback still generates local WAL/dead tuples, not durable throughput proof", samples[len(samples)/2], samples[0], samples[len(samples)-1])
			t.Logf("exact-binding write plan=%s", raw)
		})
	}

	// Keep correctness distinct from timings: rejected shapes and referenced
	// command scope are observed through the same production INSERT and rolled
	// back. This is not a substitute for the native Start integration test.
	for _, test := range []struct {
		name, state   string
		tenant        string
		flow, command []byte
		purpose       string
		ciphertext    []byte
	}{
		{"foreign-command-tenant", "23503", string(config.TenantID), flow(100002), command(100002), "identity.oauth.onetap-start", ciphertext},
		{"missing-command", "23503", string(config.TenantID), flow(200001), command(200001), "identity.oauth.onetap-start", ciphertext},
		{"duplicate-flow", "23505", string(config.TenantID), flow(1), command(100001), "identity.oauth.onetap-start", ciphertext},
		{"zero-flow", "23514", string(config.TenantID), make([]byte, 16), command(100001), "identity.oauth.onetap-start", ciphertext},
		{"unrelated-purpose", "23514", string(config.TenantID), flow(100001), command(100001), "identity.oauth.signin-start", ciphertext},
		{"empty-proof", "23514", string(config.TenantID), flow(100001), command(100001), "identity.oauth.onetap-start", []byte{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			tx, err := db.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			_, writeErr := tx.Exec(ctx, insertSQL, test.tenant, test.flow, test.command, test.purpose, issued, issued.Add(5*time.Minute), test.ciphertext)
			rollbackErr := tx.Rollback(ctx)
			var failure *pgconn.PgError
			if !errors.As(writeErr, &failure) || failure.Code != test.state || rollbackErr != nil {
				t.Fatal("native insert constraint/rollback mismatch", writeErr, rollbackErr)
			}
		})
	}
	var remaining int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM `+rpQuotedSchema(config.Schema)+`.onetap_callback_grants`).Scan(&remaining); err != nil || remaining != 100000 {
		t.Fatal("write experiment retained a row", remaining, err)
	}
}

type oneTapCustodyQueryPlan struct {
	Plan     oneTapCustodyPlanNode `json:"Plan"`
	Triggers []struct {
		Calls float64 `json:"Calls"`
	} `json:"Triggers"`
}

// PostgreSQL can encode these EXPLAIN metrics as decimals (for example 1.00).
// Exact comparisons above still require 0/1 rows, one loop and one FK call;
// the filtered-row bound accepts only the integer values zero and one.
type oneTapCustodyPlanNode struct {
	Relation  string                  `json:"Relation Name"`
	NodeType  string                  `json:"Node Type"`
	Operation string                  `json:"Operation"`
	IndexCond string                  `json:"Index Cond"`
	IndexName string                  `json:"Index Name"`
	Rows      float64                 `json:"Actual Rows"`
	Loops     float64                 `json:"Actual Loops"`
	Filtered  float64                 `json:"Rows Removed by Filter"`
	Plans     []oneTapCustodyPlanNode `json:"Plans"`
}

func oneTapCustodyPointIndex(t *testing.T, plan oneTapCustodyPlanNode) *oneTapCustodyPlanNode {
	t.Helper()
	if plan.Relation == "onetap_callback_grants" {
		if plan.NodeType != "Index Scan" && plan.NodeType != "Index Only Scan" {
			t.Fatal("point custody lookup scanned outside index", plan.NodeType)
		}
		return &plan
	}
	for _, child := range plan.Plans {
		if found := oneTapCustodyPointIndex(t, child); found != nil {
			return found
		}
	}
	return nil
}
