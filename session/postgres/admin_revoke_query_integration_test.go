//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestAdminRevokePairQueryPlan(t *testing.T) {
	ctx, pool, _ := anonymousSessionDatabase(t)
	conn, err := pool.Raw().Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()

	// LIKE retains the native domains, collations, checks and every session
	// index without creating 50,000 unrelated users/families. PostgreSQL does
	// not copy foreign keys; the synthetic corpus proves this lookup's storage
	// work, not authentication, FK maintenance or production contention.
	if _, err := conn.Exec(ctx, `CREATE SCHEMA admin_revoke_plan;
CREATE TABLE admin_revoke_plan.sessions (LIKE session_store.sessions INCLUDING ALL)`); err != nil {
		t.Fatal("clone native session storage", err)
	}
	_, record := anonymousSessionMappingFixture(t)
	payload, expires, err := encodeRecord(record)
	if err != nil {
		t.Fatal("encode native session-width template", err)
	}
	if _, err := conn.Exec(ctx, `WITH corpus AS (
 SELECT CASE WHEN g<=49900 THEN 'plan-dense' ELSE 'plan-sparse' END AS tenant_id,
        CASE WHEN g<=49900 THEN g ELSE g-49900 END AS ordinal
 FROM generate_series(1,50000) AS g
), identities AS (
 SELECT tenant_id,'pair-'||lpad(ordinal::text,6,'0') AS session_id,
        'user-'||lpad((ordinal%100)::text,3,'0') AS user_id,
        'family-'||lpad(ordinal::text,6,'0') AS family_id
 FROM corpus
)
INSERT INTO admin_revoke_plan.sessions
 (tenant_id,session_id,user_id,family_id,version,family_version,state,digest_version,digest,expires_at,record)
SELECT tenant_id,session_id,user_id,family_id,1,1,'active',1,
       sha256(convert_to(tenant_id||':'||session_id,'UTF8')),$2,
       $1::jsonb||jsonb_build_object('TenantID',tenant_id,'SessionID',session_id,
         'UserID',user_id,'FamilyID',family_id,'Version',1,'FamilyVersion',1)
FROM identities`, pgx.QueryExecModeExec, string(payload), expires); err != nil {
		t.Fatal("populate bounded skewed storage corpus", err)
	}
	if _, err := conn.Exec(ctx, "ANALYZE admin_revoke_plan.sessions"); err != nil {
		t.Fatal("refresh isolated corpus statistics", err)
	}
	var engine, columns, indexes string
	if err := conn.QueryRow(ctx, `SELECT version(),
 (SELECT string_agg(a.attname||' '||format_type(a.atttypid,a.atttypmod)||
   CASE WHEN a.attcollation=0 THEN '' ELSE ' COLLATE '||a.attcollation::regcollation::text END,
   E'\n' ORDER BY a.attnum)
  FROM pg_attribute a WHERE a.attrelid='admin_revoke_plan.sessions'::regclass
   AND a.attnum>0 AND NOT a.attisdropped),
 (SELECT string_agg(indexdef,E'\n' ORDER BY indexname) FROM pg_indexes
  WHERE schemaname='admin_revoke_plan' AND tablename='sessions')`).Scan(&engine, &columns, &indexes); err != nil {
		t.Fatal("inspect measured engine and native storage", err)
	}
	var dense, sparse int
	var averageRowBytes float64
	if err := conn.QueryRow(ctx, `SELECT count(*) FILTER (WHERE tenant_id='plan-dense'),
 count(*) FILTER (WHERE tenant_id='plan-sparse'),avg(pg_column_size(s))
 FROM admin_revoke_plan.sessions s`).Scan(&dense, &sparse, &averageRowBytes); err != nil || dense != 49900 || sparse != 100 {
		t.Fatal("wrong skewed corpus", dense, sparse, err)
	}
	t.Logf("engine=%s; synthetic isolated corpus: dense=%d sparse=%d total=%d average_row_bytes=%.1f; native encoded payload template with synthetic identities, no copied foreign keys; no production data, concurrent load, churn or cold-cache claim; columns:\n%s\nindexes:\n%s", engine, dense, sparse, dense+sparse, averageRowBytes, columns, indexes)
	t.Log("incremental admin revoke cost: one additional SELECT FOR UPDATE per invocation, at most two distinct session rows; no predecessor query or invented baseline; reported server execution/buffers exclude the other authorization, mutation, audit and commit statements; client query time excludes acquisition and transaction setup")
	query := adminRevokePairSQL(pgx.Identifier{"admin_revoke_plan"}.Sanitize())
	withTransaction := func(t *testing.T, run func(pgx.Tx)) {
		t.Helper()
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := tx.Rollback(cleanup); err != nil {
				t.Error("rollback pair-lock sample", err)
			}
		}()
		if _, err := tx.Exec(ctx, `SET LOCAL statement_timeout='3s'; SET LOCAL lock_timeout='1s'`); err != nil {
			t.Fatal(err)
		}
		run(tx)
	}
	for _, test := range []struct {
		name, tenant, actor, target string
		want                        []string
	}{
		{"dense/distinct", "plan-dense", "pair-000001", "pair-049900", []string{"pair-000001", "pair-049900"}},
		{"dense/cross-reversed", "plan-dense", "pair-049900", "pair-000001", []string{"pair-000001", "pair-049900"}},
		{"sparse/distinct", "plan-sparse", "pair-000001", "pair-000100", []string{"pair-000001", "pair-000100"}},
		{"sparse/cross-reversed", "plan-sparse", "pair-000100", "pair-000001", []string{"pair-000001", "pair-000100"}},
		{"dense/same-id", "plan-dense", "pair-000001", "pair-000001", []string{"pair-000001"}},
		{"sparse/same-id", "plan-sparse", "pair-000001", "pair-000001", []string{"pair-000001"}},
		{"dense/one-absent", "plan-dense", "pair-000001", "pair-050001", []string{"pair-000001"}},
		{"sparse/other-tenant-only-target", "plan-sparse", "pair-000001", "pair-049900", []string{"pair-000001"}},
		{"dense/no-match", "plan-dense", "pair-050001", "pair-050002", nil},
		{"sparse/no-match", "plan-sparse", "pair-050001", "pair-050002", nil},
		{"absent-tenant/no-match", "plan-absent", "pair-000001", "pair-000100", nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			args := []any{pgx.QueryExecModeExec, test.tenant, test.actor, test.target}
			t.Logf("SQL=%s; native_go_types=[%T %T %T]; tenant=%s actor=%s target=%s", query, test.tenant, test.actor, test.target, test.tenant, test.actor, test.target)
			for sample := 0; sample <= 5; sample++ {
				var clientQuery time.Duration
				withTransaction(t, func(tx pgx.Tx) {
					started := time.Now()
					rows, err := tx.Query(ctx, query, args...)
					if err != nil {
						t.Fatal("execute exact pair-lock query", err)
					}
					got, err := pgx.CollectRows(rows, pgx.RowTo[string])
					clientQuery = time.Since(started)
					if err != nil || !slices.Equal(got, test.want) {
						t.Fatalf("ordered locked sessions=%v, want=%v: %v", got, test.want, err)
					}
				})
				withTransaction(t, func(tx pgx.Tx) {
					var encoded []byte
					started := time.Now()
					if err := tx.QueryRow(ctx, "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) "+query, args...).Scan(&encoded); err != nil {
						t.Fatal("measure exact pair-lock SQL and native binds", err)
					}
					clientExplain := time.Since(started)
					var plans []struct {
						Plan          adminRevokePairQueryPlan
						PlanningTime  float64 `json:"Planning Time"`
						ExecutionTime float64 `json:"Execution Time"`
					}
					if err := json.Unmarshal(encoded, &plans); err != nil || len(plans) != 1 {
						t.Fatal("decode measured pair-lock plan", err)
					}
					plan := plans[0]
					if plan.Plan.NodeType != "LockRows" || plan.Plan.ActualRows*plan.Plan.ActualLoops != float64(len(test.want)) {
						t.Fatalf("wrong lock-node result: %s", encoded)
					}
					nodes := inspectAdminRevokePairQueryPlan(t, plan.Plan)
					// Two primary-key probes and two heap row locks must not
					// become tenant-wide work. Count inclusive root buffers once.
					if plan.Plan.SharedHitBlocks+plan.Plan.SharedReadBlocks > 64 {
						t.Fatalf("pair lock exceeded 64 shared-buffer accesses: %s", encoded)
					}
					if sample != 0 {
						t.Logf("warm_sample=%d returned=%d planning_ms=%g execution_ms=%g client_query=%s client_explain=%s root_shared_hit=%g root_shared_read=%g root_shared_dirtied=%g root_shared_written=%g nodes=%v", sample, len(test.want), plan.PlanningTime, plan.ExecutionTime, clientQuery, clientExplain, plan.Plan.SharedHitBlocks, plan.Plan.SharedReadBlocks, plan.Plan.SharedDirtiedBlocks, plan.Plan.SharedWrittenBlocks, nodes)
						t.Logf("warm_sample=%d exact_json_plan=%s", sample, encoded)
					}
				})
			}
		})
	}
}

type adminRevokePairQueryPlan struct {
	NodeType            string                     `json:"Node Type"`
	Relation            string                     `json:"Relation Name"`
	Index               string                     `json:"Index Name"`
	IndexCondition      string                     `json:"Index Cond"`
	ActualRows          float64                    `json:"Actual Rows"`
	ActualLoops         float64                    `json:"Actual Loops"`
	RemovedFilter       float64                    `json:"Rows Removed by Filter"`
	RemovedRecheck      float64                    `json:"Rows Removed by Index Recheck"`
	SharedHitBlocks     float64                    `json:"Shared Hit Blocks"`
	SharedReadBlocks    float64                    `json:"Shared Read Blocks"`
	SharedDirtiedBlocks float64                    `json:"Shared Dirtied Blocks"`
	SharedWrittenBlocks float64                    `json:"Shared Written Blocks"`
	Plans               []adminRevokePairQueryPlan `json:"Plans"`
}

func inspectAdminRevokePairQueryPlan(t *testing.T, root adminRevokePairQueryPlan) []string {
	t.Helper()
	var nodes []string
	var boundedIndex, sessionScan bool
	var visit func(adminRevokePairQueryPlan)
	visit = func(node adminRevokePairQueryPlan) {
		examined := (node.ActualRows + node.RemovedFilter + node.RemovedRecheck) * node.ActualLoops
		nodes = append(nodes, fmt.Sprintf("%s relation=%s index=%s rows=%g loops=%g examined=%g shared_hit=%g shared_read=%g", node.NodeType, node.Relation, node.Index, node.ActualRows, node.ActualLoops, examined, node.SharedHitBlocks, node.SharedReadBlocks))
		if node.Index != "" && strings.Contains(node.IndexCondition, "tenant_id") && strings.Contains(node.IndexCondition, "session_id") {
			boundedIndex = true
			if examined > 2 {
				t.Errorf("pair index examined %g rows, want at most two", examined)
			}
		}
		if node.Relation == "sessions" && strings.Contains(node.NodeType, "Scan") {
			sessionScan = true
			if strings.Contains(node.NodeType, "Seq Scan") || examined > 2 {
				t.Errorf("pair lookup used %s and examined %g session rows, want at most two through an index", node.NodeType, examined)
			}
		}
		for _, child := range node.Plans {
			visit(child)
		}
	}
	visit(root)
	if !boundedIndex || !sessionScan {
		t.Errorf("missing exact-tenant/exact-session index access: %v", nodes)
	}
	return nodes
}
