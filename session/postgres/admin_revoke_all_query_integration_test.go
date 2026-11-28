//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestAdminRevokeAllQueryPlans(t *testing.T) {
	ctx, pool, _ := anonymousSessionDatabase(t)
	conn, err := pool.Raw().Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()

	history, err := (AdminRevokeAllMigrationSource{Schema: "session_store", Version: 25, IndexVersion: 26}).LoadOffline(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range history {
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, step.UpSQL()); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal("install native administrative set schema", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	// LIKE copies domains, checks, collations and all indexes, including the
	// active-subject partial index. It does not copy the session-family FK;
	// session scan/update evidence excludes that FK, which state updates do not
	// change. Journal writes below retain the actual command/claim FK chain.
	if _, err := conn.Exec(ctx, `CREATE SCHEMA admin_revoke_all_plan;
CREATE TABLE admin_revoke_all_plan.sessions (LIKE session_store.sessions INCLUDING ALL);
INSERT INTO identity.users(tenant_id,user_id,status,version)
SELECT 'plan-a','user-'||lpad(g::text,6,'0'),'active',1 FROM generate_series(1,50000) g;
INSERT INTO identity.users(tenant_id,user_id,status,version)
SELECT tenant_id,user_id,'active',1 FROM (VALUES
 ('plan-a','dense'),('plan-a','sparse'),('plan-a','boundary'),('plan-a','empty'),
 ('plan-b','dense')) u(tenant_id,user_id)`); err != nil {
		t.Fatal("create bounded native storage corpus", err)
	}
	_, record := anonymousSessionMappingFixture(t)
	payload, expires, err := encodeRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `WITH corpus AS (
 SELECT CASE WHEN g<=49900 THEN 'plan-a' ELSE 'plan-b' END AS tenant_id,
        CASE WHEN g<=49800 THEN 'dense' WHEN g<=49900 THEN 'empty' ELSE 'dense' END AS user_id,
        'history-'||lpad(g::text,6,'0') AS session_id,'revoked' AS state
 FROM generate_series(1,50000) g
 UNION ALL
 SELECT tenant_id,user_id,user_id||'-live-'||lpad(g::text,6,'0'),'active'
 FROM (VALUES ('plan-a','dense',256),('plan-a','sparse',3),
              ('plan-a','boundary',128),('plan-b','dense',20)) u(tenant_id,user_id,n)
 CROSS JOIN LATERAL generate_series(1,n) g
)
INSERT INTO admin_revoke_all_plan.sessions
 (tenant_id,session_id,user_id,family_id,version,family_version,state,digest_version,digest,expires_at,record)
SELECT tenant_id,session_id,user_id,user_id||'-family',1,1,state,1,
       sha256(convert_to(tenant_id||':'||session_id,'UTF8')),$2,
       $1::jsonb||jsonb_build_object('TenantID',tenant_id,'SessionID',session_id,
         'UserID',user_id,'FamilyID',user_id||'-family','Version',1,'FamilyVersion',1)
FROM corpus`, pgx.QueryExecModeExec, string(payload), expires); err != nil {
		t.Fatal("seed native-width session history and live skew", err)
	}
	if _, err := conn.Exec(ctx, `INSERT INTO identity.identity_command_id_claims
 (command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields)
SELECT decode(lpad(to_hex(g),32,'0'),'hex'),'plan-a','identity.admin.session-revoke-all',
       sha256(convert_to(g::text,'UTF8')),1,decode('01','hex')
FROM generate_series(1,12002) g;
INSERT INTO identity.commands(command_id,tenant_id,purpose)
SELECT command_id,tenant_id,purpose FROM identity.identity_command_id_claims;
INSERT INTO session_store.admin_set_revocations
 (tenant_id,command_id,purpose,user_id,before_version,subject_version,revoked_count,binding_digest,result_digest)
SELECT 'plan-a',decode(lpad(to_hex(g),32,'0'),'hex'),'identity.admin.session-revoke-all',
       CASE WHEN g<=11900 THEN 'dense' ELSE 'sparse' END,
       CASE WHEN g<=11900 THEN g-1 ELSE g-11901 END,
       CASE WHEN g<=11900 THEN g ELSE g-11900 END,0,
       sha256(convert_to(g::text,'UTF8')),sha256(convert_to(g::text,'UTF8'))
FROM generate_series(1,12000) g;
ANALYZE identity.users;
ANALYZE identity.commands;
ANALYZE identity.identity_command_id_claims;
ANALYZE session_store.admin_set_revocations;
ANALYZE admin_revoke_all_plan.sessions`); err != nil {
		t.Fatal("seed retained journal with real command foreign keys", err)
	}
	var engine, columns, indexes string
	if err := conn.QueryRow(ctx, `SELECT version(),
 (SELECT string_agg(c.table_schema||'.'||c.table_name||'.'||c.column_name||' '||
    COALESCE(c.domain_schema||'.'||c.domain_name,c.udt_name)||
    COALESCE(' COLLATE '||c.collation_name,''),E'\n' ORDER BY c.table_schema,c.table_name,c.ordinal_position)
  FROM information_schema.columns c WHERE
   (c.table_schema='admin_revoke_all_plan' AND c.table_name='sessions') OR
   (c.table_schema='session_store' AND c.table_name='admin_set_revocations') OR
   (c.table_schema='identity' AND c.table_name IN ('users','commands','identity_command_id_claims'))),
 (SELECT string_agg(indexdef,E'\n' ORDER BY schemaname,tablename,indexname)
  FROM pg_indexes WHERE schemaname IN ('admin_revoke_all_plan','identity') OR
   (schemaname='session_store' AND tablename='admin_set_revocations'))`).Scan(&engine, &columns, &indexes); err != nil {
		t.Fatal("inspect representative engine, native columns and indexes", err)
	}
	var total, live, tombstones int
	var rowBytes float64
	if err := conn.QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE state='active'),
 count(*) FILTER (WHERE state='revoked'),avg(pg_column_size(s)) FROM admin_revoke_all_plan.sessions s`).Scan(&total, &live, &tombstones, &rowBytes); err != nil || total != 50407 || live != 407 || tombstones != 50000 {
		t.Fatal("wrong representative session distribution", total, live, tombstones, err)
	}
	t.Logf("engine=%s; synthetic sessions=%d live=%d tombstones=%d average_row_bytes=%.1f; users=50005 retained_journal=12000 commands=12002; columns:\n%s\nindexes:\n%s", engine, total, live, tombstones, rowBytes, columns, indexes)
	t.Log("new SQL has no predecessor baseline; native pgx extended-protocol bindings, one discarded warmup and five warm samples; normal planner, no forced index; rollback samples retain dead-tuple/index churn; client query excludes transaction/acquisition and EXPLAIN; no cold-cache, concurrent-load, commit/durability, production or complete coordinator-latency claim")
	t.Log("incremental statement count per successful participant: target=1 version=1 lock_pages=floor(active_count/128)+1 update=1 if nonempty insert=1; count=0:4 count=3:5 count=128:6 count=256:7; recovery separately uses one receipt lookup; reused coordinator/actor queries are excluded")

	sessionSchema := pgx.Identifier{"admin_revoke_all_plan"}.Sanitize()
	journalSchema := pgx.Identifier{"session_store"}.Sanitize()
	withTransaction := func(t *testing.T, run func(pgx.Tx)) {
		t.Helper()
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			cleanup, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			if err := tx.Rollback(cleanup); err != nil {
				t.Error("rollback bounded query sample", err)
			}
		}()
		if _, err := tx.Exec(ctx, `SET LOCAL statement_timeout='3s'; SET LOCAL lock_timeout='1s'`); err != nil {
			t.Fatal(err)
		}
		run(tx)
	}
	measure := func(t *testing.T, query string, bindings []any, relation string, maxExamined int, want [][]any, affected int64, after func(pgx.Tx), insert bool) {
		t.Helper()
		args := append([]any{pgx.QueryExecModeExec}, bindings...)
		var types []string
		for _, binding := range bindings {
			types = append(types, fmt.Sprintf("%T", binding))
		}
		t.Logf("SQL=%s; native_go_types=%v; synthetic_bindings=%v", query, types, bindings)
		for sample := 0; sample <= 5; sample++ {
			var clientQuery time.Duration
			withTransaction(t, func(tx pgx.Tx) {
				started := time.Now()
				rows, err := tx.Query(ctx, query, args...)
				if err != nil {
					t.Fatal("execute exact production SQL", err)
				}
				got, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) ([]any, error) { return row.Values() })
				clientQuery = time.Since(started)
				if err != nil || !adminRevokeAllPlanRowsEqual(got, want) || rows.CommandTag().RowsAffected() != affected {
					t.Fatalf("result=%v affected=%d, want=%v affected=%d: %v", got, rows.CommandTag().RowsAffected(), want, affected, err)
				}
				if after != nil {
					after(tx)
				}
			})
			withTransaction(t, func(tx pgx.Tx) {
				var encoded []byte
				started := time.Now()
				if err := tx.QueryRow(ctx, "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) "+query, args...).Scan(&encoded); err != nil {
					t.Fatal("measure exact SQL with native bindings", err)
				}
				clientExplain := time.Since(started)
				var plans []struct {
					Plan          adminRevokePairQueryPlan
					PlanningTime  float64 `json:"Planning Time"`
					ExecutionTime float64 `json:"Execution Time"`
					Triggers      []struct {
						Name  string `json:"Trigger Name"`
						Calls int
					}
				}
				if err := json.Unmarshal(encoded, &plans); err != nil || len(plans) != 1 {
					t.Fatal("decode measured query plan", err)
				}
				plan := plans[0]
				if !insert {
					inspectAdminRevokeAllQueryPlan(t, plan.Plan, relation, maxExamined)
				} else if len(plan.Triggers) == 0 || plan.Triggers[0].Calls != 1 {
					t.Fatalf("actual journal insert did not exercise its FK trigger: %s", encoded)
				}
				if after != nil {
					after(tx)
				}
				if sample != 0 {
					t.Logf("warm_sample=%d returned=%d affected=%d planning_ms=%g execution_ms=%g client_query=%s client_explain=%s root_shared_hit=%g root_shared_read=%g root_shared_dirtied=%g root_shared_written=%g", sample, len(want), affected, plan.PlanningTime, plan.ExecutionTime, clientQuery, clientExplain, plan.Plan.SharedHitBlocks, plan.Plan.SharedReadBlocks, plan.Plan.SharedDirtiedBlocks, plan.Plan.SharedWrittenBlocks)
					t.Logf("warm_sample=%d exact_json_plan=%s", sample, encoded)
				}
			})
		}
	}
	for _, test := range []struct{ name, tenant, user string }{
		{"present", "plan-a", "dense"}, {"missing-user", "plan-a", "absent"}, {"missing-tenant", "absent", "dense"},
	} {
		t.Run("target/"+test.name, func(t *testing.T) {
			var want [][]any
			if test.name == "present" {
				want = [][]any{{test.user}}
			}
			measure(t, adminRevokeAllTargetSQL, []any{test.tenant, test.user}, "users", 1, want, int64(len(want)), nil, false)
		})
	}
	for _, test := range []struct {
		name, tenant, user, marker string
		first, count               int
	}{
		{"no-user", "plan-a", "absent", "", 0, 0},
		{"tombstones-only", "plan-a", "empty", "", 0, 0},
		{"sparse", "plan-a", "sparse", "", 1, 3},
		{"dense-first", "plan-a", "dense", "", 1, 128},
		{"dense-next-marker", "plan-a", "dense", "dense-live-000128", 129, 128},
		{"dense-terminal-marker", "plan-a", "dense", "dense-live-000256", 0, 0},
		{"exact-page-boundary", "plan-a", "boundary", "", 1, 128},
		{"boundary-terminal-marker", "plan-a", "boundary", "boundary-live-000128", 0, 0},
		{"other-tenant", "plan-b", "dense", "", 1, 20},
	} {
		t.Run("lock/"+test.name, func(t *testing.T) {
			var want [][]any
			for n := test.first; n < test.first+test.count; n++ {
				want = append(want, []any{fmt.Sprintf("%s-live-%06d", test.user, n)})
			}
			measure(t, adminRevokeAllLockSQL(sessionSchema), []any{test.tenant, test.user, test.marker, int64(128)}, "sessions", test.count, want, int64(test.count), nil, false)
		})
	}
	for _, test := range []struct {
		user  string
		count int64
	}{{"absent", 0}, {"empty", 0}, {"sparse", 3}, {"boundary", 128}, {"dense", 256}} {
		t.Run("update/"+test.user, func(t *testing.T) {
			verify := func(tx pgx.Tx) {
				var remaining, revoked, untouched int64
				if err := tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE tenant_id='plan-a' AND user_id=$1 AND state='active'),
 count(*) FILTER (WHERE tenant_id='plan-a' AND user_id=$1 AND state='revoked' AND session_id LIKE '%-live-%'),
 count(*) FILTER (WHERE tenant_id='plan-b' AND state='active') FROM admin_revoke_all_plan.sessions`, test.user).Scan(&remaining, &revoked, &untouched); err != nil || remaining != 0 || revoked != test.count || untouched != 20 {
					t.Fatal("wrong exact update effect or tenant isolation", remaining, revoked, untouched, err)
				}
			}
			for sample := 0; sample <= 5; sample++ {
				withTransaction(t, func(tx pgx.Tx) {
					started := time.Now()
					var count int64
					var marker string
					pages := 0
					for {
						pages++
						if pages > int(test.count/128)+1 {
							t.Fatal("pagination exceeded exact expected terminal-page bound")
						}
						rows, err := tx.Query(ctx, adminRevokeAllLockSQL(sessionSchema), pgx.QueryExecModeExec, "plan-a", test.user, marker, int64(128))
						if err != nil {
							t.Fatal(err)
						}
						ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
						if err != nil || len(ids) > 128 {
							t.Fatal("invalid measured lock page", len(ids), err)
						}
						for _, id := range ids {
							if id <= marker {
								t.Fatal("lock pages repeated or reordered a session", id)
							}
							marker = id
							count++
						}
						if len(ids) < 128 {
							break
						}
					}
					if count != test.count || pages != int(test.count/128)+1 {
						t.Fatal("incorrect aggregate locked count/pages", count, pages)
					}
					queries := pages
					if count != 0 {
						queries++
						tag, err := tx.Exec(ctx, adminRevokeAllUpdateSQL(sessionSchema), pgx.QueryExecModeExec, "plan-a", test.user)
						if err != nil || tag.RowsAffected() != count {
							t.Fatal("locked count disagrees with exact update", tag.RowsAffected(), count, err)
						}
					}
					elapsed := time.Since(started)
					verify(tx)
					if sample != 0 {
						t.Logf("warm_lock_update_sample=%d active_count=%d lock_pages=%d statements=%d client_lock_update=%s; excludes target, version, insert, coordinator and commit", sample, count, pages, queries, elapsed)
					}
				})
			}
			measure(t, adminRevokeAllUpdateSQL(sessionSchema), []any{"plan-a", test.user}, "sessions", int(test.count), nil, test.count, verify, false)
		})
	}
	for _, test := range []struct{ user, version string }{{"dense", "11900"}, {"sparse", "100"}, {"absent", ""}} {
		t.Run("version/"+test.user, func(t *testing.T) {
			var want [][]any
			if test.version != "" {
				want = [][]any{{test.version}}
			}
			measure(t, adminRevokeAllVersionSQL(journalSchema), []any{"plan-a", test.user}, "admin_set_revocations", 1, want, int64(len(want)), nil, false)
		})
	}
	command := func(n int) []byte {
		decoded, err := hex.DecodeString(fmt.Sprintf("%032x", n))
		if err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	for _, test := range []struct {
		name string
		id   int
	}{{"latest", 11900}, {"old", 1}, {"no-match", 12002}} {
		t.Run("receipt/"+test.name, func(t *testing.T) {
			var want [][]any
			if test.name != "no-match" {
				var digest []byte
				if err := conn.QueryRow(ctx, `SELECT sha256(convert_to($1,'UTF8'))`, fmt.Sprint(test.id)).Scan(&digest); err != nil {
					t.Fatal(err)
				}
				want = [][]any{{"identity.admin.session-revoke-all", "dense", fmt.Sprint(test.id - 1), fmt.Sprint(test.id), int32(0), digest, digest}}
			}
			measure(t, adminRevokeAllReceiptSQL(journalSchema), []any{"plan-a", command(test.id)}, "admin_set_revocations", 1, want, int64(len(want)), nil, false)
		})
	}
	for _, test := range []struct {
		name, user, before, after string
		id, count                 int
	}{{"dense-successor", "dense", "11900", "11901", 12001, 256}, {"first-empty-set", "empty", "0", "1", 12002, 0}} {
		t.Run("insert/"+test.name, func(t *testing.T) {
			digest := bytes.Repeat([]byte{7}, 32)
			verify := func(tx pgx.Tx) {
				var user, before, after string
				var count int64
				var binding, result []byte
				if err := tx.QueryRow(ctx, `SELECT user_id,before_version::text,subject_version::text,revoked_count,binding_digest,result_digest
 FROM session_store.admin_set_revocations WHERE tenant_id=$1 AND command_id=$2`, "plan-a", command(test.id)).Scan(&user, &before, &after, &count, &binding, &result); err != nil || user != test.user || before != test.before || after != test.after || count != int64(test.count) || !bytes.Equal(binding, digest) || !bytes.Equal(result, digest) {
					t.Fatal("wrong exact journal insert effect", user, before, after, count, err)
				}
			}
			measure(t, adminRevokeAllInsertSQL(journalSchema), []any{"plan-a", command(test.id), "identity.admin.session-revoke-all", test.user, test.before, test.after, int64(test.count), digest, digest}, "admin_set_revocations", 0, nil, 1, verify, true)
		})
	}
}

func adminRevokeAllPlanRowsEqual(got, want [][]any) bool {
	if len(got) != len(want) {
		return false
	}
	for n := range got {
		if !slices.EqualFunc(got[n], want[n], func(a, b any) bool {
			if raw, ok := a.([]byte); ok {
				other, ok := b.([]byte)
				return ok && bytes.Equal(raw, other)
			}
			return a == b
		}) {
			return false
		}
	}
	return true
}

func inspectAdminRevokeAllQueryPlan(t *testing.T, root adminRevokePairQueryPlan, relation string, maximum int) {
	t.Helper()
	var indexed, scanned bool
	var visit func(adminRevokePairQueryPlan)
	visit = func(node adminRevokePairQueryPlan) {
		if node.Relation == relation && strings.Contains(node.NodeType, "Scan") {
			scanned = true
			examined := (node.ActualRows + node.RemovedFilter + node.RemovedRecheck) * node.ActualLoops
			if strings.Contains(node.NodeType, "Seq Scan") || examined > float64(maximum) {
				t.Errorf("%s used %s examined=%g, want indexed work <=%d", relation, node.NodeType, examined, maximum)
			}
		}
		if node.Relation == relation && node.Index != "" && strings.Contains(node.IndexCondition, "tenant_id") {
			indexed = true
		}
		for _, child := range node.Plans {
			visit(child)
		}
	}
	visit(root)
	if !indexed || !scanned {
		t.Errorf("missing native indexed %s access: %+v", relation, root)
	}
}
