//go:build integration

package impersonationpostgres

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestImpersonationRevocationStoragePointQueryEvidence(t *testing.T) {
	ctx, pool := newImpersonationStorageDatabase(t)
	installRevocationStorage(t, ctx, pool)
	seedRevocationQueryHistory(t, ctx, pool)

	guardQuery := func(source, row string) string {
		t.Helper()
		_, tail, found := strings.Cut(source, "IF EXISTS(")
		query, _, complete := strings.Cut(tail, ") THEN")
		if !found || !complete {
			t.Fatal("legacy fence no longer exposes its point lookup")
		}
		return strings.NewReplacer(row+".tenant_id", "$1", row+".grant_id", "$2").Replace(query)
	}
	approvalGuard := guardQuery(revocationApprovalFenceSQL, "OLD")
	activationGuard := guardQuery(revocationActivationFenceSQL, "NEW")
	if approvalGuard != activationGuard {
		t.Fatal("legacy approval and activation require separate measured predicates")
	}

	for _, tenant := range []struct {
		name string
		id   identity.TenantID
		base uint64
	}{
		{"dense", "tenant-dense", 0},
		{"sparse", "tenant-sparse-0", 16000},
		{"missing-tenant", "tenant-missing", 0},
		{"missing-grant", "tenant-dense", 30000},
	} {
		for _, state := range []struct {
			name   string
			offset uint64
			before uint64
		}{
			{"pending", 1, 1}, {"approved", 2, 2}, {"active", 3, 3}, {"terminal", 4, 3},
		} {
			t.Run(tenant.name+"/"+state.name, func(t *testing.T) {
				grant := storageTestGrant(tenant.base + state.offset)
				grant.tenant = tenant.id
				command, err := base64.RawURLEncoding.DecodeString(string(grant.id))
				if err != nil {
					t.Fatal(err)
				}
				command[0] = 3
				binding := storageRecoveryBinding(grant, revokeAction, identity.CommandID(base64.RawURLEncoding.EncodeToString(command)), "revoker")
				binding.PolicyID, binding.PolicyVersion = "policy", ^uint64(0)
				competitor := binding
				competitor.CommandID = identity.CommandID(storageTestGrant(99999).id)
				intent := revocationIntent{before: state.before, payload: []byte("opaque-encrypted-revocation-envelope")}
				key := []any{string(grant.tenant), string(grant.id)}
				present := !strings.HasPrefix(tenant.name, "missing-")
				terminal := present && state.name == "terminal"
				readCount, activeCount, terminalCount, insertCount := int64(0), int64(0), int64(0), int64(1)
				if present && !terminal {
					readCount = 1
				}
				if present && state.name == "active" {
					activeCount = 1
				}
				if terminal {
					terminalCount, insertCount = 1, 0
				}
				for _, operation := range []struct {
					name  string
					query string
					args  []any
					write bool
					want  int64
				}{
					{"revocable-version", revocableVersionSQL, key, false, readCount},
					{"active-cas", revocationActiveSQL, revocationActiveArgs(grant), true, activeCount},
					{"terminal-insert", revocationInsertSQL, revocationInsertArgs(grant, binding, intent, grant.requestedAt.Add(time.Minute)), true, insertCount},
					{"recover", revocationRecoverySQL, revocationRecoveryArgs(binding, revocationLifecycle(state.before)), false, terminalCount},
					{"recover-competitor", revocationRecoverySQL, revocationRecoveryArgs(competitor, revocationLifecycle(state.before)), false, 0},
					{"approval-and-activation-guard", approvalGuard, key, false, terminalCount},
				} {
					t.Run(operation.name, func(t *testing.T) {
						var bindings []string
						for index, arg := range operation.args {
							bindings = append(bindings, fmt.Sprintf("$%d=%T", index+1, arg))
						}
						t.Logf("exact SQL=%s; native binary bindings=%s", operation.query, strings.Join(bindings, ", "))
						var timings []time.Duration
						for sample := range 7 {
							tx, err := pool.Raw().Begin(ctx)
							if err != nil {
								t.Fatal(err)
							}
							func() {
								defer func() { _ = tx.Rollback(ctx) }()
								if _, err := tx.Exec(ctx, `SET LOCAL statement_timeout='2s'; SET LOCAL lock_timeout='1s'`); err != nil {
									t.Fatal(err)
								}
								if sample == 0 {
									rows := revocationNativeQuery(t, ctx, tx, "EXPLAIN (ANALYZE,BUFFERS,WAL,FORMAT JSON) "+operation.query, operation.args)
									var raw []byte
									if !rows.Next() {
										t.Fatal("missing measured plan", rows.Err())
									}
									if err := rows.Scan(&raw); err != nil {
										rows.Close()
										t.Fatal(err)
									}
									if rows.Next() || rows.Err() != nil {
										rows.Close()
										t.Fatal("unexpected measured plan rows", rows.Err())
									}
									rows.Close()
									var plans []struct{ Plan impersonationStorageQueryPlan }
									if err := json.Unmarshal(raw, &plans); err != nil || len(plans) != 1 {
										t.Fatal("decode measured plan", err)
									}
									assertRevocationPointPlan(t, plans[0].Plan)
									t.Logf("measured plan=%s", raw)
									return
								}
								started := time.Now()
								rows := revocationNativeQuery(t, ctx, tx, operation.query, operation.args)
								var count int64
								for rows.Next() {
									count++
									if operation.name == "revocable-version" {
										var version int32
										if err := rows.Scan(&version); err != nil || uint64(version) != state.before {
											rows.Close()
											t.Fatal("revocable version changed", version, state.before, err)
										}
									}
								}
								if rows.Err() != nil {
									t.Fatal(rows.Err())
								}
								elapsed := time.Since(started)
								if operation.write {
									count = rows.CommandTag().RowsAffected()
								}
								if count != operation.want {
									t.Fatal("point query cardinality", count, operation.want)
								}
								if sample > 1 {
									timings = append(timings, elapsed)
								}
							}()
						}
						t.Logf("five warm native roundtrip samples=%v; begin/rollback/setup excluded", timings)
					})
				}
			})
		}
	}
	t.Log("new storage statements per Execute: pending/approved=2, active=3; Prepare adds one version lookup; existing grant lock, authentication, authorization, coordinator, commit and service end-to-end costs are not included; terminal insert alone has no grant foreign key and accepts missing keys, while the owning operation first requires the exact revocable version")
}

func seedRevocationQueryHistory(t *testing.T, ctx context.Context, pool *database.Pool) {
	t.Helper()
	grant := storageTestGrant(1)
	for _, statement := range []string{
		`INSERT INTO identity_impersonation.grants
 (tenant_id,grant_id,requester_id,target_id,request_digest,encrypted_payload,requested_at,expires_at,state,version)
 SELECT CASE WHEN n<=16000 THEN 'tenant-dense' ELSE 'tenant-sparse-'||((n-16001)/100)::text END,
 translate(rtrim(encode(decode(lpad(to_hex(n),32,'0'),'hex'),'base64'),'='),'+/','-_'),
 'requester','target',$1,decode(repeat(md5(n::text),128),'hex'),$2,$3,
 CASE WHEN n%4=1 THEN 'pending_approval' ELSE 'approved' END,CASE WHEN n%4=1 THEN 1 ELSE 2 END
 FROM generate_series(1,20000) n`,
		`INSERT INTO identity_impersonation.approvals
 (tenant_id,grant_id,command_id,requester_id,target_id,request_digest,approver_id,encrypted_payload,decided_at)
 SELECT tenant_id,grant_id,
 translate(rtrim(encode(set_byte(decode(translate(grant_id,'-_','+/')||'==','base64'),0,1),'base64'),'='),'+/','-_'),
 requester_id,target_id,request_digest,'approver',encrypted_payload,requested_at+interval '1 second'
 FROM identity_impersonation.grants WHERE version=2`,
		`INSERT INTO identity_impersonation.active_grants
 (tenant_id,grant_id,activation_command_id,approval_command_id,actor_id,target_id,approver_id,request_digest,
 scope,policy_id,policy_version,actor_version,target_version,approver_version,approver_authority_version,
 authority_namespace,parent_id,parent_version,parent_digest_key,parent_digest,derived_digest_key,derived_digest,
 started_at,expires_at,state,version)
 SELECT g.tenant_id,g.grant_id,
 translate(rtrim(encode(set_byte(decode(translate(g.grant_id,'-_','+/')||'==','base64'),0,2),'base64'),'='),'+/','-_'),
 a.command_id,g.requester_id,g.target_id,a.approver_id,g.request_digest,'["address.read","profile.read"]'::jsonb,
 'policy',1,1,1,1,1,'operator','parent-session',1,1,g.request_digest,2,
 decode(lpad(to_hex(n),64,'0'),'hex'),g.requested_at+interval '2 seconds',g.requested_at+interval '10 minutes',
 CASE WHEN n%4=0 THEN 'revoked' ELSE 'active' END,CASE WHEN n%4=0 THEN 4 ELSE 3 END
 FROM generate_series(1,20000) n
 JOIN identity_impersonation.grants g ON g.grant_id=translate(rtrim(encode(decode(lpad(to_hex(n),32,'0'),'hex'),'base64'),'='),'+/','-_')
 JOIN identity_impersonation.approvals a ON a.tenant_id=g.tenant_id AND a.grant_id=g.grant_id WHERE n%4 IN (0,3)`,
		`INSERT INTO identity_impersonation.revocations
 (tenant_id,grant_id,command_id,revoker_id,requester_id,target_id,request_digest,policy_id,policy_version,
 before_version,after_version,encrypted_payload,revoked_at)
 SELECT g.tenant_id,g.grant_id,
 translate(rtrim(encode(set_byte(decode(translate(g.grant_id,'-_','+/')||'==','base64'),0,3),'base64'),'='),'+/','-_'),
 'revoker',g.requester_id,g.target_id,g.request_digest,'policy',18446744073709551615,3,4,
 g.encrypted_payload,g.requested_at+interval '1 minute'
 FROM identity_impersonation.grants g JOIN identity_impersonation.active_grants a USING(tenant_id,grant_id)
 WHERE a.state='revoked'`,
		`ANALYZE identity_impersonation.grants; ANALYZE identity_impersonation.approvals;
 ANALYZE identity_impersonation.active_grants; ANALYZE identity_impersonation.revocations`,
	} {
		var args []any
		if strings.Contains(statement, "$1") {
			args = []any{grant.digest[:], grant.requestedAt, grant.expiresAt}
		}
		if _, err := pool.Raw().Exec(ctx, statement, args...); err != nil {
			t.Fatal("seed skewed retained history", err)
		}
	}
	var engine, columns, indexes, settings string
	var grants, approvals, active, terminal, dense, tenants int
	if err := pool.Raw().QueryRow(ctx, `SELECT current_setting('server_version'),
 (SELECT string_agg(table_name||'.'||column_name||':'||udt_name,', ' ORDER BY table_name,ordinal_position)
 FROM information_schema.columns WHERE table_schema='identity_impersonation' AND table_name IN ('grants','active_grants','revocations')),
 (SELECT string_agg(indexdef,E'\n' ORDER BY tablename,indexname) FROM pg_indexes WHERE schemaname='identity_impersonation'),
 (SELECT string_agg(name||'='||setting,', ' ORDER BY name) FROM pg_settings
 WHERE name IN ('enable_seqscan','enable_indexscan','enable_bitmapscan','random_page_cost','effective_cache_size','shared_buffers','work_mem')),
 (SELECT count(*) FROM identity_impersonation.grants),
 (SELECT count(*) FROM identity_impersonation.approvals),
 (SELECT count(*) FROM identity_impersonation.active_grants),count(*),count(*) FILTER(WHERE tenant_id='tenant-dense'),count(DISTINCT tenant_id)
 FROM identity_impersonation.revocations`).Scan(&engine, &columns, &indexes, &settings, &grants, &approvals, &active, &terminal, &dense, &tenants); err != nil || grants != 20000 || approvals != 15000 || active != 10000 || terminal != 5000 || dense != 4000 || tenants != 41 {
		t.Fatal("inspect actual skewed revocation fixture", grants, approvals, active, terminal, dense, tenants, err)
	}
	t.Logf("PostgreSQL=%s; columns=%s; indexes=%s; planner=%s; grants=%d approvals=%d activations=%d terminals=%d dense-terminals=%d tenants=%d; synthetic 2KiB envelopes, default planner, sequential warm connection, no competing load or production cardinality/concurrency guarantee; new queries have no predecessor", engine, columns, indexes, settings, grants, approvals, active, terminal, dense, tenants)
}

func assertRevocationPointPlan(t *testing.T, plan impersonationStorageQueryPlan) {
	t.Helper()
	if plan.Relation != "" && plan.Node != "ModifyTable" && (plan.Node == "Seq Scan" || (plan.Rows+plan.Removed)*plan.Loops > 1) {
		t.Fatal("revocation lookup exceeded one unique-key candidate", plan.Relation, plan.Node, plan.Index, plan.Rows, plan.Loops, plan.Removed)
	}
	for _, child := range plan.Plans {
		assertRevocationPointPlan(t, child)
	}
}

// Work uses explicit scalar OIDs, including int16 versions, rather than a
// prepared statement's inferred domain OIDs. Match that real driver boundary.
func revocationNativeQuery(t *testing.T, ctx context.Context, tx pgx.Tx, query string, args []any) pgx.Rows {
	t.Helper()
	codecs := pgtype.NewMap()
	values, oids, formats := make([][]byte, len(args)), make([]uint32, len(args)), make([]int16, len(args))
	for index, arg := range args {
		switch arg.(type) {
		case string:
			oids[index] = pgtype.TextOID
		case []byte:
			oids[index] = pgtype.ByteaOID
		case time.Time:
			oids[index] = pgtype.TimestamptzOID
		case int16:
			oids[index] = pgtype.Int2OID
		default:
			t.Fatalf("revocation query introduced an unmeasured binding type %T", arg)
		}
		formats[index] = pgtype.BinaryFormatCode
		encoded, err := codecs.Encode(oids[index], formats[index], arg, make([]byte, 0))
		if err != nil {
			t.Fatal("encode native revocation binding", err)
		}
		values[index] = encoded
	}
	return pgx.RowsFromResultReader(codecs, tx.Conn().PgConn().ExecParams(ctx, query, values, oids, formats, nil))
}
