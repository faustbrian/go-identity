//go:build integration

package impersonationpostgres

import (
	"encoding/json"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/impersonation"
)

func TestImpersonationQuorumStoragePointQueryEvidence(t *testing.T) {
	ctx, pool := newImpersonationStorageDatabase(t)
	installDenialMigrationTestStorage(t, ctx, pool)
	seedRevocationQueryHistory(t, ctx, pool)
	seedSelfStopQueryHistory(t, ctx, pool)
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity_impersonation.denials
 (tenant_id,grant_id,command_id,denier_id,requester_id,target_id,request_digest,
 policy_id,policy_version,before_version,after_version,encrypted_payload,denied_at)
 SELECT tenant_id,grant_id,
 translate(rtrim(encode(set_byte(decode(translate(grant_id,'-_','+/')||'==','base64'),0,4),'base64'),'='),'+/','-_'),
 'denier',requester_id,target_id,request_digest,'policy',18446744073709551615,1,2,
 encrypted_payload,requested_at+interval '1 minute'
 FROM identity_impersonation.grants
 WHERE state='pending_approval' AND get_byte(decode(translate(grant_id,'-_','+/')||'==','base64'),15)%8=5;
 ANALYZE identity_impersonation.denials`); err != nil {
		t.Fatal("seed skewed quorum denial history", err)
	}
	var columns, indexes string
	var grants, approvals, activations, denials, revocations, stops, dense, tenants int
	if err := pool.Raw().QueryRow(ctx, `SELECT
 (SELECT string_agg(table_name||'.'||column_name||':'||udt_name,', ' ORDER BY table_name,ordinal_position)
 FROM information_schema.columns WHERE table_schema='identity_impersonation'
 AND table_name IN ('grants','approvals','active_grants','denials','revocations','stops')),
 (SELECT string_agg(indexdef,E'\n' ORDER BY tablename,indexname) FROM pg_indexes
 WHERE schemaname='identity_impersonation'
 AND tablename IN ('grants','approvals','active_grants','denials','revocations','stops')),
 count(*),(SELECT count(*) FROM identity_impersonation.approvals),
 (SELECT count(*) FROM identity_impersonation.active_grants),
 (SELECT count(*) FROM identity_impersonation.denials),
 (SELECT count(*) FROM identity_impersonation.revocations),
 (SELECT count(*) FROM identity_impersonation.stops),
 count(*) FILTER(WHERE tenant_id='tenant-dense'),count(DISTINCT tenant_id)
 FROM identity_impersonation.grants`).Scan(&columns, &indexes, &grants, &approvals, &activations, &denials, &revocations, &stops, &dense, &tenants); err != nil || grants != 20000 || approvals != 15000 || activations != 10000 || denials != 2500 || revocations != 5000 || stops != 2500 || dense != 16000 || tenants != 41 {
		t.Fatal("inspect actual skewed quorum fixture", grants, approvals, activations, denials, revocations, stops, dense, tenants, err)
	}
	t.Logf("quorum columns=%s; indexes=%s; grants=%d approvals=%d activations=%d denials=%d revocations=%d stops=%d dense-grants=%d grant-tenants=%d; v1-v9 native migration history, engine/planner and synthetic 2KiB historical envelopes logged above", columns, indexes, grants, approvals, activations, denials, revocations, stops, dense, tenants)

	for _, tenant := range []struct {
		name string
		id   identity.TenantID
		base uint64
	}{
		{"dense", "tenant-dense", 0},
		{"sparse", "tenant-sparse-0", 16000},
		{"missing-tenant", "tenant-missing", 0},
		{"missing-grant", "tenant-dense", 30000},
		{"foreign-tenant-grant", "tenant-sparse-0", 0},
	} {
		for _, state := range []struct {
			name     string
			offset   uint64
			status   impersonation.Status
			approved bool
		}{
			{"pending", 1, impersonation.StatusPendingApproval, false},
			{"approved", 2, impersonation.StatusApproved, true},
			{"active", 3, impersonation.StatusActive, true},
			{"revoked", 4, impersonation.StatusRevoked, true},
			{"denied", 5, impersonation.StatusDenied, false},
			{"stopped", 7, impersonation.StatusStopped, true},
		} {
			t.Run(tenant.name+"/"+state.name, func(t *testing.T) {
				grant := storageTestGrant(tenant.base + state.offset)
				grant.tenant = tenant.id
				args := []any{string(grant.tenant), string(grant.id)}
				want := int64(0)
				if tenant.name == "dense" || tenant.name == "sparse" {
					want = 1
				}
				t.Logf("exact SQL=%s; native binary bindings=$1=%T,$2=%T; tenant=%s; grant-fixture-number=%d", quorumSnapshotSQL, args[0], args[1], tenant.id, tenant.base+state.offset)
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
							rows := revocationNativeQuery(t, ctx, tx, "EXPLAIN (ANALYZE,BUFFERS,WAL,FORMAT JSON) "+quorumSnapshotSQL, args)
							defer rows.Close()
							var raw []byte
							if !rows.Next() {
								t.Fatal("missing measured quorum plan", rows.Err())
							}
							if err := rows.Scan(&raw); err != nil {
								t.Fatal(err)
							}
							if rows.Next() || rows.Err() != nil {
								t.Fatal("unexpected measured quorum plan rows", rows.Err())
							}
							var plans []struct{ Plan impersonationStorageQueryPlan }
							if err := json.Unmarshal(raw, &plans); err != nil || len(plans) != 1 {
								t.Fatal("decode measured quorum plan", err)
							}
							assertRevocationPointPlan(t, plans[0].Plan)
							if plans[0].Plan.Rows*plans[0].Plan.Loops != float64(want) {
								t.Fatal("measured quorum result cardinality", plans[0].Plan.Rows, plans[0].Plan.Loops, want)
							}
							t.Logf("measured plan=%s", raw)
							return
						}
						started := time.Now()
						rows := revocationNativeQuery(t, ctx, tx, quorumSnapshotSQL, args)
						defer rows.Close()
						var count int64
						var snapshot quorumSnapshot
						for rows.Next() {
							count++
							if err := rows.Scan(&snapshot.requester, &snapshot.target, &snapshot.requestedAt, &snapshot.expiresAt,
								&snapshot.state, &snapshot.version, &snapshot.digestValid,
								&snapshot.approvalID, &snapshot.approver, &snapshot.decidedAt, &snapshot.approvalBound,
								&snapshot.activeState, &snapshot.activeVersion, &snapshot.startedAt, &snapshot.activeExpiresAt, &snapshot.activeBound,
								&snapshot.denied, &snapshot.denialBound, &snapshot.revoked, &snapshot.revocationBound, &snapshot.stopped, &snapshot.stopBound); err != nil {
								t.Fatal("scan exact native quorum projection", err)
							}
						}
						if rows.Err() != nil {
							t.Fatal(rows.Err())
						}
						elapsed := time.Since(started)
						if count != want {
							t.Fatal("quorum point query cardinality", count, want)
						}
						if count == 1 {
							result, err := snapshot.result(grant.id, grant.requestedAt.Add(2*time.Minute))
							if err != nil || result.GrantID != grant.id || result.Status != state.status {
								t.Fatal("quorum snapshot lost current lifecycle state", result.Status, state.status, err)
							}
							if state.approved {
								approval := storageTestApproval(grant)
								if len(result.Approvals) != 1 || result.Approvals[0].ApproverID != approval.approver || !result.Approvals[0].DecidedAt.Equal(approval.decidedAt) {
									t.Fatal("quorum snapshot lost exact current approval metadata")
								}
							} else if len(result.Approvals) != 0 {
								t.Fatal("quorum snapshot disclosed an approval for a pending or denied grant")
							}
						}
						if sample > 1 {
							timings = append(timings, elapsed)
						}
					}()
				}
				t.Logf("five warm native query/projection roundtrip samples=%v; begin/rollback/setup and result validation excluded", timings)
			})
		}
	}
	t.Log("incremental quorum storage: one read-only snapshot statement per Quorum call, with six tenant/grant unique-key lookups and at most one returned row; fixed-one current approval and active/denied/revoked/stopped joins measured for true dense/sparse hits and absent/foreign keys; authentication, current authorization, connection acquisition and service end-to-end latency are excluded; default planner, sequential warm samples and no competing load do not establish production cardinality, cold-cache or concurrency performance; this new read has no predecessor baseline")
}
