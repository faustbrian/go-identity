//go:build integration

package impersonationpostgres

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/impersonation"
)

func TestImpersonationDenialStoragePointQueryEvidence(t *testing.T) {
	ctx, pool := newImpersonationStorageDatabase(t)
	installDenialMigrationTestStorage(t, ctx, pool)
	seedRevocationQueryHistory(t, ctx, pool)
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity_impersonation.denials
 (tenant_id,grant_id,command_id,denier_id,requester_id,target_id,request_digest,
 policy_id,policy_version,before_version,after_version,encrypted_payload,denied_at)
 SELECT tenant_id,grant_id,
 translate(rtrim(encode(set_byte(decode(translate(grant_id,'-_','+/')||'==','base64'),0,4),'base64'),'='),'+/','-_'),
 'denier',requester_id,target_id,request_digest,'policy',18446744073709551615,1,2,
 encrypted_payload,requested_at+interval '1 minute'
 FROM identity_impersonation.grants
 WHERE state='pending_approval' AND get_byte(decode(translate(grant_id,'-_','+/')||'==','base64'),15)%8=5`); err != nil {
		t.Fatal("seed skewed retained denials", err)
	}
	commandFor := func(grant grantRecord) identity.CommandID {
		t.Helper()
		raw, err := base64.RawURLEncoding.DecodeString(string(grant.id))
		if err != nil {
			t.Fatal(err)
		}
		raw[0] = 4
		return identity.CommandID(base64.RawURLEncoding.EncodeToString(raw))
	}
	bindingFor := func(grant grantRecord) identity.CommandBinding {
		binding := storageRecoveryBinding(grant, denyAction, commandFor(grant), "denier")
		binding.PolicyID, binding.PolicyVersion = "policy", ^uint64(0)
		return binding
	}
	// The pending predicate uses the database clock. Add live selected rows so
	// historical fixture expiry cannot conceal a broken terminal exclusion.
	at := time.Now().UTC().Truncate(time.Second)
	for _, tenant := range []identity.TenantID{"tenant-dense", "tenant-sparse-0"} {
		for offset := uint64(1); offset <= 4; offset++ {
			grant := storageTestGrant(100000 + offset)
			grant.tenant, grant.requestedAt, grant.expiresAt = tenant, at, at.Add(impersonation.ApprovalLifetime)
			if _, err := pool.Raw().Exec(ctx, grantInsertSQL, grantInsertArgs(grant)...); err != nil {
				t.Fatal(err)
			}
			switch offset {
			case 2:
				if _, err := pool.Raw().Exec(ctx, grantApproveSQL, grantApprovalArgs(grant, storageTestApproval(grant))...); err != nil {
					t.Fatal(err)
				}
			case 3:
				if _, err := pool.Raw().Exec(ctx, denialInsertSQL, denialInsertArgs(grant, bindingFor(grant), denialIntent{payload: grant.payload}, at)...); err != nil {
					t.Fatal(err)
				}
			case 4:
				if _, err := pool.Raw().Exec(ctx, revocationTestInsertSQL, revocationTestArgs(grant, 1)...); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	if _, err := pool.Raw().Exec(ctx, `ANALYZE identity_impersonation.grants; ANALYZE identity_impersonation.denials; ANALYZE identity_impersonation.revocations`); err != nil {
		t.Fatal(err)
	}
	var columns, indexes string
	var grants, denials, dense, tenants int
	if err := pool.Raw().QueryRow(ctx, `SELECT
 (SELECT string_agg(column_name||':'||udt_name,', ' ORDER BY ordinal_position) FROM information_schema.columns
 WHERE table_schema='identity_impersonation' AND table_name='denials'),
 (SELECT string_agg(indexdef,E'\n' ORDER BY indexname) FROM pg_indexes WHERE schemaname='identity_impersonation' AND tablename='denials'),
 (SELECT count(*) FROM identity_impersonation.grants),count(*),count(*) FILTER(WHERE tenant_id='tenant-dense'),count(DISTINCT tenant_id)
 FROM identity_impersonation.denials`).Scan(&columns, &indexes, &grants, &denials, &dense, &tenants); err != nil || grants != 20008 || denials != 2502 || dense != 2001 || tenants != 41 {
		t.Fatal("inspect skewed denial fixture", grants, denials, dense, tenants, err)
	}
	t.Logf("denial columns=%s; indexes=%s; grants=%d denials=%d dense-denials=%d denial-tenants=%d; inherited engine/planner and 2KiB historical envelope context logged above; selected live rows have smaller envelopes", columns, indexes, grants, denials, dense, tenants)
	guardQuery := func(source, row string) string {
		t.Helper()
		start := strings.Index(source, "SELECT 1 FROM identity_impersonation.denials")
		if start < 0 {
			t.Fatal("legacy fence lost its denial lookup")
		}
		query, _, found := strings.Cut(source[start:], ") THEN")
		if !found {
			t.Fatal("legacy denial fence no longer exposes its point lookup")
		}
		return strings.NewReplacer(row+".tenant_id", "$1", row+".grant_id", "$2").Replace(query)
	}
	guard := guardQuery(denialApprovalFenceSQL, "OLD")
	if guard != guardQuery(denialRevocationFenceSQL, "NEW") {
		t.Fatal("legacy approval and revocation require separate measured denial predicates")
	}
	type queryCase struct {
		name, query string
		args        []any
		write       bool
		want        int64
	}
	for _, tenant := range []identity.TenantID{"tenant-dense", "tenant-sparse-0", "tenant-missing"} {
		for _, state := range []struct {
			name   string
			offset uint64
		}{
			{"pending", 1}, {"approved", 2}, {"denied", 3}, {"revoked-pending", 4}, {"missing-grant", 5},
		} {
			t.Run(string(tenant)+"/"+state.name, func(t *testing.T) {
				grant := storageTestGrant(100000 + state.offset)
				grant.tenant, grant.requestedAt, grant.expiresAt = tenant, at, at.Add(impersonation.ApprovalLifetime)
				binding := bindingFor(grant)
				mismatch := binding
				mismatch.CommandID = identity.CommandID(storageTestGrant(99999).id)
				pending, denied := int64(0), int64(0)
				if tenant != "tenant-missing" {
					if state.name == "pending" {
						pending = 1
					}
					if state.name == "denied" {
						denied = 1
					}
				}
				operations := []queryCase{
					{"pending", denialPendingSQL, denialKeyArgs(binding), false, pending},
					{"recovery-exact", denialRecoverySQL, denialRecoveryArgs(binding), false, denied},
					{"recovery-mismatch", denialRecoverySQL, denialRecoveryArgs(mismatch), false, 0},
					{"both-legacy-fence-denial-lookups", guard, denialKeyArgs(binding), false, denied},
				}
				if tenant != "tenant-missing" && (state.name == "pending" || state.name == "denied") {
					operations = append(operations, queryCase{"insert-fresh-or-conflict", denialInsertSQL, denialInsertArgs(grant, binding, denialIntent{payload: grant.payload}, at), true, 1 - denied})
				}
				for _, operation := range operations {
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
								query := operation.query
								if sample == 0 {
									query = "EXPLAIN (ANALYZE,BUFFERS,WAL,FORMAT JSON) " + query
								}
								started := time.Now()
								rows := revocationNativeQuery(t, ctx, tx, query, operation.args)
								defer rows.Close()
								var count int64
								for rows.Next() {
									count++
									if sample == 0 {
										var raw []byte
										if err := rows.Scan(&raw); err != nil {
											t.Fatal(err)
										}
										var plans []struct{ Plan impersonationStorageQueryPlan }
										if err := json.Unmarshal(raw, &plans); err != nil || len(plans) != 1 {
											t.Fatal("decode measured denial plan", err)
										}
										assertRevocationPointPlan(t, plans[0].Plan)
										t.Logf("measured plan=%s", raw)
									}
								}
								if rows.Err() != nil {
									t.Fatal(rows.Err())
								}
								elapsed := time.Since(started)
								if sample == 0 {
									if count != 1 {
										t.Fatal("missing measured denial plan")
									}
									return
								}
								if operation.write {
									count = rows.CommandTag().RowsAffected()
								}
								if count != operation.want {
									t.Fatal("denial point query cardinality", count, operation.want)
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
	var retained int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity_impersonation.denials`).Scan(&retained); err != nil || retained != denials {
		t.Fatal("measured inserts escaped rollback", retained, denials, err)
	}
	t.Log("incremental denial storage: Prepare adds one pending lookup; fresh Apply adds one pending lookup and one denial append; participant reconciliation adds one exact recovery read; legacy approval and revocation each add the same denial point lookup; original grant lock, authentication, authorization, coordinator, commit and service end-to-end latency are excluded; sequential warm samples have no competing load and make no production-cardinality or concurrency guarantee; these queries have no predecessor baseline")
}
