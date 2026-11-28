//go:build integration

package impersonationpostgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

func TestImpersonationSelfStopStoragePointQueryEvidence(t *testing.T) {
	ctx, pool := newImpersonationStorageDatabase(t)
	installRevocationStorage(t, ctx, pool)
	seedRevocationQueryHistory(t, ctx, pool)
	applyRevocationMigration(t, ctx, pool, selfStopSchemaSQL)
	seedSelfStopQueryHistory(t, ctx, pool)

	commandFor := func(grant grantRecord, kind byte) identity.CommandID {
		t.Helper()
		command, err := base64.RawURLEncoding.DecodeString(string(grant.id))
		if err != nil {
			t.Fatal(err)
		}
		command[0] = kind
		return identity.CommandID(base64.RawURLEncoding.EncodeToString(command))
	}
	type queryCase struct {
		name  string
		query string
		args  []any
		write bool
		want  int64
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
			name     string
			offset   uint64
			hasProof bool
		}{
			{"active-unissued", 3, false},
			{"active-issued", 11, true},
			{"stopped", 7, true},
			{"revoked", 4, true},
		} {
			t.Run(tenant.name+"/"+state.name, func(t *testing.T) {
				grant := storageTestGrant(tenant.base + state.offset)
				grant.tenant = tenant.id
				row := activationRecord{tenant: grant.tenant, grantID: grant.id, commandID: commandFor(grant, 2), actor: grant.requester, target: grant.target}
				binding := storageRecoveryBinding(grant, stopAction, commandFor(grant, 4), grant.requester)
				binding.PolicyID, binding.PolicyVersion = "policy", ^uint64(0)
				competitor := binding
				competitor.CommandID = identity.CommandID(storageTestGrant(99999).id)
				proof := session.CSRFStateSpec{Binding: stopProofBinding(row.tenant, row.grantID), KeyVersion: ^uint32(0), Digest: grant.digest}
				present := !strings.HasPrefix(tenant.name, "missing-")
				proofPresent := present && state.hasProof
				proofCount, activeCount, terminalCount, insertCount := int64(0), int64(0), int64(0), int64(1)
				if proofPresent {
					proofCount = 1
				}
				if present && strings.HasPrefix(state.name, "active-") {
					activeCount = 1
				}
				if present && state.name == "stopped" {
					terminalCount, insertCount = 1, 0
				}
				operations := []queryCase{
					{"proof-select", stopProofSelectSQL, []any{string(row.tenant), string(row.grantID)}, false, proofCount},
					{"active-cas", stopActiveSQL, stopActiveArgs(row), true, activeCount},
					{"terminal-insert", stopInsertSQL, stopInsertArgs(binding, row, grant.requestedAt.Add(time.Minute)), true, insertCount},
					{"recover-exact", stopRecoverySQL, stopRecoveryArgs(binding), false, terminalCount},
					{"recover-competitor", stopRecoverySQL, stopRecoveryArgs(competitor), false, 0},
				}
				if !proofPresent {
					operations = append(operations, queryCase{"proof-insert", stopProofInsertSQL, stopProofInsertArgs(row, proof), true, 1})
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
								if sample == 0 {
									rows := revocationNativeQuery(t, ctx, tx, "EXPLAIN (ANALYZE,BUFFERS,WAL,FORMAT JSON) "+operation.query, operation.args)
									defer rows.Close()
									var raw []byte
									if !rows.Next() {
										t.Fatal("missing measured self-stop plan", rows.Err())
									}
									if err := rows.Scan(&raw); err != nil {
										t.Fatal(err)
									}
									if rows.Next() || rows.Err() != nil {
										t.Fatal("unexpected measured self-stop plan rows", rows.Err())
									}
									var plans []struct{ Plan impersonationStorageQueryPlan }
									if err := json.Unmarshal(raw, &plans); err != nil || len(plans) != 1 {
										t.Fatal("decode measured self-stop plan", err)
									}
									assertRevocationPointPlan(t, plans[0].Plan)
									t.Logf("measured plan=%s", raw)
									return
								}
								started := time.Now()
								rows := revocationNativeQuery(t, ctx, tx, operation.query, operation.args)
								defer rows.Close()
								var count int64
								for rows.Next() {
									count++
									if operation.name == "proof-select" {
										var command, key string
										var digest []byte
										if err := rows.Scan(&command, &key, &digest); err != nil || command != string(row.commandID) || key != "4294967295" || !bytes.Equal(digest, proof.Digest[:]) {
											t.Fatal("exact self-stop proof changed", err)
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
									t.Fatal("self-stop point query cardinality", count, operation.want)
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
	t.Log("incremental self-stop storage: activation adds one proof insert; PrepareStop adds one proof read; successful fresh ExecuteStop adds three proof reads (preflight, apply and commit), one active CAS and one terminal append; successful ExecuteStop replay adds two proof reads (before and after reservation); successful recovery authenticates twice with one proof read each and uses one exact terminal read when participant reconciliation is needed; each named proof read is paired with an additional invocation of the unchanged child-digest lookup shape, already covered by activation query evidence and not remeasured here; existing grant locks, authentication, authorization, coordinator, commit, optional parent lookup and end-to-end latency are excluded; standalone inserts have no grant foreign key and accept missing keys or inconsistent lifecycle metadata, while the owning operation authenticates the exact active child first")
}

func seedSelfStopQueryHistory(t *testing.T, ctx context.Context, pool *database.Pool) {
	t.Helper()
	// Retained revocations cannot change terminal state. Stop only a still-active
	// subset; leave another subset without a proof to measure activation issuance.
	for _, statement := range []string{
		`UPDATE identity_impersonation.active_grants SET state='stopped',version=4
 WHERE state='active' AND get_byte(decode(translate(grant_id,'-_','+/')||'==','base64'),15)%8=7`,
		`INSERT INTO identity_impersonation.stop_proofs
 (tenant_id,grant_id,activation_command_id,csrf_key,csrf_digest)
 SELECT tenant_id,grant_id,activation_command_id,4294967295,request_digest
 FROM identity_impersonation.active_grants
 WHERE get_byte(decode(translate(grant_id,'-_','+/')||'==','base64'),15)%16<>3`,
		`INSERT INTO identity_impersonation.stops
 (tenant_id,grant_id,command_id,activation_command_id,actor_id,target_id,policy_id,policy_version,stopped_at)
 SELECT tenant_id,grant_id,
 translate(rtrim(encode(set_byte(decode(translate(grant_id,'-_','+/')||'==','base64'),0,4),'base64'),'='),'+/','-_'),
 activation_command_id,actor_id,target_id,'policy',18446744073709551615,started_at+interval '1 minute'
 FROM identity_impersonation.active_grants WHERE state='stopped'`,
		`ANALYZE identity_impersonation.active_grants; ANALYZE identity_impersonation.stop_proofs;
 ANALYZE identity_impersonation.stops`,
	} {
		if _, err := pool.Raw().Exec(ctx, statement); err != nil {
			t.Fatal("seed skewed self-stop query history", err)
		}
	}
	var columns, indexes string
	var grants, activations, active, stopped, revoked, proofs, terminals, denseProofs, denseStops, tenants int
	if err := pool.Raw().QueryRow(ctx, `SELECT
 (SELECT string_agg(table_name||'.'||column_name||':'||udt_name,', ' ORDER BY table_name,ordinal_position)
 FROM information_schema.columns WHERE table_schema='identity_impersonation' AND table_name IN ('stop_proofs','stops')),
 (SELECT string_agg(indexdef,E'\n' ORDER BY tablename,indexname) FROM pg_indexes
 WHERE schemaname='identity_impersonation' AND tablename IN ('stop_proofs','stops')),
 (SELECT count(*) FROM identity_impersonation.grants),
 (SELECT count(*) FROM identity_impersonation.active_grants),
 (SELECT count(*) FROM identity_impersonation.active_grants WHERE state='active'),
 (SELECT count(*) FROM identity_impersonation.active_grants WHERE state='stopped'),
 (SELECT count(*) FROM identity_impersonation.active_grants WHERE state='revoked'),
 (SELECT count(*) FROM identity_impersonation.stop_proofs),count(*),
 (SELECT count(*) FROM identity_impersonation.stop_proofs WHERE tenant_id='tenant-dense'),
 count(*) FILTER(WHERE tenant_id='tenant-dense'),count(DISTINCT tenant_id)
 FROM identity_impersonation.stops`).Scan(&columns, &indexes, &grants, &activations, &active, &stopped, &revoked, &proofs, &terminals, &denseProofs, &denseStops, &tenants); err != nil || grants != 20000 || activations != 10000 || active != 2500 || stopped != 2500 || revoked != 5000 || proofs != 8750 || terminals != 2500 || denseProofs != 7000 || denseStops != 2000 || tenants != 41 {
		t.Fatal("inspect actual skewed self-stop fixture", grants, activations, active, stopped, revoked, proofs, terminals, denseProofs, denseStops, tenants, err)
	}
	t.Logf("self-stop columns=%s; indexes=%s; grants=%d activations=%d active=%d stopped=%d revoked=%d proofs=%d stops=%d dense-proofs=%d dense-stops=%d tenants=%d; inherited engine/planner and 2KiB-envelope fixture context logged above; synthetic retained proof digests establish query shape, not cryptographic authentication; sequential warm connection, no competing load, no production-scale or concurrency guarantee; new queries have no predecessor", columns, indexes, grants, activations, active, stopped, revoked, proofs, terminals, denseProofs, denseStops, tenants)
}
