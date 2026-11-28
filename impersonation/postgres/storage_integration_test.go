//go:build integration

package impersonationpostgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/impersonation"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestImpersonationStorageMigrationPreservesPopulatedIdentity(t *testing.T) {
	ctx, pool := newImpersonationStorageDatabase(t)
	history, err := (kernel.MigrationSource{}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, migration := range history {
		if _, err := pool.Raw().Exec(ctx, migration.UpSQL()); err != nil {
			t.Fatal("install existing identity history", err)
		}
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('existing-tenant','existing-user','active',7)`); err != nil {
		t.Fatal(err)
	}
	installImpersonationStorage(t, ctx, pool)
	var version string
	var status string
	if err := pool.Raw().QueryRow(ctx, `SELECT status,version::text FROM identity.users WHERE tenant_id='existing-tenant' AND user_id='existing-user'`).Scan(&status, &version); err != nil || status != "active" || version != "7" {
		t.Fatal("opt-in schema changed populated identity data", err)
	}
	var rows int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity_impersonation.grants`).Scan(&rows); err != nil || rows != 0 {
		t.Fatal("new grants store not empty", err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('existing-tenant','mixed-binary-user','active',1)`); err != nil {
		t.Fatal("existing binary write stopped working", err)
	}
}

func TestImpersonationStorageBoundApprovalAndRollback(t *testing.T) {
	ctx, pool := newImpersonationStorageDatabase(t)
	installImpersonationStorage(t, ctx, pool)
	grant := storageTestGrant(1)
	if _, err := pool.Raw().Exec(ctx, grantInsertSQL, grantInsertArgs(grant)...); err != nil {
		t.Fatal("persist pending grant", err)
	}
	observed, err := observeGrant(ctx, pool, grant.tenant, grant.id)
	if err != nil || !sameStorageGrant(observed, grant) {
		t.Fatal("pending envelope or binding changed", err)
	}
	if _, err := observeGrant(ctx, pool, "foreign-tenant", grant.id); !errors.Is(err, impersonation.ErrConflict) {
		t.Fatal("foreign tenant observed grant", err)
	}
	for _, invalid := range []struct {
		name   string
		change func(*grantRecord, *approvalRecord)
	}{
		{"foreign-tenant", func(g *grantRecord, _ *approvalRecord) { g.tenant = "foreign-tenant" }},
		{"foreign-grant", func(g *grantRecord, _ *approvalRecord) { g.id = storageTestGrant(2).id }},
		{"wrong-requester", func(g *grantRecord, _ *approvalRecord) { g.requester = "other-requester" }},
		{"wrong-target", func(g *grantRecord, _ *approvalRecord) { g.target = "other-target" }},
		{"wrong-digest", func(g *grantRecord, _ *approvalRecord) { g.digest[0]++ }},
		{"wrong-request-time", func(g *grantRecord, _ *approvalRecord) { g.requestedAt = g.requestedAt.Add(time.Microsecond) }},
		{"wrong-expiry", func(g *grantRecord, _ *approvalRecord) { g.expiresAt = g.expiresAt.Add(time.Microsecond) }},
		{"self-approval", func(g *grantRecord, a *approvalRecord) { a.approver = g.requester }},
		{"target-approval", func(g *grantRecord, a *approvalRecord) { a.approver = g.target }},
		{"request-command-as-approval", func(g *grantRecord, a *approvalRecord) { a.commandID = identity.CommandID(g.id) }},
		{"at-expiry", func(g *grantRecord, a *approvalRecord) { a.decidedAt = g.expiresAt }},
		{"after-expiry", func(g *grantRecord, a *approvalRecord) { a.decidedAt = g.expiresAt.Add(time.Microsecond) }},
		{"before-request", func(g *grantRecord, a *approvalRecord) { a.decidedAt = g.requestedAt.Add(-time.Microsecond) }},
	} {
		t.Run(invalid.name, func(t *testing.T) {
			selected, approval := grant, storageTestApproval(grant)
			invalid.change(&selected, &approval)
			tag, err := pool.Raw().Exec(ctx, grantApproveSQL, grantApprovalArgs(selected, approval)...)
			if err != nil || tag.RowsAffected() != 0 {
				t.Fatal("mismatched approval changed authority", err)
			}
		})
	}
	approval := storageTestApproval(grant)
	tx, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if tag, err := tx.Exec(ctx, grantApproveSQL, grantApprovalArgs(grant, approval)...); err != nil || tag.RowsAffected() != 1 {
		_ = tx.Rollback(ctx)
		t.Fatal("approve pending exact intent", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	assertStorageState(t, ctx, pool, grant, "pending_approval", 1, 0)
	if tag, err := pool.Raw().Exec(ctx, grantApproveSQL, grantApprovalArgs(grant, approval)...); err != nil || tag.RowsAffected() != 1 {
		t.Fatal("approve after whole-transaction rollback", err)
	}
	assertStorageState(t, ctx, pool, grant, "approved", 2, 1)
	if tag, err := pool.Raw().Exec(ctx, grantApproveSQL, grantApprovalArgs(grant, approval)...); err != nil || tag.RowsAffected() != 0 {
		t.Fatal("stale or duplicate approval changed authority", err)
	}
	if _, err := pool.Raw().Exec(ctx, grantInsertSQL, grantInsertArgs(grant)...); err == nil {
		t.Fatal("duplicate grant accepted")
	}
}

func TestImpersonationStorageConstraintsRejectApprovalSubstitution(t *testing.T) {
	ctx, pool := newImpersonationStorageDatabase(t)
	installImpersonationStorage(t, ctx, pool)
	grant := storageTestGrant(1)
	if _, err := pool.Raw().Exec(ctx, grantInsertSQL, grantInsertArgs(grant)...); err != nil {
		t.Fatal(err)
	}
	const direct = `INSERT INTO identity_impersonation.approvals(tenant_id,grant_id,requester_id,target_id,request_digest,approver_id,encrypted_payload,decided_at,command_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	command := storageTestApproval(grant).commandID
	for _, approver := range []identity.UserID{grant.requester, grant.target} {
		if _, err := pool.Raw().Exec(ctx, direct, string(grant.tenant), string(grant.id), string(grant.requester), string(grant.target), grant.digest[:], string(approver), []byte{1}, grant.requestedAt.Add(time.Second), string(command)); err == nil {
			t.Fatal("database accepted non-distinct approver")
		}
	}
	if _, err := pool.Raw().Exec(ctx, direct, string(grant.tenant), string(grant.id), "substituted-requester", string(grant.target), grant.digest[:], "approver", []byte{1}, grant.requestedAt.Add(time.Second), string(command)); err == nil {
		t.Fatal("database accepted substituted request identity")
	}
	if _, err := pool.Raw().Exec(ctx, direct, string(grant.tenant), string(grant.id), string(grant.requester), string(grant.target), grant.digest[:], "approver", []byte{1}, grant.requestedAt.Add(time.Second), string(grant.id)); err == nil {
		t.Fatal("database accepted the request command as its approval command")
	}
	if _, err := pool.Raw().Exec(ctx, `UPDATE identity_impersonation.grants SET requester_id='rewritten-requester' WHERE tenant_id=$1 AND grant_id=$2`, string(grant.tenant), string(grant.id)); err == nil {
		t.Fatal("database accepted rewritten immutable request")
	}
}

func TestImpersonationStorageRejectsMalformedMetadataAndPartialApproval(t *testing.T) {
	ctx, pool := newImpersonationStorageDatabase(t)
	installImpersonationStorage(t, ctx, pool)
	for _, invalid := range []struct {
		name   string
		change func(*grantRecord)
	}{
		{"empty-tenant", func(g *grantRecord) { g.tenant = "" }},
		{"oversized-tenant", func(g *grantRecord) { g.tenant = identity.TenantID(strings.Repeat("t", 129)) }},
		{"control-in-tenant", func(g *grantRecord) { g.tenant = "tenant\tother" }},
		{"space-in-requester", func(g *grantRecord) { g.requester = "requester other" }},
		{"oversized-target", func(g *grantRecord) { g.target = identity.UserID(strings.Repeat("t", 129)) }},
		{"same-requester-target", func(g *grantRecord) { g.target = g.requester }},
		{"noncanonical-grant-id", func(g *grantRecord) { g.id = "AAAAAAAAAAAAAAAAAAAAAB" }},
		{"zero-grant-id", func(g *grantRecord) { g.id = "AAAAAAAAAAAAAAAAAAAAAA" }},
		{"empty-envelope", func(g *grantRecord) { g.payload = []byte{} }},
		{"oversized-envelope", func(g *grantRecord) { g.payload = make([]byte, 65537) }},
		{"extended-expiry", func(g *grantRecord) { g.expiresAt = g.expiresAt.Add(time.Microsecond) }},
	} {
		t.Run(invalid.name, func(t *testing.T) {
			grant := storageTestGrant(1)
			invalid.change(&grant)
			if _, err := pool.Raw().Exec(ctx, grantInsertSQL, grantInsertArgs(grant)...); err == nil {
				t.Fatal("database accepted invalid clear metadata or envelope")
			}
		})
	}
	grant := storageTestGrant(2)
	grant.tenant = identity.TenantID(strings.Repeat("t", 128))
	grant.requester = identity.UserID(strings.Repeat("r", 128))
	grant.target = identity.UserID(strings.Repeat("u", 128))
	grant.payload = bytes.Repeat([]byte{0, 1, 127, 255}, 16384)
	if _, err := pool.Raw().Exec(ctx, grantInsertSQL, grantInsertArgs(grant)...); err != nil {
		t.Fatal("valid boundary request rejected", err)
	}
	observed, err := observeGrant(ctx, pool, grant.tenant, grant.id)
	if err != nil || !sameStorageGrant(grant, observed) {
		t.Fatal("maximum-size opaque envelope changed", err)
	}
	approval := storageTestApproval(grant)
	approval.payload = make([]byte, 65537)
	if _, err := pool.Raw().Exec(ctx, grantApproveSQL, grantApprovalArgs(grant, approval)...); err == nil {
		t.Fatal("oversized decision did not abort approval statement")
	}
	assertStorageState(t, ctx, pool, grant, "pending_approval", 1, 0)
	approval.payload = bytes.Repeat([]byte{255, 127, 1, 0}, 16384)
	if tag, err := pool.Raw().Exec(ctx, grantApproveSQL, grantApprovalArgs(grant, approval)...); err != nil || tag.RowsAffected() != 1 {
		t.Fatal("valid boundary approval rejected", err)
	}
	var payload []byte
	if err := pool.Raw().QueryRow(ctx, `SELECT encrypted_payload FROM identity_impersonation.approvals WHERE tenant_id=$1 AND grant_id=$2`, string(grant.tenant), string(grant.id)).Scan(&payload); err != nil || !bytes.Equal(payload, approval.payload) {
		t.Fatal("decision envelope changed", err)
	}
	assertStorageState(t, ctx, pool, grant, "approved", 2, 1)
}

func TestImpersonationStorageRecoveryDistinguishesCompetingCommand(t *testing.T) {
	ctx, pool := newImpersonationStorageDatabase(t)
	installImpersonationStorage(t, ctx, pool)
	grant := storageTestGrant(1)
	grant.requestedAt = time.Now().UTC().Truncate(time.Microsecond).Add(-2 * impersonation.ApprovalLifetime)
	grant.expiresAt = grant.requestedAt.Add(impersonation.ApprovalLifetime)
	if _, err := pool.Raw().Exec(ctx, grantInsertSQL, grantInsertArgs(grant)...); err != nil {
		t.Fatal(err)
	}
	request := storageRecoveryBinding(grant, requestAction, identity.CommandID(grant.id), grant.requester)
	approval := storageTestApproval(grant)
	approved := storageRecoveryBinding(grant, approveAction, approval.commandID, approval.approver)
	assert := func(t *testing.T, binding identity.CommandBinding, want kernel.RecoveryStatus) {
		t.Helper()
		query, args, err := grantRecoveryQuery(binding)
		if err != nil {
			t.Fatal("select exact recovery evidence", err)
		}
		rows, err := pool.Raw().Query(ctx, query, args...)
		if err != nil {
			t.Fatal(err)
		}
		got, err := decodeGrantEffect(ctx, rows)
		if err != nil || got != want {
			t.Fatal("recovery attributed another command's effect", got, want, err)
		}
	}
	assert(t, request, kernel.RecoveryCommitted)
	assert(t, approved, kernel.RecoveryNotCommitted)
	if _, err := pool.Raw().Exec(ctx, grantApproveSQL, grantApprovalArgs(grant, approval)...); err != nil {
		t.Fatal(err)
	}
	assert(t, request, kernel.RecoveryCommitted)
	assert(t, approved, kernel.RecoveryCommitted)
	for _, changed := range []struct {
		name   string
		change func(*identity.CommandBinding)
	}{
		{"competing-command-same-approver", func(b *identity.CommandBinding) { b.CommandID = identity.CommandID(storageTestGrant(300).id) }},
		{"other-approver", func(b *identity.CommandBinding) { b.ActorID = "other-approver" }},
		{"other-target", func(b *identity.CommandBinding) { b.UserID = "other-target" }},
		{"other-grant", func(b *identity.CommandBinding) { b.RecordID = string(storageTestGrant(301).id) }},
		{"other-tenant", func(b *identity.CommandBinding) { b.TenantID = "other-tenant" }},
	} {
		t.Run(changed.name, func(t *testing.T) {
			binding := approved
			changed.change(&binding)
			assert(t, binding, kernel.RecoveryNotCommitted)
		})
	}
	missing := storageTestGrant(302)
	assert(t, storageRecoveryBinding(missing, requestAction, identity.CommandID(missing.id), missing.requester), kernel.RecoveryNotCommitted)
	for _, invalid := range []identity.CommandBinding{
		storageRecoveryBinding(grant, requestAction, approval.commandID, grant.requester),
		storageRecoveryBinding(grant, approveAction, identity.CommandID(grant.id), approval.approver),
		storageRecoveryBinding(grant, "identity.impersonation.start", approval.commandID, approval.approver),
	} {
		if _, _, err := grantRecoveryQuery(invalid); err == nil {
			t.Fatal("invalid recovery binding supplied conclusive evidence")
		}
	}
	if status, err := recoverGrantEffect(ctx, kernel.RecoveryWork{}, approved); err == nil || status != kernel.RecoveryUnknown {
		t.Fatal("zero recovery capability produced conclusive evidence", status, err)
	}
	if _, err := pool.Raw().Exec(ctx, `UPDATE identity_impersonation.approvals SET command_id=$1 WHERE tenant_id=$2 AND grant_id=$3`, string(storageTestGrant(303).id), string(grant.tenant), string(grant.id)); err == nil {
		t.Fatal("approval command attribution was mutable")
	}
	for _, invalid := range []string{"", "AAAAAAAAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAAAAAAAB"} {
		candidate := storageTestGrant(500)
		if _, err := pool.Raw().Exec(ctx, grantInsertSQL, grantInsertArgs(candidate)...); err != nil {
			t.Fatal(err)
		}
		decision := storageTestApproval(candidate)
		decision.commandID = identity.CommandID(invalid)
		if _, err := pool.Raw().Exec(ctx, grantApproveSQL, grantApprovalArgs(candidate, decision)...); err == nil {
			t.Fatal("invalid approval command identifier was persisted")
		}
		assertStorageState(t, ctx, pool, candidate, "pending_approval", 1, 0)
		if _, err := pool.Raw().Exec(ctx, `DELETE FROM identity_impersonation.grants WHERE tenant_id=$1 AND grant_id=$2`, string(candidate.tenant), string(candidate.id)); err != nil {
			t.Fatal(err)
		}
	}
	for _, query := range []string{"SELECT 2", "SELECT NULL::integer", "SELECT 1 UNION ALL SELECT 1"} {
		rows, err := pool.Raw().Query(ctx, query)
		if err != nil {
			t.Fatal(err)
		}
		if status, err := decodeGrantEffect(ctx, rows); err == nil || status != kernel.RecoveryUnknown {
			t.Fatal("malformed or failing evidence became conclusive", status, err)
		}
	}
}

func storageRecoveryBinding(g grantRecord, action string, command identity.CommandID, actor identity.UserID) identity.CommandBinding {
	op, _ := approvalOperation(action)
	return identity.CommandBinding{CommandID: command, TenantID: g.tenant, UserID: g.target, ActorID: identity.ActorID(actor), ActorKind: authorization.SubjectUser, RecordID: string(g.id), OperationID: action, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, PolicyID: "impersonation-admin", PolicyVersion: 1, CorrelationID: string(command)}
}

func TestImpersonationStorageQueriesStayPointBounded(t *testing.T) {
	ctx, pool := newImpersonationStorageDatabase(t)
	installImpersonationStorage(t, ctx, pool)
	grant := storageTestGrant(1)
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity_impersonation.grants
(tenant_id,grant_id,requester_id,target_id,request_digest,encrypted_payload,requested_at,expires_at,state,version)
SELECT CASE WHEN n<=16000 THEN 'tenant-dense' ELSE 'tenant-sparse-'||((n-16001)/100)::text END,
translate(rtrim(encode(decode(lpad(to_hex(n),32,'0'),'hex'),'base64'),'='),'+/','-_'),
'requester','target',$1,decode(repeat(md5(n::text),128),'hex'),$2,$3,
CASE WHEN n%2=0 THEN 'approved' ELSE 'pending_approval' END,CASE WHEN n%2=0 THEN 2 ELSE 1 END
FROM generate_series(1,20000) n`, grant.digest[:], grant.requestedAt, grant.expiresAt); err != nil {
		t.Fatal("seed isolated 20k skewed grants", err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity_impersonation.approvals
(tenant_id,grant_id,command_id,requester_id,target_id,request_digest,approver_id,encrypted_payload,decided_at)
SELECT tenant_id,grant_id,
translate(rtrim(encode(set_byte(decode(translate(grant_id,'-_','+/')||'==','base64'),0,1),'base64'),'='),'+/','-_'),
requester_id,target_id,request_digest,'approver',encrypted_payload,requested_at+interval '1 second'
FROM identity_impersonation.grants WHERE version=2`); err != nil {
		t.Fatal("seed 10k distinct immutable approval commands", err)
	}
	if _, err := pool.Raw().Exec(ctx, `ANALYZE identity_impersonation.grants; ANALYZE identity_impersonation.approvals`); err != nil {
		t.Fatal(err)
	}
	var engine, columns, indexes string
	var total, dense, tenants int
	var heapBytes, indexBytes int64
	if err := pool.Raw().QueryRow(ctx, `SELECT current_setting('server_version'),
(SELECT string_agg(column_name||':'||udt_name,', ' ORDER BY ordinal_position) FROM information_schema.columns WHERE table_schema='identity_impersonation' AND table_name='grants'),
(SELECT string_agg(indexdef,E'\n' ORDER BY indexname) FROM pg_indexes WHERE schemaname='identity_impersonation' AND tablename='grants'),
count(*),count(*) FILTER(WHERE tenant_id='tenant-dense'),count(DISTINCT tenant_id),
pg_relation_size('identity_impersonation.grants'),pg_indexes_size('identity_impersonation.grants')
FROM identity_impersonation.grants`).Scan(&engine, &columns, &indexes, &total, &dense, &tenants, &heapBytes, &indexBytes); err != nil || total != 20000 || dense != 16000 || tenants != 41 {
		t.Fatal("inspect actual store population and schema", err)
	}
	t.Logf("PostgreSQL=%s; exact Work-style ExecParams binary text(25),bytea(17),timestamptz(1184) bindings; columns=%s; indexes=%s; rows=20k, dense tenant=16k, 40 sparse tenants of 100; synthetic 2KiB compressible envelopes; heap_bytes=%d index_bytes=%d; one connection sequential warm samples, no competing load; point-access cost only, not production capacity", engine, columns, indexes, heapBytes, indexBytes)
	var approvalRows int
	if err := pool.Raw().QueryRow(ctx, `SELECT
(SELECT string_agg(column_name||':'||udt_name,', ' ORDER BY ordinal_position) FROM information_schema.columns WHERE table_schema='identity_impersonation' AND table_name='approvals'),
(SELECT string_agg(indexdef,E'\n' ORDER BY indexname) FROM pg_indexes WHERE schemaname='identity_impersonation' AND tablename='approvals'),
count(*),pg_relation_size('identity_impersonation.approvals'),pg_indexes_size('identity_impersonation.approvals')
FROM identity_impersonation.approvals`).Scan(&columns, &indexes, &approvalRows, &heapBytes, &indexBytes); err != nil || approvalRows != 10000 {
		t.Fatal("inspect actual populated approval store", err)
	}
	t.Logf("approval rows=%d; columns=%s; indexes=%s; heap_bytes=%d index_bytes=%d", approvalRows, columns, indexes, heapBytes, indexBytes)
	for _, partition := range []struct {
		name   string
		tenant identity.TenantID
		number uint64
	}{{"dense", "tenant-dense", 1}, {"sparse", "tenant-sparse-0", 16001}, {"missing-tenant", "tenant-missing", 1}} {
		selected := storageTestGrant(partition.number)
		selected.tenant = partition.tenant
		for _, operation := range []string{"observe", "lock", "approve", "wrong-digest", "expired", "self", "insert", "recover-request", "recover-request-wrong-actor", "recover-request-wrong-target", "recover-approval", "recover-approval-competing-command", "recover-approval-wrong-actor", "recover-approval-wrong-target"} {
			t.Run(partition.name+"/"+operation, func(t *testing.T) {
				approval := storageTestApproval(selected)
				query, args := grantSelectSQL, []any{string(selected.tenant), string(selected.id)}
				rows := 1.0
				if partition.name == "missing-tenant" {
					rows = 0
				}
				switch operation {
				case "lock":
					query += " FOR UPDATE"
				case "approve", "wrong-digest", "expired", "self":
					candidate := selected
					if operation == "wrong-digest" {
						candidate.digest[0]++
					}
					if operation == "expired" {
						approval.decidedAt = candidate.expiresAt
					}
					if operation == "self" {
						approval.approver = candidate.requester
					}
					query, args = grantApproveSQL, grantApprovalArgs(candidate, approval)
					if operation != "approve" {
						rows = 0
					}
				case "insert":
					candidate := storageTestGrant(30000)
					candidate.tenant = partition.tenant
					query, args = grantInsertSQL, grantInsertArgs(candidate)
				case "recover-request", "recover-request-wrong-actor", "recover-request-wrong-target":
					binding := storageRecoveryBinding(selected, requestAction, identity.CommandID(selected.id), selected.requester)
					if operation == "recover-request-wrong-actor" {
						binding.ActorID = "other-requester"
						rows = 0
					}
					if operation == "recover-request-wrong-target" {
						binding.UserID = "other-target"
						rows = 0
					}
					var err error
					query, args, err = grantRecoveryQuery(binding)
					if err != nil {
						t.Fatal(err)
					}
				case "recover-approval", "recover-approval-competing-command", "recover-approval-wrong-actor", "recover-approval-wrong-target":
					candidate := storageTestGrant(partition.number + 1)
					candidate.tenant = partition.tenant
					decision := storageTestApproval(candidate)
					binding := storageRecoveryBinding(candidate, approveAction, decision.commandID, decision.approver)
					if operation == "recover-approval-competing-command" {
						binding.CommandID = identity.CommandID(storageTestGrant(50000).id)
						rows = 0
					}
					if operation == "recover-approval-wrong-actor" {
						binding.ActorID = "other-approver"
						rows = 0
					}
					if operation == "recover-approval-wrong-target" {
						binding.UserID = "other-target"
						rows = 0
					}
					var err error
					query, args, err = grantRecoveryQuery(binding)
					if err != nil {
						t.Fatal(err)
					}
				}
				var bindings []string
				for index, arg := range args {
					bindings = append(bindings, fmt.Sprintf("$%d=%T", index+1, arg))
				}
				t.Logf("exact SQL=%s; native bindings=%s", query, strings.Join(bindings, ", "))
				var samples []time.Duration
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
							var raw []byte
							planRows := storageNativeQuery(t, ctx, tx, "EXPLAIN (ANALYZE,BUFFERS,WAL,FORMAT JSON) "+query, args)
							if !planRows.Next() {
								t.Fatal("explain exact native statement", planRows.Err())
							}
							if err := planRows.Scan(&raw); err != nil {
								planRows.Close()
								t.Fatal("decode native plan row", err)
							}
							if planRows.Next() || planRows.Err() != nil {
								planRows.Close()
								t.Fatal("unexpected native plan rows", planRows.Err())
							}
							planRows.Close()
							var plans []struct{ Plan impersonationStorageQueryPlan }
							if err := json.Unmarshal(raw, &plans); err != nil || len(plans) != 1 {
								t.Fatal("decode exact statement plan", err)
							}
							if operation != "insert" {
								assertStoragePointPlan(t, plans[0].Plan)
							}
							t.Logf("measured plan=%s", raw)
							return
						}
						started := time.Now()
						result := storageNativeQuery(t, ctx, tx, query, args)
						count := 0.0
						for result.Next() {
							count++
						}
						if result.Err() != nil {
							t.Fatal(result.Err())
						}
						elapsed := time.Since(started)
						if operation == "observe" || operation == "lock" || strings.HasPrefix(operation, "recover-") {
							if count != rows {
								t.Fatal("point read changed result cardinality", count, rows)
							}
						} else {
							want := int64(rows)
							if operation == "insert" {
								want = 1
							}
							if result.CommandTag().RowsAffected() != want {
								t.Fatal("conditional mutation changed affected rows", result.CommandTag().RowsAffected(), want)
							}
						}
						if sample > 1 {
							samples = append(samples, elapsed)
						}
					}()
				}
				t.Logf("five warm native roundtrip durations=%v; transaction begin/rollback and fixture setup excluded", samples)
			})
		}
	}
}

// The production Work codec fixes these exact scalar OIDs and binary formats
// rather than letting preparation infer a domain's OID. This runner reproduces
// that binding path on the isolated fixture, not a second transaction authority.
func storageNativeQuery(t *testing.T, ctx context.Context, tx pgx.Tx, query string, args []any) pgx.Rows {
	t.Helper()
	codecs := pgtype.NewMap()
	values := make([][]byte, len(args))
	oids := make([]uint32, len(args))
	formats := make([]int16, len(args))
	for index, arg := range args {
		switch arg.(type) {
		case string:
			oids[index] = pgtype.TextOID
		case []byte:
			oids[index] = pgtype.ByteaOID
		case time.Time:
			oids[index] = pgtype.TimestamptzOID
		default:
			t.Fatalf("storage query introduced an unmeasured binding type %T", arg)
		}
		formats[index] = pgtype.BinaryFormatCode
		encoded, err := codecs.Encode(oids[index], formats[index], arg, make([]byte, 0))
		if err != nil {
			t.Fatal("encode exact native binding", err)
		}
		values[index] = encoded
	}
	return pgx.RowsFromResultReader(codecs, tx.Conn().PgConn().ExecParams(ctx, query, values, oids, formats, nil))
}

type impersonationStorageQueryPlan struct {
	Node     string                          `json:"Node Type"`
	Relation string                          `json:"Relation Name"`
	Index    string                          `json:"Index Name"`
	Rows     float64                         `json:"Actual Rows"`
	Loops    float64                         `json:"Actual Loops"`
	Removed  float64                         `json:"Rows Removed by Filter"`
	Plans    []impersonationStorageQueryPlan `json:"Plans"`
}

func assertStoragePointPlan(t *testing.T, plan impersonationStorageQueryPlan) {
	t.Helper()
	if (plan.Relation == "grants" || plan.Relation == "approvals") && (plan.Node == "Seq Scan" || plan.Rows*plan.Loops+plan.Removed*plan.Loops > 1) {
		t.Fatal("grant/approval lookup exceeded one unique-key candidate", plan.Node, plan.Index, plan.Rows, plan.Loops, plan.Removed)
	}
	for _, child := range plan.Plans {
		assertStoragePointPlan(t, child)
	}
}

func storageTestGrant(number uint64) grantRecord {
	var id [16]byte
	binary.BigEndian.PutUint64(id[8:], number)
	at := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	return grantRecord{tenant: "tenant-a", id: impersonation.GrantID(base64.RawURLEncoding.EncodeToString(id[:])), requester: "requester", target: "target", digest: [32]byte{3}, payload: []byte("opaque-encrypted-request-envelope"), requestedAt: at, expiresAt: at.Add(impersonation.ApprovalLifetime), version: 1}
}

func storageTestApproval(g grantRecord) approvalRecord {
	raw, err := base64.RawURLEncoding.DecodeString(string(g.id))
	if err != nil || len(raw) != 16 {
		panic("invalid storage test grant identifier")
	}
	raw[0] ^= 1
	command := identity.CommandID(base64.RawURLEncoding.EncodeToString(raw))
	return approvalRecord{commandID: command, approver: "approver", payload: []byte("opaque-encrypted-approval-envelope"), decidedAt: g.requestedAt.Add(time.Second)}
}

func sameStorageGrant(a, b grantRecord) bool {
	return a.tenant == b.tenant && a.id == b.id && a.requester == b.requester && a.target == b.target && a.digest == b.digest && bytes.Equal(a.payload, b.payload) && a.requestedAt.Equal(b.requestedAt) && a.expiresAt.Equal(b.expiresAt) && a.version == b.version
}

func assertStorageState(t *testing.T, ctx context.Context, pool *database.Pool, grant grantRecord, status string, version, approvals int) {
	t.Helper()
	var gotStatus string
	var gotVersion, gotApprovals int
	if err := pool.Raw().QueryRow(ctx, `SELECT state,version,(SELECT count(*) FROM identity_impersonation.approvals a WHERE a.tenant_id=g.tenant_id AND a.grant_id=g.grant_id) FROM identity_impersonation.grants g WHERE tenant_id=$1 AND grant_id=$2`, string(grant.tenant), string(grant.id)).Scan(&gotStatus, &gotVersion, &gotApprovals); err != nil || gotStatus != status || gotVersion != version || gotApprovals != approvals {
		t.Fatal("grant and distinct approval were not atomic", gotStatus, gotVersion, gotApprovals, err)
	}
}

func installImpersonationStorage(t *testing.T, ctx context.Context, pool *database.Pool) {
	t.Helper()
	history, err := (MigrationSource{}).Load(ctx)
	if err != nil || len(history) != 1 || history[0].Version() != 1 || history[0].DownSQL() != "" {
		t.Fatal("independent forward-only migration history", err)
	}
	if _, err := pool.Raw().Exec(ctx, history[0].UpSQL()); err != nil {
		t.Fatal("install new empty impersonation namespace", err)
	}
}

func newImpersonationStorageDatabase(t *testing.T) (context.Context, *database.Pool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	t.Cleanup(cancel)
	dsn, directory := os.Getenv("IDENTITY_IMPERSONATION_TEST_DSN"), os.Getenv("IDENTITY_POSTGRES_TEST_DATA_DIRECTORY")
	config, err := pgx.ParseConfig(dsn)
	if dsn == "" || err != nil || config.Host != "127.0.0.1" || config.Database != "identity_test" || !filepath.IsAbs(directory) {
		t.Fatal("explicit task-owned loopback identity_test cluster required")
	}
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("owned cluster unavailable", err)
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	var actual string
	if err := admin.QueryRow(ctx, "SHOW data_directory").Scan(&actual); err != nil || actual != directory {
		t.Fatal("not the exact task-owned cluster")
	}
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	name := pgx.Identifier{"impersonation_storage_" + string(id)}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+name); err != nil {
			t.Error("owned database cleanup", err)
		}
	})
	pool, err := database.Connect(ctx, database.Config{DSN: dsn, MaxConns: 4, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = "impersonation_storage_" + string(id)
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := pool.Close(cleanup); err != nil {
			t.Error("owned pool cleanup", err)
		}
	})
	return ctx, pool
}
