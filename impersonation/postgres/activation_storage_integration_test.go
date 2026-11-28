//go:build integration

package impersonationpostgres

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/impersonation"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

func TestImpersonationActivationMigrationPreservesPopulatedV1(t *testing.T) {
	ctx, pool := newImpersonationStorageDatabase(t)
	installImpersonationStorage(t, ctx, pool)
	grant := storageTestGrant(1)
	approval := storageTestApproval(grant)
	if _, err := pool.Raw().Exec(ctx, grantInsertSQL, grantInsertArgs(grant)...); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, grantApproveSQL, grantApprovalArgs(grant, approval)...); err != nil {
		t.Fatal(err)
	}
	legacy, err := (MigrationSource{}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	history, err := (ActivationMigrationSource{}).Load(ctx)
	if err != nil || len(history) != 2 || history[0].UpSQL() != legacy[0].UpSQL() {
		t.Fatal("activation did not append unchanged v1 history", err)
	}
	if _, err := pool.Raw().Exec(ctx, history[1].UpSQL()); err != nil {
		t.Fatal("upgrade populated v1", err)
	}
	assertStorageState(t, ctx, pool, grant, "approved", 2, 1)
	observed, err := observeGrant(ctx, pool, grant.tenant, grant.id)
	grant.version = 2
	if err != nil || !sameStorageGrant(observed, grant) {
		t.Fatal("activation migration rewrote retained request", err)
	}
	var retained []byte
	if err := pool.Raw().QueryRow(ctx, `SELECT encrypted_payload FROM identity_impersonation.approvals WHERE tenant_id=$1 AND grant_id=$2`, string(grant.tenant), string(grant.id)).Scan(&retained); err != nil || string(retained) != string(approval.payload) {
		t.Fatal("activation migration rewrote retained decision", err)
	}
	var count int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity_impersonation.active_grants`).Scan(&count); err != nil || count != 0 {
		t.Fatal("upgrade created activation effects", err)
	}
}

func TestImpersonationActivationStorageBindsExactApproval(t *testing.T) {
	ctx, pool := newImpersonationStorageDatabase(t)
	installActivationStorage(t, ctx, pool)
	grant := storageTestGrant(1)
	approval := storageTestApproval(grant)
	if _, err := pool.Raw().Exec(ctx, grantInsertSQL, grantInsertArgs(grant)...); err != nil {
		t.Fatal(err)
	}
	row := activationStorageTestRow(t, grant, approval)
	assertActivationInsert := func(candidate activationRecord, want int64) {
		t.Helper()
		tag, err := pool.Raw().Exec(ctx, activationInsertSQL, activationInsertArgs(candidate)...)
		if err != nil || tag.RowsAffected() != want {
			t.Fatal("activation exact approval selection", tag.RowsAffected(), want, err)
		}
	}
	assertActivationInsert(row, 0)
	if _, err := pool.Raw().Exec(ctx, grantApproveSQL, grantApprovalArgs(grant, approval)...); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []struct {
		name   string
		change func(*activationRecord)
	}{
		{"wrong-tenant", func(r *activationRecord) { r.tenant = "other" }},
		{"wrong-grant", func(r *activationRecord) { r.grantID = storageTestGrant(2).id }},
		{"wrong-approval-command", func(r *activationRecord) { r.approvalID = identity.CommandID(storageTestGrant(3).id) }},
		{"wrong-actor", func(r *activationRecord) { r.actor = "other" }},
		{"wrong-target", func(r *activationRecord) { r.target = "other" }},
		{"wrong-approver", func(r *activationRecord) { r.approver = "other" }},
		{"requester-delegation", func(r *activationRecord) { r.actor, r.approver = r.approver, r.actor }},
		{"wrong-digest", func(r *activationRecord) { r.requestDigest[0]++ }},
		{"before-approval", func(r *activationRecord) { r.startedAt = approval.decidedAt.Add(-time.Microsecond) }},
		{"at-approval-expiry", func(r *activationRecord) { r.startedAt = grant.expiresAt; r.expiresAt = r.startedAt.Add(time.Minute) }},
		{"request-command-reused", func(r *activationRecord) { r.commandID = identity.CommandID(grant.id) }},
		{"approval-command-reused", func(r *activationRecord) { r.commandID = approval.commandID }},
	} {
		t.Run(invalid.name, func(t *testing.T) {
			candidate := row
			invalid.change(&candidate)
			assertActivationInsert(candidate, 0)
		})
	}
	if _, err := readActivation(ctx, pool, row.tenant, row.derivedDigest); !errors.Is(err, identity.ForbiddenError{}) {
		t.Fatal("missing derived credential was not forbidden", err)
	}
	assertActivationInsert(row, 1)
	observed, err := readActivation(ctx, pool, row.tenant, row.derivedDigest)
	if err != nil || !reflect.DeepEqual(row, observed) {
		t.Fatal("retained activation lineage changed", err)
	}
	if _, err := readActivation(ctx, pool, "other", row.derivedDigest); !errors.Is(err, identity.ForbiddenError{}) {
		t.Fatal("foreign tenant read active lineage", err)
	}
	competitor := row
	competitor.commandID = identity.CommandID(storageTestGrant(4).id)
	competitor.derivedDigest.Sum[0]++
	if _, err := pool.Raw().Exec(ctx, activationInsertSQL, activationInsertArgs(competitor)...); err == nil {
		t.Fatal("same grant acquired a competing activation")
	}
	for _, update := range []string{
		`UPDATE identity_impersonation.active_grants SET actor_id='other'`,
		`UPDATE identity_impersonation.active_grants SET expires_at=expires_at+interval '1 second'`,
		`UPDATE identity_impersonation.active_grants SET activation_command_id='AAAAAAAAAAAAAAAAAAAABA'`,
		`DELETE FROM identity_impersonation.active_grants`,
	} {
		if _, err := pool.Raw().Exec(ctx, update); err == nil {
			t.Fatal("activation lineage was mutable")
		}
	}
	assertActivationRecovery(t, ctx, pool, row, kernel.RecoveryCommitted)
	assertActivationRecovery(t, ctx, pool, competitor, kernel.RecoveryNotCommitted)
	if _, err := pool.Raw().Exec(ctx, `UPDATE identity_impersonation.active_grants SET state='revoked',version=4 WHERE tenant_id=$1 AND grant_id=$2`, string(row.tenant), string(row.grantID)); err != nil {
		t.Fatal("retained lineage cannot represent inactive state", err)
	}
	observed, err = readActivation(ctx, pool, row.tenant, row.derivedDigest)
	if err != nil || observed.status != impersonation.StatusRevoked || observed.version != 4 {
		t.Fatal("terminal activation was disguised as active", err)
	}
	assertActivationRecovery(t, ctx, pool, row, kernel.RecoveryCommitted)
	if _, err := pool.Raw().Exec(ctx, `UPDATE identity_impersonation.active_grants SET state='active',version=3`); err == nil {
		t.Fatal("terminal activation resurrected")
	}
	if err := insertActivation(ctx, kernel.Work{}, row); err == nil {
		t.Fatal("zero Work wrote activation")
	}
	if status, err := recoverActivationEffect(ctx, kernel.RecoveryWork{}, activationStorageBinding(row)); err == nil || status != kernel.RecoveryUnknown {
		t.Fatal("zero recovery Work established historical effect", status, err)
	}
}

func activationStorageTestRow(t *testing.T, grant grantRecord, approval approvalRecord) activationRecord {
	t.Helper()
	scope, err := impersonation.NewScope([]string{"profile.read", "address.read"})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := impersonation.NewPolicy("policy", 18446744073709551615)
	if err != nil {
		t.Fatal(err)
	}
	return activationRecord{
		tenant: grant.tenant, grantID: grant.id, commandID: identity.CommandID(storageTestGrant(1000).id), approvalID: approval.commandID,
		actor: grant.requester, target: grant.target, approver: approval.approver, requestDigest: grant.digest,
		scope: scope, policy: policy, actorVersion: 18446744073709551615, targetVersion: 2, approverVersion: 3, approverAuthorityVersion: 4,
		authorityNamespace: "operator", parentID: "parent-session", parentVersion: 18446744073709551615,
		parentDigest: session.TokenDigest{KeyVersion: 1, Sum: [32]byte{5}}, derivedDigest: session.TokenDigest{KeyVersion: 2, Sum: [32]byte{6}},
		startedAt: approval.decidedAt.Add(time.Second), expiresAt: approval.decidedAt.Add(10 * time.Minute), version: 3, status: impersonation.StatusActive,
	}
}

func activationStorageBinding(row activationRecord) identity.CommandBinding {
	op := identity.FeatureOperation{Owner: "identity/impersonation", OperationID: "identity.impersonation.start", SchemaID: "impersonation-start", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	b := storageRecoveryBinding(storageTestGrant(1), op.OperationID, row.commandID, row.actor)
	b.TenantID, b.UserID, b.RecordID = row.tenant, row.target, string(row.grantID)
	b.ActorKind = authorization.SubjectUser
	b.PolicyID, b.PolicyVersion = row.policy.ID(), row.policy.Version()
	b.SchemaID, b.SchemaVersion = op.SchemaID, op.SchemaVersion
	return b
}

func assertActivationRecovery(t *testing.T, ctx context.Context, pool *database.Pool, row activationRecord, want kernel.RecoveryStatus) {
	t.Helper()
	query, args, err := activationRecoveryQuery(activationStorageBinding(row))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := pool.Raw().Query(ctx, query, args...)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeGrantEffect(ctx, rows)
	if err != nil || got != want {
		t.Fatal("activation recovery attributed another command", got, want, err)
	}
}

func installActivationStorage(t *testing.T, ctx context.Context, pool *database.Pool) {
	t.Helper()
	history, err := (ActivationMigrationSource{}).Load(ctx)
	if err != nil || len(history) != 2 || history[1].Version() != 2 || history[1].DownSQL() != "" {
		t.Fatal("forward activation history", err)
	}
	for _, migration := range history {
		if _, err := pool.Raw().Exec(ctx, migration.UpSQL()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestImpersonationActivationStorageSingleConcurrentWinner(t *testing.T) {
	ctx, pool := newImpersonationStorageDatabase(t)
	installActivationStorage(t, ctx, pool)
	grant := storageTestGrant(10)
	approval := storageTestApproval(grant)
	if _, err := pool.Raw().Exec(ctx, grantInsertSQL, grantInsertArgs(grant)...); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, grantApproveSQL, grantApprovalArgs(grant, approval)...); err != nil {
		t.Fatal(err)
	}
	first := activationStorageTestRow(t, grant, approval)
	second := first
	second.commandID = identity.CommandID(storageTestGrant(1001).id)
	second.derivedDigest.Sum[0]++
	candidates := []activationRecord{first, second}
	var group sync.WaitGroup
	errors := make([]error, 2)
	for i := range candidates {
		group.Go(func() {
			tag, err := pool.Raw().Exec(ctx, activationInsertSQL, activationInsertArgs(candidates[i])...)
			if err == nil && tag.RowsAffected() != 1 {
				err = impersonation.ErrConflict
			}
			errors[i] = err
		})
	}
	group.Wait()
	winners := 0
	for i, err := range errors {
		want := kernel.RecoveryNotCommitted
		if err == nil {
			winners++
			want = kernel.RecoveryCommitted
		}
		assertActivationRecovery(t, ctx, pool, candidates[i], want)
	}
	if winners != 1 {
		t.Fatal("concurrent activation did not retain exactly one command", winners)
	}
}

func TestImpersonationActivationStorageRejectsDigestAndCommandReuseAndCorruption(t *testing.T) {
	ctx, pool := newImpersonationStorageDatabase(t)
	installActivationStorage(t, ctx, pool)
	firstGrant := storageTestGrant(20)
	first := activationStorageTestRow(t, firstGrant, storageTestApproval(firstGrant))
	for _, grant := range []grantRecord{firstGrant, storageTestGrant(21)} {
		if _, err := pool.Raw().Exec(ctx, grantInsertSQL, grantInsertArgs(grant)...); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Raw().Exec(ctx, grantApproveSQL, grantApprovalArgs(grant, storageTestApproval(grant))...); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Raw().Exec(ctx, activationInsertSQL, activationInsertArgs(first)...); err != nil {
		t.Fatal(err)
	}
	secondGrant := storageTestGrant(21)
	second := activationStorageTestRow(t, secondGrant, storageTestApproval(secondGrant))
	second.commandID = identity.CommandID(storageTestGrant(2000).id)
	if _, err := pool.Raw().Exec(ctx, activationInsertSQL, activationInsertArgs(second)...); err == nil {
		t.Fatal("derived digest reused across grants")
	}
	second.derivedDigest.Sum[0]++
	second.commandID = first.commandID
	if _, err := pool.Raw().Exec(ctx, activationInsertSQL, activationInsertArgs(second)...); err == nil {
		t.Fatal("activation command reused across grants")
	}
	second.commandID = identity.CommandID(storageTestGrant(2000).id)
	args := activationInsertArgs(second)
	args[8] = []byte(`["profile.read","profile.read"]`)
	if _, err := pool.Raw().Exec(ctx, activationInsertSQL, args...); err != nil {
		t.Fatal("seed malformed retained scope", err)
	}
	if _, err := readActivation(ctx, pool, second.tenant, second.derivedDigest); !errors.Is(err, identity.UnavailableError{}) {
		t.Fatal("corrupt scope authorized or became absence", err)
	}
}

func TestImpersonationActivationStorageQueriesStayPointBounded(t *testing.T) {
	ctx, pool := newImpersonationStorageDatabase(t)
	installActivationStorage(t, ctx, pool)
	grant := storageTestGrant(1)
	row := activationStorageTestRow(t, grant, storageTestApproval(grant))
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity_impersonation.grants
(tenant_id,grant_id,requester_id,target_id,request_digest,encrypted_payload,requested_at,expires_at,state,version)
SELECT CASE WHEN n<=16000 THEN 'tenant-dense' ELSE 'tenant-sparse-'||((n-16001)/100)::text END,
translate(rtrim(encode(decode(lpad(to_hex(n),32,'0'),'hex'),'base64'),'='),'+/','-_'),
'requester','target',$1,decode(repeat(md5(n::text),128),'hex'),$2,$3,'approved',2
FROM generate_series(1,20000) n`, grant.digest[:], grant.requestedAt, grant.expiresAt); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity_impersonation.approvals
(tenant_id,grant_id,command_id,requester_id,target_id,request_digest,approver_id,encrypted_payload,decided_at)
SELECT tenant_id,grant_id,
translate(rtrim(encode(set_byte(decode(translate(grant_id,'-_','+/')||'==','base64'),0,1),'base64'),'='),'+/','-_'),
requester_id,target_id,request_digest,'approver',encrypted_payload,requested_at+interval '1 second'
FROM identity_impersonation.grants`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity_impersonation.active_grants
(tenant_id,grant_id,activation_command_id,approval_command_id,actor_id,target_id,approver_id,request_digest,
scope,policy_id,policy_version,actor_version,target_version,approver_version,approver_authority_version,
authority_namespace,parent_id,parent_version,parent_digest_key,parent_digest,derived_digest_key,derived_digest,
started_at,expires_at,state,version)
SELECT g.tenant_id,g.grant_id,
translate(rtrim(encode(set_byte(decode(translate(g.grant_id,'-_','+/')||'==','base64'),0,2),'base64'),'='),'+/','-_'),
a.command_id,g.requester_id,g.target_id,a.approver_id,g.request_digest,'["address.read","profile.read"]'::jsonb,
'policy',1,1,1,1,1,'operator','parent-session',1,1,$1,2,
decode(lpad(to_hex(n),64,'0'),'hex'),$2,$3,'active',3
FROM generate_series(1,20000) n
JOIN identity_impersonation.grants g ON g.grant_id=translate(rtrim(encode(decode(lpad(to_hex(n),32,'0'),'hex'),'base64'),'='),'+/','-_')
JOIN identity_impersonation.approvals a ON a.tenant_id=g.tenant_id AND a.grant_id=g.grant_id
WHERE n%2=0`, row.parentDigest.Sum[:], row.startedAt, row.expiresAt); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `ANALYZE identity_impersonation.grants; ANALYZE identity_impersonation.approvals; ANALYZE identity_impersonation.active_grants`); err != nil {
		t.Fatal(err)
	}
	var engine, columns, indexes string
	var count, dense, tenants int
	var heapBytes, indexBytes int64
	if err := pool.Raw().QueryRow(ctx, `SELECT current_setting('server_version'),
(SELECT string_agg(column_name||':'||udt_name,', ' ORDER BY ordinal_position) FROM information_schema.columns WHERE table_schema='identity_impersonation' AND table_name='active_grants'),
(SELECT string_agg(indexdef,E'\n' ORDER BY indexname) FROM pg_indexes WHERE schemaname='identity_impersonation' AND tablename='active_grants'),
count(*),count(*) FILTER(WHERE tenant_id='tenant-dense'),count(DISTINCT tenant_id),
pg_relation_size('identity_impersonation.active_grants'),pg_indexes_size('identity_impersonation.active_grants')
FROM identity_impersonation.active_grants`).Scan(&engine, &columns, &indexes, &count, &dense, &tenants, &heapBytes, &indexBytes); err != nil || count != 10000 || dense != 8000 || tenants != 41 {
		t.Fatal("inspect actual populated activation store", err)
	}
	t.Logf("PostgreSQL=%s columns=%s indexes=%s; history=20k grants+20k approvals, authority=%d rows, dense=%d, tenants=%d; heap_bytes=%d index_bytes=%d; synthetic fixture, one sequential connection, no competing load; point cost only, not production capacity", engine, columns, indexes, count, dense, tenants, heapBytes, indexBytes)
	for _, partition := range []struct {
		name   string
		tenant identity.TenantID
		number uint64
	}{
		{"dense", "tenant-dense", 1}, {"sparse", "tenant-sparse-0", 16001}, {"missing", "missing-tenant", 1},
	} {
		for _, operation := range []string{"insert", "wrong-approval", "retained-approval", "read", "recover", "recover-competitor"} {
			t.Run(partition.name+"/"+operation, func(t *testing.T) {
				g := storageTestGrant(partition.number)
				g.tenant = partition.tenant
				r := activationStorageTestRow(t, g, storageTestApproval(g))
				query, args := activationInsertSQL, activationInsertArgs(r)
				want := int64(1)
				if partition.name == "missing" {
					want = 0
				}
				if operation == "wrong-approval" {
					r.approvalID = identity.CommandID(storageTestGrant(99999).id)
					args = activationInsertArgs(r)
					want = 0
				}
				if operation == "retained-approval" {
					query, args = retainedActivationApprovalSQL, []any{string(g.tenant), string(g.id)}
					t.Logf("retained approval native bindings: $1=%T, $2=%T; text(25), binary", args[0], args[1])
				}
				if operation == "read" || strings.HasPrefix(operation, "recover") {
					g = storageTestGrant(partition.number + 1)
					g.tenant = partition.tenant
					r = activationStorageTestRow(t, g, storageTestApproval(g))
					var command [16]byte
					binary.BigEndian.PutUint64(command[8:], partition.number+1)
					command[0] = 2
					r.commandID = identity.CommandID(base64.RawURLEncoding.EncodeToString(command[:]))
					r.derivedDigest.Sum = [32]byte{}
					binary.BigEndian.PutUint64(r.derivedDigest.Sum[24:], partition.number+1)
					query, args = activationSelectSQL, []any{string(r.tenant), strconv.FormatUint(uint64(r.derivedDigest.KeyVersion), 10), r.derivedDigest.Sum[:]}
					if strings.HasPrefix(operation, "recover") {
						r.policy, _ = impersonation.NewPolicy("policy", 1)
						if operation == "recover-competitor" {
							r.commandID = identity.CommandID(storageTestGrant(99999).id)
							want = 0
						}
						var err error
						query, args, err = activationRecoveryQuery(activationStorageBinding(r))
						if err != nil {
							t.Fatal(err)
						}
					}
				}
				t.Logf("exact SQL=%s; native bindings text(25), bytea(17), timestamptz(1184), binary; numeric/key arguments are decimal text with explicit casts", query)
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
							rows := storageNativeQuery(t, ctx, tx, "EXPLAIN (ANALYZE,BUFFERS,WAL,FORMAT JSON) "+query, args)
							var raw []byte
							if !rows.Next() {
								t.Fatal(rows.Err())
							}
							if err := rows.Scan(&raw); err != nil {
								rows.Close()
								t.Fatal(err)
							}
							if rows.Next() || rows.Err() != nil {
								rows.Close()
								t.Fatal("unexpected plan rows")
							}
							rows.Close()
							var plans []struct{ Plan impersonationStorageQueryPlan }
							if json.Unmarshal(raw, &plans) != nil || len(plans) != 1 {
								t.Fatal("decode plan")
							}
							assertActivationPointPlan(t, plans[0].Plan)
							t.Logf("measured plan=%s", raw)
							return
						}
						started := time.Now()
						rows := storageNativeQuery(t, ctx, tx, query, args)
						var returned int64
						for rows.Next() {
							returned++
						}
						if rows.Err() != nil {
							t.Fatal(rows.Err())
						}
						if operation == "insert" || operation == "wrong-approval" {
							returned = rows.CommandTag().RowsAffected()
						}
						if returned != want {
							t.Fatal("query cardinality", returned, want)
						}
						if sample > 1 {
							samples = append(samples, time.Since(started))
						}
					}()
				}
				t.Logf("five warm native roundtrip samples=%v; begin/rollback and setup excluded", samples)
			})
		}
	}
}

func assertActivationPointPlan(t *testing.T, plan impersonationStorageQueryPlan) {
	t.Helper()
	assertStoragePointPlan(t, plan)
	if plan.Relation == "active_grants" && (plan.Node == "Seq Scan" || (plan.Rows+plan.Removed)*plan.Loops > 1) {
		t.Fatal("activation lookup exceeded one unique-key candidate", plan.Node, plan.Index, plan.Rows, plan.Loops, plan.Removed)
	}
	for _, child := range plan.Plans {
		assertActivationPointPlan(t, child)
	}
}
