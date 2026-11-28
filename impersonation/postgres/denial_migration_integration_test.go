//go:build integration

package impersonationpostgres

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestImpersonationDenialMigrationLoad(t *testing.T) {
	ctx := context.Background()
	legacy, err := (SelfStopMigrationSource{}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	history, err := (DenialMigrationSource{}).Load(ctx)
	if err != nil || len(history) != 9 {
		t.Fatal("denial must append three forward migrations", err)
	}
	for index, migration := range history {
		if uint64(migration.Version()) != uint64(index+1) || migration.DownSQL() != "" {
			t.Fatal("denial history must remain ordered and forward-only")
		}
		if index < len(legacy) && (migration.Checksum() != legacy[index].Checksum() || migration.UpSQL() != legacy[index].UpSQL()) {
			t.Fatal("denial changed installed v1-v6 history")
		}
	}
	var invalid identity.InvalidInputError
	if _, err := (DenialMigrationSource{}).Load(nil); !errors.As(err, &invalid) {
		t.Fatal("nil migration context accepted", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := (DenialMigrationSource{}).Load(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled migration context accepted", err)
	}
	history[0] = history[8]
	fresh, err := (DenialMigrationSource{}).Load(ctx)
	if err != nil || fresh[0].Version() != 1 {
		t.Fatal("migration history shares caller-owned storage", err)
	}
}

func TestImpersonationDenialMigrationPreservesPopulatedHistory(t *testing.T) {
	ctx, pool := newImpersonationStorageDatabase(t)
	history, err := (DenialMigrationSource{}).Load(ctx)
	if err != nil || len(history) != 9 {
		t.Fatal("complete denial migration history required", err)
	}
	for _, migration := range history[:6] {
		applyRevocationMigration(t, ctx, pool, migration.UpSQL())
	}
	pending, approved := storageTestGrant(1), storageTestGrant(2)
	active, revoked := storageTestGrant(3), storageTestGrant(4)
	for _, grant := range []grantRecord{pending, approved, active, revoked} {
		if _, err := pool.Raw().Exec(ctx, grantInsertSQL, grantInsertArgs(grant)...); err != nil {
			t.Fatal(err)
		}
	}
	for _, grant := range []grantRecord{approved, active} {
		if _, err := pool.Raw().Exec(ctx, grantApproveSQL, grantApprovalArgs(grant, storageTestApproval(grant))...); err != nil {
			t.Fatal(err)
		}
	}
	activation := activationStorageTestRow(t, active, storageTestApproval(active))
	if _, err := pool.Raw().Exec(ctx, activationInsertSQL, activationInsertArgs(activation)...); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, revocationTestInsertSQL, revocationTestArgs(revoked, 1)...); err != nil {
		t.Fatal(err)
	}
	before := denialMigrationHistorySnapshot(t, ctx, pool)
	var approvalFunction, approvalTrigger uint32
	if err := pool.Raw().QueryRow(ctx, `SELECT 'identity_impersonation.reject_revoked_approval()'::regprocedure::oid,
 (SELECT oid FROM pg_trigger WHERE tgrelid='identity_impersonation.grants'::regclass AND tgname='reject_revoked_approval')`).Scan(&approvalFunction, &approvalTrigger); err != nil {
		t.Fatal(err)
	}
	assertDenialMigrationNotReady(t, ctx, pool)
	locked, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = locked.Rollback(ctx) }()
	if _, err := locked.Exec(ctx, `LOCK TABLE identity_impersonation.grants, identity_impersonation.approvals,
 identity_impersonation.active_grants, identity_impersonation.revocations,
 identity_impersonation.stop_proofs, identity_impersonation.stops IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	// v7 creates only new storage; v8 replaces the existing function in place.
	for _, migration := range history[6:8] {
		applyRevocationMigration(t, ctx, pool, migration.UpSQL())
		assertDenialMigrationNotReady(t, ctx, pool)
		var count int
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity_impersonation.denials`).Scan(&count); err != nil || count != 0 {
			t.Fatal("v7 must install empty denial storage before either fence", count, err)
		}
	}
	if err := locked.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var retainedFunction, retainedTrigger uint32
	if err := pool.Raw().QueryRow(ctx, `SELECT 'identity_impersonation.reject_revoked_approval()'::regprocedure::oid,
 (SELECT oid FROM pg_trigger WHERE tgrelid='identity_impersonation.grants'::regclass AND tgname='reject_revoked_approval')`).Scan(&retainedFunction, &retainedTrigger); err != nil || retainedFunction != approvalFunction || retainedTrigger != approvalTrigger {
		t.Fatal("approval fence was replaced instead of upgraded in place", err)
	}
	probe, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = probe.Rollback(ctx) }()
	if _, err := probe.Exec(ctx, denialMigrationTestInsertSQL, denialMigrationTestArgs(pending)...); err != nil {
		t.Fatal(err)
	}
	_, err = probe.Exec(ctx, grantApproveSQL, grantApprovalArgs(pending, storageTestApproval(pending))...)
	assertRevocationSQLState(t, err, "23514")
	if err := probe.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	_, err = pool.Raw().Exec(ctx, grantApproveSQL, grantApprovalArgs(revoked, storageTestApproval(revoked))...)
	assertRevocationSQLState(t, err, "23514")
	applyRevocationMigration(t, ctx, pool, history[8].UpSQL())
	var ready bool
	if err := pool.Raw().QueryRow(ctx, `SELECT identity_impersonation.denial_ready()`).Scan(&ready); err != nil || !ready {
		t.Fatal("final denial fence did not publish readiness", err)
	}
	if after := denialMigrationHistorySnapshot(t, ctx, pool); !reflect.DeepEqual(before, after) {
		t.Fatal("denial installation changed retained history")
	}
	var count int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity_impersonation.denials`).Scan(&count); err != nil || count != 0 {
		t.Fatal("denial installation generated terminal effects", count, err)
	}
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM pg_constraint WHERE conrelid='identity_impersonation.denials'::regclass AND contype='f'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("denial storage introduced a foreign-key lock on existing authority", count, err)
	}
	assertStorageState(t, ctx, pool, pending, "pending_approval", 1, 0)
	assertStorageState(t, ctx, pool, approved, "approved", 2, 1)
	observed, err := readActivation(ctx, pool, activation.tenant, activation.derivedDigest)
	if err != nil || !reflect.DeepEqual(activation, observed) {
		t.Fatal("denial installation changed active authority", err)
	}
	_, err = pool.Raw().Exec(ctx, grantApproveSQL, grantApprovalArgs(revoked, storageTestApproval(revoked))...)
	assertRevocationSQLState(t, err, "23514")
}

func TestImpersonationDenialStorageConstraintsAndImmutability(t *testing.T) {
	ctx, pool := newImpersonationStorageDatabase(t)
	installDenialMigrationTestStorage(t, ctx, pool)
	grant := storageTestGrant(1)
	for _, invalid := range []struct {
		name  string
		index int
		value any
	}{
		{"empty-tenant", 0, ""}, {"spaced-tenant", 0, "tenant a"},
		{"invalid-grant", 1, "invalid"}, {"zero-grant", 1, "AAAAAAAAAAAAAAAAAAAAAA"},
		{"noncanonical-grant", 1, "AAAAAAAAAAAAAAAAAAAAAB"},
		{"invalid-command", 2, "invalid"}, {"zero-command", 2, "AAAAAAAAAAAAAAAAAAAAAA"},
		{"noncanonical-command", 2, "AAAAAAAAAAAAAAAAAAAAAB"}, {"command-as-grant", 2, string(grant.id)},
		{"empty-denier", 3, ""}, {"requester-as-denier", 3, string(grant.requester)},
		{"target-as-denier", 3, string(grant.target)}, {"empty-requester", 4, ""},
		{"empty-target", 5, ""}, {"requester-as-target", 5, string(grant.requester)},
		{"short-digest", 6, []byte{1}}, {"long-digest", 6, make([]byte, 33)},
		{"empty-policy", 7, ""}, {"zero-policy-version", 8, "0"},
		{"overflow-policy-version", 8, "18446744073709551616"},
		{"before-zero", 9, int16(0)}, {"before-approved", 9, int16(2)},
		{"after-pending", 10, int16(1)}, {"after-active", 10, int16(3)},
		{"empty-payload", 11, []byte{}}, {"oversized-payload", 11, make([]byte, 65537)},
		{"infinite-time", 12, pgtype.Timestamptz{InfinityModifier: pgtype.Infinity, Valid: true}},
		{"before-portable-time", 12, time.Date(0, 12, 31, 23, 59, 59, 0, time.UTC)},
		{"after-portable-time", 12, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)},
	} {
		t.Run(invalid.name, func(t *testing.T) {
			args := denialMigrationTestArgs(grant)
			args[invalid.index] = invalid.value
			_, err := pool.Raw().Exec(ctx, denialMigrationTestInsertSQL, args...)
			assertRevocationSQLState(t, err, "23514")
		})
	}
	args := denialMigrationTestArgs(grant)
	if _, err := pool.Raw().Exec(ctx, denialMigrationTestInsertSQL, args...); err != nil {
		t.Fatal("valid retained denial rejected", err)
	}
	_, err := pool.Raw().Exec(ctx, denialMigrationTestInsertSQL, args...)
	assertRevocationSQLState(t, err, "23505")
	conflict := denialMigrationTestArgs(storageTestGrant(2))
	conflict[2] = args[2]
	_, err = pool.Raw().Exec(ctx, denialMigrationTestInsertSQL, conflict...)
	assertRevocationSQLState(t, err, "23505")
	otherTenant := grant
	otherTenant.tenant = "tenant-b"
	if _, err := pool.Raw().Exec(ctx, denialMigrationTestInsertSQL, denialMigrationTestArgs(otherTenant)...); err != nil {
		t.Fatal("denial uniqueness leaked across tenants", err)
	}
	for _, statement := range []string{
		`UPDATE identity_impersonation.denials SET encrypted_payload=$3 WHERE tenant_id=$1 AND grant_id=$2`,
		`DELETE FROM identity_impersonation.denials WHERE tenant_id=$1 AND grant_id=$2 AND $3::bytea IS NOT NULL`,
	} {
		_, err := pool.Raw().Exec(ctx, statement, args[0], args[1], []byte("replacement"))
		assertRevocationSQLState(t, err, "23514")
	}
	var count int
	var retained []byte
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity_impersonation.denials`).Scan(&count); err != nil || count != 2 {
		t.Fatal("immutable denial rows changed", count, err)
	}
	if err := pool.Raw().QueryRow(ctx, `SELECT encrypted_payload FROM identity_impersonation.denials WHERE tenant_id=$1 AND grant_id=$2`, args[:2]...).Scan(&retained); err != nil || !reflect.DeepEqual(retained, args[11]) {
		t.Fatal("immutable denial payload changed", err)
	}
}

func TestImpersonationDenialFencesExactLegacyWriters(t *testing.T) {
	ctx, pool := newImpersonationStorageDatabase(t)
	installDenialMigrationTestStorage(t, ctx, pool)
	denied, otherGrant := storageTestGrant(1), storageTestGrant(2)
	otherTenant := denied
	otherTenant.tenant = "tenant-b"
	for _, grant := range []grantRecord{denied, otherGrant, otherTenant} {
		if _, err := pool.Raw().Exec(ctx, grantInsertSQL, grantInsertArgs(grant)...); err != nil {
			t.Fatal(err)
		}
	}
	args := denialMigrationTestArgs(denied)
	if _, err := pool.Raw().Exec(ctx, denialMigrationTestInsertSQL, args...); err != nil {
		t.Fatal(err)
	}
	_, err := pool.Raw().Exec(ctx, grantApproveSQL, grantApprovalArgs(denied, storageTestApproval(denied))...)
	assertRevocationSQLState(t, err, "23514")
	_, err = pool.Raw().Exec(ctx, revocationInsertSQL, revocationTestArgs(denied, 1)...)
	assertRevocationSQLState(t, err, "23514")
	assertStorageState(t, ctx, pool, denied, "pending_approval", 1, 0)
	var count int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity_impersonation.revocations WHERE tenant_id=$1 AND grant_id=$2`, args[:2]...).Scan(&count); err != nil || count != 0 {
		t.Fatal("legacy revocation superseded a denial", count, err)
	}
	var retained []byte
	if err := pool.Raw().QueryRow(ctx, `SELECT encrypted_payload FROM identity_impersonation.denials WHERE tenant_id=$1 AND grant_id=$2`, args[:2]...).Scan(&retained); err != nil || !reflect.DeepEqual(retained, args[11]) {
		t.Fatal("legacy writers changed retained denial", err)
	}
	for _, grant := range []grantRecord{otherGrant, otherTenant} {
		if tag, err := pool.Raw().Exec(ctx, grantApproveSQL, grantApprovalArgs(grant, storageTestApproval(grant))...); err != nil || tag.RowsAffected() != 1 {
			t.Fatal("foreign denial blocked unrelated legacy approval", err)
		}
		if tag, err := pool.Raw().Exec(ctx, revocationInsertSQL, revocationTestArgs(grant, 2)...); err != nil || tag.RowsAffected() != 1 {
			t.Fatal("foreign denial blocked unrelated legacy revocation", err)
		}
	}
}

const denialMigrationTestInsertSQL = `INSERT INTO identity_impersonation.denials
 (tenant_id,grant_id,command_id,denier_id,requester_id,target_id,request_digest,
 policy_id,policy_version,before_version,after_version,encrypted_payload,denied_at)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::text::numeric,$10,$11,$12,$13)`

func denialMigrationTestArgs(grant grantRecord) []any {
	return []any{string(grant.tenant), string(grant.id), string(storageTestApproval(grant).commandID),
		"denier", string(grant.requester), string(grant.target), grant.digest[:], "policy", "18446744073709551615",
		int16(1), int16(2), []byte("opaque-encrypted-denial-envelope"), grant.requestedAt.Add(time.Minute)}
}

func installDenialMigrationTestStorage(t *testing.T, ctx context.Context, pool *database.Pool) {
	t.Helper()
	history, err := (DenialMigrationSource{}).Load(ctx)
	if err != nil || len(history) != 9 {
		t.Fatal("complete denial migration history required", err)
	}
	for _, migration := range history {
		applyRevocationMigration(t, ctx, pool, migration.UpSQL())
	}
}

func assertDenialMigrationNotReady(t *testing.T, ctx context.Context, pool *database.Pool) {
	t.Helper()
	var ready bool
	err := pool.Raw().QueryRow(ctx, `SELECT identity_impersonation.denial_ready()`).Scan(&ready)
	assertRevocationSQLState(t, err, "42883")
}

func denialMigrationHistorySnapshot(t *testing.T, ctx context.Context, pool *database.Pool) []string {
	t.Helper()
	var snapshot []string
	for _, table := range []string{"grants", "approvals", "active_grants", "revocations", "stop_proofs", "stops"} {
		var retained string
		if err := pool.Raw().QueryRow(ctx, `SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY tenant_id,grant_id),'[]'::jsonb)::text FROM identity_impersonation.`+table+` r`).Scan(&retained); err != nil {
			t.Fatal(err)
		}
		snapshot = append(snapshot, retained)
	}
	return snapshot
}
