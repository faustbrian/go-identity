//go:build integration

package impersonationpostgres

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestImpersonationRevocationMigrationLoad(t *testing.T) {
	ctx := context.Background()
	legacy, err := (ActivationMigrationSource{}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	history, err := (RevocationMigrationSource{}).Load(ctx)
	if err != nil || len(history) != 5 {
		t.Fatal("revocation must append three forward migrations", err)
	}
	for index, migration := range history {
		if uint64(migration.Version()) != uint64(index+1) || migration.DownSQL() != "" {
			t.Fatal("revocation history must remain ordered and forward-only")
		}
		if index < len(legacy) && (migration.Checksum() != legacy[index].Checksum() || migration.UpSQL() != legacy[index].UpSQL()) {
			t.Fatal("revocation changed installed v1/v2 history")
		}
	}
	var invalid identity.InvalidInputError
	if _, err := (RevocationMigrationSource{}).Load(nil); !errors.As(err, &invalid) {
		t.Fatal("nil migration context accepted", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := (RevocationMigrationSource{}).Load(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled migration context accepted", err)
	}
}

func TestImpersonationRevocationMigrationPreservesPopulatedHistory(t *testing.T) {
	for _, installedVersion := range []int{1, 2} {
		t.Run("v"+strconv.Itoa(installedVersion), func(t *testing.T) {
			ctx, pool := newImpersonationStorageDatabase(t)
			history, err := (RevocationMigrationSource{}).Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			for _, migration := range history[:installedVersion] {
				applyRevocationMigration(t, ctx, pool, migration.UpSQL())
			}
			pending, approved := storageTestGrant(1), storageTestGrant(2)
			for _, grant := range []grantRecord{pending, approved} {
				if _, err := pool.Raw().Exec(ctx, grantInsertSQL, grantInsertArgs(grant)...); err != nil {
					t.Fatal(err)
				}
			}
			approval := storageTestApproval(approved)
			if _, err := pool.Raw().Exec(ctx, grantApproveSQL, grantApprovalArgs(approved, approval)...); err != nil {
				t.Fatal(err)
			}
			active := activationStorageTestRow(t, approved, approval)
			if installedVersion == 2 {
				if _, err := pool.Raw().Exec(ctx, activationInsertSQL, activationInsertArgs(active)...); err != nil {
					t.Fatal(err)
				}
			}
			for _, migration := range history[installedVersion:] {
				applyRevocationMigration(t, ctx, pool, migration.UpSQL())
				if migration.Version() < 5 {
					var ready bool
					err := pool.Raw().QueryRow(ctx, `SELECT identity_impersonation.revocation_ready()`).Scan(&ready)
					assertRevocationSQLState(t, err, "42883")
				}
			}
			var ready bool
			if err := pool.Raw().QueryRow(ctx, `SELECT identity_impersonation.revocation_ready()`).Scan(&ready); err != nil || !ready {
				t.Fatal("final fence did not publish readiness", err)
			}
			assertStorageState(t, ctx, pool, pending, "pending_approval", 1, 0)
			assertStorageState(t, ctx, pool, approved, "approved", 2, 1)
			approved.version = 2
			for _, grant := range []grantRecord{pending, approved} {
				observed, err := observeGrant(ctx, pool, grant.tenant, grant.id)
				if err != nil || !sameStorageGrant(observed, grant) {
					t.Fatal("revocation migration rewrote retained intent", err)
				}
			}
			var retained []byte
			if err := pool.Raw().QueryRow(ctx, `SELECT encrypted_payload FROM identity_impersonation.approvals WHERE tenant_id=$1 AND grant_id=$2`, string(approved.tenant), string(approved.id)).Scan(&retained); err != nil || string(retained) != string(approval.payload) {
				t.Fatal("revocation migration rewrote retained approval", err)
			}
			if installedVersion == 2 {
				observed, err := readActivation(ctx, pool, active.tenant, active.derivedDigest)
				if err != nil || !reflect.DeepEqual(active, observed) {
					t.Fatal("revocation migration rewrote active authority", err)
				}
			}
			var count int
			if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity_impersonation.revocations`).Scan(&count); err != nil || count != 0 {
				t.Fatal("migration generated terminal effects", err)
			}
		})
	}
}

func TestImpersonationRevocationFencesExactLegacyWriters(t *testing.T) {
	ctx, pool := newImpersonationStorageDatabase(t)
	installRevocationStorage(t, ctx, pool)
	pending := storageTestGrant(1)
	otherGrant := storageTestGrant(2)
	otherTenant := pending
	otherTenant.tenant = "tenant-b"
	approved := storageTestGrant(3)
	legacyActive := storageTestGrant(4)
	for _, grant := range []grantRecord{pending, otherGrant, otherTenant, approved, legacyActive} {
		if _, err := pool.Raw().Exec(ctx, grantInsertSQL, grantInsertArgs(grant)...); err != nil {
			t.Fatal(err)
		}
	}
	for _, grant := range []grantRecord{approved, legacyActive} {
		if _, err := pool.Raw().Exec(ctx, grantApproveSQL, grantApprovalArgs(grant, storageTestApproval(grant))...); err != nil {
			t.Fatal("nonrevoked legacy approval rejected", err)
		}
	}
	for _, grant := range []grantRecord{pending, approved} {
		before := int16(1)
		if grant.id == approved.id {
			before = 2
		}
		if _, err := pool.Raw().Exec(ctx, revocationTestInsertSQL, revocationTestArgs(grant, before)...); err != nil {
			t.Fatal(err)
		}
	}
	_, err := pool.Raw().Exec(ctx, grantApproveSQL, grantApprovalArgs(pending, storageTestApproval(pending))...)
	assertRevocationSQLState(t, err, "23514")
	assertStorageState(t, ctx, pool, pending, "pending_approval", 1, 0)
	for _, grant := range []grantRecord{otherGrant, otherTenant} {
		if tag, err := pool.Raw().Exec(ctx, grantApproveSQL, grantApprovalArgs(grant, storageTestApproval(grant))...); err != nil || tag.RowsAffected() != 1 {
			t.Fatal("foreign marker blocked unrelated legacy approval", err)
		}
	}
	blocked := activationStorageTestRow(t, approved, storageTestApproval(approved))
	_, err = pool.Raw().Exec(ctx, activationInsertSQL, activationInsertArgs(blocked)...)
	assertRevocationSQLState(t, err, "23514")
	for index, grant := range []grantRecord{otherGrant, otherTenant, legacyActive} {
		row := activationStorageTestRow(t, grant, storageTestApproval(grant))
		row.commandID = identity.CommandID(storageTestGrant(uint64(100 + index)).id)
		row.derivedDigest.Sum[0] = byte(100 + index)
		if tag, err := pool.Raw().Exec(ctx, activationInsertSQL, activationInsertArgs(row)...); err != nil || tag.RowsAffected() != 1 {
			t.Fatal("foreign marker blocked unrelated legacy activation", err)
		}
	}
	for _, statement := range []string{
		`UPDATE identity_impersonation.revocations SET encrypted_payload=$3 WHERE tenant_id=$1 AND grant_id=$2`,
		`DELETE FROM identity_impersonation.revocations WHERE tenant_id=$1 AND grant_id=$2 AND $3::bytea IS NOT NULL`,
	} {
		_, err := pool.Raw().Exec(ctx, statement, string(pending.tenant), string(pending.id), []byte("replacement"))
		assertRevocationSQLState(t, err, "23514")
	}
	var count int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity_impersonation.revocations`).Scan(&count); err != nil || count != 2 {
		t.Fatal("immutable terminal marker changed", err)
	}
}

func TestImpersonationRevocationStorageConstraints(t *testing.T) {
	ctx, pool := newImpersonationStorageDatabase(t)
	installRevocationStorage(t, ctx, pool)
	grant := storageTestGrant(1)
	for _, invalid := range []struct {
		name  string
		index int
		value any
	}{
		{"empty-tenant", 0, ""},
		{"invalid-grant", 1, "not-an-opaque-id"},
		{"zero-grant", 1, "AAAAAAAAAAAAAAAAAAAAAA"},
		{"invalid-command", 2, "not-an-opaque-id"},
		{"reused-command", 2, string(grant.id)},
		{"target-as-revoker", 3, string(grant.target)},
		{"target-as-requester", 4, string(grant.target)},
		{"short-digest", 6, []byte{1}},
		{"empty-policy", 7, ""},
		{"zero-policy-version", 8, "0"},
		{"overflow-policy-version", 8, "18446744073709551616"},
		{"before-zero", 9, int16(0)},
		{"before-terminal", 9, int16(4)},
		{"after-not-next", 10, int16(3)},
		{"empty-payload", 11, []byte{}},
		{"oversized-payload", 11, make([]byte, 65537)},
		{"infinite-time", 12, pgtype.Timestamptz{InfinityModifier: pgtype.Infinity, Valid: true}},
		{"before-portable-time", 12, time.Date(0, 12, 31, 23, 59, 59, 0, time.UTC)},
		{"after-portable-time", 12, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)},
	} {
		t.Run(invalid.name, func(t *testing.T) {
			args := revocationTestArgs(grant, 1)
			args[invalid.index] = invalid.value
			_, err := pool.Raw().Exec(ctx, revocationTestInsertSQL, args...)
			assertRevocationSQLState(t, err, "23514")
		})
	}
	for _, before := range []int16{1, 2, 3} {
		selected := storageTestGrant(uint64(before))
		args := revocationTestArgs(selected, before)
		args[3] = string(selected.requester)
		if _, err := pool.Raw().Exec(ctx, revocationTestInsertSQL, args...); err != nil {
			t.Fatal("requester may revoke through every supported transition", err)
		}
	}
	_, err := pool.Raw().Exec(ctx, revocationTestInsertSQL, revocationTestArgs(grant, 1)...)
	assertRevocationSQLState(t, err, "23505")
	otherGrant := storageTestGrant(4)
	args := revocationTestArgs(otherGrant, 1)
	args[2] = revocationTestArgs(grant, 1)[2]
	_, err = pool.Raw().Exec(ctx, revocationTestInsertSQL, args...)
	assertRevocationSQLState(t, err, "23505")
	otherTenant := grant
	otherTenant.tenant = "tenant-b"
	if _, err := pool.Raw().Exec(ctx, revocationTestInsertSQL, revocationTestArgs(otherTenant, 1)...); err != nil {
		t.Fatal("terminal uniqueness leaked across tenants", err)
	}
}

const revocationTestInsertSQL = `INSERT INTO identity_impersonation.revocations
 (tenant_id,grant_id,command_id,revoker_id,requester_id,target_id,request_digest,
 policy_id,policy_version,before_version,after_version,encrypted_payload,revoked_at)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::text::numeric,$10,$11,$12,$13)`

func revocationTestArgs(grant grantRecord, before int16) []any {
	command := storageTestApproval(grant).commandID
	return []any{string(grant.tenant), string(grant.id), string(command), "revoker", string(grant.requester), string(grant.target), grant.digest[:], "policy", "18446744073709551615", before, before + 1, []byte("opaque-encrypted-revocation-envelope"), grant.requestedAt.Add(time.Minute)}
}

func installRevocationStorage(t *testing.T, ctx context.Context, pool *database.Pool) {
	t.Helper()
	history, err := (RevocationMigrationSource{}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, migration := range history {
		applyRevocationMigration(t, ctx, pool, migration.UpSQL())
	}
}

func applyRevocationMigration(t *testing.T, ctx context.Context, pool *database.Pool, sql string) {
	t.Helper()
	tx, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, sql); err != nil {
		t.Fatal("apply one bounded revocation migration", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func assertRevocationSQLState(t *testing.T, err error, code string) {
	t.Helper()
	var databaseError *pgconn.PgError
	if !errors.As(err, &databaseError) || databaseError.Code != code {
		t.Fatal("unexpected revocation SQL outcome", code, err)
	}
}
