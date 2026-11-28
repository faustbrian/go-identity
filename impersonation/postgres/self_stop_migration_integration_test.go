//go:build integration

package impersonationpostgres

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestImpersonationSelfStopMigrationLoad(t *testing.T) {
	ctx := context.Background()
	legacy, err := (RevocationMigrationSource{}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	history, err := (SelfStopMigrationSource{}).Load(ctx)
	if err != nil || len(history) != 6 {
		t.Fatal("self-stop must append one forward migration", err)
	}
	for index, migration := range history {
		if uint64(migration.Version()) != uint64(index+1) || migration.DownSQL() != "" {
			t.Fatal("self-stop history must remain ordered and forward-only")
		}
		if index < len(legacy) && (migration.Checksum() != legacy[index].Checksum() || migration.UpSQL() != legacy[index].UpSQL()) {
			t.Fatal("self-stop changed installed v1-v5 history")
		}
	}
	var invalid identity.InvalidInputError
	if _, err := (SelfStopMigrationSource{}).Load(nil); !errors.As(err, &invalid) {
		t.Fatal("nil migration context accepted", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := (SelfStopMigrationSource{}).Load(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled migration context accepted", err)
	}
	history[0] = history[5]
	fresh, err := (SelfStopMigrationSource{}).Load(ctx)
	if err != nil || fresh[0].Version() != 1 {
		t.Fatal("migration history shares caller-owned storage", err)
	}
}

func TestImpersonationSelfStopMigrationPreservesPopulatedHistory(t *testing.T) {
	ctx, pool := newImpersonationStorageDatabase(t)
	installRevocationStorage(t, ctx, pool)
	pending, active, revoked := storageTestGrant(1), storageTestGrant(2), storageTestGrant(3)
	for _, grant := range []grantRecord{pending, active, revoked} {
		if _, err := pool.Raw().Exec(ctx, grantInsertSQL, grantInsertArgs(grant)...); err != nil {
			t.Fatal(err)
		}
	}
	approval := storageTestApproval(active)
	if _, err := pool.Raw().Exec(ctx, grantApproveSQL, grantApprovalArgs(active, approval)...); err != nil {
		t.Fatal(err)
	}
	activation := activationStorageTestRow(t, active, approval)
	if _, err := pool.Raw().Exec(ctx, activationInsertSQL, activationInsertArgs(activation)...); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, revocationTestInsertSQL, revocationTestArgs(revoked, 1)...); err != nil {
		t.Fatal(err)
	}
	snapshot := func() []string {
		t.Helper()
		var rows []string
		for _, table := range []string{"grants", "approvals", "active_grants", "revocations"} {
			var retained string
			if err := pool.Raw().QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(r) ORDER BY tenant_id,grant_id)::text FROM identity_impersonation.`+table+` r`).Scan(&retained); err != nil {
				t.Fatal(err)
			}
			rows = append(rows, retained)
		}
		return rows
	}
	before := snapshot()
	history, err := (SelfStopMigrationSource{}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Existing-table locks would make any accidental v6 DDL or backfill fail.
	locked, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = locked.Rollback(ctx) }()
	if _, err := locked.Exec(ctx, `LOCK TABLE identity_impersonation.grants, identity_impersonation.approvals, identity_impersonation.active_grants, identity_impersonation.revocations IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	applyRevocationMigration(t, ctx, pool, history[5].UpSQL())
	if err := locked.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if after := snapshot(); !reflect.DeepEqual(before, after) {
		t.Fatal("self-stop installation changed retained history")
	}
	for _, table := range []string{"stop_proofs", "stops"} {
		var count int
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity_impersonation.`+table).Scan(&count); err != nil || count != 0 {
			t.Fatal("self-stop installation generated lifecycle effects", table, count, err)
		}
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM pg_constraint WHERE conrelid=$1::regclass AND contype='f'`, "identity_impersonation."+table).Scan(&count); err != nil || count != 0 {
			t.Fatal("new self-stop table locks existing authority through a foreign key", table, err)
		}
	}
}

func TestImpersonationSelfStopStorageConstraintsAndImmutability(t *testing.T) {
	ctx, pool := newImpersonationStorageDatabase(t)
	history, err := (SelfStopMigrationSource{}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, migration := range history {
		applyRevocationMigration(t, ctx, pool, migration.UpSQL())
	}
	grant := storageTestGrant(1)
	for _, table := range []struct {
		name    string
		insert  string
		args    func(grantRecord) []any
		invalid []struct {
			name  string
			index int
			value any
		}
	}{
		{
			name: "stop_proofs", insert: selfStopProofTestInsertSQL, args: selfStopProofTestArgs,
			invalid: []struct {
				name  string
				index int
				value any
			}{
				{"empty-tenant", 0, ""}, {"spaced-tenant", 0, "tenant a"},
				{"invalid-grant", 1, "invalid"}, {"zero-grant", 1, "AAAAAAAAAAAAAAAAAAAAAA"},
				{"noncanonical-grant", 1, "AAAAAAAAAAAAAAAAAAAAAB"},
				{"invalid-activation-command", 2, "invalid"}, {"zero-activation-command", 2, "AAAAAAAAAAAAAAAAAAAAAA"},
				{"activation-as-grant", 2, string(grant.id)},
				{"zero-key", 3, int64(0)}, {"overflow-key", 3, int64(4294967296)},
				{"short-digest", 4, []byte{1}}, {"long-digest", 4, make([]byte, 33)},
			},
		},
		{
			name: "stops", insert: selfStopTestInsertSQL, args: selfStopTestArgs,
			invalid: []struct {
				name  string
				index int
				value any
			}{
				{"empty-tenant", 0, ""}, {"invalid-grant", 1, "invalid"}, {"zero-grant", 1, "AAAAAAAAAAAAAAAAAAAAAA"},
				{"invalid-command", 2, "invalid"}, {"zero-command", 2, "AAAAAAAAAAAAAAAAAAAAAA"},
				{"command-as-grant", 2, string(grant.id)},
				{"invalid-activation-command", 3, "invalid"}, {"zero-activation-command", 3, "AAAAAAAAAAAAAAAAAAAAAA"},
				{"activation-as-grant", 3, string(grant.id)}, {"activation-as-command", 3, selfStopTestArgs(grant)[2]},
				{"empty-actor", 4, ""}, {"empty-target", 5, ""}, {"target-as-actor", 5, string(grant.requester)},
				{"empty-policy", 6, ""}, {"zero-policy-version", 7, "0"}, {"overflow-policy-version", 7, "18446744073709551616"},
				{"infinite-time", 8, pgtype.Timestamptz{InfinityModifier: pgtype.Infinity, Valid: true}},
				{"before-portable-time", 8, time.Date(0, 12, 31, 23, 59, 59, 0, time.UTC)},
				{"after-portable-time", 8, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)},
			},
		},
	} {
		t.Run(table.name, func(t *testing.T) {
			for _, invalid := range table.invalid {
				t.Run(invalid.name, func(t *testing.T) {
					args := table.args(grant)
					args[invalid.index] = invalid.value
					_, err := pool.Raw().Exec(ctx, table.insert, args...)
					assertRevocationSQLState(t, err, "23514")
				})
			}
			args := table.args(grant)
			if _, err := pool.Raw().Exec(ctx, table.insert, args...); err != nil {
				t.Fatal("valid retained self-stop row rejected", err)
			}
			_, err := pool.Raw().Exec(ctx, table.insert, args...)
			assertRevocationSQLState(t, err, "23505")
			conflict := table.args(storageTestGrant(2))
			conflict[2] = args[2]
			_, err = pool.Raw().Exec(ctx, table.insert, conflict...)
			assertRevocationSQLState(t, err, "23505")
			otherTenant := grant
			otherTenant.tenant = "tenant-b"
			if _, err := pool.Raw().Exec(ctx, table.insert, table.args(otherTenant)...); err != nil {
				t.Fatal("self-stop uniqueness leaked across tenants", err)
			}
			for _, statement := range []string{
				`UPDATE identity_impersonation.` + table.name + ` SET tenant_id=tenant_id WHERE tenant_id=$1 AND grant_id=$2`,
				`DELETE FROM identity_impersonation.` + table.name + ` WHERE tenant_id=$1 AND grant_id=$2`,
			} {
				_, err := pool.Raw().Exec(ctx, statement, args[:2]...)
				assertRevocationSQLState(t, err, "23514")
			}
			var count int
			if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity_impersonation.`+table.name).Scan(&count); err != nil || count != 2 {
				t.Fatal("immutable self-stop rows changed", count, err)
			}
		})
	}
}

const selfStopProofTestInsertSQL = `INSERT INTO identity_impersonation.stop_proofs
 (tenant_id,grant_id,activation_command_id,csrf_key,csrf_digest) VALUES($1,$2,$3,$4,$5)`

func selfStopProofTestArgs(grant grantRecord) []any {
	return []any{string(grant.tenant), string(grant.id), string(storageTestApproval(grant).commandID), int64(4294967295), make([]byte, 32)}
}

const selfStopTestInsertSQL = `INSERT INTO identity_impersonation.stops
 (tenant_id,grant_id,command_id,activation_command_id,actor_id,target_id,policy_id,policy_version,stopped_at)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8::text::numeric,$9)`

func selfStopTestArgs(grant grantRecord) []any {
	return []any{string(grant.tenant), string(grant.id), string(storageTestApproval(grant).commandID), string(storageTestGrant(100).id), string(grant.requester), string(grant.target), "policy", "18446744073709551615", grant.requestedAt.Add(time.Minute)}
}
