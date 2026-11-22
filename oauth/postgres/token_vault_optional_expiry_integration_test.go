//go:build integration

package postgres

import (
	"bytes"
	"strings"
	"testing"

	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/jackc/pgx/v5/pgtype"
)

// This checks installed/populated SQL history and nullable scalar storage, not
// provider authentication. The native consumer separately supplies real token
// custody through the canonical link Work and session owners.
func TestRPTokenVaultOptionalExpiryPopulatedForwardHistoryAndMixedRows(t *testing.T) {
	ctx, db := rpMigrationDatabase(t)
	prerequisites, err := (kernel.AccountMigrationSource{Base: kernel.CredentialMigrationSource{Base: kernel.MigrationSource{}, Version: 30}, Version: 31}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, migration := range prerequisites {
		if migration.Version() > 9 {
			if _, err := db.Exec(ctx, migration.UpSQL()); err != nil {
				t.Fatal("account prerequisite", err)
			}
		}
	}
	oldRP, err := (MigrationSource{Schema: "oauth_rp", Version: 100}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, oldRP[0].UpSQL()); err != nil {
		t.Fatal(err)
	}
	oldVault, err := (TokenVaultMigrationSource{Schema: "oauth_rp", Version: 101}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, oldVault[0].UpSQL()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('tenant-a','user-a','active',7)`); err != nil {
		t.Fatal(err)
	}
	origin := bytes.Repeat([]byte{61}, 16)
	if _, err := db.Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,'tenant-a','identity.account.link-token',$2,1,$3)`, origin, bytes.Repeat([]byte{1}, 32), []byte{1}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,'tenant-a','identity.account.link-token')`, origin); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO identity.accounts(tenant_id,user_id,account_id,provider,issuer,subject,subject_key,version,social_link_version,linked) SELECT 'tenant-a','user-a','account-'||n,'github','https://github.com',n::text,sha256(convert_to(octet_length('github')::text||':github'||octet_length('https://github.com')::text||':https://github.com'||octet_length(n::text)::text||':'||n::text,'UTF8')),1,1,true FROM generate_series(1,1000) n`); err != nil {
		t.Fatal("populated account fixture", err)
	}
	statement := strings.ReplaceAll(rpTokenVaultInsert, "@schema@", rpQuotedSchema("oauth_rp"))
	args := []any{"tenant-a", "user-a", "account-1", "github", "https://github.com", "registered-client", uint64(1), uint64(1), uint64(1), "read:user user:email", "read:user user:email", true, int64(1794650400), 123456789, int64(1794650460), 123456789, []byte{1, 2, 3}, origin}
	if _, err := db.Exec(ctx, statement, args...); err != nil {
		t.Fatal("original positive expiry writer", err)
	}
	var original string
	if db.QueryRow(ctx, `SELECT row_to_json(t)::text FROM oauth_rp.token_sets t WHERE account_id='account-1'`).Scan(&original) != nil {
		t.Fatal("original row snapshot")
	}
	absent := append([]any(nil), args...)
	absent[2], absent[14], absent[15] = "account-2", nil, nil
	if _, err := db.Exec(ctx, statement, absent...); err == nil {
		t.Fatal("old installed schema unexpectedly permits absent expiry")
	}
	history, err := (TokenVaultOptionalExpiryMigrationSource{Schema: "oauth_rp", Version: 102}).Load(ctx)
	if err != nil || len(history) != 2 {
		t.Fatal("forward history", err)
	}
	for index, migration := range history {
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, migration.UpSQL()); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal("phased forward migration", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		var validated bool
		if db.QueryRow(ctx, `SELECT convalidated FROM pg_constraint WHERE conrelid='oauth_rp.token_sets'::regclass AND conname='token_sets_optional_expiry_pair'`).Scan(&validated) != nil || validated != (index == 1) {
			t.Fatal("pair check was not separately installed/validated")
		}
	}
	var after string
	if db.QueryRow(ctx, `SELECT row_to_json(t)::text FROM oauth_rp.token_sets t WHERE account_id='account-1'`).Scan(&after) != nil || after != original {
		t.Fatal("forward migration rewrote populated history")
	}
	// Exercise the unchanged insert shape with the new actual NULL parameter
	// class in a populated table. EXPLAIN ANALYZE writes only inside this owned
	// transaction, which is rolled back before the ordinary write assertion.
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := tx.Query(ctx, "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) "+statement, absent...)
	if err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal("nullable insert query plan", err)
	}
	var plan string
	if !rows.Next() || rows.Scan(&plan) != nil {
		rows.Close()
		_ = tx.Rollback(ctx)
		t.Fatal("insert plan missing")
	}
	rows.Close()
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan, `"Operation": "Insert"`) {
		t.Fatal("wrong query plan")
	}
	t.Log("nullable insert plan", plan)
	if _, err := db.Exec(ctx, statement, absent...); err != nil {
		t.Fatal("new absent-expiry writer", err)
	}
	var seconds pgtype.Int8
	var nanos pgtype.Int4
	if db.QueryRow(ctx, `SELECT access_expires_at_seconds,access_expires_at_nanoseconds FROM oauth_rp.token_sets WHERE account_id='account-2'`).Scan(&seconds, &nanos) != nil || seconds.Valid || nanos.Valid {
		t.Fatal("absent expiry was stored as a fabricated timestamp")
	}
	if db.QueryRow(ctx, `SELECT access_expires_at_seconds,access_expires_at_nanoseconds FROM oauth_rp.token_sets WHERE account_id='account-1'`).Scan(&seconds, &nanos) != nil || !seconds.Valid || !nanos.Valid || seconds.Int64 != args[14] || int(nanos.Int32) != args[15] {
		t.Fatal("positive expiry reader lost original exact timestamp")
	}
	for _, pair := range [][2]any{{nil, 0}, {int64(1794650460), nil}, {int64(0), 0}, {int64(1794650400), 123456789}, {int64(1794650460), 1}} {
		bad := append([]any(nil), args...)
		bad[2], bad[14], bad[15] = "account-3", pair[0], pair[1]
		if _, err := db.Exec(ctx, statement, bad...); err == nil {
			t.Fatal("half-null or malformed positive expiry escaped existing checks")
		}
	}
	args[2] = "account-3"
	if _, err := db.Exec(ctx, statement, args...); err != nil {
		t.Fatal("old positive writer no longer compatible", err)
	}
	var count int
	if db.QueryRow(ctx, `SELECT count(*) FROM oauth_rp.token_sets`).Scan(&count) != nil || count != 3 {
		t.Fatal("query-plan rollback or mixed writer changed custody cardinality")
	}
}
