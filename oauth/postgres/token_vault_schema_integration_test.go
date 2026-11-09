//go:build integration

package postgres

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/jackc/pgx/v5/pgconn"
)

// These are actual migration/FK/transaction storage checks. The seeded account
// and command are explicitly not provider/session admission or a fabricated
// AccountLinkWork. The root callback consumer separately proves sealed-Work use.
func TestRPTokenVaultForwardStorageForeignKeysExactTimesAndRollback(t *testing.T) {
	ctx, db := rpMigrationDatabase(t)
	accountHistory, err := (kernel.AccountMigrationSource{Base: kernel.CredentialMigrationSource{Base: kernel.MigrationSource{}, Version: 30}, Version: 31}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, migration := range accountHistory {
		if migration.Version() > 9 {
			if _, err := db.Exec(ctx, migration.UpSQL()); err != nil {
				t.Fatal("account prerequisite migration failed", err)
			}
		}
	}
	rpHistory, err := (MigrationSource{Schema: "oauth_rp", Version: 100}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, rpHistory[0].UpSQL()); err != nil {
		t.Fatal("RP predecessor migration failed", err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('tenant-a','user-a','active',7)`); err != nil {
		t.Fatal("existing user fixture failed")
	}
	history, err := (TokenVaultMigrationSource{Schema: "oauth_rp", Version: 101}).Load(ctx)
	if err != nil || len(history) != 1 {
		t.Fatal("vault migration unavailable", err)
	}
	if history[0].DownSQL() != "" {
		t.Fatal("vault provides destructive downgrade")
	}
	if _, err := db.Exec(ctx, history[0].UpSQL()); err != nil {
		t.Fatal("forward vault migration failed", err)
	}
	var userVersion string
	if db.QueryRow(ctx, `SELECT version::text FROM identity.users WHERE tenant_id='tenant-a' AND user_id='user-a'`).Scan(&userVersion) != nil || userVersion != "7" {
		t.Fatal("vault migration changed existing identity")
	}
	if _, err := db.Exec(ctx, history[0].UpSQL()); err == nil {
		t.Fatal("existing vault storage was silently adopted")
	}
	s, b, tokens := rpVaultFixture(t, true)
	prepared, err := s.sealProviderTokens(ctx, b, tokens)
	if err != nil {
		t.Fatal(err)
	}
	origin := bytes.Repeat([]byte{63}, 16)
	if _, err := db.Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,'tenant-a','identity.account.link-token',$2,1,$3)`, origin, bytes.Repeat([]byte{1}, 32), []byte{1}); err != nil {
		t.Fatal("origin claim fixture failed")
	}
	if _, err := db.Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,'tenant-a','identity.account.link-token')`, origin); err != nil {
		t.Fatal("origin journal fixture failed")
	}
	statement := strings.ReplaceAll(rpTokenVaultInsert, "@schema@", rpQuotedSchema("oauth_rp"))
	args := []any{string(b.TenantID), string(b.UserID), string(b.AccountID), b.ProviderID, b.Issuer, b.ClientID, b.ConfigurationVersion, b.AccountVersion, b.SocialLinkVersion, strings.Join(prepared.RequestedScopes, " "), strings.Join(prepared.GrantedScopes, " "), prepared.ScopeReported, prepared.ReceivedAt.Unix(), prepared.ReceivedAt.Nanosecond(), prepared.AccessExpiresAt.Unix(), prepared.AccessExpiresAt.Nanosecond(), prepared.Ciphertext, origin}
	if _, err := db.Exec(ctx, statement, args...); err == nil {
		t.Fatal("vault admitted missing authoritative account")
	}
	if _, err := db.Exec(ctx, `INSERT INTO identity.accounts(tenant_id,user_id,account_id,provider,issuer,subject,subject_key,version,social_link_version,linked) VALUES($1,$2,$3,$4::text,$5::text,$6::text,sha256(convert_to(octet_length($4::text)::text||':'||$4::text||octet_length($5::text)::text||':'||$5::text||octet_length($6::text)::text||':'||$6::text,'UTF8')),$7::numeric,$8::numeric,true)`, string(b.TenantID), string(b.UserID), string(b.AccountID), b.ProviderID, b.Issuer, "provider-subject", b.AccountVersion, b.SocialLinkVersion); err != nil {
		t.Fatal("account storage fixture failed", err)
	}
	for name, mutate := range map[string]func([]any){
		"foreign owner":         func(v []any) { v[1] = "foreign-user" },
		"foreign account":       func(v []any) { v[2] = "foreign-account" },
		"foreign command":       func(v []any) { v[17] = bytes.Repeat([]byte{64}, 16) },
		"empty ciphertext":      func(v []any) { v[16] = []byte{} },
		"nanosecond corruption": func(v []any) { v[13] = 1000000000 },
		"scope expansion":       func(v []any) { v[10] = "admin" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := append([]any(nil), args...)
			mutate(changed)
			_, err := db.Exec(ctx, statement, changed...)
			var pgError *pgconn.PgError
			if !errors.As(err, &pgError) || (pgError.Code != "23503" && pgError.Code != "23514") {
				t.Fatal("invalid storage input escaped authoritative constraints")
			}
			if name == "scope expansion" && pgError.Code != "23514" {
				t.Fatal("expanded scope did not reach the server check constraint")
			}
		})
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, statement, args...); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal("provisional vault insert failed", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal("owned rollback failed")
	}
	var count int
	if db.QueryRow(ctx, `SELECT count(*) FROM oauth_rp.token_sets`).Scan(&count) != nil || count != 0 {
		t.Fatal("rollback retained provisional token custody")
	}
	if _, err := db.Exec(ctx, statement, args...); err != nil {
		t.Fatal("valid committed storage denied", err)
	}
	var receivedSeconds, expiresSeconds int64
	var receivedNanos, expiresNanos int
	var ciphertext, storedOrigin []byte
	if db.QueryRow(ctx, `SELECT received_at_seconds,received_at_nanoseconds,access_expires_at_seconds,access_expires_at_nanoseconds,token_ciphertext,origin_command_id FROM oauth_rp.token_sets WHERE tenant_id='tenant-a' AND account_id='account-a'`).Scan(&receivedSeconds, &receivedNanos, &expiresSeconds, &expiresNanos, &ciphertext, &storedOrigin) != nil || !time.Unix(receivedSeconds, int64(receivedNanos)).Equal(prepared.ReceivedAt) || !time.Unix(expiresSeconds, int64(expiresNanos)).Equal(prepared.AccessExpiresAt) || !bytes.Equal(storedOrigin, origin) {
		t.Fatal("storage changed exact original time or atomic command attribution")
	}
	prepared.Ciphertext = ciphertext
	if s.validatePreparedProviderTokens(ctx, prepared) != nil {
		t.Fatal("stored actual envelope cannot restore original custody")
	}
	if _, err := db.Exec(ctx, `DELETE FROM identity.accounts WHERE tenant_id='tenant-a' AND account_id='account-a'`); err == nil {
		t.Fatal("account deletion orphaned provider token custody")
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if _, err := db.Exec(cancelled, statement, args...); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled storage operation lost cancellation")
	}
}
