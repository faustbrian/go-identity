//go:build integration

package postgres

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// This fixture proves storage installation/constraints only. Seeded command
// metadata and ciphertext-shaped bytes are not authentication or encryption
// proof; actual issuance and AEAD contracts have their own real-owner tests.
func rpMigrationDatabase(t *testing.T) (context.Context, *pgx.Conn) {
	t.Helper()
	dsn := os.Getenv("IDENTITY_POSTGRES_TEST_DSN")
	config, err := pgx.ParseConfig(dsn)
	if dsn == "" || err != nil || config.Host != "127.0.0.1" || config.Database != "identity_test" {
		t.Fatal("explicit disposable loopback identity_test required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("disposable PostgreSQL unavailable")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := admin.Close(cleanup); err != nil {
			t.Error("admin cleanup failed")
		}
	})
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	name := "oauth_rp_" + string(id)
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatal("owned database creation failed")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+quoted); err != nil {
			t.Error("owned database cleanup failed")
		}
	})
	config.Database = name
	db, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("owned database connection failed")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := db.Close(cleanup); err != nil {
			t.Error("database connection cleanup failed")
		}
	})
	history, err := (kernel.MigrationSource{}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, migration := range history {
		if _, err := db.Exec(ctx, migration.UpSQL()); err != nil {
			t.Fatal("kernel migration failed")
		}
	}
	return ctx, db
}

func TestRPTransactionForwardStorage(t *testing.T) {
	ctx, db := rpMigrationDatabase(t)
	if _, err := db.Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('tenant-a','original-user','active',7)`); err != nil {
		t.Fatal("populated predecessor seed failed")
	}
	history, err := (MigrationSource{Schema: "oauth_rp", Version: 100}).Load(ctx)
	if err != nil || len(history) != 1 {
		t.Fatal("RP forward history unavailable", err)
	}
	if _, err := db.Exec(ctx, history[0].UpSQL()); err != nil {
		t.Fatal("RP install failed", err)
	}
	var version string
	if err := db.QueryRow(ctx, `SELECT version::text FROM identity.users WHERE tenant_id='tenant-a' AND user_id='original-user'`).Scan(&version); err != nil || version != "7" {
		t.Fatal("RP installation changed existing identity")
	}
	for index, operation := range []string{"identity.account.link-start", "identity.oauth.signin-start"} {
		id, fingerprint := bytes.Repeat([]byte{byte(index + 1)}, 16), bytes.Repeat([]byte{byte(index + 1)}, 32)
		if _, err := db.Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,'tenant-a',$2,$3,1,$4)`, id, operation, fingerprint, []byte{1}); err != nil {
			t.Fatal("command claim fixture failed")
		}
		if _, err := db.Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,'tenant-a',$2)`, id, operation); err != nil {
			t.Fatal("command journal fixture failed")
		}
		statement := rpInsertTransaction
		if index == 1 {
			statement = strings.Replace(statement, "'original-user',NULL,'original-session',1", "NULL,'original-preauth',NULL,NULL", 1)
		}
		for name, alter := range map[string]func(string) string{
			"mixed subject": func(s string) string {
				if index == 0 {
					return strings.Replace(s, "'original-user',NULL", "'original-user','foreign-preauth'", 1)
				}
				return strings.Replace(s, "NULL,'original-preauth'", "'original-user','original-preauth'", 1)
			},
			"foreign tenant":         func(s string) string { return strings.Replace(s, "VALUES('tenant-a'", "VALUES('tenant-b'", 1) },
			"foreign origin command": func(s string) string { return strings.Replace(s, "$1,$2,", "set_byte($1::bytea,0,99),$2,", 1) },
			"non-query mode":         func(s string) string { return strings.Replace(s, "'query'", "'form_post'", 1) },
			"extended expiry":        func(s string) string { return strings.Replace(s, "12:10:00Z", "12:10:01Z", 1) },
			"no verifier ciphertext": func(s string) string { return strings.Replace(s, "$4,$4,$4", "''::bytea,$4,$4", 1) },
			"empty state commitment": func(s string) string {
				return strings.Replace(s, "1,$3,1,$3", "1,decode(repeat('00',32),'hex'),1,$3", 1)
			},
		} {
			t.Run(operation+"/"+name, func(t *testing.T) {
				_, err := db.Exec(ctx, alter(statement), id, operation, fingerprint, bytes.Repeat([]byte{5}, 64))
				var failure *pgconn.PgError
				if !errors.As(err, &failure) || failure.Code != "23514" && failure.Code != "23503" {
					t.Fatalf("malformed RP custody was not constraint-rejected: %T", err)
				}
			})
		}
		if _, err := db.Exec(ctx, statement, id, operation, fingerprint, bytes.Repeat([]byte{5}, 64)); err != nil {
			t.Fatal("valid original RP storage denied", err)
		}
		if _, err := db.Exec(ctx, `DELETE FROM identity.commands WHERE command_id=$1`, id); err == nil {
			t.Fatal("RP custody allowed its original journal to be erased")
		}
		if _, err := db.Exec(ctx, `UPDATE oauth_rp.transactions SET pkce_ciphertext=NULL WHERE origin_command_id=$1`, id); err == nil {
			t.Fatal("partial undocumented secret erasure admitted")
		}
		if _, err := db.Exec(ctx, `UPDATE oauth_rp.transactions SET pkce_ciphertext=NULL,state_proof_ciphertext=NULL,secrets_erased_at=expires_at WHERE origin_command_id=$1`, id); err != nil {
			t.Fatal("terminal secret erasure denied", err)
		}
		var erased bool
		var retainedDigest []byte
		if err := db.QueryRow(ctx, `SELECT pkce_ciphertext IS NULL AND state_proof_ciphertext IS NULL AND secrets_erased_at IS NOT NULL,state_digest FROM oauth_rp.transactions WHERE origin_command_id=$1`, id).Scan(&erased, &retainedDigest); err != nil || !erased || !bytes.Equal(retainedDigest, fingerprint) {
			t.Fatal("secret erasure lost immutable lookup metadata")
		}
	}
	var total, anonymous int
	if err := db.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE user_id IS NULL AND preauth_id IS NOT NULL) FROM oauth_rp.transactions`).Scan(&total, &anonymous); err != nil || total != 2 || anonymous != 1 {
		t.Fatal("RP storage fabricated anonymous user or lost original record")
	}
}

const rpInsertTransaction = `INSERT INTO oauth_rp.transactions(
 tenant_id,transaction_id,origin_command_id,operation,user_id,preauth_id,session_id,session_version,
 provider_id,configuration_version,issuer,client_id,redirect_uri,response_mode,
 state_key_version,state_digest,pkce_key_version,pkce_commitment,
 pkce_ciphertext,state_proof_ciphertext,binding_ciphertext,issued_at,expires_at,version)
 VALUES('tenant-a',encode($1::bytea,'hex'),$1,$2,'original-user',NULL,'original-session',1,
 'configured-provider',1,'https://issuer.example','configured-client','https://identity.example/v1/oauth/callback','query',
 1,$3,1,$3,$4,$4,$4,'2026-11-01T12:00:00Z','2026-11-01T12:10:00Z',1)`
