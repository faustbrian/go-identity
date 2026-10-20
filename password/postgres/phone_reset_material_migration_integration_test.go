//go:build integration

package passwordpostgres_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	passworddb "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
)

// This is storage compatibility proof through the existing runner, not proof
// of OTP, risk, password hashing, or the composed public recovery operation.
func TestPhonePasswordResetMaterialMigrationPopulatedUpgrade(t *testing.T) {
	port, file := os.Getenv("IDENTITY_REFERENCE_POSTGRES_PORT"), os.Getenv("IDENTITY_REFERENCE_PASSWORD_FILE")
	credential, err := os.ReadFile(file)
	if err != nil || file == "" || port == "" {
		t.Fatal("disposable PostgreSQL required")
	}
	u := &url.URL{Scheme: "postgres", User: url.UserPassword("postgres", strings.TrimSpace(string(credential))), Host: net.JoinHostPort("127.0.0.1", port), Path: "/postgres", RawQuery: "sslmode=disable"}
	clear(credential)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, u.String())
	if err != nil {
		t.Fatal("disposable primary unavailable")
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := admin.Close(cleanup); err != nil {
			t.Error("fixture administration cleanup failed")
		}
	}()
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal("fixture identity unavailable")
	}
	database := "phone_reset_material_" + string(id)
	quoted := pgx.Identifier{database}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatal("isolated migration database creation failed")
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+quoted); err != nil {
			t.Error("isolated migration database cleanup failed")
		}
	}()
	u.Path = "/" + database
	config, err := pgx.ParseConfig(u.String())
	if err != nil {
		t.Fatal("disposable configuration rejected")
	}
	db := stdlib.OpenDB(*config)
	defer db.Close()
	backend, err := migrationdb.New(db)
	if err != nil {
		t.Fatal("migration backend rejected")
	}
	base := kernel.CredentialReplacementMigrationSource{Base: kernel.CredentialMigrationSource{Base: kernel.StatusMigrationSource{Base: kernel.MigrationSource{}, Version: 10}, Version: 11}, Version: 12}
	runner, err := migrations.NewRunner(base, backend)
	if err != nil {
		t.Fatal("kernel history rejected")
	}
	if _, err = runner.Up(ctx); err != nil {
		t.Fatal("native kernel install failed")
	}
	owned, err := backend.ForNamespace("identity_password")
	if err != nil {
		t.Fatal("owned namespace rejected")
	}
	runner, err = migrations.NewRunner(passworddb.MigrationSource{}, owned)
	if err != nil {
		t.Fatal("predecessor password history rejected")
	}
	if _, err = runner.Up(ctx); err != nil {
		t.Fatal("predecessor password install failed")
	}
	conn, err := pgx.Connect(ctx, u.String())
	if err != nil {
		t.Fatal("native storage unavailable")
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := conn.Close(cleanup); err != nil {
			t.Error("fixture storage cleanup failed")
		}
	}()
	command := func(purpose string) []byte {
		t.Helper()
		id, err := identity.NewCommandID()
		if err != nil {
			t.Fatal("fixture command unavailable")
		}
		wire, err := base64.RawURLEncoding.Strict().DecodeString(string(id))
		if err != nil {
			t.Fatal("fixture command invalid")
		}
		if _, err = conn.Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,'tenant-a',$2,$3,1,decode('01','hex'))`, wire, purpose, make([]byte, 32)); err != nil {
			t.Fatal("fixture claim rejected")
		}
		if _, err = conn.Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,'tenant-a',$2)`, wire, purpose); err != nil {
			t.Fatal("fixture command rejected")
		}
		return wire
	}
	insert := func(cmd []byte, tenant, purpose string, before, after int64) error {
		_, err := conn.Exec(ctx, `INSERT INTO identity_password.replacements(tenant_id,command_id,purpose,user_id,credential_id,before_version,after_version,binding_digest) VALUES($1,$2,$3,'user-a','password-a',$4,$5,$6)`, tenant, cmd, purpose, before, after, make([]byte, 32))
		return err
	}
	checkCode := func(t *testing.T, err error, code string) {
		t.Helper()
		var failure *pgconn.PgError
		if !errors.As(err, &failure) || failure.Code != code {
			t.Fatalf("expected storage denial %s", code)
		}
	}
	for _, purpose := range []string{"identity.password.change", "identity.password.reset-complete"} {
		if err := insert(command(purpose), "tenant-a", purpose, 7, 8); err != nil {
			t.Fatal("predecessor replacement fixture rejected")
		}
	}
	snapshot := func(query string) string {
		t.Helper()
		var wire string
		if err := conn.QueryRow(ctx, query).Scan(&wire); err != nil {
			t.Fatal("storage snapshot unavailable")
		}
		return wire
	}
	const existingRows = `SELECT jsonb_agg(to_jsonb(r) ORDER BY command_id)::text FROM identity_password.replacements r WHERE purpose<>'identity.phone.password-reset-complete'`
	const originalLedger = `SELECT jsonb_agg(to_jsonb(r) ORDER BY version)::text FROM public.golib_migrations_identity_password r WHERE version<=8`
	beforeRows, beforeLedger := snapshot(existingRows), snapshot(originalLedger)
	const phonePurpose = "identity.phone.password-reset-complete"
	phoneCommand := command(phonePurpose)
	checkCode(t, insert(phoneCommand, "tenant-a", phonePurpose, 7, 8), "23514")
	runner, err = migrations.NewRunner(passworddb.PhonePasswordResetMigrationSource{Base: passworddb.MigrationSource{}, Version: 9}, owned)
	if err != nil {
		t.Fatal("phone suffix history rejected")
	}
	if _, err = runner.Up(ctx); err != nil {
		t.Fatal("populated phone material upgrade failed")
	}
	if err = insert(phoneCommand, "tenant-a", phonePurpose, 7, 8); err != nil {
		t.Fatal("phone reset material purpose remains rejected after upgrade")
	}
	if snapshot(existingRows) != beforeRows || snapshot(originalLedger) != beforeLedger {
		t.Fatal("upgrade changed original replacement rows or installed receipts")
	}
	for _, tc := range []struct {
		name, tenant, purpose, code string
		cmd                         []byte
		before, after               int64
	}{
		{"unknown purpose", "tenant-a", "identity.phone.unknown", "23514", command("identity.phone.unknown"), 7, 8},
		{"foreign command purpose", "tenant-a", phonePurpose, "23503", command("identity.password.change"), 7, 8},
		{"orphan command", "tenant-a", phonePurpose, "23503", make([]byte, 16), 7, 8},
		{"cross tenant", "tenant-b", phonePurpose, "23503", command(phonePurpose), 7, 8},
		{"duplicate marker", "tenant-a", phonePurpose, "23505", phoneCommand, 7, 8},
		{"non-successor version", "tenant-a", phonePurpose, "23514", command(phonePurpose), 7, 9},
		{"zero version", "tenant-a", phonePurpose, "23514", command(phonePurpose), 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkCode(t, insert(tc.cmd, tc.tenant, tc.purpose, tc.before, tc.after), tc.code)
		})
	}
	const allRows = `SELECT jsonb_agg(to_jsonb(r) ORDER BY command_id)::text FROM identity_password.replacements r`
	const allLedger = `SELECT jsonb_agg(to_jsonb(r) ORDER BY version)::text FROM public.golib_migrations_identity_password r`
	retainedRows, retainedLedger := snapshot(allRows), snapshot(allLedger)
	if _, err = runner.Up(ctx); err != nil {
		t.Fatal("phone suffix replay failed")
	}
	if snapshot(allRows) != retainedRows || snapshot(allLedger) != retainedLedger || snapshot(existingRows) != beforeRows {
		t.Fatal("replay changed material markers or migration receipts")
	}
	var count int
	if conn.QueryRow(ctx, `SELECT count(*) FROM identity_password.replacements`).Scan(&count) != nil || count != 3 {
		t.Fatal("upgrade/replay lost or duplicated replacement markers")
	}
}
