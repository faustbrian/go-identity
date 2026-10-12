//go:build integration

package passwordpostgres_test

import (
	"bytes"
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
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	passworddb "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
)

// Exercise the populated native password history with the real migration
// runner. These fixtures prove storage constraints, not proof authentication,
// protected enrollment or public workflow delivery.
func TestReauthenticationConsumptionMigrationAdmitsOnlyOwnedMFAEnable(t *testing.T) {
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
	defer admin.Close(context.Background())
	id, _ := identity.NewCommandID()
	database := "mfa_consumption_" + string(id)
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
	// Start at the actually installed six-migration history, populated with a
	// consumed password-change proof before adopting the additive extension.
	original := reauthenticationPreMFAHistory{}
	runner, err = migrations.NewRunner(original, owned)
	if err != nil {
		t.Fatal("original password history rejected")
	}
	if _, err = runner.Up(ctx); err != nil {
		t.Fatal("original password install failed")
	}
	conn, err := pgx.Connect(ctx, u.String())
	if err != nil {
		t.Fatal("native storage unavailable")
	}
	defer conn.Close(context.Background())
	command := func(purpose string) []byte {
		t.Helper()
		id, err := identity.NewCommandID()
		if err != nil {
			t.Fatal("fixture identity unavailable")
		}
		wire, err := base64.RawURLEncoding.Strict().DecodeString(string(id))
		if err != nil {
			t.Fatal("fixture identity invalid")
		}
		if _, err = conn.Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,'tenant-a',$2,$3,1,decode('01','hex'))`, wire, purpose, make([]byte, 32)); err != nil {
			t.Fatal("fixture claim rejected")
		}
		if _, err = conn.Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,'tenant-a',$2)`, wire, purpose); err != nil {
			t.Fatal("fixture command rejected")
		}
		return wire
	}
	oldProof, oldConsumer := command("identity.password.verify"), command("identity.password.change")
	newProof, newConsumer := command("identity.password.verify"), command("identity.mfa.enable")
	unsupportedConsumer := command("identity.mfa.disable")
	const oldID = "old-proof-aaaaaaaaaaaa"
	const newID = "new-proof-aaaaaaaaaaaa"
	payload := []byte("migration-only-opaque-fixture")
	if _, err = conn.Exec(ctx, `INSERT INTO identity_password.reauthentication_records(proof_id,tenant_id,user_id,command_id,purpose,record,consumed_command_id,consumed_purpose,consumed_at) VALUES($1,'tenant-a','user-a',$2,'identity.password.verify',$3,$4,'identity.password.change',clock_timestamp())`, oldID, oldProof, payload, oldConsumer); err != nil {
		t.Fatal("populated predecessor receipt rejected")
	}
	if _, err = conn.Exec(ctx, `INSERT INTO identity_password.reauthentication_records(proof_id,tenant_id,user_id,command_id,purpose,record) VALUES($1,'tenant-a','user-a',$2,'identity.password.verify',$3)`, newID, newProof, payload); err != nil {
		t.Fatal("unconsumed proof fixture rejected")
	}
	update := func(consumer []byte, purpose string) error {
		_, err := conn.Exec(ctx, `UPDATE identity_password.reauthentication_records SET consumed_command_id=$2,consumed_purpose=$3,consumed_at=clock_timestamp() WHERE proof_id=$1`, newID, consumer, purpose)
		return err
	}
	checkViolation := func(err error) {
		t.Helper()
		var failure *pgconn.PgError
		if !errors.As(err, &failure) || failure.Code != "23514" {
			t.Fatal("closed consumption constraint was not enforced")
		}
	}
	checkViolation(update(newConsumer, "identity.mfa.enable"))
	// Capture the real predecessor's missing storage boundary before upgrade.
	_, absent := conn.Exec(ctx, `INSERT INTO identity_password.mfa_primary_records(proof_id,tenant_id,user_id,command_id,purpose,record_digest,record) VALUES($1,'tenant-a','user-a',$2,'identity.password.signin',$3,$4)`, newID, newProof, make([]byte, 32), payload)
	var predecessorError *pgconn.PgError
	if !errors.As(absent, &predecessorError) || predecessorError.Code != "42P01" {
		t.Fatal("predecessor unexpectedly has non-final primary storage")
	}
	runner, err = migrations.NewRunner(passworddb.MigrationSource{}, owned)
	if err != nil {
		t.Fatal("current password history rejected")
	}
	if _, err = runner.Up(ctx); err != nil {
		t.Fatal("populated native upgrade failed")
	}
	if err = update(newConsumer, "identity.mfa.enable"); err != nil {
		t.Fatal("MFA enable cannot atomically consume owned reauthentication after upgrade")
	}
	checkViolation(update(unsupportedConsumer, "identity.mfa.disable"))
	if _, err = conn.Exec(ctx, `UPDATE identity_password.reauthentication_records SET consumed_purpose=NULL WHERE proof_id=$1`, newID); err == nil {
		t.Fatal("partial consumption custody accepted")
	} else {
		checkViolation(err)
	}
	var originalPayload, originalConsumer []byte
	var purpose string
	if conn.QueryRow(ctx, `SELECT record,consumed_command_id,consumed_purpose FROM identity_password.reauthentication_records WHERE proof_id=$1`, oldID).Scan(&originalPayload, &originalConsumer, &purpose) != nil || !bytes.Equal(originalPayload, payload) || !bytes.Equal(originalConsumer, oldConsumer) || purpose != "identity.password.change" {
		t.Fatal("populated password-change receipt changed")
	}
	if _, err = runner.Up(ctx); err != nil {
		t.Fatal("owned additive migration replay failed")
	}
	checkMFAPrimaryStorageConstraints(t, ctx, conn, command)
	checkPasswordContinuationUpgrade(t, ctx, conn, backend, command)
}

func checkPasswordContinuationUpgrade(t *testing.T, ctx context.Context, conn *pgx.Conn, backend *migrationdb.Backend, command func(string) []byte) {
	t.Helper()
	owned, err := backend.ForNamespace("identity_mfa")
	if err != nil {
		t.Fatal(err)
	}
	base := mfapg.ContinuationMigrationSource{Base: mfapg.MigrationSource{Version: 1}, Version: 2}
	runner, err := migrations.NewRunner(base, owned)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = runner.Up(ctx); err != nil {
		t.Fatal("original MFA install failed", err)
	}
	if _, err = conn.Exec(ctx, `INSERT INTO identity_mfa.factor_authorities(tenant_id,user_id,version,active_factors,initialized_command_id,initialized_purpose) VALUES('tenant-a','user-a',1,1,$1,'identity.password.signup')`, command("identity.password.signup")); err != nil {
		t.Fatal(err)
	}
	insert := func(purpose string) error {
		cmd := command(purpose)
		id := base64.RawURLEncoding.EncodeToString(cmd)
		_, err := conn.Exec(ctx, `INSERT INTO identity_mfa.continuations(tenant_id,continuation_id,user_id,source_preauth_id,origin_command_id,origin_purpose,origin_fingerprint,origin_generation,scope_digest,original_scope,state,version,max_attempts,attempts_remaining,issued_at,expires_at) VALUES('tenant-a',$1,'user-a',$1,$2,$3,$4,1,$4,decode('01','hex'),1,1,3,3,to_timestamp(1791820800),to_timestamp(1791820920))`, id, cmd, purpose, make([]byte, 32))
		return err
	}
	if err = insert("identity.magic-link.consume"); err != nil {
		t.Fatal("original magic-link history rejected", err)
	}
	var rejected *pgconn.PgError
	if err = insert("identity.password.signin"); !errors.As(err, &rejected) || rejected.Code != "23514" {
		t.Fatal("predecessor admitted password continuation")
	}
	runner, err = migrations.NewRunner(mfapg.PasswordContinuationMigrationSource{Base: base, Version: 3}, owned)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = runner.Up(ctx); err != nil {
		t.Fatal("populated MFA upgrade failed", err)
	}
	if err = insert("identity.password.signin"); err != nil {
		t.Fatal("genuine password continuation rejected", err)
	}
	if err = insert("identity.magic-link.consume"); err != nil {
		t.Fatal("magic-link compatibility lost", err)
	}
	if err = insert("identity.password.verify"); !errors.As(err, &rejected) || rejected.Code != "23514" {
		t.Fatal("unrelated primary origin admitted")
	}
	var count int
	if err = conn.QueryRow(ctx, `SELECT count(*) FROM identity_mfa.continuations`).Scan(&count); err != nil || count != 3 {
		t.Fatal("upgrade lost or duplicated original continuation", err)
	}
	if _, err = runner.Up(ctx); err != nil {
		t.Fatal("MFA upgrade replay failed", err)
	}
}

// Storage-only fixtures: no successful password comparison or public challenge
// delivery is claimed by these rows. The owning workflow must prove those.
func checkMFAPrimaryStorageConstraints(t *testing.T, ctx context.Context, conn *pgx.Conn, command func(string) []byte) {
	t.Helper()
	if _, err := conn.Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('tenant-a','user-a','active',1)`); err != nil {
		t.Fatal("primary storage user fixture rejected")
	}
	original := command("identity.password.signin")
	proof := base64.RawURLEncoding.EncodeToString(original)
	foreignCommand := command("identity.password.signin")
	foreignProof := base64.RawURLEncoding.EncodeToString(foreignCommand)
	orphanID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal("orphan fixture identity unavailable")
	}
	orphanCommand, err := base64.RawURLEncoding.Strict().DecodeString(string(orphanID))
	if err != nil {
		t.Fatal("orphan fixture identity invalid")
	}
	payload, digest := []byte("non-final-storage-only-fixture"), make([]byte, 32)
	insert := func(id, tenant, user, purpose string, cmd, sum, record []byte) error {
		_, err := conn.Exec(ctx, `INSERT INTO identity_password.mfa_primary_records(proof_id,tenant_id,user_id,command_id,purpose,record_digest,record) VALUES($1,$2,$3,$4,$5,$6,$7)`, id, tenant, user, cmd, purpose, sum, record)
		return err
	}
	if err := insert(proof, "tenant-a", "user-a", "identity.password.signin", original, digest, payload); err != nil {
		t.Fatal("owned non-final primary cannot be retained")
	}
	for name, attempt := range map[string]struct {
		code string
		run  func() error
	}{
		"duplicate primary": {"23505", func() error {
			return insert(proof, "tenant-a", "user-a", "identity.password.signin", original, digest, payload)
		}},
		"second proof for original command": {"23505", func() error {
			return insert(foreignProof, "tenant-a", "user-a", "identity.password.signin", original, digest, payload)
		}},
		"orphan command": {"23503", func() error {
			return insert(string(orphanID), "tenant-a", "user-a", "identity.password.signin", orphanCommand, digest, payload)
		}},
		"cross tenant": {"23503", func() error {
			return insert(foreignProof, "tenant-b", "user-a", "identity.password.signin", foreignCommand, digest, payload)
		}},
		"foreign user": {"23503", func() error {
			return insert(foreignProof, "tenant-a", "other", "identity.password.signin", foreignCommand, digest, payload)
		}},
		"different purpose": {"23514", func() error {
			return insert(proof, "tenant-a", "user-a", "identity.password.verify", original, digest, payload)
		}},
		"missing digest": {"23514", func() error {
			return insert(proof, "tenant-a", "user-a", "identity.password.signin", original, []byte{1}, payload)
		}},
		"oversized record": {"23514", func() error {
			return insert(proof, "tenant-a", "user-a", "identity.password.signin", original, digest, make([]byte, 32769))
		}},
	} {
		t.Run(name, func(t *testing.T) {
			var failure *pgconn.PgError
			if !errors.As(attempt.run(), &failure) || failure.Code != attempt.code {
				t.Fatal("closed primary storage boundary not enforced")
			}
		})
	}
	var retained, sum []byte
	if conn.QueryRow(ctx, `SELECT record,record_digest FROM identity_password.mfa_primary_records WHERE proof_id=$1`, proof).Scan(&retained, &sum) != nil || !bytes.Equal(retained, payload) || !bytes.Equal(sum, digest) {
		t.Fatal("rejected write changed original non-final evidence")
	}
	var count int
	if conn.QueryRow(ctx, `SELECT count(*) FROM identity_password.signin_records WHERE proof_id=$1`, proof).Scan(&count) != nil || count != 0 {
		t.Fatal("non-final primary entered completed signin source")
	}
}

type reauthenticationPreMFAHistory struct{}

func (reauthenticationPreMFAHistory) Load(ctx context.Context) ([]migrations.Migration, error) {
	history, err := (passworddb.MigrationSource{}).Load(ctx)
	if err != nil {
		return nil, err
	}
	return history[:6], nil
}
