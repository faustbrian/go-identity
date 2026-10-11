//go:build integration

package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestMagicLinkRegistrationPopulatedMigration(t *testing.T) {
	dsn := os.Getenv("IDENTITY_POSTGRES_TEST_DSN")
	c, err := pgx.ParseConfig(dsn)
	if err != nil || dsn == "" || c.Host != "127.0.0.1" || c.Database != "identity_test" {
		t.Fatal("explicit disposable loopback primary required")
	}
	ctx, stop := context.WithTimeout(t.Context(), 20*time.Second)
	defer stop()
	admin, err := pgx.ConnectConfig(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := admin.Close(cleanup); err != nil {
			t.Error(err)
		}
	}()
	const name = "identity_test_magic_registration"
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+name); err != nil {
			t.Error(err)
		}
	}()
	c.Database = name
	conn, err := pgx.ConnectConfig(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := conn.Close(cleanup); err != nil {
			t.Error(err)
		}
	}()
	base := PasswordSignupAcceptanceMigrationSource{Base: PasswordRegistrationMigrationSource{Base: MigrationSource{}, Version: 10}, Version: 11}
	history, err := base.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range history {
		if _, err := conn.Exec(ctx, m.UpSQL()); err != nil {
			t.Fatal("base migration", m.Version(), err)
		}
	}
	// Separate parameterized statements: extended protocol does not admit a
	// multi-command prepared query. Both seed rows belong to the test, not a claim
	// that production callers may manufacture original-command authority.
	for id, purpose := range map[int]string{1: "identity.password.signup", 2: "identity.password.signup", 3: "identity.magic-link.consume", 4: "identity.magic-link.consume", 5: "identity.magic-link.consume", 6: "identity.password.signup"} {
		if _, err := conn.Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES(decode(lpad(to_hex($1::int),32,'0'),'hex'),'tenant',$2,decode(repeat('01',32),'hex'),1,decode('01','hex'))`, id, purpose); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES(decode(lpad(to_hex($1::int),32,'0'),'hex'),'tenant',$2)`, id, purpose); err != nil {
			t.Fatal(err)
		}
	}
	insert := func(id int, purpose string, user, identifier, credential any, accepted bool) error {
		_, err := conn.Exec(ctx, `INSERT INTO identity.registration_bindings(tenant_id,purpose,command_id,user_id,identifier_id,credential_id,accepted_only) VALUES('tenant',$1,decode(lpad(to_hex($2::int),32,'0'),'hex'),$3,$4,$5,$6)`, purpose, id, user, identifier, credential, accepted)
		return err
	}
	if err := insert(1, "identity.password.signup", "old-user", "old-email", "old-password", false); err != nil {
		t.Fatal(err)
	}
	if err := insert(2, "identity.password.signup", nil, nil, nil, true); err != nil {
		t.Fatal(err)
	}
	var oldConstraint *pgconn.PgError
	if err := insert(3, "identity.magic-link.consume", "new-user", "new-email", nil, false); !errors.As(err, &oldConstraint) || oldConstraint.Code != "23514" {
		t.Fatal("old schema did not deny passwordless disposition by constraint", err)
	}
	extended, err := (MagicLinkRegistrationMigrationSource{Base: base, Version: 12}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Exec(ctx, extended[len(history)].UpSQL()); err != nil {
		t.Fatal("populated forward migration", err)
	}
	if err := insert(3, "identity.magic-link.consume", "new-user", "new-email", nil, false); err != nil {
		t.Fatal("passwordless evidence rejected", err)
	}
	for _, bad := range []struct {
		id                           int
		purpose                      string
		user, identifier, credential any
		accepted                     bool
	}{{4, "identity.magic-link.consume", "bad-user", "bad-email", "dummy-password", false}, {5, "identity.magic-link.consume", nil, nil, nil, true}, {6, "identity.password.signup", "bad-user", "bad-email", nil, false}} {
		var constraint *pgconn.PgError
		if err := insert(bad.id, bad.purpose, bad.user, bad.identifier, bad.credential, bad.accepted); !errors.As(err, &constraint) || constraint.Code != "23514" {
			t.Fatal("cross-profile disposition admitted", err)
		}
	}
	var created, accepted, magic int
	if err := conn.QueryRow(ctx, `SELECT count(*) FILTER(WHERE purpose='identity.password.signup' AND NOT accepted_only AND credential_id='old-password'),count(*) FILTER(WHERE purpose='identity.password.signup' AND accepted_only),count(*) FILTER(WHERE purpose='identity.magic-link.consume' AND NOT accepted_only AND credential_id IS NULL) FROM identity.registration_bindings`).Scan(&created, &accepted, &magic); err != nil || created != 1 || accepted != 1 || magic != 1 {
		t.Fatal("populated dispositions changed", err)
	}
}
