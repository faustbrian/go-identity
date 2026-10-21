//go:build integration

package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestAnonymousPlaceholderPostgres(t *testing.T) {
	dsn := os.Getenv("IDENTITY_POSTGRES_TEST_DSN")
	config, err := pgx.ParseConfig(dsn)
	if dsn == "" || err != nil || config.Host != "127.0.0.1" || config.Database != "identity_test" {
		t.Fatal("explicit disposable loopback identity_test database required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("disposable cluster unavailable")
	}
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := admin.Close(bounded); err != nil {
			t.Error("admin connection cleanup")
		}
	})
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	name := "identity_test_" + string(id)
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatal("isolated database creation")
	}
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := admin.Exec(bounded, "DROP DATABASE "+quoted); err != nil {
			t.Error("isolated database cleanup")
		}
	})
	config.Database = name
	db := stdlib.OpenDB(*config)
	defer db.Close()
	backend, err := migrationdb.New(db)
	if err != nil {
		t.Fatal(err)
	}
	base := IdentifierNormalizationMigrationSource{Base: IdentifierMutationMigrationSource{Base: CredentialMigrationSource{Base: StatusMigrationSource{Base: MigrationSource{}, Version: 10}, Version: 11}, Version: 12}, Version: 13}
	runner, err := migrations.NewRunner(base, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(ctx); err != nil {
		t.Fatal("predecessor migration", err)
	}
	pool, err := database.Connect(ctx, database.Config{DSN: dsn, MaxConns: 2, Configure: func(native *database.PoolConfig) error {
		native.ConnConfig.Database = name
		return nil
	}})
	if err != nil {
		t.Fatal("owned pool", err)
	}
	defer func() {
		bounded, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := pool.Close(bounded); err != nil {
			t.Error("owned pool cleanup")
		}
	}()
	var selectedDatabase string
	if err := pool.Raw().QueryRow(ctx, `SELECT current_database()`).Scan(&selectedDatabase); err != nil || selectedDatabase != name {
		t.Fatal("owned pool did not select its isolated database")
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('tenant','guest','active',1);
INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,verified,is_primary,version,verification_state,verification_version,verified_at) VALUES('tenant','guest','email','email','retained@example.test',true,true,1,2,1,clock_timestamp())`); err != nil {
		t.Fatal(err)
	}
	insert := `INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,version,verification_state,verification_version) VALUES('tenant','guest','placeholder','anonymous-placeholder','AAAAAAAAAAAAAAAAAAAAAQ@anonymous.invalid',1,1,1)`
	if _, err := pool.Raw().Exec(ctx, insert); err == nil {
		t.Fatal("unselected old schema admitted anonymous placeholder")
	}
	selected, err := migrations.NewRunner(AnonymousIdentityMigrationSource{Base: base, Version: 14}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := selected.Up(ctx); err != nil {
		t.Fatal("populated forward migration", err)
	}
	if _, err := pool.Raw().Exec(ctx, insert); err != nil {
		t.Fatal("new placeholder was not persisted", err)
	}
	if _, err := selected.Up(ctx); err != nil {
		t.Fatal("populated replay", err)
	}
	for name, update := range map[string]string{
		"verified":               `verified=true,verification_state=2,verified_at=clock_timestamp()`,
		"primary":                `is_primary=true`,
		"deliverable":            `canonical_value='guest@example.test'`,
		"display":                `display_value='guest@example.test'`,
		"noncanonical opaque id": `canonical_value='AAAAAAAAAAAAAAAAAAAAAR@anonymous.invalid'`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity.identifiers SET `+update+` WHERE identifier_id='placeholder'`); err == nil {
				t.Fatal("database allowed placeholder contact escalation")
			}
		})
	}
	repository, err := NewRepository(pool, Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for _, eligibility := range []RecipientEligibility{RecipientVerified, RecipientPendingOrVerified} {
		q := RecipientQuery{TenantID: "tenant", Kind: identity.IdentifierAnonymousPlaceholder, CanonicalValue: "AAAAAAAAAAAAAAAAAAAAAQ@anonymous.invalid", Eligibility: eligibility}
		if _, err := repository.ResolveRecipient(ctx, q); err == nil {
			t.Fatal("placeholder namespace became a recipient")
		}
		q.Kind = identity.IdentifierEmail
		out, err := repository.ResolveRecipient(ctx, q)
		if err != nil || !out.Suppressed || out.User.ID != "" {
			t.Fatal("email lookup crossed reserved namespace", err)
		}
	}
	out, err := repository.ResolveRecipient(ctx, RecipientQuery{TenantID: "tenant", Kind: identity.IdentifierEmail, CanonicalValue: "retained@example.test", Eligibility: RecipientVerified})
	if err != nil || out.Suppressed || out.Identifier.ID != "email" {
		t.Fatal("populated predecessor contact changed", err)
	}
}
