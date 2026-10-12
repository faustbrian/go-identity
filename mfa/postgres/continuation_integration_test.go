//go:build integration

package mfapostgres

import (
	"context"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	auditpostgres "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization"
	identitycapability "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	deliverypostgres "github.com/faustbrian/go-identity/delivery/postgres"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpostgres "github.com/faustbrian/go-migrations/v3/postgres"
	database "github.com/faustbrian/go-postgres"
	outboxpostgres "github.com/faustbrian/go-transactional-outbox/v2/postgres"
	identityoutbox "github.com/faustbrian/go-transactional-outbox/v2/postgres/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

type testPolicy struct{}

func (testPolicy) Decide(ctx context.Context, _ authorization.Request) (authorization.Decision, error) {
	if ctx.Err() != nil {
		return authorization.Decision{}, ctx.Err()
	}
	return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
}

func TestNativeContinuationPostgres(t *testing.T) {
	dsn := os.Getenv("IDENTITY_MFA_TEST_DSN")
	config, err := pgx.ParseConfig(dsn)
	if dsn == "" || err != nil || config.Host != "127.0.0.1" || config.Database != "identity_test" {
		t.Fatal("explicit disposable loopback identity_test cluster required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("disposable cluster unavailable")
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := admin.Close(cleanup); err != nil {
			t.Error("admin cleanup failed")
		}
	}()
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	name := "identity_mfa_" + string(id)
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatal(err)
	}
	rolesOwned := false
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+quoted); err != nil {
			t.Error("database cleanup failed")
		}
		if rolesOwned {
			if _, err := admin.Exec(cleanup, "DROP ROLE audit_writer,audit_reader,audit_retention"); err != nil {
				t.Error("role cleanup failed")
			}
		}
	}()
	config.Database = name
	db := stdlib.OpenDB(*config)
	defer db.Close()
	backend, err := migrationpostgres.New(db)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(identitypostgres.MigrationSource{}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(ctx); err != nil {
		t.Fatal("identity install failed", err)
	}
	pool, err := database.Connect(ctx, database.Config{DSN: dsn, MaxConns: 4, Configure: func(native *database.PoolConfig) error { native.ConnConfig.Database = name; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if pool.Close(cleanup) != nil {
			t.Error("pool cleanup failed")
		}
	}()
	install, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer install.Rollback(ctx)
	if _, err := install.Exec(ctx, auditpostgres.FreshInstallPreflightSQL()); err != nil {
		t.Fatal(err)
	}
	for _, source := range []fs.FS{auditpostgres.Migrations(), outboxpostgres.Migrations(), identityoutbox.Migrations(), identitycapability.Migrations()} {
		entries, err := fs.ReadDir(source, ".")
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			contents, err := fs.ReadFile(source, entry.Name())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := install.Exec(ctx, strings.Split(string(contents), "-- +migrations Down")[0]); err != nil {
				t.Fatal("owned install failed", entry.Name(), err)
			}
		}
	}
	if err := install.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	rolesOwned = true
	deliveryRunner, err := migrations.NewRunner(deliverypostgres.MigrationSource{Base: identitypostgres.MigrationSource{}, Version: 10, WorkerVersion: 11, PolicyVersion: 12, KeyedVersion: 13, StateVersion: 14}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deliveryRunner.Up(ctx); err != nil {
		t.Fatal("delivery install", err)
	}
	registrationSource := identitypostgres.PasswordRegistrationMigrationSource{Base: identitypostgres.CredentialMigrationSource{Base: identitypostgres.IdentifierMutationMigrationSource{Base: deliverypostgres.MigrationSource{Base: identitypostgres.MigrationSource{}, Version: 10, WorkerVersion: 11, PolicyVersion: 12, KeyedVersion: 13, StateVersion: 14}, Version: 15}, Version: 16}, Version: 17}
	registrationRunner, err := migrations.NewRunner(registrationSource, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registrationRunner.Up(ctx); err != nil {
		t.Fatal("registration history install", err)
	}
	statusRunner, err := migrations.NewRunner(identitypostgres.StatusMigrationSource{Base: registrationSource, Version: 18}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := statusRunner.Up(ctx); err != nil {
		t.Fatal("current recipient authority install", err)
	}
	preparationRunner, err := migrations.NewRunner(identitypostgres.AdmissionPreparationMigrationSource{Base: identitypostgres.PreparationMigrationSource{Base: identitypostgres.StatusMigrationSource{Base: registrationSource, Version: 18}, Version: 19}, Version: 20}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := preparationRunner.Up(ctx); err != nil {
		t.Fatal("original preparation install", err)
	}
	repo, err := identitypostgres.NewRepository(pool, identitypostgres.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	auditing, err := auditpostgres.NewIdentityContributor(auditpostgres.Config{})
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := identityoutbox.NewContributor()
	if err != nil {
		t.Fatal(err)
	}
	testMFAIssuance(t, ctx, pool, repo, auditing, lifecycle)
	testRecoveryStorage(t, ctx, pool)
}
