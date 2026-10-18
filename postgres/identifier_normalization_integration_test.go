//go:build integration

package postgres

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
)

// This is a storage/migration contract, not a substitute for the genuine
// username signup/password/session consumer. Seeded directory rows establish
// exactly which bytes an optional schema upgrade may and may not change.
func TestIdentifierNormalizationPopulatedUpgrade(t *testing.T) {
	dsn := os.Getenv("IDENTITY_POSTGRES_TEST_DSN")
	directory := os.Getenv("IDENTITY_POSTGRES_TEST_DATA_DIRECTORY")
	config, err := pgx.ParseConfig(dsn)
	if err != nil || dsn == "" || config.Host != "127.0.0.1" || config.Database != "identity_test" || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		t.Fatal("explicit task-owned loopback cluster and exact data directory required")
	}
	ctx, stop := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(stop)
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := admin.Close(cleanup); err != nil {
			t.Error("admin cleanup failed")
		}
	})
	var actualDirectory string
	if err := admin.QueryRow(ctx, "SHOW data_directory").Scan(&actualDirectory); err != nil || actualDirectory != directory {
		t.Fatal("fixture is not the exact task-owned cluster")
	}
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	name := "username_binding_" + string(id)
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+quoted); err != nil {
			t.Error("owned database cleanup failed")
		}
	})
	config.Database = name
	db := stdlib.OpenDB(*config)
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error("SQL pool cleanup failed")
		}
	})
	backend, err := migrationdb.New(db)
	if err != nil {
		t.Fatal(err)
	}
	base, err := migrations.NewRunner(MigrationSource{}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := base.Up(ctx); err != nil {
		t.Fatal("base installation", err)
	}
	pool, err := database.Connect(ctx, database.Config{DSN: dsn, MaxConns: 2, Configure: func(native *database.PoolConfig) error { native.ConnConfig.Database = name; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := pool.Close(cleanup); err != nil {
			t.Error("primary pool cleanup failed")
		}
	})
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('tenant','old-user','active',1),('tenant','new-user','active',1);
INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,display_value,version,verification_state,verification_version) VALUES('tenant','old-user','email','email','old@example.test','Old@example.test',1,1,1)`); err != nil {
		t.Fatal(err)
	}
	repository, err := NewRepository(pool, Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	query := identity.IdentifierQuery{TenantID: "tenant", UserID: "old-user", MaximumIdentifiers: 128}
	before, err := repository.GetIdentifierState(ctx, query)
	if err != nil || len(before.Identifiers) != 1 || before.Identifiers[0].NormalizationProfile != "" {
		t.Fatal("legacy reader requires an unrelated optional migration", err)
	}
	insert := `INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,display_value,version,verification_state,verification_version,normalization_profile,normalization_version) VALUES('tenant','new-user','username','username','strasse','Straße',1,1,1,$1,$2::text::numeric)`
	if _, err := pool.Raw().Exec(ctx, insert, "identity.username.latin-v1", "1"); err == nil {
		t.Fatal("legacy schema unexpectedly stored bound username metadata")
	}
	source := IdentifierNormalizationMigrationSource{Base: MigrationSource{}, Version: 10}
	upgrade, err := migrations.NewRunner(source, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := upgrade.Up(ctx); err != nil {
		t.Fatal("populated upgrade", err)
	}
	if _, err := upgrade.Up(ctx); err != nil {
		t.Fatal("migration replay", err)
	}
	after, err := repository.GetIdentifierState(ctx, query)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("upgrade reinterpreted legacy canonical/display/verification state", err)
	}
	for _, pair := range []struct{ profile, version string }{
		{"identity.username.latin-v1", "0"}, {"", "1"}, {"", "0.0"}, {"Bad", "1"},
		{"identity.username.latin-v1", "4294967296"}, {"identity.username.latin-v1", "1.0"},
	} {
		_, err := pool.Raw().Exec(ctx, insert, pair.profile, pair.version)
		var constraint *pgconn.PgError
		if !errors.As(err, &constraint) || constraint.Code != "23514" {
			t.Fatal("database did not constrain malformed normalization binding", err)
		}
	}
	if _, err := pool.Raw().Exec(ctx, insert, "identity.username.latin-v1", "1"); err != nil {
		t.Fatal(err)
	}
	query.UserID = "new-user"
	bound, err := repository.GetIdentifierState(ctx, query)
	if err != nil || len(bound.Identifiers) != 1 || bound.Identifiers[0].NormalizationProfile != "identity.username.latin-v1" || bound.Identifiers[0].NormalizationVersion != 1 || bound.Identifiers[0].CanonicalValue != "strasse" || bound.Identifiers[0].DisplayValue != "Straße" {
		t.Fatal("primary read lost complete persisted normalization identity", err)
	}
	retirementSource := IdentifierMutationMigrationSource{Base: source, Version: 11}
	retirements, err := migrations.NewRunner(retirementSource, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := retirements.Up(ctx); err != nil {
		t.Fatal(err)
	}
	// Exercise the actual common CAS writer under its storage-test Work. This
	// does not create public authentication or coordinator command authority.
	for _, commit := range []bool{true, false} {
		tx, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_ = tx.Rollback(cleanup)
		})
		workCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		w := Work{state: &workState{tx: tx, ctx: workCtx, cancel: cancel}}
		t.Cleanup(func() { invalidateWork(w) })
		change := identity.IdentifierChange{TenantID: query.TenantID, UserID: query.UserID, ID: "username", Action: identity.IdentifierReplace,
			Kind: identity.IdentifierUsername, CanonicalValue: "renamed", DisplayValue: "Renamed",
			NormalizationProfile: "identity.username.latin-v1", NormalizationVersion: 1,
			ExpectedUserVersion: bound.User.Version, ExpectedAuthorityVersion: bound.AuthorityVersion,
			ExpectedIdentifierVersion: bound.Identifiers[0].Version, ExpectedVerificationVersion: bound.Verifications[0].Version}
		if !commit {
			change.CanonicalValue, change.DisplayValue = "rolled-back", "Rolled-back"
		}
		locked, now, err := lockIdentifierPartition(ctx, w, change)
		if err != nil || !reflect.DeepEqual(locked, bound) {
			t.Fatal("locked projection lost normalization identity", err)
		}
		mutation, err := identity.ApplyIdentifierChange(locked, change, now)
		if err != nil {
			t.Fatal(err)
		}
		commandID, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		policy := identifierMutationPolicy{currentKeyVersion: 1, keys: map[uint32][32]byte{1: {1}}, reuseCooldown: 30 * 24 * time.Hour}
		if err := persistIdentifierMutation(ctx, w, identity.CommandBinding{CommandID: commandID}, change, locked, mutation, policy, now); err != nil {
			t.Fatal("normalization-aware CAS writer", err)
		}
		if commit {
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			bound = mutation.State
		} else if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		invalidateWork(w)
		read, err := repository.GetIdentifierState(ctx, query)
		if err != nil || !reflect.DeepEqual(read, bound) {
			t.Fatal("commit/rollback did not preserve exact bound directory state", err)
		}
	}
	// Authentication discovery additionally requires the real status and
	// credential epochs, not defaults inferred from absent authority storage.
	authorities, err := migrations.NewRunner(CredentialMigrationSource{Base: StatusMigrationSource{Base: retirementSource, Version: 12}, Version: 13}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authorities.Up(ctx); err != nil {
		t.Fatal("username discovery authority histories", err)
	}
	t.Run("username-primary-lookup", func(t *testing.T) { testUsernameLookupPostgres(t, ctx, pool, repository) })
	t.Run("username-native-rename", func(t *testing.T) { testUsernameRenamePostgres(t, ctx, pool, repository) })
}
