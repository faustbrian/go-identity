//go:build integration

package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	authorization "github.com/faustbrian/go-authorization"
	authority "github.com/faustbrian/go-authorization/postgres"
	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestOTPAuthorityPostgresIntegration(t *testing.T) {
	dsn := os.Getenv("IDENTITY_POSTGRES_TEST_DSN")
	config, err := pgx.ParseConfig(dsn)
	if dsn == "" || err != nil || config.Host != "127.0.0.1" || config.Database != "identity_test" {
		t.Fatal("explicit disposable loopback identity_test database required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("disposable cluster unavailable")
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if admin.Close(cleanup) != nil {
			t.Error("admin cleanup failed")
		}
	}()
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	name := "identity_test_otp_" + string(id)
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, e := admin.Exec(cleanup, "DROP DATABASE "+quoted); e != nil {
			t.Error("database cleanup failed")
		}
	}()
	config.Database = name
	db := stdlib.OpenDB(*config)
	defer db.Close()
	backend, err := migrationdb.New(db)
	if err != nil {
		t.Fatal(err)
	}
	source := DirectoryAuthorityMigrationSource{Base: CredentialMigrationSource{Base: StatusMigrationSource{Base: MigrationSource{}, Version: 12}, Version: 13}, Version: 14, GlobalAuthorityID: "otp-bootstrap"}
	runner, err := migrations.NewRunner(source, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = runner.Up(ctx); err != nil {
		t.Fatal(err)
	}
	pool, err := database.Connect(ctx, database.Config{DSN: dsn, MaxConns: 2, Configure: func(native *database.PoolConfig) error { native.ConnConfig.Database = name; return nil }})
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
	testOTPCurrentAuthority(t, ctx, pool)
	testOTPUserAuthority(t, ctx, pool)
	t.Run("recipient", func(t *testing.T) { testRecipientPostgres(t, ctx, pool) })
}

// Exercise real authority SQL through each sealed handle, not OTP cryptography
// or complete login admission. The existing OTP dispatch suites independently
// prove that poisoned Work cannot commit participant/domain prefixes.
func testOTPCurrentAuthority(t *testing.T, ctx context.Context, pool *database.Pool) {
	migration, err := authority.AuthoritySchemaMigration(2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Raw().Exec(ctx, migration.Up); err != nil {
		t.Fatal(err)
	}
	w, _, _ := otpAuthorityFixture(t, ctx, "attempt", "")
	b := w.state.binding
	scope := authority.AuthorityScope{TenantID: authorization.TenantID(b.TenantID), PolicyNamespace: "otp-user", SubjectID: authorization.SubjectID(b.UserID)}
	if _, err = pool.Raw().Exec(ctx, `CREATE TABLE identity.otp_authority_effects(id text PRIMARY KEY); INSERT INTO identity.global_authorities(authority_id,version) VALUES('otp-global',7)`); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Raw().Exec(ctx, `INSERT INTO identity.tenant_authorities(tenant_id,version,enabled) VALUES($1,11,true)`, string(b.TenantID)); err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{
		`INSERT INTO identity.users(tenant_id,user_id,status,version,authority_version,identifier_version,credential_version) VALUES($1,$2,'active',101,13,17,19)`,
		`INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES($1,$2,'otp-ref',1,'identity/password',5,true)`,
	} {
		if _, err = pool.Raw().Exec(ctx, sql, string(b.TenantID), string(b.UserID)); err != nil {
			t.Fatal(err)
		}
	}
	tx, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = authority.InitializeAuthority(ctx, tx, scope, time.Second); err != nil {
		tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"attempt", "reservation", "apply", "finalize"} {
		for _, mode := range []string{"exact", "global-stale", "global-absent", "tenant-disabled", "user-blocked", "credential-disabled", "credential-stale", "credential-expired", "authorization-stale", "authorization-absent", "primary-lock-deadline", "cursor-directory", "cursor-credential"} {
			t.Run(phase+"/"+mode, func(t *testing.T) {
				// Reset outside the checked transaction. Each check compares the same
				// original expectation; none may adopt these current values as new intent.
				if _, e := pool.Raw().Exec(ctx, `UPDATE identity.tenant_authorities SET enabled=true WHERE tenant_id=$1`, string(b.TenantID)); e != nil {
					t.Fatal(e)
				}
				for _, sql := range []string{`UPDATE identity.users SET status='active' WHERE tenant_id=$1 AND user_id=$2`, `UPDATE identity.credential_references SET enabled=true,expires_at=NULL WHERE tenant_id=$1 AND user_id=$2 AND credential_id='otp-ref'`} {
					if _, e := pool.Raw().Exec(ctx, sql, string(b.TenantID), string(b.UserID)); e != nil {
						t.Fatal(e)
					}
				}
				switch mode {
				case "tenant-disabled":
					_, err = pool.Raw().Exec(ctx, `UPDATE identity.tenant_authorities SET enabled=false WHERE tenant_id=$1`, string(b.TenantID))
				case "user-blocked":
					_, err = pool.Raw().Exec(ctx, `UPDATE identity.users SET status='suspended' WHERE tenant_id=$1 AND user_id=$2`, string(b.TenantID), string(b.UserID))
				case "credential-disabled":
					_, err = pool.Raw().Exec(ctx, `UPDATE identity.credential_references SET enabled=false WHERE tenant_id=$1 AND user_id=$2`, string(b.TenantID), string(b.UserID))
				case "credential-expired":
					_, err = pool.Raw().Exec(ctx, `UPDATE identity.credential_references SET expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND user_id=$2`, string(b.TenantID), string(b.UserID))
				}
				if err != nil {
					t.Fatal(err)
				}
				tx, e := pool.Raw().Begin(ctx)
				if e != nil {
					t.Fatal(e)
				}
				defer tx.Rollback(ctx)
				live, checks, deactivate := otpAuthorityFixture(t, ctx, phase, "")
				live.state.tx = tx
				defer invalidateWork(live)
				defer deactivate()
				id := phase + "-" + mode
				if _, e = live.Exec(ctx, `INSERT INTO identity.otp_authority_effects(id) VALUES($1)`, id); e != nil {
					t.Fatal(e)
				}
				directory := DirectoryAuthorityAdmission{Query: DirectoryAuthorityQuery{GlobalAuthorityID: "otp-global", TenantID: b.TenantID}, GlobalVersion: 7, TenantVersion: 11}
				credential := CredentialAdmission{Credential: identity.CredentialRef{TenantID: b.TenantID, UserID: b.UserID, ID: "otp-ref", Kind: identity.CredentialPassword, Owner: "identity/password", Version: 5}, UserAuthorityVersion: 13, IdentifierAuthorityVersion: 17, CredentialAuthorityVersion: 19}
				authorization := UserAuthorizationAdmission{Scope: scope, Version: 1}
				switch mode {
				case "global-stale":
					directory.GlobalVersion++
				case "global-absent":
					directory.Query.GlobalAuthorityID = "missing"
				case "credential-stale":
					credential.Credential.Version++
				case "authorization-stale":
					authorization.Version++
				case "authorization-absent":
					authorization.Scope.PolicyNamespace = "missing"
				}
				checkCtx := ctx
				var blocker pgx.Tx
				if mode == "primary-lock-deadline" {
					blocker, e = pool.Raw().Begin(ctx)
					if e != nil {
						t.Fatal(e)
					}
					defer blocker.Rollback(ctx)
					if _, e = blocker.Exec(ctx, `SELECT authority_id FROM identity.global_authorities WHERE authority_id='otp-global' FOR UPDATE`); e != nil {
						t.Fatal(e)
					}
					var stop context.CancelFunc
					checkCtx, stop = context.WithTimeout(ctx, 20*time.Millisecond)
					defer stop()
				}
				var now time.Time
				cursorDenied := mode == "cursor-directory" || mode == "cursor-credential"
				if cursorDenied {
					rows, queryErr := live.Query(ctx, "SELECT 1")
					if queryErr != nil {
						t.Fatal(queryErr)
					}
					if mode == "cursor-directory" {
						e = checks.directory(ctx, directory)
					} else {
						now, e = checks.credential(ctx, credential)
					}
					rows.Close()
					if live.usable() == nil || !now.IsZero() {
						t.Fatal("cursor cleanup erased admission failure")
					}
				} else {
					e = checks.directory(checkCtx, directory)
					if e == nil {
						now, e = checks.credential(ctx, credential)
					}
					if e == nil {
						if now.IsZero() || now.Location() != time.UTC {
							t.Fatal("primary credential clock missing")
						}
						e = checks.authorization(ctx, authorization)
					}
				}
				if mode == "exact" {
					if e != nil || live.state.failed != nil {
						t.Fatalf("exact authority rejected: %v", e)
					}
					if e = tx.Commit(ctx); e != nil {
						t.Fatal(e)
					}
				} else {
					var denied identity.ForbiddenError
					if mode == "primary-lock-deadline" {
						if !errors.Is(e, context.DeadlineExceeded) {
							t.Fatalf("primary lock ignored caller deadline: %v", e)
						}
					} else if cursorDenied {
						var invalid identity.InvalidInputError
						if !errors.As(e, &invalid) {
							t.Fatalf("cursor rejection classification: %v", e)
						}
					} else if !errors.As(e, &denied) {
						t.Fatalf("live denial classification: %v", e)
					}
					if live.state.failed == nil {
						t.Fatal("ignored denial did not poison work")
					}
					if mode == "user-blocked" || mode == "credential-disabled" || mode == "credential-stale" || mode == "credential-expired" {
						if !now.IsZero() {
							t.Fatal("credential denial leaked successful clock")
						}
					}
					if _, e = live.Exec(ctx, `INSERT INTO identity.otp_authority_effects(id) VALUES('ignored-denial')`); e == nil {
						t.Fatal("ignored denial permitted effects")
					}
					// pgx may close the connection on bounded query cancellation;
					// that also aborts this uncommitted test transaction. Accept
					// only a confirmed closed connection in the deadline case.
					if e = tx.Rollback(ctx); e != nil && !(mode == "primary-lock-deadline" && tx.Conn().IsClosed()) {
						t.Fatal(e)
					}
					if blocker != nil {
						if e = blocker.Rollback(ctx); e != nil {
							t.Fatal(e)
						}
					}
				}
				var count int
				if e = pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.otp_authority_effects WHERE id=$1`, id).Scan(&count); e != nil {
					t.Fatal(e)
				}
				if (mode == "exact" && count != 1) || (mode != "exact" && count != 0) {
					t.Fatal("authority/effect transaction outcome diverged")
				}
			})
		}
	}
}
