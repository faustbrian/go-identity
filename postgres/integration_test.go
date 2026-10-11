//go:build integration

package postgres

import (
	"context"
	"errors"
	"math"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
)

// Run only against a task-owned disposable database. Missing infrastructure
// fails explicitly; it never turns a selected integration lane into a skip.
func TestPostgresIntegration(t *testing.T) {
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
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if admin.Close(cleanup) != nil {
			t.Error("administrative connection cleanup failed")
		}
	})
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal("database namespace entropy unavailable")
	}
	name := "identity_test_" + string(id)
	quoted := pgx.Identifier{name}.Sanitize()
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+quoted); err != nil {
			t.Error("disposable database cleanup failed")
		}
	})
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatal("disposable database creation failed")
	}
	config.Database = name
	db := stdlib.OpenDB(*config)
	defer db.Close()
	backend, err := migrationdb.New(db)
	if err != nil {
		t.Fatal("invalid migration backend")
	}
	runner, err := migrations.NewRunner(MigrationSource{}, backend)
	if err != nil {
		t.Fatal("invalid migration source")
	}
	result, err := runner.Up(ctx)
	if err != nil || len(result.Records()) != 9 {
		t.Fatalf("empty install failed: %v (records=%d)", err, len(result.Records()))
	}
	pool, err := database.Connect(ctx, database.Config{DSN: dsn, MaxConns: 2, Configure: func(native *database.PoolConfig) error { native.ConnConfig.Database = name; return nil }})
	if err != nil {
		t.Fatal("primary pool unavailable")
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if pool.Close(cleanup) != nil {
			t.Error("pool cleanup failed")
		}
	}()
	repo, err := NewRepository(pool, Config{MaximumDuration: time.Second, AttributeSchemas: []identity.AttributeSchema{storageSchema()}, ProfileSchema: ProfileSchemaRef{ID: "fields", Version: 1}})
	if err != nil {
		t.Fatal("repository unavailable")
	}
	t.Run("global command claims", func(t *testing.T) { testCommandClaims(t, ctx, pool) })
	t.Run("journal leases", func(t *testing.T) { testJournalLeases(t, ctx, pool) })
	t.Run("terminal journal", func(t *testing.T) { testJournalTerminal(t, ctx, pool) })
	t.Run("begin ownership", func(t *testing.T) { testBeginJournal(t, ctx, pool) })
	t.Run("work execution", func(t *testing.T) { testWorkExecution(t, ctx, pool) })
	t.Run("coordinator reservation", func(t *testing.T) { testCoordinatorReservation(t, ctx, pool) })
	t.Run("capability reservation", func(t *testing.T) { testCapabilityReservation(t, ctx, pool) })
	t.Run("risk reservation", func(t *testing.T) { testRiskReservation(t, ctx, pool) })
	t.Run("captcha replay reservation", func(t *testing.T) { testCaptchaReplayReservation(t, ctx, pool) })
	t.Run("captcha use reservation", func(t *testing.T) { testCaptchaUseReservation(t, ctx, pool) })
	t.Run("populated plan upgrade", func(t *testing.T) { testCoordinatorPlanUpgrade(t, ctx, pool) })
	t.Run("domain execution", func(t *testing.T) { testDomainExecution(t, ctx, pool, repo) })
	t.Run("delivery execution", func(t *testing.T) { testDeliveryExecution(t, ctx, pool, repo) })
	t.Run("issuance execution", func(t *testing.T) { testIssuanceExecution(t, ctx, pool, repo) })
	t.Run("feature observation", func(t *testing.T) { testFeatureObservation(t, ctx, pool) })
	t.Run("command admission", func(t *testing.T) { testCommandAdmissionPrimary(t, ctx, pool) })
	t.Run("feature execution", func(t *testing.T) { testFeatureExecution(t, ctx, pool, repo) })
	t.Run("prepared feature", func(t *testing.T) { testPreparedFeature(t, ctx, pool, repo) })
	t.Run("command counters", func(t *testing.T) { testCommandCounterReservation(t, ctx, pool, repo) })
	t.Run("OTP attempt denial", func(t *testing.T) { testOTPAttemptDenial(t, ctx, pool, repo) })
	t.Run("OTP reservation", func(t *testing.T) { testOTPReservation(t, ctx, pool, repo) })
	t.Run("OTP execution", func(t *testing.T) { testOTPExecution(t, ctx, pool, repo) })
	t.Run("owned creation service", func(t *testing.T) { testCreationOwner(t, ctx, pool, repo) })
	t.Run("command recovery", func(t *testing.T) { testCommandRecovery(t, ctx, pool, repo) })
	t.Run("capability recovery", func(t *testing.T) { testCapabilityRecovery(t, ctx, pool, repo) })
	t.Run("identifier primary reads", func(t *testing.T) { testIdentifierReads(t, ctx, pool, repo) })
	t.Run("status lifecycle", func(t *testing.T) {
		for _, status := range []string{"active", "suspended", "banned", "deleted", "anonymized"} {
			if _, e := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version,identifier_version) VALUES('status-migration',$1::text,$1::text,9223372036854775811,7)`, status); e != nil {
				t.Fatal(e)
			}
		}
		statusRunner, e := migrations.NewRunner(StatusMigrationSource{Base: MigrationSource{}, Version: 12}, backend)
		if e != nil {
			t.Fatal(e)
		}
		if _, e := statusRunner.Up(ctx); e != nil {
			t.Fatal("populated status migration failed", e)
		}
		if _, e := statusRunner.Up(ctx); e != nil {
			t.Fatal("status migration retry failed", e)
		}
		// Subsequent replay checks use the complete installed history rather
		// than presenting the original nine-migration prefix as a downgrade.
		runner = statusRunner
		for _, status := range []string{"active", "suspended", "banned", "deleted", "anonymized"} {
			q := identity.UserStatusQuery{TenantID: "status-migration", UserID: identity.UserID(status)}
			got, e := repo.GetStatus(ctx, q)
			if e != nil || got.User.Status != identity.Status(status) || got.User.Version != 9223372036854775811 || got.AuthorityVersion != 1 {
				t.Fatal("populated lifecycle state changed", e)
			}
			ids, e := repo.GetIdentifierState(ctx, identity.IdentifierQuery{TenantID: q.TenantID, UserID: q.UserID, MaximumIdentifiers: 1})
			if e != nil || ids.AuthorityVersion != 7 {
				t.Fatal("populated identifier epoch changed", e)
			}
		}
		testStatusLifecycle(t, ctx, pool, repo)
	})
	t.Run("credential primary authority", func(t *testing.T) {
		q := identity.CredentialAuthorityQuery{TenantID: "status-migration", UserID: "active", CredentialID: "absent"}
		if got, e := repo.GetCredentialAuthority(ctx, q); e == nil || errors.Is(e, identity.ErrUserAbsent) || got != (identity.CredentialAuthorityRecord{}) {
			t.Fatal("uninstalled credential schema supplied absence/authority", e)
		}
		credentialRunner, e := migrations.NewRunner(CredentialMigrationSource{Base: StatusMigrationSource{Base: MigrationSource{}, Version: 12}, Version: 13}, backend)
		if e != nil {
			t.Fatal(e)
		}
		if _, e := credentialRunner.Up(ctx); e != nil {
			t.Fatal("populated credential migration failed", e)
		}
		if _, e := credentialRunner.Up(ctx); e != nil {
			t.Fatal("credential migration replay failed", e)
		}
		runner = credentialRunner
		for _, status := range []string{"active", "suspended", "banned", "deleted", "anonymized"} {
			var aggregate, userEpoch, identifierEpoch, credentialEpoch, storedStatus string
			e := pool.Raw().QueryRow(ctx, `SELECT version::text,authority_version::text,identifier_version::text,credential_version::text,status FROM identity.users WHERE tenant_id='status-migration' AND user_id=$1`, status).Scan(&aggregate, &userEpoch, &identifierEpoch, &credentialEpoch, &storedStatus)
			if e != nil || aggregate != "9223372036854775811" || userEpoch != "1" || identifierEpoch != "7" || credentialEpoch != "1" || storedStatus != status {
				t.Fatal("populated migration altered existing dimensions", e)
			}
		}
		testCredentialAuthority(t, ctx, pool, repo)
	})
	t.Run("locked credential admission", func(t *testing.T) { testLockedCredentialAdmission(t, ctx, pool, repo) })
	t.Run("password hash upgrade", func(t *testing.T) { testPasswordHashUpgrade(t, ctx, pool, repo) })
	t.Run("user authorization admission", func(t *testing.T) { testUserAuthorizationAdmission(t, ctx, pool, repo) })
	t.Run("credential compromise transaction", func(t *testing.T) {
		compromiseRunner, e := migrations.NewRunner(CredentialCompromiseMigrationSource{Base: CredentialMigrationSource{Base: StatusMigrationSource{Base: MigrationSource{}, Version: 12}, Version: 13}, Version: 14}, backend)
		if e != nil {
			t.Fatal(e)
		}
		if _, e := compromiseRunner.Up(ctx); e != nil {
			t.Fatal("compromise migration", e)
		}
		if _, e := compromiseRunner.Up(ctx); e != nil {
			t.Fatal("compromise migration replay", e)
		}
		runner = compromiseRunner
		testCredentialCompromise(t, ctx, pool, repo)
	})
	t.Run("directory authority", func(t *testing.T) {
		authorityRunner, e := migrations.NewRunner(DirectoryAuthorityMigrationSource{Base: CredentialCompromiseMigrationSource{Base: CredentialMigrationSource{Base: StatusMigrationSource{Base: MigrationSource{}, Version: 12}, Version: 13}, Version: 14}, Version: 15, GlobalAuthorityID: "deployment'\\opaque", TenantIDs: []identity.TenantID{"directory"}}, backend)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = authorityRunner.Up(ctx); e != nil {
			t.Fatal("directory bootstrap migration", e)
		}
		runner = authorityRunner
		testDirectoryAuthority(t, ctx, pool, repo)
	})
	insert := func(tenant, user, status, version string) error {
		_, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,$2,$3,$4::numeric)`, tenant, user, status, version)
		return err
	}
	if insert("tenant-a", "shared-user", "active", "18446744073709551615") != nil || insert("tenant-b", "shared-user", "banned", "1") != nil {
		t.Fatal("tenant fixtures failed")
	}
	t.Run("stable user listing", func(t *testing.T) { testUserListing(t, ctx, pool, repo) })
	t.Run("primary reads", func(t *testing.T) {
		a, err := repo.Get(ctx, identity.GetUserQuery{TenantID: "tenant-a", UserID: "shared-user"})
		if err != nil || a.Version != math.MaxUint64 || a.Status != identity.StatusActive {
			t.Fatal("full-width primary read failed")
		}
		b, err := repo.Get(ctx, identity.GetUserQuery{TenantID: "tenant-b", UserID: "shared-user"})
		if err != nil || b.Version != 1 || b.Status != identity.StatusBanned {
			t.Fatal("tenant isolation failed")
		}
		_, err = repo.Get(ctx, identity.GetUserQuery{TenantID: "tenant-c", UserID: "shared-user"})
		if !errors.Is(err, identity.ErrUserAbsent) {
			t.Fatal("cross-tenant absence failed")
		}
		for _, status := range []string{"active", "suspended", "banned", "anonymized", "deleted"} {
			id := "state-" + status
			if insert("tenant-a", id, status, "1") != nil {
				t.Fatal("valid lifecycle state rejected")
			}
			got, err := repo.Get(ctx, identity.GetUserQuery{TenantID: "tenant-a", UserID: identity.UserID(id)})
			if err != nil || string(got.Status) != status {
				t.Fatal("persisted lifecycle state changed")
			}
		}
		for _, id := range []string{"Shared-user", "01ARZ3NDEKTSV4RRFFQ69G5FAV", "nonbreaking\u00a0space"} {
			if insert("tenant-a", id, "active", "1") != nil {
				t.Fatal("valid canonical ID rejected")
			}
			got, err := repo.Get(ctx, identity.GetUserQuery{TenantID: "tenant-a", UserID: identity.UserID(id)})
			if err != nil || string(got.ID) != id || got.Version != 1 {
				t.Fatal("ID preservation or bytewise uniqueness failed")
			}
		}
	})
	t.Run("public query service composition", func(t *testing.T) {
		authorize, err := authorization.NewDecisionService(integrationAuthorizer{})
		if err != nil {
			t.Fatal("authorization composition failed")
		}
		service, err := identity.NewUserQueryService(repo, authorize,
			func(_ context.Context, in identity.RedactionPolicyInput) (identity.RedactionPolicyDecision, error) {
				return identity.RedactionPolicyDecision{VisibleFields: in.Fields, PolicyID: "integration", PolicyVersion: 1, Reason: "visible"}, nil
			},
			identity.UserQueryConfig{Clock: clock.System{}, MaximumDuration: time.Second, PolicyID: "integration", PolicyVersion: 1, RedactionReasons: []identity.PolicyReason{"visible"}, ValidateCanonicalUserID: func(context.Context, identity.UserID) error { return nil }})
		if err != nil {
			t.Fatal("query service composition failed")
		}
		request := identity.UserGetRequest{TenantID: "tenant-a", UserID: "shared-user", Context: authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: "actor-a"}, Action: "identity.user.get", Tenant: "tenant-a", Resource: authorization.Resource{Type: "identity.user", ID: "shared-user"}}}}
		got, err := service.UserGet(ctx, request)
		if err != nil || got.User.Version != math.MaxUint64 {
			t.Fatal("public service cannot consume durable repository")
		}
		request.Context.Request.Subject.ID = "denied-actor"
		got, err = service.UserGet(ctx, request)
		var forbidden identity.ForbiddenError
		if !errors.As(err, &forbidden) || got != (identity.UserGetResult{}) {
			t.Fatal("denied service returned persisted projection")
		}
	})
	t.Run("schema constraints", func(t *testing.T) {
		cases := [][4]string{
			{"tenant-a", "shared-user", "active", "1"},
			{"", "invalid-a", "active", "1"}, {"bad tenant", "invalid-b", "active", "1"},
			{"tenant-a", "", "active", "1"}, {"tenant-a", strings.Repeat("x", 129), "active", "1"},
			{"tenant-a", strings.Repeat("é", 65), "active", "1"},
			{"tenant-a", "bad\x7fuser", "active", "1"}, {"tenant-a", "bad\nuser", "active", "1"},
			{"tenant-a", "invalid-c", "unknown", "1"},
			{"tenant-a", "invalid-d", "active", "0"}, {"tenant-a", "invalid-e", "active", "-1"},
			{"tenant-a", "invalid-f", "active", "18446744073709551616"},
			{"tenant-a", "invalid-g", "active", "1.5"}, {"tenant-a", "invalid-h", "active", "1.0"},
			{"tenant-a", "invalid-i", "active", "NaN"}, {"tenant-a", "invalid-j", "active", "Infinity"},
		}
		for _, value := range cases {
			err := insert(value[0], value[1], value[2], value[3])
			var failure *pgconn.PgError
			if !errors.As(err, &failure) || failure.Code != "23514" && failure.Code != "23505" {
				t.Fatal("database invariant not enforced")
			}
		}
	})
	t.Run("populated migration replay", func(t *testing.T) {
		result, err := runner.Up(ctx)
		if err != nil || len(result.Records()) != 0 {
			t.Fatal("migration replay changed history")
		}
		got, err := repo.Get(ctx, identity.GetUserQuery{TenantID: "tenant-a", UserID: "shared-user"})
		if err != nil || got.Version != math.MaxUint64 {
			t.Fatal("migration replay damaged data")
		}
		if _, err := runner.Down(ctx, 1); !errors.Is(err, migrations.ErrIrreversible) {
			t.Fatal("destructive downgrade permitted")
		}
	})
	t.Run("query deadline releases connection", func(t *testing.T) {
		lock, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal("lock fixture unavailable")
		}
		defer lock.Rollback(context.Background())
		if _, err = lock.Exec(ctx, "LOCK TABLE identity.users IN ACCESS EXCLUSIVE MODE"); err != nil {
			t.Fatal("lock fixture failed")
		}
		short, stop := context.WithTimeout(ctx, 50*time.Millisecond)
		_, err = repo.Get(short, identity.GetUserQuery{TenantID: "tenant-a", UserID: "shared-user"})
		stop()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("query did not honor deadline")
		}
		if lock.Rollback(ctx) != nil {
			t.Fatal("lock cleanup failed")
		}
		if _, err = repo.Get(ctx, identity.GetUserQuery{TenantID: "tenant-a", UserID: "shared-user"}); err != nil {
			t.Fatal("query connection leaked")
		}
	})
	t.Run("acquisition deadline and pool ownership", func(t *testing.T) {
		a, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatal("first connection unavailable")
		}
		defer a.Release()
		b, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatal("second connection unavailable")
		}
		defer b.Release()
		short, stop := context.WithTimeout(ctx, 50*time.Millisecond)
		_, err = repo.Get(short, identity.GetUserQuery{TenantID: "tenant-a", UserID: "shared-user"})
		stop()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("acquisition did not honor deadline")
		}
		a.Release()
		b.Release()
		if pool.Ping(ctx) != nil {
			t.Fatal("repository closed caller-owned pool")
		}
	})
	t.Run("credential replacement transaction", func(t *testing.T) {
		base := DirectoryAuthorityMigrationSource{Base: CredentialCompromiseMigrationSource{Base: CredentialMigrationSource{Base: StatusMigrationSource{Base: MigrationSource{}, Version: 12}, Version: 13}, Version: 14}, Version: 15, GlobalAuthorityID: "deployment'\\opaque", TenantIDs: []identity.TenantID{"directory"}}
		replacementRunner, e := migrations.NewRunner(CredentialReplacementMigrationSource{Base: base, Version: 16}, backend)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = replacementRunner.Up(ctx); e != nil {
			t.Fatal("replacement migration", e)
		}
		if _, e = replacementRunner.Up(ctx); e != nil {
			t.Fatal("replacement migration replay", e)
		}
		testCredentialReplacement(t, ctx, pool, repo)
	})
	t.Run("credential reset transaction", func(t *testing.T) {
		base := DirectoryAuthorityMigrationSource{Base: CredentialCompromiseMigrationSource{Base: CredentialMigrationSource{Base: StatusMigrationSource{Base: MigrationSource{}, Version: 12}, Version: 13}, Version: 14}, Version: 15, GlobalAuthorityID: "deployment'\\opaque", TenantIDs: []identity.TenantID{"directory"}}
		history := CredentialReplacementMigrationSource{Base: base, Version: 16}
		runner, err := migrations.NewRunner(CredentialResetMigrationSource{Base: history, Version: 17}, backend)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := runner.Up(ctx); err != nil {
			t.Fatal("reset migration", err)
		}
		if _, err := runner.Up(ctx); err != nil {
			t.Fatal("reset migration replay", err)
		}
		testCredentialReset(t, ctx, pool, repo)
	})
}

// This test policy selects the existing upstream authorization.Service seam;
// it is not a replacement policy engine or an authorization interoperability test.
type integrationAuthorizer struct{}

func (integrationAuthorizer) Decide(_ context.Context, r authorization.Request) (authorization.Decision, error) {
	outcome := authorization.Deny
	if r.Subject.ID == "actor-a" && r.Tenant == "tenant-a" && r.Action == "identity.user.get" && r.Resource.ID == "shared-user" {
		outcome = authorization.Allow
	}
	return authorization.Decision{Outcome: outcome, Revision: 1}, nil
}
