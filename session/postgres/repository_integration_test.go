//go:build integration

package postgres

import (
	"context"
	"errors"
	"math"
	"os"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
)

type combinedSource struct{ session MigrationSource }
type fixtureSource []migrations.Migration

func (s fixtureSource) Load(context.Context) ([]migrations.Migration, error) {
	return append([]migrations.Migration(nil), s...), nil
}
func (s combinedSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	// Minimal real parent-table fixture; full kernel composition is a later gate.
	parent, err := migrations.NewMigration(1, "test_identity_parent", migrations.TransactionModeDefault, `CREATE SCHEMA identity;CREATE TABLE identity.users(tenant_id text COLLATE "C",user_id text COLLATE "C",PRIMARY KEY(tenant_id,user_id));`, "")
	if err != nil {
		return nil, err
	}
	child, err := s.session.Load(ctx)
	if err != nil {
		return nil, err
	}
	return append([]migrations.Migration{parent}, child...), nil
}

func TestSessionPostgresIntegration(t *testing.T) {
	dsn := os.Getenv("IDENTITY_SESSION_POSTGRES_TEST_DSN")
	config, err := pgx.ParseConfig(dsn)
	if dsn == "" || err != nil || config.Host != "127.0.0.1" || config.Database != "identity_test" {
		t.Fatal("explicit disposable loopback identity_test required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("isolated cluster unavailable")
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if e := admin.Close(cleanup); e != nil {
			t.Error("admin cleanup failed")
		}
	}()
	id, e := identity.NewSubjectID()
	if e != nil {
		t.Fatal("fixture namespace unavailable")
	}
	name := "session_test_" + string(id)
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatal("fixture creation failed")
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if _, e := admin.Exec(cleanup, "DROP DATABASE "+quoted); e != nil {
			t.Error("fixture database cleanup failed")
		}
	}()
	config.Database = name
	db := stdlib.OpenDB(*config)
	defer db.Close()
	migrate := func(source migrations.Source) {
		t.Helper()
		backend, e := migrationdb.New(db)
		if e != nil {
			t.Fatal(e)
		}
		runner, e := migrations.NewRunner(source, backend)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = runner.Up(ctx); e != nil {
			t.Fatal("migration failed", e)
		}
	}
	// Install parent first, then upgrade the populated database without changing it.
	parent := combinedSource{MigrationSource{Schema: "session_store", Version: 10}}
	all, err := parent.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	migrate(fixtureSource(all[:1]))
	if _, err = db.ExecContext(ctx, `INSERT INTO identity.users VALUES('tenant-a','user-a'),('tenant-b','user-a')`); err != nil {
		t.Fatal("parent fixture failed")
	}
	migrate(parent)
	migrate(parent)
	preAuthHistory, err := (PreAuthMigrationSource{Schema: "session_store", Version: 11}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	migrate(fixtureSource(append(all, preAuthHistory...)))
	checkPreAuthUpgrade := seedPreAuthReleaseUpgrade(t, ctx, db)
	releaseHistory, err := (PreAuthReleaseMigrationSource{Schema: "session_store", Version: 12}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	migrate(fixtureSource(append(append(all, preAuthHistory...), releaseHistory...)))
	checkPreAuthUpgrade()
	pool, err := database.Connect(ctx, database.Config{DSN: dsn, MaxConns: 2, Configure: func(c *database.PoolConfig) error { c.ConnConfig.Database = name; return nil }})
	if err != nil {
		t.Fatal("pool failed")
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if e := pool.Close(cleanup); e != nil {
			t.Error("pool cleanup failed")
		}
	}()
	repo, err := NewRepository(pool, Config{Schema: "session_store", MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	native := testSession(t)
	spec, _ := native.Bindings()
	payload, expiry, err := encodeRecord(native)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.ExecContext(ctx, `INSERT INTO session_store.families VALUES('tenant-a','family-a','user-a',$1,'active',$2)`, "18446744073709551615", spec.IssuedAt.UTC().Format(storedTimeLayout))
	if err != nil {
		t.Fatal("family insert", err)
	}
	insert := `INSERT INTO session_store.sessions(tenant_id,session_id,user_id,family_id,version,family_version,state,digest_version,digest,expires_at,record) VALUES('tenant-a','session-a','user-a','family-a',$1,$1,'active',$2,$3,$4,$5)`
	if _, err = db.ExecContext(ctx, insert, "18446744073709551615", int64(spec.Lookup.KeyVersion), spec.Lookup.Sum[:], expiry, payload); err != nil {
		t.Fatal("session insert", err)
	}
	got, err := repo.Lookup(ctx, "tenant-a", spec.Lookup)
	if err != nil || got.Revoked || got.FamilyRevoked || got.CurrentFamilyVersion != math.MaxUint64 {
		t.Fatal("primary lookup failed", err)
	}
	recovered, _ := got.Session.Bindings()
	a, _ := recovered.Authority.Bindings()
	want, _ := spec.Authority.Bindings()
	if a != want || !recovered.IssuedAt.Equal(spec.IssuedAt) || recovered.Remember != spec.Remember || recovered.Authentication != spec.Authentication {
		t.Fatal("database precision or authority lost")
	}
	if _, err = repo.Lookup(ctx, "tenant-b", spec.Lookup); !errors.Is(err, ErrRecordAbsent) {
		t.Fatal("cross-tenant digest lookup escaped")
	}
	if _, err = repo.Get(ctx, "tenant-b", "session-a"); !errors.Is(err, ErrRecordAbsent) {
		t.Fatal("cross-tenant ID lookup escaped")
	}
	if _, err = repo.Get(ctx, "tenant-a", "session-a"); err != nil {
		t.Fatal("ID reconstruction failed", err)
	}
	csrfHistory, err := (CSRFMigrationSource{Schema: "session_store", Version: 13}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fullHistory := append(append(append(append([]migrations.Migration(nil), all...), preAuthHistory...), releaseHistory...), csrfHistory...)
	migrate(fixtureSource(fullHistory))
	migrate(fixtureSource(fullHistory))
	upgradedRecord, err := repo.Get(ctx, "tenant-a", "session-a")
	if err != nil {
		t.Fatal("populated legacy record lost during CSRF upgrade", err)
	}
	upgradedPayload, _, err := encodeRecord(upgradedRecord.Session)
	if err != nil || string(upgradedPayload) != string(payload) {
		t.Fatal("upgrade rewrote legacy recovery bytes", err)
	}
	otpHistory, err := (OTPMigrationSource{Schema: "session_store", Version: 14}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fullHistory = append(fullHistory, otpHistory...)
	migrate(fixtureSource(fullHistory))
	migrate(fixtureSource(fullHistory))
	upgradedRecord, err = repo.Get(ctx, "tenant-a", "session-a")
	if err != nil {
		t.Fatal("populated legacy record lost during OTP upgrade", err)
	}
	upgradedPayload, _, err = encodeRecord(upgradedRecord.Session)
	if err != nil || string(upgradedPayload) != string(payload) {
		t.Fatal("OTP upgrade rewrote legacy recovery bytes", err)
	}
	continuationHistory, err := (CredentialContinuationMigrationSource{Schema: "session_store", Version: 15}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fullHistory = append(fullHistory, continuationHistory...)
	migrate(fixtureSource(fullHistory))
	migrate(fixtureSource(fullHistory))
	upgradedRecord, err = repo.Get(ctx, "tenant-a", "session-a")
	if err != nil {
		t.Fatal("populated legacy record lost during continuation upgrade", err)
	}
	upgradedPayload, _, err = encodeRecord(upgradedRecord.Session)
	if err != nil || string(upgradedPayload) != string(payload) {
		t.Fatal("continuation upgrade rewrote legacy recovery bytes", err)
	}
	magicLinkHistory, err := (MagicLinkMigrationSource{Schema: "session_store", Version: 16}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fullHistory = append(fullHistory, magicLinkHistory...)
	migrate(fixtureSource(fullHistory))
	migrate(fixtureSource(fullHistory))
	upgradedRecord, err = repo.Get(ctx, "tenant-a", "session-a")
	if err != nil {
		t.Fatal("magic-link upgrade lost legacy record", err)
	}
	upgradedPayload, _, err = encodeRecord(upgradedRecord.Session)
	if err != nil || string(upgradedPayload) != string(payload) {
		t.Fatal("magic-link upgrade rewrote legacy bytes", err)
	}
	mfaHistory, err := (MFAMigrationSource{Schema: "session_store", Version: 17}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fullHistory = append(fullHistory, mfaHistory...)
	migrate(fixtureSource(fullHistory))
	migrate(fixtureSource(fullHistory))
	upgradedRecord, err = repo.Get(ctx, "tenant-a", "session-a")
	if err != nil {
		t.Fatal("MFA upgrade lost legacy record", err)
	}
	upgradedPayload, _, err = encodeRecord(upgradedRecord.Session)
	if err != nil || string(upgradedPayload) != string(payload) {
		t.Fatal("MFA upgrade rewrote legacy recovery bytes", err)
	}
	t.Run("complete MFA primary record", func(t *testing.T) { testMFAPrimaryRecord(t, ctx, pool) })
	t.Run("complete MFA issuance purposes", func(t *testing.T) { testMFASigninPurposes(t, ctx, pool) })
	t.Run("verification signin migration", func(t *testing.T) { testVerificationSigninMigration(t, ctx, pool) })
	t.Run("complete OTP primary record", func(t *testing.T) { testOTPPrimaryRecord(t, ctx, pool) })
	t.Run("complete magic-link primary record", func(t *testing.T) { testMagicLinkPrimaryRecord(t, ctx, pool) })
	t.Run("complete continued primary record", func(t *testing.T) { testContinuedPrimaryRecord(t, ctx, pool, native) })
	t.Run("canonical pre-auth", func(t *testing.T) { testNativePreAuth(t, ctx, pool) })
	t.Run("borrowed session admission", func(t *testing.T) { testSessionAdmission(t, ctx, pool, native) })
	t.Run("complete CSRF primary record", func(t *testing.T) { testCSRFPrimaryRecord(t, ctx, pool, native) })
	t.Run("transactional CSRF enforcement", func(t *testing.T) { testCSRFFencedMutation(t, ctx, pool, native) })
	t.Run("native identifier session projection", func(t *testing.T) { testIdentifierSessionProjection(t, ctx, pool) })
	t.Run("native privacy session projection", func(t *testing.T) { testPrivacySessionProjection(t, ctx, pool) })
	canceled, stop := context.WithCancel(ctx)
	stop()
	var cancelled identity.CancelledError
	if _, err = repo.Get(canceled, "tenant-a", "session-a"); !errors.As(err, &cancelled) {
		t.Fatal("cancellation lost")
	}
	if _, err = repo.Lookup(ctx, "tenant-a", session.TokenDigest{}); err == nil {
		t.Fatal("zero digest accepted")
	}
	for _, pair := range [][2]string{{"", "session-a"}, {"tenant-a", ""}, {"bad tenant", "session-a"}} {
		if _, err = repo.Get(ctx, identity.TenantID(pair[0]), pair[1]); err == nil {
			t.Fatal("invalid read scope accepted")
		}
	}
	var deadline identity.DeadlineExceededError
	timed, release := context.WithDeadline(ctx, time.Now().Add(-time.Second))
	defer release()
	if _, err = repo.Get(timed, "tenant-a", "session-a"); !errors.As(err, &deadline) {
		t.Fatal("expired deadline lost")
	}
	var zero *Repository
	if _, err = zero.Get(ctx, "tenant-a", "session-a"); err == nil {
		t.Fatal("zero repository accepted")
	}
	// Saturating the real pool must honor the caller's shorter acquisition bound.
	one, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal("first lease failed")
	}
	two, err := pool.Acquire(ctx)
	if err != nil {
		one.Release()
		t.Fatal("second lease failed")
	}
	short, shortStop := context.WithTimeout(ctx, 10*time.Millisecond)
	_, err = repo.Get(short, "tenant-a", "session-a")
	shortStop()
	one.Release()
	two.Release()
	if !errors.As(err, &deadline) {
		t.Fatal("pool wait exceeded deadline")
	}
	for _, bad := range []Config{{}, {Schema: "public", MaximumDuration: time.Second}, {Schema: "session_store", MaximumDuration: time.Minute + 1}} {
		if _, e := NewRepository(pool, bad); e == nil {
			t.Fatal("invalid repository config accepted")
		}
	}
	// Tombstones survive reload and are never reconstructed as fresh authority.
	if _, err = db.ExecContext(ctx, `UPDATE session_store.families SET state='revoked' WHERE tenant_id='tenant-a';UPDATE session_store.sessions SET state='revoked' WHERE tenant_id='tenant-a'`); err != nil {
		t.Fatal(err)
	}
	got, err = repo.Get(ctx, "tenant-a", "session-a")
	if err != nil || !got.Revoked || !got.FamilyRevoked {
		t.Fatal("revocation tombstones disappeared")
	}
	// Same indexed digest cannot become another session in the tenant.
	other := spec
	other.SessionID = "session-b"
	otherAuthority, _ := other.Authority.Bindings()
	otherAuthority.Session.ScopeKey = "session:tenant-a:session-b"
	other.Authority, err = session.NewAuthoritySnapshot(otherAuthority)
	if err != nil {
		t.Fatal("second record vector failed")
	}
	otherSession, err := session.NewSession(other)
	if err != nil {
		t.Fatal("second native record failed")
	}
	otherPayload, otherExpiry, err := encodeRecord(otherSession)
	if err != nil {
		t.Fatal("second projection failed")
	}
	secondInsert := `INSERT INTO session_store.sessions(tenant_id,session_id,user_id,family_id,version,family_version,state,digest_version,digest,expires_at,record) VALUES('tenant-a','session-b','user-a','family-a',$1,$1,'active',$2,$3,$4,$5)`
	_, err = db.ExecContext(ctx, secondInsert, "18446744073709551615", int64(spec.Lookup.KeyVersion), spec.Lookup.Sum[:], otherExpiry, otherPayload)
	var uniqueness *pgconn.PgError
	if !errors.As(err, &uniqueness) || uniqueness.Code != "23505" || uniqueness.ConstraintName != "sessions_tenant_id_digest_version_digest_key" {
		t.Fatal("digest uniqueness was not the rejecting constraint")
	}
	if _, err = db.ExecContext(ctx, `UPDATE session_store.sessions SET version=1.1 WHERE tenant_id='tenant-a'`); err == nil {
		t.Fatal("fractional version rounded")
	}
	if _, err = db.ExecContext(ctx, `UPDATE session_store.sessions SET record=jsonb_set(record,'{Authority,Passkey}', 'null') WHERE tenant_id='tenant-a'`); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.Get(ctx, "tenant-a", "session-a"); !errors.Is(err, ErrInvalidRecord) {
		t.Fatal("partial authority snapshot admitted", err)
	}
	if _, err = db.ExecContext(ctx, `UPDATE session_store.sessions SET record=$1::jsonb WHERE tenant_id='tenant-a'`, payload); err != nil {
		t.Fatal("restore fixture failed")
	}
	for _, statement := range []string{
		`UPDATE session_store.sessions SET expires_at='2026-10-03T01:00:00.123456791Z' WHERE tenant_id='tenant-a'`,
		`UPDATE session_store.sessions SET expires_at='2026-10-03T01:00:00.123456790Z',digest=decode(repeat('02',32),'hex') WHERE tenant_id='tenant-a'`,
	} {
		if _, err = db.ExecContext(ctx, statement); err != nil {
			t.Fatal("corruption fixture failed")
		}
		if _, err = repo.Get(ctx, "tenant-a", "session-a"); !errors.Is(err, ErrInvalidRecord) {
			t.Fatal("indexed projection drift accepted")
		}
	}
	// Bounded primary query; after a connection failure no driver diagnostic leaks.
	if _, err = repo.Get(nil, "tenant-a", "session-a"); err == nil {
		t.Fatal("nil context accepted")
	}
	var count int
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM identity.users`).Scan(&count); err != nil || count != 2 {
		t.Fatal("populated parent migration changed users")
	}
	cleanup, done := context.WithTimeout(context.Background(), 3*time.Second)
	if err = pool.Close(cleanup); err != nil {
		done()
		t.Fatal("owned lease leaked")
	}
	done()
	var unavailable identity.UnavailableError
	if _, err = repo.Get(ctx, "tenant-a", "session-a"); !errors.As(err, &unavailable) {
		t.Fatal("closed pool driver error escaped")
	}
}
