//go:build integration

package passwordpostgres_test

import (
	"context"
	"errors"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	password "github.com/faustbrian/go-identity/password"
	passworddb "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	primitive "github.com/faustbrian/go-password"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestPrimaryPasswordCredentialIntegration(t *testing.T) {
	port, passwordFile := os.Getenv("IDENTITY_REFERENCE_POSTGRES_PORT"), os.Getenv("IDENTITY_REFERENCE_PASSWORD_FILE")
	credential, err := os.ReadFile(passwordFile)
	if err != nil || port == "" || passwordFile == "" {
		t.Fatal("disposable loopback PostgreSQL required")
	}
	dsn := (&url.URL{Scheme: "postgres", User: url.UserPassword("postgres", strings.TrimSpace(string(credential))), Host: net.JoinHostPort("127.0.0.1", port), Path: "/identity_test", RawQuery: "sslmode=disable"}).String()
	clear(credential)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid disposable connection")
	}
	db := stdlib.OpenDB(*config)
	defer db.Close()
	backend, err := migrationdb.New(db)
	if err != nil {
		t.Fatal("migration backend unavailable")
	}
	base := kernel.CredentialReplacementMigrationSource{Base: kernel.CredentialMigrationSource{Base: kernel.StatusMigrationSource{Base: kernel.MigrationSource{}, Version: 10}, Version: 11}, Version: 12}
	runner, err := migrations.NewRunner(base, backend)
	if err != nil {
		t.Fatal("kernel history unavailable")
	}
	if _, err = runner.Up(ctx); err != nil {
		t.Fatal("kernel install failed")
	}
	owned, err := backend.ForNamespace("identity_password")
	if err != nil {
		t.Fatal("password history unavailable")
	}
	runner, err = migrations.NewRunner(passwordMaterialHistory{}, owned)
	if err != nil {
		t.Fatal("password history unavailable")
	}
	if _, err = runner.Up(ctx); err != nil {
		t.Fatal("password install failed")
	}
	if _, err = runner.Up(ctx); err != nil {
		t.Fatal("password replay failed")
	}
	pool, err := database.Connect(ctx, database.Config{DSN: dsn, MaxConns: 3})
	if err != nil {
		t.Fatal("primary unavailable")
	}
	defer func() {
		stop, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if pool.Close(stop) != nil {
			t.Error("pool cleanup failed")
		}
	}()
	limits := primitive.Limits{PasswordBytes: 128, EncodedHashBytes: 256, Argon2Time: 2, MemoryKiB: 16, Parallelism: 1, SaltBytes: 16, OutputBytes: 32, BcryptCost: 4, Concurrent: 2, Queue: 2}
	policy, err := primitive.NewPolicy(primitive.PolicyConfig{Algorithm: primitive.Argon2id, Argon2id: primitive.Argon2idParameters{Version: 19, Time: 1, MemoryKiB: 8, Parallelism: 1, SaltLength: 8, OutputLength: 16}, Limits: limits})
	if err != nil {
		t.Fatal("test policy unavailable")
	}
	crypto, err := primitive.New(policy)
	if err != nil {
		t.Fatal("test crypto unavailable")
	}
	hash, err := crypto.Hash(ctx, []byte("synthetic-test-password"))
	if err != nil {
		t.Fatal("synthetic material unavailable")
	}
	_, err = pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('tenant-a','user-a','active',3),('tenant-b','user-a','banned',4);
INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES('tenant-a','user-a','password-a',1,'identity/password',7,true),('tenant-b','user-a','password-a',1,'identity/password',8,true)`)
	if err != nil {
		t.Fatal("kernel fixture failed")
	}
	_, err = pool.Raw().Exec(ctx, `INSERT INTO identity_password.credentials(tenant_id,user_id,credential_id,version,algorithm,encoded_hash) VALUES('tenant-a','user-a','password-a',7,'argon2id',$1),('tenant-b','user-a','password-a',8,'argon2id',$1)`, hash.String())
	if err != nil {
		t.Fatal("password fixture failed")
	}
	// Upgrade installed version1 with populated material. Its checksum and
	// credential bytes must survive the additive retained-effect history.
	runner, err = migrations.NewRunner(passworddb.MigrationSource{}, owned)
	if err != nil {
		t.Fatal("password upgrade history unavailable")
	}
	if _, err = runner.Up(ctx); err != nil {
		t.Fatal("populated password upgrade failed")
	}
	if _, err = runner.Up(ctx); err != nil {
		t.Fatal("password upgrade replay failed")
	}
	repo, err := passworddb.NewRepository(pool, passworddb.Config{MaximumDuration: time.Second, HashPolicy: policy})
	if err != nil {
		t.Fatal("password reader unavailable")
	}
	var portContract password.CredentialVerificationRepository = repo
	key := password.CredentialKey{TenantID: "tenant-a", SubjectID: "user-a"}
	got, err := portContract.ReadPasswordCredential(ctx, key)
	if err != nil || got.EncodedHash().String() != hash.String() || got.Authority().Credential.Version != 7 || got.Authority().User.Version != 3 {
		t.Fatal("exact primary credential roundtrip failed")
	}
	secret, _ := primitive.NewSecret([]byte("synthetic-test-password"))
	defer secret.Destroy()
	verifier, err := password.NewPasswordVerifier(password.VerifierConfig{Primitive: crypto, Repository: repo, MaximumBytes: 128, Timeout: time.Second, DummyHash: hash, Now: time.Now})
	if err != nil {
		t.Fatal("core composition unavailable")
	}
	result, err := verifier.VerifyPassword(ctx, password.VerifyPasswordRequest{TenantID: key.TenantID, SubjectID: key.SubjectID, Password: secret})
	if err != nil || !result.Matched || result.CredentialVersion != 7 {
		t.Fatal("public core did not consume real primary credential")
	}
	result, err = verifier.VerifyPassword(ctx, password.VerifyPasswordRequest{TenantID: "tenant-b", SubjectID: key.SubjectID, Password: secret})
	if err != nil || result.Matched {
		t.Fatal("blocked foreign tenant authenticated")
	}
	testNativePasswordReplacement(t, ctx, pool, policy, hash)
	testNativeReauthenticationRead(t, ctx, pool, repo)
	_, err = repo.ReadPasswordCredential(ctx, password.CredentialKey{TenantID: "absent", SubjectID: key.SubjectID})
	if !errors.Is(err, password.ErrCredentialAbsent) {
		t.Fatal("missing scope not classified")
	}
	if _, err = pool.Raw().Exec(ctx, `UPDATE identity.credential_references SET enabled=false WHERE tenant_id='tenant-a'`); err != nil {
		t.Fatal("disable fixture failed")
	}
	got, err = repo.ReadPasswordCredential(ctx, key)
	if err != nil || got.Authority().Enabled {
		t.Fatal("disabled credential restored")
	}
	if _, err = pool.Raw().Exec(ctx, `UPDATE identity.credential_references SET version=9 WHERE tenant_id='tenant-a'`); err != nil {
		t.Fatal("version fixture failed")
	}
	got, err = repo.ReadPasswordCredential(ctx, key)
	if !errors.Is(err, password.ErrPasswordWork) || got.EncodedHash().String() != "" {
		t.Fatal("inconsistent version granted partial material")
	}
	stopped, stop := context.WithCancel(ctx)
	stop()
	_, err = repo.ReadPasswordCredential(stopped, key)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("read cancellation lost")
	}
	if _, err = pool.Raw().Exec(ctx, `INSERT INTO identity_password.credentials(tenant_id,user_id,credential_id,version,algorithm,encoded_hash) VALUES('tenant-a','user-a','password-a',7,'argon2id',$1)`, hash.String()); err == nil {
		t.Fatal("duplicate account credential accepted")
	}
	if _, err = pool.Raw().Exec(ctx, `INSERT INTO identity_password.credentials(tenant_id,user_id,credential_id,version,algorithm,encoded_hash) VALUES('tenant-missing','user-missing','password-missing',1,'argon2id',$1)`, hash.String()); err == nil {
		t.Fatal("orphan material accepted")
	}
	if _, err = pool.Raw().Exec(ctx, `UPDATE identity.credential_references SET version=7 WHERE tenant_id='tenant-a'`); err != nil {
		t.Fatal("corruption setup failed")
	}
	for _, sql := range []string{
		`UPDATE identity_password.credentials SET algorithm='bcrypt' WHERE tenant_id='tenant-a'`,
		`UPDATE identity_password.credentials SET encoded_hash='malformed' WHERE tenant_id='tenant-a'`,
		`UPDATE identity_password.credentials SET encoded_hash=repeat('x',257) WHERE tenant_id='tenant-a'`,
	} {
		if _, err = pool.Raw().Exec(ctx, sql); err != nil {
			t.Fatal("corruption fixture failed")
		}
		got, err = repo.ReadPasswordCredential(ctx, key)
		if !errors.Is(err, password.ErrPasswordWork) || got.EncodedHash().String() != "" {
			t.Fatal("corrupt primary material granted snapshot")
		}
		if _, err = pool.Raw().Exec(ctx, `UPDATE identity_password.credentials SET algorithm='argon2id',encoded_hash=$1 WHERE tenant_id='tenant-a'`, hash.String()); err != nil {
			t.Fatal("corruption fixture restoration failed")
		}
	}
	// A complete writer changes both material/reference versions and the user
	// credential epoch together. Readers must not combine two committed states.
	write := func(version uint64) error {
		tx, err := pool.Raw().Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)
		v := strconv.FormatUint(version, 10)
		if _, err = tx.Exec(ctx, `UPDATE identity.users SET credential_version=$1::numeric WHERE tenant_id='tenant-a';`, v); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE identity.credential_references SET version=$1::numeric WHERE tenant_id='tenant-a'`, v); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE identity_password.credentials SET version=$1::numeric WHERE tenant_id='tenant-a'`, v); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	if write(100) != nil {
		t.Fatal("snapshot consistency setup failed")
	}
	done := make(chan error, 1)
	go func() {
		for version := uint64(101); version <= 116; version++ {
			if err := write(version); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	consistent := true
	for range 40 {
		value, readErr := repo.ReadPasswordCredential(ctx, key)
		if readErr != nil || value.Authority().Credential.Version != value.Authority().AuthorityVersion {
			consistent = false
		}
	}
	if <-done != nil || !consistent {
		t.Fatal("primary joined snapshot mixed concurrent commits")
	}
	if write(^uint64(0)) != nil {
		t.Fatal("maximum version fixture failed")
	}
	got, err = repo.ReadPasswordCredential(ctx, key)
	if err != nil || got.Authority().Credential.Version != ^uint64(0) {
		t.Fatal("native uint64 version narrowed")
	}
	locked, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal("lock fixture unavailable")
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := locked.Rollback(cleanup); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Error("lock cleanup failed")
		}
	}()
	if _, err = locked.Exec(ctx, `LOCK TABLE identity_password.credentials IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal("lock fixture failed")
	}
	limited, err := passworddb.NewRepository(pool, passworddb.Config{MaximumDuration: 20 * time.Millisecond, HashPolicy: policy})
	if err != nil {
		t.Fatal("bounded read fixture unavailable")
	}
	got, err = limited.ReadPasswordCredential(ctx, key)
	if !errors.Is(err, context.DeadlineExceeded) || got.EncodedHash().String() != "" {
		t.Fatal("blocked read did not retain bounded deadline")
	}
	if locked.Rollback(ctx) != nil {
		t.Fatal("lock cleanup failed")
	}
	if _, err = repo.ReadPasswordCredential(ctx, key); err != nil {
		t.Fatal("reader failed after lock rollback")
	}
}

type passwordMaterialHistory struct{}

func (passwordMaterialHistory) Load(ctx context.Context) ([]migrations.Migration, error) {
	all, err := (passworddb.MigrationSource{}).Load(ctx)
	if err != nil {
		return nil, err
	}
	return all[:1], nil
}
