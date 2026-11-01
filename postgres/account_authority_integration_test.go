//go:build integration

package postgres

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// These rows are storage fixtures, not provider identity proof or an account
// linking workflow. The consumer journey must use the actual protected owner.
func newAccountAuthorityStore(t *testing.T) (context.Context, *database.Pool, *Repository) {
	t.Helper()
	ctx, stop := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(stop)
	dsn, directory := os.Getenv("IDENTITY_POSTGRES_TEST_DSN"), os.Getenv("IDENTITY_POSTGRES_TEST_DATA_DIRECTORY")
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil || dsn == "" || cfg.Host != "127.0.0.1" || cfg.Database != "identity_test" || !filepath.IsAbs(directory) {
		t.Fatal("explicit task-owned loopback cluster required")
	}
	admin, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal("task-owned cluster unavailable")
	}
	t.Cleanup(func() {
		bounded, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := admin.Close(bounded); err != nil {
			t.Error("admin cleanup failed")
		}
	})
	var actualDirectory string
	if err := admin.QueryRow(ctx, "SHOW data_directory").Scan(&actualDirectory); err != nil || actualDirectory != directory {
		t.Fatal("cluster is not the exact owned fixture")
	}
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	name := "account_" + string(id)
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		bounded, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := admin.Exec(bounded, "DROP DATABASE "+quoted); err != nil {
			t.Error("owned database cleanup failed")
		}
	})
	cfg.Database = name
	sqlDB := stdlib.OpenDB(*cfg)
	t.Cleanup(func() { _ = sqlDB.Close() })
	backend, err := migrationdb.New(sqlDB)
	if err != nil {
		t.Fatal(err)
	}
	base := CredentialMigrationSource{Base: StatusMigrationSource{Base: MigrationSource{}, Version: 10}, Version: 11}
	runner, err := migrations.NewRunner(base, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(ctx); err != nil {
		t.Fatal("existing history", err)
	}
	pool, err := database.Connect(ctx, database.Config{DSN: dsn, MaxConns: 2, Configure: func(c *database.PoolConfig) error { c.ConnConfig.Database = name; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		bounded, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := pool.Close(bounded); err != nil {
			t.Error("pool cleanup failed")
		}
	})
	exec := func(sql string, args ...any) error {
		_, err := pool.Raw().Exec(ctx, sql, args...)
		return err
	}
	if err := exec(`INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES ('tenant-a','owner','active',1),('tenant-a','other','active',1),('tenant-b','owner','banned',1)`); err != nil {
		t.Fatal(err)
	}
	upgraded, err := migrations.NewRunner(AccountMigrationSource{Base: base, Version: 12}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := upgraded.Up(ctx); err != nil {
		t.Fatal("populated account upgrade", err)
	}
	repo, err := NewRepository(pool, Config{MaximumDuration: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return ctx, pool, repo
}

func TestAccountAuthorityStorage(t *testing.T) {
	ctx, pool, repo := newAccountAuthorityStore(t)
	exec := func(sql string, args ...any) error {
		_, err := pool.Raw().Exec(ctx, sql, args...)
		return err
	}
	query := identity.AccountQuery{TenantID: "tenant-a", UserID: "owner", MaximumAccounts: 100}
	empty, err := repo.ListAccounts(ctx, query)
	if err != nil || empty.User.Version != 1 || len(empty.Accounts) != 0 {
		t.Fatal("populated user lost or empty account scope invented", err)
	}
	account := identity.Account{ID: "account", TenantID: "tenant-a", UserID: "owner", Provider: "oidc-local", Issuer: "https://issuer.example", Subject: "provider-user", Version: 1}
	linkQuery := identity.AccountLinkQuery{Account: account, Mode: identity.AccountLinkExplicit}
	state, err := repo.GetAccountLinkState(ctx, linkQuery)
	if err != nil || state.Candidate != account || state.Access.User != empty.User || state.RecordVersion != 0 || state.SocialLinkVersion != 1 || state.CredentialVersion != 1 || state.SubjectOwner != nil {
		t.Fatal("first link authority snapshot", err)
	}
	insert := func(a identity.Account, linked bool, socialVersion uint64) error {
		return exec(`INSERT INTO identity.accounts(tenant_id,user_id,account_id,provider,issuer,subject,subject_key,version,social_link_version,linked) VALUES($1,$2,$3,$4::text,$5::text,$6::text,sha256(convert_to(octet_length($4::text)::text||':'||$4::text||octet_length($5::text)::text||':'||$5::text||octet_length($6::text)::text||':'||$6::text,'UTF8')),$7::numeric,$8::numeric,$9)`, string(a.TenantID), string(a.UserID), string(a.ID), a.Provider, a.Issuer, a.Subject, a.Version, socialVersion, linked)
	}
	if err := insert(account, true, 2); err != nil {
		t.Fatal(err)
	}
	foreign := account
	foreign.TenantID = "tenant-b"
	if err := insert(foreign, true, 2); err != nil {
		t.Fatal("tenant-scoped provider subject", err)
	}
	collision := account
	collision.ID, collision.UserID = "other-account", "other"
	if err := insert(collision, true, 2); err == nil {
		t.Fatal("duplicate provider subject accepted")
	}
	state, err = repo.GetAccountLinkState(ctx, identity.AccountLinkQuery{Account: collision, Mode: identity.AccountLinkExplicit})
	if err != nil || state.SubjectOwner == nil || *state.SubjectOwner != account || state.Access.User.ID != "other" {
		t.Fatal("collision lookup confused ownership or absence", err)
	}
	long := account
	// Incompressible bounded values expose oversized tuple indexes that repeated
	// characters can hide through PostgreSQL TOAST compression.
	noise := make([]byte, 1300)
	if _, err := rand.Read(noise); err != nil {
		t.Fatal("boundary fixture entropy")
	}
	encoded := hex.EncodeToString(noise)
	long.ID, long.Issuer, long.Subject = "long-account", "https://issuer.example/"+encoded[:1950], encoded[1950:2462]
	if err := long.Validate(long.TenantID, long.UserID); err != nil {
		t.Fatal("boundary fixture invalid", err)
	}
	if err := insert(long, true, 2); err != nil {
		t.Fatal("valid bounded provider tuple could not be stored", err)
	}
	// Exercise all bounded tuple components together, not only an issuer whose
	// combined key could still fit a normal B-tree entry.
	wide := long
	wide.TenantID, wide.UserID, wide.Provider = identity.TenantID(strings.Repeat("t", 128)), "wide-user", strings.Repeat("p", 128)
	wide.Issuer = "https://issuer.example/" + encoded[:2048-len("https://issuer.example/")]
	if err := exec(`INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,$2,'active',1)`, string(wide.TenantID), string(wide.UserID)); err != nil {
		t.Fatal("wide user fixture", err)
	}
	if err := insert(wide, true, 2); err != nil {
		t.Fatal("maximum public tuple could not be stored", err)
	}
	wideState, err := repo.GetAccountLinkState(ctx, identity.AccountLinkQuery{Account: wide, Mode: identity.AccountLinkExplicit})
	if err != nil || wideState.SubjectOwner == nil || *wideState.SubjectOwner != wide {
		t.Fatal("maximum tuple did not round trip exactly", err)
	}
	if err := exec(`INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES('tenant-a','owner','password',1,'identity/password',7,true),('tenant-a','owner','provider',3,'identity/oauth',11,true);
 INSERT INTO identity.account_credentials(tenant_id,user_id,credential_id,account_id) VALUES('tenant-a','owner','provider','account')`); err != nil {
		t.Fatal("credential association fixtures", err)
	}
	state, err = repo.GetAccountLinkState(ctx, linkQuery)
	if err != nil || len(state.Access.Methods) != 2 || state.Access.Methods[0].Credential.ID != "password" || state.Access.Methods[0].AccountID != "" || state.Access.Methods[1].Credential.ID != "provider" || state.Access.Methods[1].AccountID != "account" {
		t.Fatal("current credential ownership or association lost", err)
	}
	for _, m := range state.Access.Methods {
		if m.Usable {
			t.Fatal("metadata reader invented feature/factor eligibility")
		}
	}
	for _, version := range []uint64{1<<53 + 1, 1 << 63, math.MaxUint64} {
		v := strconv.FormatUint(version, 10)
		if err := exec(`UPDATE identity.users SET version=$1::numeric,credential_version=$1::numeric WHERE tenant_id='tenant-a' AND user_id='owner'`, v); err != nil {
			t.Fatal(err)
		}
		if err := exec(`UPDATE identity.accounts SET version=$1::numeric,social_link_version=$1::numeric WHERE tenant_id='tenant-a' AND account_id='account'`, v); err != nil {
			t.Fatal(err)
		}
		if err := exec(`UPDATE identity.credential_references SET version=$1::numeric WHERE tenant_id='tenant-a' AND user_id='owner'`, v); err != nil {
			t.Fatal(err)
		}
		state, err = repo.GetAccountLinkState(ctx, linkQuery)
		if err != nil || state.Access.User.Version != version || state.RecordVersion != version || state.SocialLinkVersion != version || state.CredentialVersion != version || len(state.Access.Methods) != 2 || state.Access.Methods[0].Credential.Version != version {
			t.Fatal("security version rounded or narrowed", err)
		}
	}
	query.MaximumAccounts = 1
	partial, err := repo.ListAccounts(ctx, query)
	var unavailable identity.UnavailableError
	if !errors.As(err, &unavailable) || partial.User.ID != "" || len(partial.Accounts) != 0 {
		t.Fatal("bounded account projection silently truncated", err)
	}
	if err := exec(`UPDATE identity.credential_references SET enabled=false WHERE tenant_id='tenant-a' AND user_id='owner' AND credential_id='provider'; UPDATE identity.accounts SET linked=false,version=2,social_link_version=3 WHERE tenant_id='tenant-a' AND account_id='account'`); err != nil {
		t.Fatal(err)
	}
	state, err = repo.GetAccountLinkState(ctx, linkQuery)
	if err != nil || state.RecordVersion != 2 || state.SocialLinkVersion != 3 || state.SubjectOwner != nil || len(state.Access.Accounts) != 1 || state.Access.Accounts[0].ID != long.ID {
		t.Fatal("unlink tombstone lost or returned as live link", err)
	}
	if len(state.Access.Methods) != 1 || state.Access.Methods[0].Credential.ID != "password" {
		t.Fatal("retired provider reference was restored as a linked login method")
	}
	missing := query
	missing.TenantID, missing.MaximumAccounts = "absent-tenant", 100
	if out, err := repo.ListAccounts(ctx, missing); !errors.Is(err, identity.ErrUserAbsent) || out.User.ID != "" {
		t.Fatal("foreign scope fabricated accounts", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if out, err := repo.GetAccountLinkState(cancelled, linkQuery); !errors.Is(err, context.Canceled) || out.Access.User.ID != "" {
		t.Fatal("cancelled lookup returned authority", err)
	}
	for _, invalid := range []identity.AccountQuery{{}, {TenantID: "tenant-a", UserID: "owner", MaximumAccounts: 0}, {TenantID: "tenant-a", UserID: "owner", MaximumAccounts: 101}} {
		var input identity.InvalidInputError
		if out, err := repo.ListAccounts(ctx, invalid); !errors.As(err, &input) || out.User.ID != "" || out.Accounts != nil {
			t.Fatal("invalid account query returned partial state", err)
		}
	}
	if out, err := repo.ListAccounts(nil, query); err == nil || out.User.ID != "" {
		t.Fatal("nil context reached account storage")
	}
	if out, err := repo.GetAccountLinkState(nil, linkQuery); err == nil || out.Access.User.ID != "" {
		t.Fatal("nil context reached link storage")
	}
	// The bound is on current login methods, not the lifetime of retained unlink
	// history. Repeated safe unlink must not eventually prevent another link.
	if err := exec(`WITH old AS (SELECT 'retired-'||i::text AS id,'retired-subject-'||i::text AS subject FROM generate_series(1,128) i)
 INSERT INTO identity.accounts(tenant_id,user_id,account_id,provider,issuer,subject,subject_key,version,social_link_version,linked)
 SELECT 'tenant-a','owner',id,'oidc-local','https://issuer.example',subject,
 sha256(convert_to('10:oidc-local22:https://issuer.example'||octet_length(subject)::text||':'||subject,'UTF8')),2,3,false FROM old;
 INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled)
 SELECT 'tenant-a','owner','retired-'||i::text,3,'identity/oauth',1,false FROM generate_series(1,128) i;
 INSERT INTO identity.account_credentials(tenant_id,user_id,credential_id,account_id)
 SELECT 'tenant-a','owner','retired-'||i::text,'retired-'||i::text FROM generate_series(1,128) i`); err != nil {
		t.Fatal("retained unlink fixtures", err)
	}
	if out, err := repo.GetAccountLinkState(ctx, linkQuery); err != nil || len(out.Access.Methods) != 1 || out.Access.Methods[0].Credential.ID != "password" {
		t.Fatal("retained unlink history exhausted the current-method budget", err)
	}
	for _, retired := range []struct {
		name, owner string
		kind        int16
	}{{"passkey", "passkey", 2}, {"password", "identity/password", 1}, {"apikey", "identity/apikey", 4}} {
		if err := exec(`INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled)
 SELECT 'tenant-a','owner',$1::text||'-retired-'||i::text,$2,$3,1,false FROM generate_series(1,128) i`, retired.name, retired.kind, retired.owner); err != nil {
			t.Fatal("retained credential fixtures", err)
		}
		if out, err := repo.GetAccountLinkState(ctx, linkQuery); err != nil || len(out.Access.Methods) != 1 || out.Access.Methods[0].Credential.ID != "password" {
			t.Fatal("retired "+retired.name+" history exhausted the current-method budget", err)
		}
	}
	if err := exec(`INSERT INTO identity.account_credentials(tenant_id,user_id,credential_id,account_id) VALUES('tenant-a','owner','passkey-retired-1','long-account')`); err != nil {
		t.Fatal("corrupt non-provider association fixture", err)
	}
	if out, err := repo.GetAccountLinkState(ctx, linkQuery); !errors.As(err, &unavailable) || out.Access.User.ID != "" || out.Access.Methods != nil {
		t.Fatal("disabled non-provider corruption disappeared with history", err)
	}
	if err := exec(`DELETE FROM identity.account_credentials WHERE tenant_id='tenant-a' AND user_id='owner' AND credential_id='passkey-retired-1'`); err != nil {
		t.Fatal(err)
	}
	if err := exec(`DELETE FROM identity.account_credentials WHERE tenant_id='tenant-a' AND user_id='owner' AND credential_id='provider'`); err != nil {
		t.Fatal(err)
	}
	if out, err := repo.GetAccountLinkState(ctx, linkQuery); err != nil || len(out.Access.Methods) != 1 || out.Access.Methods[0].Credential.ID != "password" {
		t.Fatal("unassociated disabled provider tombstone became a current method", err)
	}
	if err := exec(`UPDATE identity.credential_references SET enabled=true WHERE tenant_id='tenant-a' AND user_id='owner' AND credential_id='provider'`); err != nil {
		t.Fatal(err)
	}
	if out, err := repo.GetAccountLinkState(ctx, linkQuery); !errors.As(err, &unavailable) || out.Access.User.ID != "" || out.Access.Methods != nil {
		t.Fatal("enabled provider missing its association did not fail closed", err)
	}
	if err := exec(`UPDATE identity.credential_references SET enabled=false WHERE tenant_id='tenant-a' AND user_id='owner' AND credential_id='provider'`); err != nil {
		t.Fatal(err)
	}
	if err := exec(`INSERT INTO identity.account_credentials(tenant_id,user_id,credential_id,account_id) VALUES('tenant-a','owner','provider','account')`); err != nil {
		t.Fatal(err)
	}
	if err := exec(`INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('tenant-a','method-overflow','active',1);
 INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled)
 SELECT 'tenant-a','method-overflow','credential-'||i::text,2,'passkey',1,true FROM generate_series(1,129) i`); err != nil {
		t.Fatal("current-method overflow fixtures", err)
	}
	overflow := account
	overflow.UserID, overflow.ID, overflow.Subject = "method-overflow", "overflow-account", "overflow-subject"
	if out, err := repo.GetAccountLinkState(ctx, identity.AccountLinkQuery{Account: overflow, Mode: identity.AccountLinkExplicit}); !errors.As(err, &unavailable) || out.Access.User.ID != "" || out.Access.Methods != nil {
		t.Fatal("current-method overflow returned partial authority", err)
	}
	// A live user reference alone cannot restore a retired provider link.
	if err := exec(`UPDATE identity.credential_references SET enabled=true WHERE tenant_id='tenant-a' AND user_id='owner' AND credential_id='provider'`); err != nil {
		t.Fatal(err)
	}
	if out, err := repo.GetAccountLinkState(ctx, linkQuery); !errors.As(err, &unavailable) || out.Access.User.ID != "" || out.SubjectOwner != nil {
		t.Fatal("corrupt active credential restored an unlinked account", err)
	}
	if err := exec(`UPDATE identity.credential_references SET enabled=false WHERE tenant_id='tenant-a' AND user_id='owner' AND credential_id='provider'`); err != nil {
		t.Fatal(err)
	}
	if err := exec(`UPDATE identity.accounts SET subject_key=decode(repeat('ff',32),'hex') WHERE tenant_id='tenant-a' AND account_id='account'`); err == nil {
		t.Fatal("caller-supplied subject index could diverge from exact metadata")
	}
	// Mutating a returned slice cannot change a later primary observation.
	query.MaximumAccounts = 100
	owned, err := repo.ListAccounts(ctx, query)
	if err != nil || len(owned.Accounts) != 1 {
		t.Fatal("owned projection missing", err)
	}
	owned.Accounts[0].Subject = "mutated"
	if again, err := repo.ListAccounts(ctx, query); err != nil || len(again.Accounts) != 1 || again.Accounts[0] != long {
		t.Fatal("projection aliases stored state", err)
	}
	// Read against atomic concurrent epoch changes. Every field must come from
	// the same primary snapshot even though the adapter uses several statements.
	if err := exec(`UPDATE identity.accounts SET linked=true WHERE tenant_id='tenant-a' AND account_id='account'; UPDATE identity.credential_references SET enabled=true WHERE tenant_id='tenant-a' AND user_id='owner' AND credential_id='provider'`); err != nil {
		t.Fatal(err)
	}
	setEpoch := func(call context.Context, version uint64) error {
		tx, err := pool.Raw().Begin(call)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(call) }()
		v := strconv.FormatUint(version, 10)
		// Only the two current references participate in the snapshot invariant;
		// rewriting retained history would multiply unrelated fixture work.
		for _, sql := range []string{`UPDATE identity.users SET version=$1::numeric,credential_version=$1::numeric WHERE tenant_id='tenant-a' AND user_id='owner'`, `UPDATE identity.accounts SET version=$1::numeric,social_link_version=$1::numeric WHERE tenant_id='tenant-a' AND account_id='account'`, `UPDATE identity.credential_references SET version=$1::numeric WHERE tenant_id='tenant-a' AND user_id='owner' AND enabled=true`} {
			if _, err := tx.Exec(call, sql, v); err != nil {
				return err
			}
		}
		return tx.Commit(call)
	}
	if err := setEpoch(ctx, 1); err != nil {
		t.Fatal(err)
	}
	concurrent, stopConcurrent := context.WithCancel(ctx)
	var writers sync.WaitGroup
	writers.Add(1)
	writerResult := make(chan error, 1)
	go func() {
		defer writers.Done()
		for i := range 32 {
			if concurrent.Err() != nil {
				writerResult <- nil
				return
			}
			if err := setEpoch(concurrent, uint64(i+2)); err != nil {
				writerResult <- err
				return
			}
		}
		writerResult <- nil
	}()
	t.Cleanup(func() { stopConcurrent(); writers.Wait() })
	for range 32 {
		snapshot, err := repo.GetAccountLinkState(ctx, linkQuery)
		if err != nil || len(snapshot.Access.Methods) != 2 || snapshot.Access.User.Version != snapshot.RecordVersion || snapshot.RecordVersion != snapshot.SocialLinkVersion || snapshot.SocialLinkVersion != snapshot.CredentialVersion || snapshot.Access.Methods[0].Credential.Version != snapshot.CredentialVersion || snapshot.Access.Methods[1].Credential.Version != snapshot.CredentialVersion {
			t.Fatal("torn primary account/credential snapshot", err)
		}
	}
	writers.Wait()
	stopConcurrent()
	if err := <-writerResult; err != nil {
		t.Fatal("concurrent fixture writer", err)
	}
	if err := exec(`DROP TABLE identity.account_credentials`); err != nil {
		t.Fatal(err)
	}
	if out, err := repo.GetAccountLinkState(ctx, linkQuery); !errors.As(err, &unavailable) || out.Access.User.ID != "" || out.SubjectOwner != nil || out.Access.Accounts != nil {
		t.Fatal("missing authority schema produced partial success", err)
	}
}
