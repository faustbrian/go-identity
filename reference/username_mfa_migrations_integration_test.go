//go:build integration

package reference_test

import (
	"context"
	"errors"
	"testing"
	"time"

	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/jackc/pgx/v5/pgconn"
)

// Isolate the two forward constraint changes with populated predecessor rows.
// The separate HTTPS journey proves the complete actual native schema graph;
// these minimal tables do not stand in for authentication or migration-ledger
// compatibility of a previously deployed reference server.
func TestReferencePostgresUsernameMFAForwardPurposes(t *testing.T) {
	ctx, stop := context.WithTimeout(t.Context(), 20*time.Second)
	defer stop()
	f := newLiveStoresProfile(t, ctx, false, true)
	for _, verification := range []bool{false, true} {
		name := "password-first"
		if verification {
			name = "verification-first"
		}
		t.Run(name, func(t *testing.T) {
			tx, err := f.pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			constraint, purposes := "continuations_origin_purpose_check", "'identity.magic-link.consume','identity.password.signin'"
			if verification {
				constraint, purposes = "continuations_origin_purpose_v2", purposes+",'identity.email.verification-signin'"
			}
			if _, err := tx.Exec(ctx, `CREATE SCHEMA identity_mfa;
CREATE SCHEMA identity_password;
CREATE TABLE identity_mfa.continuations(origin_purpose text NOT NULL, payload text NOT NULL, CONSTRAINT `+constraint+` CHECK(origin_purpose IN (`+purposes+`)));
CREATE TABLE identity_password.mfa_primary_records(purpose text NOT NULL, payload text NOT NULL, CONSTRAINT mfa_primary_records_purpose_check CHECK(purpose='identity.password.signin'));
INSERT INTO identity_mfa.continuations VALUES('identity.password.signin','retained-password'),('identity.magic-link.consume','retained-magic-link');
INSERT INTO identity_password.mfa_primary_records VALUES('identity.password.signin','retained-signed-primary');`); err != nil {
				t.Fatal("populated predecessor setup failed")
			}
			if verification {
				if _, err := tx.Exec(ctx, `INSERT INTO identity_mfa.continuations VALUES('identity.email.verification-signin','retained-verification')`); err != nil {
					t.Fatal("verification predecessor setup failed")
				}
			}
			mfaHistory, err := (mfapg.UsernameContinuationMigrationSource{Version: 1, VerificationSignin: verification}).Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			base, err := (passwordpg.MigrationSource{}).Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			passwordHistory, err := (passwordpg.UsernameMFAMigrationSource{Base: migrationCheckPrefix(base), Version: 22}).Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, mfaHistory[0].UpSQL()); err != nil {
				t.Fatal("populated continuation upgrade failed")
			}
			if _, err := tx.Exec(ctx, passwordHistory[len(passwordHistory)-1].UpSQL()); err != nil {
				t.Fatal("populated signed-primary upgrade failed")
			}
			if _, err := tx.Exec(ctx, `INSERT INTO identity_mfa.continuations VALUES('identity.username.signin','new-username'); INSERT INTO identity_password.mfa_primary_records VALUES('identity.username.signin','new-username-primary')`); err != nil {
				t.Fatal("username successor purpose denied")
			}
			var retained, primary int
			want := 2
			if verification {
				want++
			}
			if err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM identity_mfa.continuations WHERE (origin_purpose,payload) IN (('identity.password.signin','retained-password'),('identity.magic-link.consume','retained-magic-link'),('identity.email.verification-signin','retained-verification'))),(SELECT count(*) FROM identity_password.mfa_primary_records WHERE purpose='identity.password.signin' AND payload='retained-signed-primary')`).Scan(&retained, &primary); err != nil || retained != want || primary != 1 {
				t.Fatal("forward suffix changed retained original purpose or record")
			}
			if _, err := tx.Exec(ctx, `SAVEPOINT wrong_purpose`); err != nil {
				t.Fatal(err)
			}
			var rejected *pgconn.PgError
			if _, err := tx.Exec(ctx, `INSERT INTO identity_mfa.continuations VALUES('identity.password.reset-complete','wrong-origin')`); !errors.As(err, &rejected) || rejected.Code != "23514" {
				t.Fatal("unrelated continuation purpose admitted")
			}
			if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT wrong_purpose`); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, `INSERT INTO identity_password.mfa_primary_records VALUES('identity.magic-link.consume','wrong-primary')`); !errors.As(err, &rejected) || rejected.Code != "23514" {
				t.Fatal("non-password primary purpose admitted")
			}
		})
	}
}
