//go:build integration

package postgres

import (
	"context"
	"errors"
	"testing"

	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5/pgconn"
)

// These are real populated upgrades and database-enforced parent uniqueness,
// not evidence of the separately tested authentication workflow.
func testVerificationSigninMigration(t *testing.T, ctx context.Context, pool *database.Pool) {
	for _, mfa := range []bool{false, true} {
		t.Run(map[bool]string{false: "email-grant history", true: "MFA history"}[mfa], func(t *testing.T) {
			tx, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			prior := "v5"
			purposes := "'identity.session.issue','identity.otp.signin','identity.password.signin','identity.password.signup','identity.magic-link.consume'"
			if mfa {
				prior = "v6"
				purposes += ",'identity.mfa.totp-verify','identity.mfa.otp-verify','identity.mfa.recovery-use','identity.mfa.security-key-assert-verify'"
			}
			if _, err := tx.Exec(ctx, `CREATE SCHEMA verification_session;
CREATE TABLE verification_session.session_issuances(tenant_id text NOT NULL,purpose text NOT NULL, CONSTRAINT session_issuances_purpose_`+prior+` CHECK(purpose IN(`+purposes+`)));
INSERT INTO verification_session.session_issuances VALUES('tenant-a','identity.password.signin'),('tenant-a','identity.magic-link.consume');`); err != nil {
				t.Fatal(err)
			}
			source, err := (EmailVerificationSigninMigrationSource{Schema: "verification_session", Version: 19, MFASignin: mfa}).Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, source[0].UpSQL()); err != nil {
				t.Fatal("populated verification upgrade", err)
			}
			var legacy int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM verification_session.session_issuances WHERE verification_command_id IS NULL`).Scan(&legacy); err != nil || legacy != 2 {
				t.Fatal("legacy issuances altered", err)
			}
			parent := make([]byte, 16)
			if _, err := tx.Exec(ctx, `INSERT INTO verification_session.session_issuances VALUES('tenant-a','identity.email.verification-signin',$1)`, parent); err != nil {
				t.Fatal("new parent-bound purpose rejected", err)
			}
			for _, bad := range []struct {
				purpose string
				parent  []byte
				code    string
			}{
				{"identity.email.verification-signin", parent, "23505"},
				{"identity.email.verification-signin", nil, "23514"},
				{"identity.email.verification-signin", make([]byte, 15), "23514"},
				{"identity.magic-link.consume", parent, "23514"},
				{"identity.email.change", nil, "23514"},
			} {
				if _, err := tx.Exec(ctx, "SAVEPOINT rejected"); err != nil {
					t.Fatal(err)
				}
				_, err := tx.Exec(ctx, `INSERT INTO verification_session.session_issuances VALUES('tenant-a',$1,$2)`, bad.purpose, bad.parent)
				var denied *pgconn.PgError
				if !errors.As(err, &denied) || denied.Code != bad.code {
					t.Fatal("parent/purpose fence missing", err)
				}
				if _, err := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT rejected"); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := tx.Exec(ctx, `INSERT INTO verification_session.session_issuances VALUES('tenant-b','identity.email.verification-signin',$1)`, parent); err != nil {
				t.Fatal("parent uniqueness crosses tenants", err)
			}
			if mfa {
				if _, err := tx.Exec(ctx, `INSERT INTO verification_session.session_issuances VALUES('tenant-a','identity.mfa.totp-verify',NULL)`); err != nil {
					t.Fatal("selected MFA purpose lost", err)
				}
			} else {
				if _, err := tx.Exec(ctx, "SAVEPOINT before_mfa"); err != nil {
					t.Fatal(err)
				}
				_, err := tx.Exec(ctx, `INSERT INTO verification_session.session_issuances VALUES('tenant-a','identity.mfa.totp-verify',NULL)`)
				var denied *pgconn.PgError
				if !errors.As(err, &denied) || denied.Code != "23514" {
					t.Fatal("unselected MFA purpose widened", err)
				}
				if _, err = tx.Exec(ctx, "ROLLBACK TO SAVEPOINT before_mfa"); err != nil {
					t.Fatal(err)
				}
				forward, e := (EmailVerificationMFASigninMigrationSource{Schema: "verification_session", Version: 20}).Load(ctx)
				if e != nil {
					t.Fatal(e)
				}
				if _, e = tx.Exec(ctx, forward[0].UpSQL()); e != nil {
					t.Fatal("populated verification-first MFA extension", e)
				}
				for _, purpose := range []string{"identity.mfa.totp-verify", "identity.mfa.otp-verify", "identity.mfa.recovery-use", "identity.mfa.security-key-assert-verify"} {
					if _, e = tx.Exec(ctx, `INSERT INTO verification_session.session_issuances VALUES('tenant-a',$1,NULL)`, purpose); e != nil {
						t.Fatal("forward MFA purpose absent", e)
					}
				}
				var parents, old int
				if e = tx.QueryRow(ctx, `SELECT count(*) FILTER(WHERE verification_command_id IS NOT NULL),count(*) FILTER(WHERE purpose IN('identity.password.signin','identity.magic-link.consume')) FROM verification_session.session_issuances`).Scan(&parents, &old); e != nil || parents != 2 || old != 2 {
					t.Fatal("forward MFA extension changed populated verification/legacy rows", e)
				}
			}
		})
	}
}
