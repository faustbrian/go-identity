//go:build integration

package postgres

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// This is the real PostgreSQL constraint boundary, not an authentication test.
// The migration changes only this column's existing CHECK; no domain stores,
// journal records or old migration checksums are fabricated to admit a session.
func TestPasskeyIssuanceMigrationPreservesPopulatedConstraint(t *testing.T) {
	ctx, pool, _ := anonymousSessionDatabase(t)
	for i, previous := range []string{"session_issuances_purpose_check", "session_issuances_purpose_v4", "session_issuances_purpose_anonymous_upgrade_v1"} {
		schema := fmt.Sprintf("passkey_migration_%d", i)
		if _, err := pool.Raw().Exec(ctx, `CREATE SCHEMA `+schema+`; CREATE TABLE `+schema+`.session_issuances(purpose text NOT NULL, marker text NOT NULL, CONSTRAINT `+previous+` CHECK(purpose IN('identity.session.issue','identity.password.signin'))); INSERT INTO `+schema+`.session_issuances VALUES('identity.password.signin','retained')`); err != nil {
			t.Fatal(err)
		}
		source := PasskeySigninMigrationSource{Schema: schema, Version: 71, PreviousConstraint: previous}
		steps, err := source.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Raw().Exec(ctx, `INSERT INTO `+schema+`.session_issuances VALUES('identity.passkey.signin-verify','new')`); err == nil {
			t.Fatal("passkey purpose accepted before forward extension")
		}
		if _, err := pool.Raw().Exec(ctx, steps[0].UpSQL()); err != nil {
			t.Fatal("forward migration", err)
		}
		for _, purpose := range []string{"identity.session.issue", "identity.password.signin", "identity.passkey.signin-verify"} {
			if _, err := pool.Raw().Exec(ctx, `INSERT INTO `+schema+`.session_issuances VALUES($1,'new')`, purpose); err != nil {
				t.Fatal("supported old/new purpose rejected", err)
			}
		}
		for _, purpose := range []string{"identity.passkey.register-verify", "identity.unselected.signin"} {
			_, err := pool.Raw().Exec(ctx, `INSERT INTO `+schema+`.session_issuances VALUES($1,'invalid')`, purpose)
			var pg *pgconn.PgError
			if !errors.As(err, &pg) || pg.Code != "23514" || pg.ConstraintName != "session_issuances_purpose_passkey_v1" {
				t.Fatal("unselected purpose constraint not enforced")
			}
		}
		var retained int
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM `+schema+`.session_issuances WHERE purpose='identity.password.signin' AND marker='retained'`).Scan(&retained); err != nil || retained != 1 {
			t.Fatal("populated history changed", err)
		}
		if _, err := pool.Raw().Exec(ctx, steps[0].UpSQL()); err == nil {
			t.Fatal("already changed history silently adopted")
		}
	}
	for i, invalid := range []string{
		`CHECK(marker='retained')`,
		`CHECK(purpose='identity.session.issue') NOT VALID`,
	} {
		schema := fmt.Sprintf("passkey_drift_%d", i)
		if _, err := pool.Raw().Exec(ctx, `CREATE SCHEMA `+schema+`; CREATE TABLE `+schema+`.session_issuances(purpose text NOT NULL,marker text NOT NULL); ALTER TABLE `+schema+`.session_issuances ADD CONSTRAINT session_issuances_purpose_check `+invalid); err != nil {
			t.Fatal(err)
		}
		steps, err := (PasskeySigninMigrationSource{Schema: schema, Version: 72, PreviousConstraint: "session_issuances_purpose_check"}).Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = pool.Raw().Exec(ctx, steps[0].UpSQL())
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "55000" {
			t.Fatal("non-purpose/unvalidated predecessor silently adopted")
		}
		var prior int
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM pg_constraint WHERE conrelid=$1::regclass AND conname='session_issuances_purpose_check'`, schema+".session_issuances").Scan(&prior); err != nil || prior != 1 {
			t.Fatal("failed migration removed predecessor", err)
		}
	}
}
