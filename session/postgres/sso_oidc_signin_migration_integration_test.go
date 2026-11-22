//go:build integration

package postgres

import (
	"errors"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestSSOOIDCSigninMigrationPreservesPopulatedHistory(t *testing.T) {
	ctx, pool, _ := anonymousSessionDatabase(t)
	const schema = "sso_signin_migration"
	const previous = "session_issuances_purpose_oauth_v1"
	const next = "session_issuances_purpose_sso_oidc_v1"
	const enterprise = "identity.sso.oidc-callback"
	const password = "identity.password.signin"
	const social = "identity.oauth.callback"
	if _, err := pool.Raw().Exec(ctx, `CREATE SCHEMA `+schema+`; CREATE TABLE `+schema+`.session_issuances(
 purpose text NOT NULL, marker text PRIMARY KEY, CONSTRAINT `+previous+` CHECK(purpose IN('`+password+`','`+social+`')));
 INSERT INTO `+schema+`.session_issuances VALUES('`+password+`','password-history'),('`+social+`','social-history')`); err != nil {
		t.Fatal(err)
	}
	insert := func(purpose, marker string) error {
		_, err := pool.Raw().Exec(ctx, `INSERT INTO `+schema+`.session_issuances VALUES($1,$2)`, purpose, marker)
		return err
	}
	requireDenied := func(purpose, constraint string) {
		t.Helper()
		var pgErr *pgconn.PgError
		if err := insert(purpose, "denied"); !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.ConstraintName != constraint {
			t.Fatalf("%s was not rejected by %s: %v", purpose, constraint, err)
		}
	}
	requireDenied(enterprise, previous)
	steps, err := (SSOOIDCSigninMigrationSource{Schema: schema, Version: 81, ValidationVersion: 82, PreviousConstraint: previous}).Load(ctx)
	if err != nil || len(steps) != 2 {
		t.Fatalf("want separate expansion and validation: %v", err)
	}
	apply := func(step migrations.Migration) error {
		_, err := pool.Raw().Exec(ctx, step.UpSQL())
		return err
	}
	requireValidation := func(want bool) {
		t.Helper()
		var validated bool
		if err := pool.Raw().QueryRow(ctx, `SELECT convalidated FROM pg_constraint WHERE conrelid=$1::regclass AND conname=$2`, schema+".session_issuances", next).Scan(&validated); err != nil || validated != want {
			t.Fatalf("constraint validation = %v, want %v: %v", validated, want, err)
		}
	}
	if err := apply(steps[0]); err != nil {
		t.Fatal("expand without validation scan", err)
	}
	requireValidation(false)
	for purpose, marker := range map[string]string{password: "new-password", social: "new-social", enterprise: "enterprise"} {
		if err := insert(purpose, marker); err != nil {
			t.Fatalf("purpose %s unavailable after expansion: %v", purpose, err)
		}
	}
	requireDenied("arbitrary-purpose", next)
	if err := apply(steps[1]); err != nil {
		t.Fatal("validate in separate migration", err)
	}
	requireValidation(true)
	var retained int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM `+schema+`.session_issuances WHERE (purpose,marker) IN(($1,'password-history'),($2,'social-history'))`, password, social).Scan(&retained); err != nil || retained != 2 {
		t.Fatalf("lost existing password or social issuance: retained %d, %v", retained, err)
	}
	if err := apply(steps[0]); err == nil {
		t.Fatal("re-expansion without the selected predecessor succeeded")
	}
	requireValidation(true)
}
