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

func TestSSOOAuth2SigninMigrationPreservesPopulatedOIDCHistory(t *testing.T) {
	ctx, pool, _ := anonymousSessionDatabase(t)
	const schema = "sso_oauth2_signin_migration"
	const previous = "session_issuances_purpose_sso_oidc_v1"
	const next = "session_issuances_purpose_sso_oauth2_v1"
	const oauth = "identity.sso.oauth-callback"
	if _, err := pool.Raw().Exec(ctx, `CREATE SCHEMA `+schema+`; CREATE TABLE `+schema+`.session_issuances(
 purpose text NOT NULL, marker text PRIMARY KEY, CONSTRAINT `+previous+` CHECK(purpose IN('identity.password.signin','identity.sso.oidc-callback')));
 INSERT INTO `+schema+`.session_issuances VALUES('identity.password.signin','password-history'),('identity.sso.oidc-callback','oidc-history')`); err != nil {
		t.Fatal(err)
	}
	insert := func(purpose, marker string) error {
		_, err := pool.Raw().Exec(ctx, `INSERT INTO `+schema+`.session_issuances VALUES($1,$2)`, purpose, marker)
		return err
	}
	denied := func(purpose, constraint string) {
		t.Helper()
		var pgErr *pgconn.PgError
		if err := insert(purpose, "denied"); !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.ConstraintName != constraint {
			t.Fatalf("unexpected result inserting %s: %v", purpose, err)
		}
	}
	denied(oauth, previous)
	steps, err := (SSOOAuth2SigninMigrationSource{Schema: schema, Version: 83, ValidationVersion: 84}).Load(ctx)
	if err != nil || len(steps) != 2 {
		t.Fatalf("want expansion and separate validation: %v", err)
	}
	checkValidation := func(want bool) {
		t.Helper()
		var validated bool
		if err := pool.Raw().QueryRow(ctx, `SELECT convalidated FROM pg_constraint WHERE conrelid=$1::regclass AND conname=$2`, schema+".session_issuances", next).Scan(&validated); err != nil || validated != want {
			t.Fatalf("constraint validated = %v, want %v: %v", validated, want, err)
		}
	}
	if _, err := pool.Raw().Exec(ctx, steps[0].UpSQL()); err != nil {
		t.Fatal("expand without validation scan", err)
	}
	checkValidation(false)
	if err := insert(oauth, "oauth-new"); err != nil {
		t.Fatal("OAuth purpose unavailable after expansion", err)
	}
	denied("identity.oauth.unregistered", next)
	if _, err := pool.Raw().Exec(ctx, steps[1].UpSQL()); err != nil {
		t.Fatal("validate in separate migration", err)
	}
	checkValidation(true)
	var retained int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM `+schema+`.session_issuances WHERE (purpose,marker) IN(('identity.password.signin','password-history'),('identity.sso.oidc-callback','oidc-history'))`).Scan(&retained); err != nil || retained != 2 {
		t.Fatalf("lost previous history: %d, %v", retained, err)
	}
	if _, err := pool.Raw().Exec(ctx, steps[0].UpSQL()); err == nil {
		t.Fatal("expansion accepted missing OIDC predecessor")
	}
	checkValidation(true)
}

func TestSSOSAMLSigninMigrationPreservesPopulatedOAuth2History(t *testing.T) {
	ctx, pool, _ := anonymousSessionDatabase(t)
	const schema = "sso_saml_signin_migration"
	const previous = "session_issuances_purpose_sso_oauth2_v1"
	const next = "session_issuances_purpose_sso_saml_v1"
	const password = "identity.password.signin"
	const social = "identity.oauth.callback"
	const oidc = "identity.sso.oidc-callback"
	const oauth2 = "identity.sso.oauth-callback"
	const saml = "identity.sso.saml-acs"
	if _, err := pool.Raw().Exec(ctx, `CREATE SCHEMA `+schema+`; CREATE TABLE `+schema+`.session_issuances(
 purpose text NOT NULL, marker text PRIMARY KEY, CONSTRAINT `+previous+` CHECK(purpose IN('`+password+`','`+social+`','`+oidc+`','`+oauth2+`')));
 INSERT INTO `+schema+`.session_issuances VALUES('`+password+`','password-history'),('`+social+`','social-history'),('`+oidc+`','oidc-history'),('`+oauth2+`','oauth2-history')`); err != nil {
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
	requireHistory := func() {
		t.Helper()
		var retained int
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM `+schema+`.session_issuances WHERE (purpose,marker) IN(($1,'password-history'),($2,'social-history'),($3,'oidc-history'),($4,'oauth2-history'))`, password, social, oidc, oauth2).Scan(&retained); err != nil || retained != 4 {
			t.Fatalf("changed installed issuance history: retained %d, %v", retained, err)
		}
	}
	requireDenied(saml, previous)
	steps, err := (SSOSAMLSigninMigrationSource{Schema: schema, Version: 85, ValidationVersion: 86}).Load(ctx)
	if err != nil || len(steps) != 2 {
		t.Fatalf("want SAML expansion and separate validation: %v", err)
	}
	requireValidation := func(want bool) {
		t.Helper()
		var validated bool
		if err := pool.Raw().QueryRow(ctx, `SELECT convalidated FROM pg_constraint WHERE conrelid=$1::regclass AND conname=$2`, schema+".session_issuances", next).Scan(&validated); err != nil || validated != want {
			t.Fatalf("constraint validated = %v, want %v: %v", validated, want, err)
		}
	}
	for phase, step := range steps {
		if _, err := pool.Raw().Exec(ctx, step.UpSQL()); err != nil {
			t.Fatalf("apply SAML migration phase %d: %v", phase, err)
		}
		requireValidation(phase == 1)
		requireHistory()
		for purpose, marker := range map[string]string{
			password: "new-password", social: "new-social", oidc: "new-oidc", oauth2: "new-oauth2", saml: "new-saml",
		} {
			if phase == 1 {
				marker += "-validated"
			}
			if err := insert(purpose, marker); err != nil {
				t.Fatalf("purpose %s unavailable in phase %d: %v", purpose, phase, err)
			}
		}
		for _, purpose := range []string{"arbitrary-purpose", "identity.sso.saml-idp-init", "identity.sso.saml-acs-extra"} {
			requireDenied(purpose, next)
		}
	}
	if _, err := pool.Raw().Exec(ctx, steps[0].UpSQL()); err == nil {
		t.Fatal("SAML expansion accepted missing OAuth2 predecessor")
	}
	requireValidation(true)
	requireHistory()
}

func TestSSOSAMLIDPSigninMigrationPreservesPopulatedSPHistory(t *testing.T) {
	ctx, pool, _ := anonymousSessionDatabase(t)
	const schema = "sso_saml_idp_migration"
	const previous = "session_issuances_purpose_sso_saml_v1"
	const next = "session_issuances_purpose_sso_saml_idp_v1"
	const sp = "identity.sso.saml-acs"
	const idp = "identity.sso.saml-idp-init"
	if _, err := pool.Raw().Exec(ctx, `CREATE SCHEMA `+schema+`; CREATE TABLE `+schema+`.session_issuances(
 purpose text NOT NULL, marker text PRIMARY KEY, CONSTRAINT `+previous+` CHECK(purpose IN('identity.password.signin','`+sp+`')));
 INSERT INTO `+schema+`.session_issuances VALUES('identity.password.signin','password-history'),('`+sp+`','sp-history')`); err != nil {
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
	requireDenied(idp, previous)
	steps, err := (SSOSAMLIDPSigninMigrationSource{Schema: schema, Version: 87, ValidationVersion: 88}).Load(ctx)
	if err != nil || len(steps) != 2 {
		t.Fatal("need ordered expansion and validation", err)
	}
	for phase, step := range steps {
		if _, err := pool.Raw().Exec(ctx, step.UpSQL()); err != nil {
			t.Fatal("apply migration phase", phase, err)
		}
		var validated bool
		if err := pool.Raw().QueryRow(ctx, `SELECT convalidated FROM pg_constraint WHERE conrelid=$1::regclass AND conname=$2`, schema+".session_issuances", next).Scan(&validated); err != nil || validated != (phase == 1) {
			t.Fatal("expansion must be installed before validation", phase, err)
		}
		requireDenied("identity.sso.saml-idp-prepare", next)
		if phase == 0 {
			if err := insert(idp, "new-idp"); err != nil {
				t.Fatal("unvalidated successor still must enforce the new profile", err)
			}
		}
	}
	var retained int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM `+schema+`.session_issuances WHERE (purpose,marker) IN(('identity.password.signin','password-history'),($1,'sp-history'),($2,'new-idp'))`, sp, idp).Scan(&retained); err != nil || retained != 3 {
		t.Fatal("old or new issuance was lost", retained, err)
	}
}
