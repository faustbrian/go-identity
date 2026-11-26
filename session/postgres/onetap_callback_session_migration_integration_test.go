//go:build integration

package postgres

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestOneTapCallbackSessionMigrationPreservesPopulatedHistory(t *testing.T) {
	ctx, pool, _ := anonymousSessionDatabase(t)
	const next = "session_issuances_purpose_onetap_v1"
	const oneTap = "identity.oauth.onetap-callback"
	for index, test := range []struct {
		previous string
		purposes []string
	}{
		{"session_issuances_purpose_check", []string{"identity.session.issue"}},
		{"session_issuances_purpose_v4", []string{"identity.session.issue", "identity.otp.signin", "identity.password.signin", "identity.password.signup"}},
		{"session_issuances_purpose_anonymous_upgrade_v1", []string{"identity.session.issue", "identity.anonymous.signin", "identity.anonymous.upgrade"}},
		{"session_issuances_purpose_passkey_signup_v1", []string{"identity.session.issue", "identity.passkey.signin-verify", "identity.passkey.register-verify"}},
		{"session_issuances_purpose_oauth_v1", []string{"identity.password.signin", "identity.oauth.callback"}},
		{"session_issuances_purpose_sso_oidc_v1", []string{"identity.password.signin", "identity.oauth.callback", "identity.sso.oidc-callback"}},
		{"session_issuances_purpose_sso_oauth2_v1", []string{"identity.password.signin", "identity.sso.oidc-callback", "identity.sso.oauth-callback"}},
		{"session_issuances_purpose_sso_saml_v1", []string{"identity.password.signin", "identity.sso.oauth-callback", "identity.sso.saml-acs"}},
		{"session_issuances_purpose_sso_saml_idp_v1", []string{"identity.password.signin", "identity.sso.saml-acs", "identity.sso.saml-idp-init"}},
	} {
		t.Run(test.previous, func(t *testing.T) {
			schema := fmt.Sprintf("onetap_session_migration_%d", index)
			predicate := "purpose IN('" + strings.Join(test.purposes, "','") + "')"
			if _, err := pool.Raw().Exec(ctx, `CREATE SCHEMA `+schema+`; CREATE TABLE `+schema+`.session_issuances(
 purpose text NOT NULL, marker text PRIMARY KEY,
 CONSTRAINT `+test.previous+` CHECK(`+predicate+`), CONSTRAINT marker_check CHECK(marker<>''))`); err != nil {
				t.Fatal(err)
			}
			insert := func(purpose, marker string) error {
				_, err := pool.Raw().Exec(ctx, `INSERT INTO `+schema+`.session_issuances VALUES($1,$2)`, purpose, marker)
				return err
			}
			requireDenied := func(purpose, marker, constraint string) {
				t.Helper()
				var pgErr *pgconn.PgError
				if err := insert(purpose, marker); !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.ConstraintName != constraint {
					t.Fatalf("want %s denied by %s: %v", purpose, constraint, err)
				}
			}
			for i, purpose := range test.purposes {
				if err := insert(purpose, fmt.Sprintf("retained-%d", i)); err != nil {
					t.Fatal("populate installed history", err)
				}
			}
			requireDenied(oneTap, "before-expansion", test.previous)
			steps, err := (OneTapCallbackSessionMigrationSource{Schema: schema, Version: 91, ValidationVersion: 92, PreviousConstraint: test.previous}).Load(ctx)
			if err != nil || len(steps) != 2 {
				t.Fatalf("want separate expansion and validation: %v", err)
			}
			for phase, step := range steps {
				if _, err := pool.Raw().Exec(ctx, step.UpSQL()); err != nil {
					t.Fatalf("apply phase %d: %v", phase, err)
				}
				var validated bool
				if err := pool.Raw().QueryRow(ctx, `SELECT convalidated FROM pg_constraint WHERE conrelid=$1::regclass AND conname=$2`, schema+".session_issuances", next).Scan(&validated); err != nil || validated != (phase == 1) {
					t.Fatalf("phase %d validated = %v: %v", phase, validated, err)
				}
				for i, purpose := range test.purposes {
					var retained string
					if err := pool.Raw().QueryRow(ctx, `SELECT purpose FROM `+schema+`.session_issuances WHERE marker=$1`, fmt.Sprintf("retained-%d", i)).Scan(&retained); err != nil || retained != purpose {
						t.Fatalf("changed populated history for %s: %v", purpose, err)
					}
					if err := insert(purpose, fmt.Sprintf("phase-%d-old-%d", phase, i)); err != nil {
						t.Fatalf("old purpose %s unavailable in phase %d: %v", purpose, phase, err)
					}
				}
				if err := insert(oneTap, fmt.Sprintf("phase-%d-onetap", phase)); err != nil {
					t.Fatal("One Tap purpose unavailable", err)
				}
				for _, purpose := range []string{"arbitrary-purpose", "identity.oauth.onetap-start", "identity.oauth.onetap-callback-extra"} {
					requireDenied(purpose, "denied", next)
				}
				requireDenied(oneTap, "", "marker_check")
			}
			var total int
			if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM `+schema+`.session_issuances`).Scan(&total); err != nil || total != 3*len(test.purposes)+2 {
				t.Fatalf("unexpected issuance rows after validation: %d, %v", total, err)
			}
			if _, err := pool.Raw().Exec(ctx, steps[0].UpSQL()); err == nil {
				t.Fatal("expansion adopted missing selected predecessor")
			}
		})
	}
}

func TestOneTapCallbackSessionMigrationRejectsMissingOrDriftedPredecessor(t *testing.T) {
	ctx, pool, _ := anonymousSessionDatabase(t)
	const previous = "session_issuances_purpose_check"
	for index, test := range []struct {
		name       string
		constraint string
	}{
		{"missing", `CONSTRAINT another_purpose_check CHECK(purpose='identity.session.issue')`},
		{"unvalidated", `CONSTRAINT ` + previous + ` CHECK(purpose='identity.session.issue') NOT VALID`},
		{"other column", `CONSTRAINT ` + previous + ` CHECK(marker='retained')`},
		{"multiple columns", `CONSTRAINT ` + previous + ` CHECK(purpose='identity.session.issue' AND marker='retained')`},
		{"not a check", `CONSTRAINT ` + previous + ` UNIQUE(purpose)`},
	} {
		t.Run(test.name, func(t *testing.T) {
			schema := fmt.Sprintf("onetap_session_drift_%d", index)
			if _, err := pool.Raw().Exec(ctx, `CREATE SCHEMA `+schema+`; CREATE TABLE `+schema+`.session_issuances(purpose text NOT NULL,marker text NOT NULL);
 INSERT INTO `+schema+`.session_issuances VALUES('identity.session.issue','retained');
 ALTER TABLE `+schema+`.session_issuances ADD `+test.constraint); err != nil {
				t.Fatal(err)
			}
			var beforeConstraints int
			if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM pg_constraint WHERE conrelid=$1::regclass`, schema+".session_issuances").Scan(&beforeConstraints); err != nil {
				t.Fatal(err)
			}
			steps, err := (OneTapCallbackSessionMigrationSource{Schema: schema, Version: 91, ValidationVersion: 92, PreviousConstraint: previous}).Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			var pgErr *pgconn.PgError
			if _, err := pool.Raw().Exec(ctx, steps[0].UpSQL()); !errors.As(err, &pgErr) || pgErr.Code != "55000" {
				t.Fatalf("want predecessor scope rejection: %v", err)
			}
			var afterConstraints, successor, retained int
			if err := pool.Raw().QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE conname='session_issuances_purpose_onetap_v1') FROM pg_constraint WHERE conrelid=$1::regclass`, schema+".session_issuances").Scan(&afterConstraints, &successor); err != nil || afterConstraints != beforeConstraints || successor != 0 {
				t.Fatalf("failed expansion changed installed constraints: %v", err)
			}
			if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM `+schema+`.session_issuances WHERE purpose='identity.session.issue' AND marker='retained'`).Scan(&retained); err != nil || retained != 1 {
				t.Fatalf("failed expansion changed retained history: %v", err)
			}
		})
	}
}
