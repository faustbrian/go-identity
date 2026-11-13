//go:build integration

package postgres

import (
	"fmt"
	"testing"
)

// The real constraint boundary proves additive populated upgrades, not OAuth
// authentication. No migration rewrites session records or original commitments.
func TestOAuthSigninMigrationPreservesPopulatedHistory(t *testing.T) {
	ctx, pool, _ := anonymousSessionDatabase(t)
	for index, previous := range []string{"session_issuances_purpose_check", "session_issuances_purpose_v4", "session_issuances_purpose_passkey_signup_v1"} {
		schema := fmt.Sprintf("oauth_session_migration_%d", index)
		if _, err := pool.Raw().Exec(ctx, `CREATE SCHEMA `+schema+`; CREATE TABLE `+schema+`.session_issuances(purpose text NOT NULL,marker text NOT NULL,CONSTRAINT `+previous+` CHECK(purpose IN('identity.session.issue','identity.password.signin'))); INSERT INTO `+schema+`.session_issuances VALUES('identity.password.signin','retained')`); err != nil {
			t.Fatal(err)
		}
		steps, err := (OAuthSigninMigrationSource{Schema: schema, Version: 81, ValidationVersion: 82, PreviousConstraint: previous}).Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Raw().Exec(ctx, `INSERT INTO `+schema+`.session_issuances VALUES('identity.oauth.callback','new')`); err == nil {
			t.Fatal("OAuth selected before expansion")
		}
		if _, err := pool.Raw().Exec(ctx, steps[0].UpSQL()); err != nil {
			t.Fatal("metadata-only expansion", err)
		}
		var validated bool
		if err := pool.Raw().QueryRow(ctx, `SELECT convalidated FROM pg_constraint WHERE conrelid=$1::regclass AND conname='session_issuances_purpose_oauth_v1'`, schema+".session_issuances").Scan(&validated); err != nil || validated {
			t.Fatal("expansion performed validation scan", err)
		}
		if _, err := pool.Raw().Exec(ctx, `INSERT INTO `+schema+`.session_issuances VALUES('identity.oauth.callback','new')`); err != nil {
			t.Fatal("expanded purpose unavailable", err)
		}
		if _, err := pool.Raw().Exec(ctx, `INSERT INTO `+schema+`.session_issuances VALUES('arbitrary-purpose','invalid')`); err == nil {
			t.Fatal("expansion dropped purpose validation")
		}
		if _, err := pool.Raw().Exec(ctx, steps[1].UpSQL()); err != nil {
			t.Fatal("separate validation", err)
		}
		if err := pool.Raw().QueryRow(ctx, `SELECT convalidated FROM pg_constraint WHERE conrelid=$1::regclass AND conname='session_issuances_purpose_oauth_v1'`, schema+".session_issuances").Scan(&validated); err != nil || !validated {
			t.Fatal("validated history unavailable", err)
		}
		var count int
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM `+schema+`.session_issuances WHERE purpose='identity.password.signin' AND marker='retained'`).Scan(&count); err != nil || count != 1 {
			t.Fatal("populated history changed", err)
		}
		if _, err := pool.Raw().Exec(ctx, steps[0].UpSQL()); err == nil {
			t.Fatal("changed predecessor silently adopted")
		}
	}
	for index, predicate := range []string{`CHECK(marker='retained')`, `CHECK(purpose='identity.session.issue') NOT VALID`} {
		schema := fmt.Sprintf("oauth_session_drift_%d", index)
		if _, err := pool.Raw().Exec(ctx, `CREATE SCHEMA `+schema+`; CREATE TABLE `+schema+`.session_issuances(purpose text NOT NULL,marker text NOT NULL); ALTER TABLE `+schema+`.session_issuances ADD CONSTRAINT session_issuances_purpose_check `+predicate); err != nil {
			t.Fatal(err)
		}
		var wasValidated bool
		if err := pool.Raw().QueryRow(ctx, `SELECT convalidated FROM pg_constraint WHERE conrelid=$1::regclass AND conname='session_issuances_purpose_check'`, schema+".session_issuances").Scan(&wasValidated); err != nil {
			t.Fatal(err)
		}
		if wasValidated != (index == 0) {
			t.Fatal("drift fixture did not establish its expected validation state")
		}
		steps, err := (OAuthSigninMigrationSource{Schema: schema, Version: 81, ValidationVersion: 82, PreviousConstraint: "session_issuances_purpose_check"}).Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Raw().Exec(ctx, steps[0].UpSQL()); err == nil {
			t.Fatal("non-purpose/unvalidated history adopted")
		}
		var retained int
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM pg_constraint WHERE conrelid=$1::regclass AND conname='session_issuances_purpose_check'`, schema+".session_issuances").Scan(&retained); err != nil || retained != 1 {
			t.Fatal("failed expansion changed predecessor", err)
		}
	}
}
