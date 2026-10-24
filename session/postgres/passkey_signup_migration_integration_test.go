//go:build integration

package postgres

import (
	"fmt"
	"testing"
)

func TestPasskeySignupMigrationPreservesPopulatedPurpose(t *testing.T) {
	ctx, pool, _ := anonymousSessionDatabase(t)
	for i, previous := range []string{"session_issuances_purpose_v4", "session_issuances_purpose_passkey_v1"} {
		schema := fmt.Sprintf("passkey_signup_history_%d", i)
		if _, err := pool.Raw().Exec(ctx, `CREATE SCHEMA `+schema+`; CREATE TABLE `+schema+`.session_issuances(purpose text NOT NULL,marker text NOT NULL,CONSTRAINT `+previous+` CHECK(purpose IN('identity.session.issue','identity.password.signup','identity.passkey.signin-verify')));INSERT INTO `+schema+`.session_issuances VALUES('identity.password.signup','retained')`); err != nil {
			t.Fatal(err)
		}
		steps, err := (PasskeySignupMigrationSource{Schema: schema, Version: 72, PreviousConstraint: previous}).Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Raw().Exec(ctx, `INSERT INTO `+schema+`.session_issuances VALUES('identity.passkey.register-verify','too-early')`); err == nil {
			t.Fatal("signup enabled before explicit migration")
		}
		if _, err := pool.Raw().Exec(ctx, steps[0].UpSQL()); err != nil {
			t.Fatal(err)
		}
		for _, purpose := range []string{"identity.session.issue", "identity.password.signup", "identity.passkey.signin-verify", "identity.passkey.register-verify"} {
			if _, err := pool.Raw().Exec(ctx, `INSERT INTO `+schema+`.session_issuances VALUES($1,'new')`, purpose); err != nil {
				t.Fatal("old/new purpose rejected", err)
			}
		}
		if _, err := pool.Raw().Exec(ctx, `INSERT INTO `+schema+`.session_issuances VALUES('identity.unselected.signin','forbidden')`); err == nil {
			t.Fatal("unknown purpose admitted")
		}
		var retained int
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM `+schema+`.session_issuances WHERE purpose='identity.password.signup' AND marker='retained'`).Scan(&retained); err != nil || retained != 1 {
			t.Fatal("old issuance row changed", err)
		}
		if _, err := pool.Raw().Exec(ctx, steps[0].UpSQL()); err == nil {
			t.Fatal("changed predecessor silently adopted")
		}
	}
}
