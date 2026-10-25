//go:build integration

package mfapostgres

import (
	"context"
	"fmt"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
)

// This proves actual populated SQL constraint upgrades, not authentication or
// TOTP activation. The surrounding fixture owns the real kernel and MFA tables.
func testPasskeyContinuationMigrationPostgres(t *testing.T, ctx context.Context, pool *database.Pool) {
	for _, profile := range []struct{ password, verification, username, phone bool }{
		{}, {true, false, false, false}, {true, true, false, false},
		{true, false, true, false}, {true, true, true, false},
		{true, false, false, true}, {true, true, false, true},
		{true, false, true, true}, {true, true, true, true},
	} {
		t.Run(fmt.Sprintf("p%v-v%v-u%v-h%v", profile.password, profile.verification, profile.username, profile.phone), func(t *testing.T) {
			var base migrations.Source = ContinuationMigrationSource{Base: MigrationSource{Version: 1}, Version: 2}
			if profile.password {
				base = PasswordContinuationMigrationSource{Base: base, Version: 3}
			}
			if profile.verification {
				base = VerificationContinuationMigrationSource{Base: base, Version: 4}
			}
			if profile.username {
				base = UsernameContinuationMigrationSource{Base: base, Version: 5, VerificationSignin: profile.verification}
			}
			if profile.phone {
				base = PhoneContinuationMigrationSource{Base: base, Version: 6, VerificationSignin: profile.verification, UsernameSignin: profile.username}
			}
			history, err := base.Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			for _, step := range history[1:] { // Factor authority is already installed by the enclosing fixture.
				if _, err := pool.Raw().Exec(ctx, step.UpSQL()); err != nil {
					t.Fatal("actual predecessor migration failed", err)
				}
			}
			t.Cleanup(func() {
				if _, err := pool.Raw().Exec(ctx, `DROP TABLE identity_mfa.continuations`); err != nil {
					t.Error("owned continuation table cleanup failed", err)
				}
			})
			insert := func(purpose string, completed bool) (identity.CommandID, error) {
				id, err := identity.NewCommandID()
				if err != nil {
					t.Fatal(err)
				}
				raw := mustContinuationCommandBytes(string(id))
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,'tenant-a',$2,decode(repeat('01',32),'hex'),1,decode('01','hex'))`, raw, purpose); err != nil {
					t.Fatal(err)
				}
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,'tenant-a',$2)`, raw, purpose); err != nil {
					t.Fatal(err)
				}
				now := time.Now().UTC().Truncate(time.Second)
				state, version, remaining := 1, 1, 3
				if completed {
					state, version, remaining = 3, 2, 2
				}
				_, err = pool.Raw().Exec(ctx, `INSERT INTO identity_mfa.continuations(tenant_id,continuation_id,user_id,source_preauth_id,origin_command_id,origin_purpose,origin_fingerprint,origin_generation,scope_digest,original_scope,state,version,max_attempts,attempts_remaining,issued_at,expires_at) VALUES('tenant-a',$1,'user-a',$1,$2,$3,decode(repeat('01',32),'hex'),1,decode(repeat('02',32),'hex'),decode('01','hex'),$4,$5,3,$6,$7,$8)`, string(id), raw, purpose, state, version, remaining, now, now.Add(time.Minute))
				return id, err
			}
			var originals []string
			origins := []string{"identity.magic-link.consume"}
			if profile.password {
				origins = append(origins, "identity.password.signin")
			}
			if profile.verification {
				origins = append(origins, "identity.email.verification-signin")
			}
			if profile.username {
				origins = append(origins, "identity.username.signin")
			}
			if profile.phone {
				origins = append(origins, "identity.phone.password-signin")
			}
			for _, origin := range origins {
				for _, completed := range []bool{false, true} {
					id, err := insert(origin, completed)
					if err != nil {
						t.Fatal(err)
					}
					var encoded string
					if err := pool.Raw().QueryRow(ctx, `SELECT to_jsonb(c)::text FROM identity_mfa.continuations c WHERE continuation_id=$1`, string(id)).Scan(&encoded); err != nil {
						t.Fatal(err)
					}
					originals = append(originals, encoded)
				}
			}
			if _, err := insert("identity.passkey.signin-verify", false); err == nil {
				t.Fatal("unselected predecessor accepted passkey origin")
			}
			source := PasskeyContinuationMigrationSource{Base: base, Version: 7, PasswordSignin: profile.password, VerificationSignin: profile.verification, UsernameSignin: profile.username, PhoneSignin: profile.phone}
			updated, err := source.Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Raw().Exec(ctx, updated[len(updated)-1].UpSQL()); err != nil {
				t.Fatal("actual passkey constraint upgrade failed", err)
			}
			for _, original := range originals {
				var unchanged bool
				if err := pool.Raw().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM identity_mfa.continuations c WHERE to_jsonb(c)::text=$1)`, original).Scan(&unchanged); err != nil || !unchanged {
					t.Fatal("migration reset original pending or completed custody", err)
				}
			}
			if _, err := insert("identity.passkey.signin-verify", false); err != nil {
				t.Fatal("selected native passkey origin denied", err)
			}
			if _, err := insert("identity.unsupported", false); err == nil {
				t.Fatal("migration broadened unrelated origins")
			}
			if !profile.password {
				if _, err := insert("identity.password.signin", false); err == nil {
					t.Fatal("migration enabled an unselected password origin")
				}
			}
		})
	}
}
