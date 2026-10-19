//go:build integration

package passwordpostgres

import (
	"context"
	"strconv"
	"testing"

	identity "github.com/faustbrian/go-identity"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
)

// Populated storage fixtures check purpose upgrades, not authentication. The
// surrounding consumer obtained tenant/user through actual enrollment owners.
func testPhoneSigninPurposeHistories(t *testing.T, ctx context.Context, pool *database.Pool, tenant identity.TenantID, user identity.UserID) {
	t.Helper()
	for index, mode := range []string{"verification", "mfa-before-verification", "mfa-after-verification"} {
		for _, username := range []bool{false, true} {
			name := mode
			if username {
				name += "-username"
			}
			t.Run(name, func(t *testing.T) {
				tx, err := pool.Raw().Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(ctx)
				schema := "phone_history_" + strconv.Itoa(index)
				if username {
					schema += "_username"
				}
				sources := []migrations.Source{
					sessionpg.IssueMigrationSource{Base: sessionpg.RevocationMigrationSource{Base: sessionpg.MigrationSource{Schema: schema, Version: 1}, Version: 2}, Version: 3},
					sessionpg.OTPIssueMigrationSource{Schema: schema, Version: 4},
					sessionpg.PasswordSigninMigrationSource{Schema: schema, Version: 5},
					sessionpg.PasswordSignupMigrationSource{Schema: schema, Version: 6},
					sessionpg.MagicLinkSigninMigrationSource{Schema: schema, Version: 7},
				}
				if mode == "mfa-before-verification" {
					sources = append(sources, sessionpg.MFASigninMigrationSource{Schema: schema, Version: 8})
				}
				sources = append(sources, sessionpg.EmailVerificationSigninMigrationSource{Schema: schema, Version: 9, MFASignin: mode == "mfa-before-verification"})
				predecessor := sessionpg.UsernameSigninAfterVerification
				if mode == "mfa-after-verification" {
					sources = append(sources, sessionpg.EmailVerificationMFASigninMigrationSource{Schema: schema, Version: 10})
					predecessor = sessionpg.UsernameSigninAfterVerificationMFA
				}
				if username {
					sources = append(sources, sessionpg.UsernameSigninMigrationSource{Schema: schema, Version: 11, Predecessor: predecessor, MFASignin: mode == "mfa-before-verification"})
				}
				for _, source := range sources {
					history, err := source.Load(ctx)
					if err != nil {
						t.Fatal(err)
					}
					for _, step := range history {
						if _, err := tx.Exec(ctx, step.UpSQL()); err != nil {
							t.Fatal("selected old purpose history", err)
						}
					}
				}
				table := schema + ".session_issuances"
				insert := func(id byte, purpose string) {
					t.Helper()
					command := [16]byte{id}
					var parent []byte
					if purpose == "identity.email.verification-signin" {
						original := [16]byte{22}
						parent = original[:]
					}
					if _, err := tx.Exec(ctx, `INSERT INTO `+table+`(tenant_id,command_id,purpose,user_id,session_id,family_id,binding_digest,record_digest,verification_command_id) VALUES($1,$2,$3,$4,'retained-session-'||$7::text,'retained-family-'||$7::text,$5,$5,$6)`, string(tenant), command[:], purpose, string(user), make([]byte, 32), parent, strconv.Itoa(int(id))); err != nil {
						t.Fatal("purpose profile lost required issuance", err)
					}
				}
				insert(1, "identity.password.signin")
				insert(2, "identity.email.verification-signin")
				if mode != "verification" {
					insert(3, "identity.mfa.totp-verify")
				}
				if username {
					insert(4, "identity.username.signin")
				}
				var before, after string
				query := `SELECT jsonb_agg(to_jsonb(s) ORDER BY command_id)::text FROM ` + table + ` s`
				if err := tx.QueryRow(ctx, query).Scan(&before); err != nil {
					t.Fatal(err)
				}
				history, err := (sessionpg.PhonePasswordSigninMigrationSource{Schema: schema, Version: 12, Predecessor: predecessor, MFASignin: mode == "mfa-before-verification", UsernameSignin: username}).Load(ctx)
				if err != nil {
					t.Fatal(err)
				}
				for _, step := range history {
					if _, err := tx.Exec(ctx, step.UpSQL()); err != nil {
						t.Fatal("phone populated forward migration", err)
					}
				}
				if err := tx.QueryRow(ctx, query).Scan(&after); err != nil || before != after {
					t.Fatal("phone suffix rewrote retained original issuance", err)
				}
				insert(5, "identity.phone.password-signin")
				// An unselected OTP-phone operation must not inherit password
				// provenance just because it shares the phone namespace.
				id := [16]byte{6}
				if _, err := tx.Exec(ctx, `INSERT INTO `+table+`(tenant_id,command_id,purpose,user_id,session_id,family_id,binding_digest,record_digest) VALUES($1,$2,'identity.phone.signin',$3,'foreign','foreign',$4,$4)`, string(tenant), id[:], string(user), make([]byte, 32)); err == nil {
					t.Fatal("phone OTP obtained password issuance provenance")
				}
			})
		}
	}
}
