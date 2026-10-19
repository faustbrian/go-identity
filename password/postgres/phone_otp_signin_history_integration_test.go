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
	"github.com/jackc/pgx/v5"
)

// These populated rows prove storage upgrades, not authentication. Tenant/user
// come from the genuine consumer; no retained original row may be rewritten.
func testPhoneOTPPurposeHistories(t *testing.T, ctx context.Context, pool *database.Pool, tenant identity.TenantID, user identity.UserID) {
	t.Helper()
	for _, profile := range []struct {
		prior sessionpg.UsernameSigninPredecessor
		mfa   bool
	}{
		{sessionpg.UsernameSigninAfterPassword, false},
		{sessionpg.UsernameSigninAfterSignup, false},
		{sessionpg.UsernameSigninAfterMagicLink, false},
		{sessionpg.UsernameSigninAfterMFA, false},
		{sessionpg.UsernameSigninAfterVerification, false},
		{sessionpg.UsernameSigninAfterVerification, true},
		{sessionpg.UsernameSigninAfterVerificationMFA, false},
	} {
		for _, username := range []bool{false, true} {
			for _, phonePassword := range []bool{false, true} {
				name := "v" + strconv.Itoa(int(profile.prior)) + "_mfa_" + strconv.FormatBool(profile.mfa) + "_user_" + strconv.FormatBool(username) + "_password_" + strconv.FormatBool(phonePassword)
				t.Run(name, func(t *testing.T) {
					tx, err := pool.Raw().Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer tx.Rollback(ctx)
					schema := "phone_otp_" + name
					sources := []migrations.Source{
						sessionpg.IssueMigrationSource{Base: sessionpg.RevocationMigrationSource{Base: sessionpg.MigrationSource{Schema: schema, Version: 1}, Version: 2}, Version: 3},
						sessionpg.OTPIssueMigrationSource{Schema: schema, Version: 4},
						sessionpg.PasswordSigninMigrationSource{Schema: schema, Version: 5},
					}
					purposes := []string{"identity.session.issue", "identity.otp.signin", "identity.password.signin"}
					if profile.prior >= sessionpg.UsernameSigninAfterSignup {
						sources = append(sources, sessionpg.PasswordSignupMigrationSource{Schema: schema, Version: 6})
						purposes = append(purposes, "identity.password.signup")
					}
					if profile.prior >= sessionpg.UsernameSigninAfterMagicLink {
						sources = append(sources, sessionpg.MagicLinkSigninMigrationSource{Schema: schema, Version: 7})
						purposes = append(purposes, "identity.magic-link.consume")
					}
					if profile.prior == sessionpg.UsernameSigninAfterMFA || profile.mfa {
						sources = append(sources, sessionpg.MFASigninMigrationSource{Schema: schema, Version: 8})
					}
					if profile.prior >= sessionpg.UsernameSigninAfterVerification {
						sources = append(sources, sessionpg.EmailVerificationSigninMigrationSource{Schema: schema, Version: 9, MFASignin: profile.mfa})
						purposes = append(purposes, "identity.email.verification-signin")
					}
					if profile.prior == sessionpg.UsernameSigninAfterVerificationMFA {
						sources = append(sources, sessionpg.EmailVerificationMFASigninMigrationSource{Schema: schema, Version: 10})
					}
					if profile.prior == sessionpg.UsernameSigninAfterMFA || profile.prior == sessionpg.UsernameSigninAfterVerificationMFA || profile.mfa {
						purposes = append(purposes, "identity.mfa.totp-verify", "identity.mfa.otp-verify", "identity.mfa.recovery-use", "identity.mfa.security-key-assert-verify")
					}
					if username {
						sources = append(sources, sessionpg.UsernameSigninMigrationSource{Schema: schema, Version: 11, Predecessor: profile.prior, MFASignin: profile.mfa})
						purposes = append(purposes, "identity.username.signin")
					}
					if phonePassword {
						sources = append(sources, sessionpg.PhonePasswordSigninMigrationSource{Schema: schema, Version: 12, Predecessor: profile.prior, MFASignin: profile.mfa, UsernameSignin: username})
						purposes = append(purposes, "identity.phone.password-signin")
					}
					for _, source := range sources {
						history, err := source.Load(ctx)
						if err != nil {
							t.Fatal(err)
						}
						for _, step := range history {
							if _, err := tx.Exec(ctx, step.UpSQL()); err != nil {
								t.Fatal("selected phone OTP predecessor history", err)
							}
						}
					}
					table := pgx.Identifier{schema, "session_issuances"}.Sanitize()
					insert := func(index int, purpose string) {
						t.Helper()
						command := [16]byte{byte(index + 1)}
						var parent []byte
						if purpose == "identity.email.verification-signin" {
							original := [16]byte{90, byte(index + 1)}
							parent = original[:]
						}
						columns := "tenant_id,command_id,purpose,user_id,session_id,family_id,binding_digest,record_digest"
						values := "$1,$2,$3,$4,'retained-session-'||$6::text,'retained-family-'||$6::text,$5,$5"
						args := []any{string(tenant), command[:], purpose, string(user), make([]byte, 32), strconv.Itoa(index)}
						if profile.prior >= sessionpg.UsernameSigninAfterVerification {
							columns += ",verification_command_id"
							values += ",$7"
							args = append(args, parent)
						}
						if _, err := tx.Exec(ctx, "INSERT INTO "+table+"("+columns+") VALUES("+values+")", args...); err != nil {
							t.Fatal("purpose history dropped a selected method", err)
						}
					}
					for index, purpose := range purposes {
						insert(index, purpose)
					}
					query := `SELECT jsonb_agg(to_jsonb(s) ORDER BY command_id)::text FROM ` + table + ` s`
					var before, after string
					if err := tx.QueryRow(ctx, query).Scan(&before); err != nil {
						t.Fatal(err)
					}
					history, err := (sessionpg.PhoneOTPSigninMigrationSource{Schema: schema, Version: 13, Predecessor: profile.prior, MFASignin: profile.mfa, UsernameSignin: username, PhonePasswordSignin: phonePassword}).Load(ctx)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := tx.Exec(ctx, history[0].UpSQL()); err != nil {
						t.Fatal("populated phone OTP forward migration", err)
					}
					if err := tx.QueryRow(ctx, query).Scan(&after); err != nil || before != after {
						t.Fatal("phone OTP migration rewrote original history", err)
					}
					insert(30, "identity.phone.signin")
					for index, purpose := range purposes {
						insert(index+40, purpose)
					}
					// No selected predecessor may admit an unrelated new operation.
					command := [16]byte{99}
					if _, err := tx.Exec(ctx, `INSERT INTO `+table+`(tenant_id,command_id,purpose,user_id,session_id,family_id,binding_digest,record_digest) VALUES($1,$2,'identity.phone.signup',$3,'foreign','foreign',$4,$4)`, string(tenant), command[:], string(user), make([]byte, 32)); err == nil {
						t.Fatal("phone OTP suffix admitted an unselected signup workflow")
					}
				})
			}
		}
	}
}
