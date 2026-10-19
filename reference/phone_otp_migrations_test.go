package reference

import (
	"testing"

	otppg "github.com/faustbrian/go-identity/otp/postgres"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
)

func TestPhoneOTPMigrationsAppendAfterSelectedHistories(t *testing.T) {
	for _, profile := range []string{"otp-only", "password", "username", "phone-password"} {
		t.Run(profile, func(t *testing.T) {
			f := &featureState{migrations: featureMigrationConfig{otpSchema: "otp_store", sessionSchema: "preauth_store", signinSchema: "session_store", global: "deployment"}}
			if profile != "otp-only" {
				f.migrations.passwordSigninSchema = "session_store"
				f.passwordSignin = &passwordpg.SigninService{}
				f.passwordSignup = &passwordpg.SignupService{}
			}
			if profile == "username" {
				f.username = &usernameState{signin: &passwordpg.SigninService{}}
			}
			if profile == "phone-password" {
				f.phoneSignin = &phoneSigninState{owner: &passwordpg.SigninService{}}
			}
			s := StoreSet{state: &storeState{config: VelocityStoreConfiguration{Schema: "risk_store"}, features: f}}
			before, err := s.migrationCatalog(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			// Metadata only here; real selected HTTPS tests execute native SQL.
			f.phoneOTPSignin = &phoneOTPSigninState{owner: &otppg.PhoneSigninService{}}
			f.migrations.otpSigninFactors = true
			after, err := s.migrationCatalog(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if after[len(after)-1].namespace != "identity_phone_otp_signin_session" {
				t.Fatal("phone OTP has no final native provenance suffix")
			}
			seen := map[string]bool{}
			for _, h := range after {
				if seen[h.namespace] {
					t.Fatal("duplicate physical history", h.namespace)
				}
				seen[h.namespace] = true
				for _, old := range before {
					if old.namespace == h.namespace {
						for i, step := range old.history {
							if i >= len(h.history) || h.history[i] != step {
								t.Fatal("phone OTP rewrote a predecessor", h.namespace)
							}
						}
					}
				}
			}
			for _, old := range before {
				if !seen[old.namespace] {
					t.Fatal("phone OTP removed a predecessor", old.namespace)
				}
			}
			if !seen["identity_username_kernel"] || !seen["identity_mfa"] {
				t.Fatal("phone OTP omitted real normalization/factor authority")
			}
		})
	}
}
