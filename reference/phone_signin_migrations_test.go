package reference

import (
	"testing"

	passwordpg "github.com/faustbrian/go-identity/password/postgres"
)

func TestPhoneSigninMigrationsAppendAfterSelectedHistories(t *testing.T) {
	for _, profile := range []string{"password", "username", "enrollment", "enrollment-username"} {
		t.Run(profile, func(t *testing.T) {
			f := &featureState{migrations: featureMigrationConfig{otpSchema: "otp_store", sessionSchema: "preauth_store", authenticatedSchema: "session_store", passwordSigninSchema: "session_store", global: "deployment"}, passwordSignup: &passwordpg.SignupService{}, passwordSignin: &passwordpg.SigninService{}}
			if profile == "username" || profile == "enrollment-username" {
				f.username = &usernameState{signin: &passwordpg.SigninService{}}
			}
			if profile == "enrollment" || profile == "enrollment-username" {
				f.phone = &phoneState{owner: &passwordpg.PhoneVerificationService{}}
				f.passwordVerification = &passwordVerificationState{native: &passwordpg.ReauthenticationService{}}
			}
			s := StoreSet{state: &storeState{config: VelocityStoreConfiguration{Schema: "risk_store"}, features: f}}
			before, err := s.migrationCatalog(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			// Zero owners select migration metadata only; actual consumer tests
			// prove durable runtime and do not use these uninitialized services.
			f.phoneSignin = &phoneSigninState{owner: &passwordpg.SigninService{}}
			after, err := s.migrationCatalog(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			wanted := map[string]bool{"identity_phone_signin_password": true, "identity_phone_signin_session": true}
			seen := map[string]bool{}
			for _, h := range after {
				if seen[h.namespace] {
					t.Fatal("phone signin duplicated a migration history", h.namespace)
				}
				seen[h.namespace] = true
				delete(wanted, h.namespace)
				for _, old := range before {
					if old.namespace != h.namespace {
						continue
					}
					for i, step := range old.history {
						if i >= len(h.history) || h.history[i] != step {
							t.Fatal("phone signin changed an installed predecessor", old.namespace)
						}
					}
				}
			}
			if len(wanted) != 0 {
				t.Fatal("selected phone signin lacks native purpose histories", wanted)
			}
		})
	}
}
