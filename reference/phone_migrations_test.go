package reference

import (
	"testing"

	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	ratepg "github.com/faustbrian/go-rate-limit/v2/postgres"
)

func TestPhoneHTTPAloneInstallsAtomicRateHistory(t *testing.T) {
	features := &featureState{
		migrations:            featureMigrationConfig{otpSchema: "otp_store", sessionSchema: "session_store", global: "deployment"},
		httpPhoneVerification: &emailOTPVerificationHTTPState{},
	}
	stores := StoreSet{state: &storeState{config: VelocityStoreConfiguration{Schema: "risk_store"}, httpRate: &httpRateState{}, features: features}}
	catalog, err := stores.migrationCatalog(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	native := ratepg.AtomicSchemaMigration()
	found := 0
	for _, history := range catalog {
		for _, step := range history.history {
			if step.Name() == native.Name {
				if history.namespace != "identity_http_rate" || step.UpSQL() != native.Up || history.owners[step.Version()] != "rate-limit/postgres" {
					t.Fatal("phone HTTP lost native atomic-rate migration ownership")
				}
				found++
			}
		}
	}
	if found != 1 {
		t.Fatal("phone HTTP requires its native atomic-rate history without sibling HTTP features", found)
	}
}

func TestPhoneMigrationsPreserveExistingOwners(t *testing.T) {
	for _, username := range []string{"none", "rename", "totp"} {
		t.Run(username, func(t *testing.T) {
			f := &featureState{migrations: featureMigrationConfig{otpSchema: "otp_store", sessionSchema: "preauth_store", authenticatedSchema: "session_store", passwordSigninSchema: "session_store", global: "deployment"}, passwordSignup: &passwordpg.SignupService{}, passwordSignin: &passwordpg.SigninService{}, passwordVerification: &passwordVerificationState{native: &passwordpg.ReauthenticationService{}}}
			if username != "none" {
				f.username = &usernameState{signin: &passwordpg.SigninService{}}
				if username == "rename" {
					f.username.rename = &passwordpg.UsernameRenameService{}
				}
				if username == "totp" {
					f.migrations.passwordMFA, f.migrations.passwordTOTP = true, true
					f.username.totp = &magicLinkTOTPService{}
				}
			}
			stores := StoreSet{state: &storeState{config: VelocityStoreConfiguration{Schema: "risk_store"}, features: f}}
			before, err := stores.migrationCatalog(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			// Zero native handles select only migration metadata in this test;
			// they neither grant runtime authority nor prove the actual journey.
			f.phone = &phoneState{owner: &passwordpg.PhoneVerificationService{}}
			after, err := stores.migrationCatalog(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			seen := map[string]bool{}
			wanted := map[string]bool{"identity_identifier_normalization": true, "identity_password_action_reauthentication_consumption": true, "identity_password_phone_reauthentication_consumption": true, "identity_otp_phone_purpose": true, "identity_otp_original_consuming_custody": true}
			for _, h := range after {
				if seen[h.namespace] {
					t.Fatal("phone duplicated a physical history owner", h.namespace)
				}
				seen[h.namespace] = true
				for _, step := range h.history {
					delete(wanted, step.Name())
				}
				for _, old := range before {
					if old.namespace != h.namespace {
						continue
					}
					for i, step := range old.history {
						if i >= len(h.history) || h.history[i] != step {
							t.Fatal("phone rewrote an installed migration", h.namespace)
						}
					}
				}
			}
			for _, old := range before {
				if !seen[old.namespace] {
					t.Fatal("phone removed an installed history", old.namespace)
				}
			}
			if len(wanted) != 0 {
				t.Fatal("selected phone cannot bootstrap its actual owners", wanted)
			}
		})
	}
}
