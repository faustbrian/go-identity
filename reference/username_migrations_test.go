package reference

import (
	"testing"

	magicpg "github.com/faustbrian/go-identity/magiclink/postgres"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
)

func TestUsernameMigrationsRetainSelectedNativePredecessors(t *testing.T) {
	for _, profile := range []string{"password", "magiclink", "mfa", "verification", "mfa-before-verification", "verification-before-mfa"} {
		t.Run(profile, func(t *testing.T) {
			c := featureMigrationConfig{otpSchema: "otp_store", sessionSchema: "session_store", signinSchema: "session_store", passwordSigninSchema: "session_store", global: "deployment"}
			f := &featureState{migrations: c, passwordSignup: &passwordpg.SignupService{}}
			if profile == "magiclink" {
				f.magicRequest = &magicpg.RequestService{}
				f.migrations.magicSessionSchema, f.migrations.magicSignup = "session_store", true
			}
			if profile == "mfa" || profile == "mfa-before-verification" || profile == "verification-before-mfa" {
				f.migrations.passwordMFA, f.migrations.passwordTOTP = true, true
			}
			if profile == "verification" || profile == "mfa-before-verification" || profile == "verification-before-mfa" {
				f.verificationSignin = &passwordpg.VerificationSigninService{}
			}
			if profile == "mfa-before-verification" {
				f.verificationSessionLineage = MFABeforeVerification
			}
			if profile == "verification-before-mfa" {
				f.verificationSessionLineage = VerificationBeforeMFA
				f.verificationTOTP = &magicLinkTOTPService{}
			}
			s := StoreSet{state: &storeState{config: VelocityStoreConfiguration{Schema: "risk_store"}, features: f}}
			before, err := s.migrationCatalog(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			f.username = &usernameState{signup: &passwordpg.SignupService{}, signin: &passwordpg.SigninService{}, rename: &passwordpg.UsernameRenameService{}}
			after, err := s.migrationCatalog(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			want := map[string]bool{"identity_username_kernel": true, "identity_username_registration": true, "identity_username_factors": true, "identity_username_password": true, "identity_username_session": true, "identity_username_actions": true, "identity_risk_lockouts": true}
			seen := map[string]bool{}
			for _, h := range after {
				if seen[h.namespace] {
					t.Fatal("username duplicated a physical migration namespace", h.namespace)
				}
				seen[h.namespace] = true
				delete(want, h.namespace)
				for _, prior := range before {
					if prior.namespace != h.namespace {
						continue
					}
					for i, m := range prior.history {
						if i >= len(h.history) || m != h.history[i] {
							t.Fatal("username rewrote an installed native prefix", h.namespace)
						}
					}
				}
			}
			for _, prior := range before {
				if !seen[prior.namespace] {
					t.Fatal("username removed installed migration history", prior.namespace)
				}
			}
			if len(want) != 0 {
				t.Fatal("selected username cannot deploy native prerequisites", want)
			}
		})
	}
}

func TestUsernameAvailabilityRetainsPhysicalCounterHistory(t *testing.T) {
	for _, durable := range []bool{false, true} {
		for _, schema := range []string{"risk_store", "username_counters"} {
			f := &featureState{migrations: featureMigrationConfig{otpSchema: "otp_store", sessionSchema: "session_store", global: "deployment"}, username: &usernameState{available: &passwordpg.UsernameAvailabilityService{}, availabilitySchema: schema}}
			s := StoreSet{state: &storeState{config: VelocityStoreConfiguration{Schema: "risk_store"}, durable: durable, features: f}}
			catalog, err := s.migrationCatalog(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			want, err := (riskpg.DurableCounterMigrationSource{Schema: schema, Version: 1}).Load(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			matches := 0
			for _, history := range catalog {
				for _, step := range history.history {
					if step.Checksum() == want[0].Checksum() && step.Name() == want[0].Name() {
						matches++
						if schema == "risk_store" && history.namespace != "identity_durable_admission" {
							t.Fatal("shared physical counter tables acquired a second history owner")
						}
					}
				}
			}
			if matches != 1 {
				t.Fatal("selected availability must install its actual counter history exactly once", durable, schema, matches)
			}
		}
	}
}
