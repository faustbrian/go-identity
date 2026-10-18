package reference

import "testing"

func TestPasswordTOTPHistoryExtendsOriginalPrefixesWithoutDuplicateOwners(t *testing.T) {
	c := featureMigrationConfig{otpSchema: "otp_store", sessionSchema: "session_store", signinSchema: "session_store", passwordSigninSchema: "session_store", global: "deployment"}
	s := StoreSet{state: &storeState{config: VelocityStoreConfiguration{Schema: "risk_store"}, features: &featureState{migrations: c}}}
	before, err := s.migrationCatalog(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	after, err := passwordTOTPMigrationCatalog(t.Context(), before, "session_store", "risk_store", true, false)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, h := range after {
		if seen[h.namespace] {
			t.Fatal("duplicate migration authority")
		}
		seen[h.namespace] = true
		for _, old := range before {
			if old.namespace != h.namespace {
				continue
			}
			for j, step := range old.history {
				if j >= len(h.history) || step != h.history[j] {
					t.Fatal("installed history rewritten")
				}
			}
		}
		if h.namespace == "identity_mfa" && len(h.history) != 7 {
			t.Fatal("password origin extension missing")
		}
	}
	for _, name := range []string{"identity_mfa", "identity_mfa_counters", "identity_magiclink_session", "identity_password_mfa_session"} {
		if !seen[name] {
			t.Fatal("completion bootstrap owner absent", name)
		}
	}
}
