package reference

import (
	"testing"

	passwordpg "github.com/faustbrian/go-identity/password/postgres"
)

func TestVerificationTOTPUpgradePreservesVerificationFirstHistory(t *testing.T) {
	s := StoreSet{state: &storeState{config: VelocityStoreConfiguration{Schema: "risk_store"}, features: &featureState{verificationSignin: &passwordpg.VerificationSigninService{}, migrations: featureMigrationConfig{passwordSigninSchema: "session_store"}}}}
	before, err := s.verificationSigninMigrationCatalog(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	s.state.features.verificationSigninMFA = true
	s.state.features.verificationSessionLineage = VerificationBeforeMFA
	s.state.features.verificationTOTP = &magicLinkTOTPService{}
	after, err := s.verificationSigninMigrationCatalog(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, old := range before {
		found := false
		for _, current := range after {
			if old.namespace != current.namespace {
				continue
			}
			found = true
			if len(current.history) < len(old.history) {
				t.Fatal("selected TOTP removed applied history")
			}
			for index, step := range old.history {
				if step != current.history[index] {
					t.Fatal("selected TOTP rewrote applied verification-first migration", old.namespace)
				}
			}
		}
		if !found {
			t.Fatal("selected TOTP removed installed namespace", old.namespace)
		}
	}
}

func TestVerificationFirstMFACompositionRetainsBothShippedPrefixes(t *testing.T) {
	for _, lineage := range []VerificationSessionLineage{VerificationBeforeMFA, MFABeforeVerification} {
		baseStore := StoreSet{state: &storeState{config: VelocityStoreConfiguration{Schema: "risk_store"}, features: &featureState{migrations: featureMigrationConfig{otpSchema: "otp_store", sessionSchema: "session_store", signinSchema: "session_store", passwordSigninSchema: "session_store", global: "deployment"}}}}
		base, e := baseStore.migrationCatalog(t.Context())
		if e != nil {
			t.Fatal(e)
		}
		s := StoreSet{state: &storeState{config: VelocityStoreConfiguration{Schema: "risk_store"}, features: &featureState{verificationSignin: &passwordpg.VerificationSigninService{}, verificationSessionLineage: lineage, migrations: featureMigrationConfig{passwordSigninSchema: "session_store"}}}}
		prefix := append([]migrationHistory(nil), base...)
		var err error
		if lineage == MFABeforeVerification {
			prefix, err = magicLinkMigrationCatalog(t.Context(), prefix, "session_store")
			if err != nil {
				t.Fatal(err)
			}
			prefix, err = magicLinkTOTPRequiredMigrations(t.Context(), prefix, "session_store", "risk_store", false)
			if err != nil {
				t.Fatal(err)
			}
		}
		before, err := s.verificationSigninMigrationCatalog(t.Context(), prefix)
		if err != nil {
			t.Fatal(err)
		}
		s.state.features.verificationSigninMFA = true
		s.state.features.verificationTOTP = &magicLinkTOTPService{}
		s.state.features.migrations.passwordTOTP = true
		later, err := passwordTOTPMigrationCatalog(t.Context(), append([]migrationHistory(nil), base...), "session_store", "risk_store", true, lineage == VerificationBeforeMFA)
		if err != nil {
			t.Fatal(err)
		}
		after, err := s.verificationSigninMigrationCatalog(t.Context(), later)
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		bridge, password := -1, -1
		for index, current := range after {
			if seen[current.namespace] {
				t.Fatal("shared MFA composition duplicated a migration namespace")
			}
			seen[current.namespace] = true
			if current.namespace == "identity_verification_mfa_session" {
				bridge = index
			}
			if current.namespace == "identity_password_mfa_session" {
				password = index
			}
			for _, old := range before {
				if old.namespace == current.namespace {
					for i, step := range old.history {
						if i >= len(current.history) || step != current.history[i] {
							t.Fatal("later MFA composition rewrote an installed prefix", old.namespace)
						}
					}
				}
			}
		}
		for _, old := range before {
			if !seen[old.namespace] {
				t.Fatal("later MFA removed an installed namespace", old.namespace)
			}
		}
		if lineage == VerificationBeforeMFA && (bridge < 0 || password <= bridge || seen["identity_magiclink_mfa_session"]) {
			t.Fatal("verification-first composition replayed legacy MFA or ordered its successor first")
		}
		if lineage == MFABeforeVerification && (bridge >= 0 || !seen["identity_magiclink_mfa_session"]) {
			t.Fatal("MFA-first composition replaced original session history")
		}
	}
}
