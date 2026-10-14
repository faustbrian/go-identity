package reference

import (
	"testing"
	"time"

	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestPasswordOTPHistoryPreservesAppliedPrefixesAndLaterSelection(t *testing.T) {
	c := featureMigrationConfig{otpSchema: "otp_store", sessionSchema: "session_store", signinSchema: "session_store", passwordSigninSchema: "session_store", global: "deployment", passwordMFA: true, passwordTOTP: true, passwordRecovery: true}
	s := StoreSet{state: &storeState{config: VelocityStoreConfiguration{Schema: "risk_store"}, features: &featureState{migrations: c}}}
	before, err := s.migrationCatalog(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	after, err := passwordOTPMigrationCatalog(t.Context(), before, "session_store", "risk_store")
	if err != nil {
		t.Fatal("OTP storage cannot extend the selected native predecessors", err)
	}
	for _, old := range before {
		found := false
		for _, current := range after {
			if old.namespace != current.namespace {
				continue
			}
			found = true
			records := make([]migrations.Record, len(old.history))
			for i, step := range old.history {
				if i >= len(current.history) || current.history[i] != step || current.owners[step.Version()] != old.owners[step.Version()] {
					t.Fatal("OTP selection rewrote installed native history")
				}
				records[i], err = migrations.NewRecord(migrations.RecordKindMigration, step.Version(), step.Name(), step.Checksum(), time.Unix(1700000000, 0).UTC(), 0, false)
				if err != nil {
					t.Fatal(err)
				}
			}
			plan, err := migrations.PlanUp(current.history, records)
			if err != nil || len(plan.Steps()) != 0 {
				t.Fatal("OTP selection replayed an applied predecessor", err)
			}
		}
		if !found {
			t.Fatal("OTP selection removed an installed owner")
		}
	}
	// The shared MFA namespace remains eligible for its permanently allocated
	// management suffix. OTP's independent suffix cannot occupy those versions.
	for _, h := range after {
		if h.namespace == "identity_mfa" {
			if len(h.history) != 7 {
				t.Fatal("OTP replaced the existing shared MFA allocation")
			}
			var source migrations.Source = mfapg.FactorVerificationMigrationSource{Base: fixedMigrationSource(h.history), Version: 8}
			source = mfapg.FactorManagementMigrationSource{Base: source, Version: 9}
			source = mfapg.FactorRemovalMigrationSource{Base: source, Version: 10}
			source = mfapg.DisableMigrationSource{Base: source, Version: 11}
			source = mfapg.TOTPReplacementMigrationSource{Base: source, Version: 12}
			future, err := source.Load(t.Context())
			if err != nil || len(future) != len(h.history)+5 {
				t.Fatal("OTP allocation prevented later native management selection", err)
			}
			for i, old := range h.history {
				if future[i] != old {
					t.Fatal("later management selection rewrote the shared prefix")
				}
			}
			if _, err := migrations.PlanUp(future, nil); err != nil {
				t.Fatal(err)
			}
		}
	}
}
