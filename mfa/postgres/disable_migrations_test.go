package mfapostgres

import "testing"

func TestDisableHistoryPreservesPopulatedRemovalPrefix(t *testing.T) {
	base := FactorRemovalMigrationSource{Base: FactorManagementMigrationSource{Base: FactorVerificationMigrationSource{Base: MigrationSource{Version: 1}, Version: 2}, Version: 3}, Version: 4}
	before, err := base.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	after, err := (DisableMigrationSource{Base: base, Version: 5}).Load(t.Context())
	if err != nil || len(after) != len(before)+1 {
		t.Fatal("disable history is not an additive suffix", err)
	}
	for i := range before {
		if before[i] != after[i] {
			t.Fatal("disable rewrote installed MFA history")
		}
	}
}
