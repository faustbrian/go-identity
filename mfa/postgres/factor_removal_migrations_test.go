package mfapostgres

import "testing"

func TestFactorRemovalHistoryPreservesInstalledManagement(t *testing.T) {
	base := FactorManagementMigrationSource{Base: FactorVerificationMigrationSource{Base: MigrationSource{Version: 1}, Version: 2}, Version: 3}
	before, err := base.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	after, err := (FactorRemovalMigrationSource{Base: base, Version: 4}).Load(t.Context())
	if err != nil || len(after) != len(before)+1 {
		t.Fatal("removal history is not forward-only", err)
	}
	for i := range before {
		if after[i] != before[i] {
			t.Fatal("installed factor/management migration changed")
		}
	}
}
