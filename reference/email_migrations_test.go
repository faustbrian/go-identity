package reference

import (
	"context"
	"testing"

	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestEmailMigrationsConserveExistingOwnerPrefixes(t *testing.T) {
	ctx := context.Background()
	shared, err := (kernel.AdmissionPreparationMigrationSource{Base: kernel.PreparationMigrationSource{Base: kernel.MigrationSource{}, Version: 1012}, Version: 1013}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	password, err := (passwordpg.MigrationSource{}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	base := []migrationHistory{{history: shared}, {namespace: "identity_password", history: password, owners: map[migrations.Version]ModuleID{1: "identity/password/postgres"}}}
	selected, err := emailMigrationCatalog(ctx, base, "risk_store", true, true)
	if err != nil {
		t.Fatal(err)
	}
	again, err := emailMigrationCatalog(ctx, selected, "risk_store", true, true)
	if err != nil || len(again) != len(selected) {
		t.Fatal("email selection duplicated native histories", err)
	}
	seen := map[string]bool{}
	for i, h := range selected {
		if seen[h.namespace] {
			t.Fatal("two histories claimed one ledger")
		}
		seen[h.namespace] = true
		if len(h.history) != len(again[i].history) {
			t.Fatal("repeat selection appended a migration twice")
		}
		for n, step := range h.history {
			if step.Checksum() != again[i].history[n].Checksum() {
				t.Fatal("repeat selection rewrote native source")
			}
		}
		if h.namespace == "identity_password" {
			if len(h.history) != len(password)+1 {
				t.Fatal("email proof history is not additive")
			}
			for n, step := range password {
				if h.history[n].Checksum() != step.Checksum() {
					t.Fatal("email selection rewrote installed password history")
				}
			}
		}
	}
	if len(base[1].history) != len(password) {
		t.Fatal("caller-owned history was mutated")
	}
}
