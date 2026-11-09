package postgres

import (
	"context"
	"errors"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestAccountLinkErasureMigrationPreservesInstalledHistory(t *testing.T) {
	preparation := AccountLinkPreparationMigrationSource{Base: CounterPreparationMigrationSource{Base: AdmissionPreparationMigrationSource{Base: PreparationMigrationSource{Base: MigrationSource{}, Version: 10}, Version: 11}, Version: 12}, Version: 13}
	base := OAuthRPPreparationErasureMigrationSource{Base: preparation, Version: 14}
	installed, err := base.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	erasure := AccountLinkPreparationErasureMigrationSource{Base: base, Version: 15}
	validation := AccountLinkPreparationErasureValidationMigrationSource{Base: erasure, Version: 16}
	for _, source := range []migrations.Source{erasure, validation} {
		history, err := source.Load(t.Context())
		if err != nil || len(history) <= len(installed) {
			t.Fatal("missing forward erasure history", err)
		}
		for i, previous := range installed {
			if history[i] != previous {
				t.Fatal("published preparation/account-link/RP history rewritten")
			}
		}
		for _, next := range history[len(installed):] {
			if next.DownSQL() != "" {
				t.Fatal("erased provider secrets cannot have a destructive rollback")
			}
		}
		history[0] = history[len(installed)]
		again, err := source.Load(t.Context())
		if err != nil || again[0] != installed[0] {
			t.Fatal("caller mutated installed history", err)
		}
	}
	for _, invalid := range []migrations.Source{
		AccountLinkPreparationErasureMigrationSource{},
		AccountLinkPreparationErasureMigrationSource{Base: base, Version: 14},
		AccountLinkPreparationErasureValidationMigrationSource{},
		AccountLinkPreparationErasureValidationMigrationSource{Base: erasure, Version: 15},
	} {
		if history, err := invalid.Load(t.Context()); err == nil || history != nil {
			t.Fatal("invalid erasure migration accepted")
		}
	}
	for _, source := range []migrations.Source{erasure, validation} {
		if history, err := source.Load(nil); err == nil || history != nil {
			t.Fatal("nil migration context accepted")
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if history, err := source.Load(ctx); !errors.Is(err, context.Canceled) || history != nil {
			t.Fatal("migration cancellation lost", err)
		}
	}
}
