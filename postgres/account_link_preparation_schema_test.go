package postgres

import (
	"context"
	"errors"
	"testing"
)

func TestAccountLinkPreparationMigrationPreservesInstalledHistory(t *testing.T) {
	base := CounterPreparationMigrationSource{Base: AdmissionPreparationMigrationSource{Base: PreparationMigrationSource{Base: MigrationSource{}, Version: 10}, Version: 11}, Version: 12}
	installed, err := base.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	source := AccountLinkPreparationMigrationSource{Base: base, Version: 13}
	history, err := source.Load(t.Context())
	if err != nil || len(history) != len(installed)+1 || history[len(installed)].DownSQL() != "" {
		t.Fatal("missing forward account-link preparation history", err)
	}
	for i := range installed {
		if installed[i] != history[i] {
			t.Fatal("installed preparation history rewritten")
		}
	}
	history[0] = history[len(installed)]
	again, err := source.Load(t.Context())
	if err != nil || again[0] != installed[0] {
		t.Fatal("caller mutated migration history", err)
	}
	for _, invalid := range []AccountLinkPreparationMigrationSource{{}, {Base: base, Version: 12}} {
		if h, err := invalid.Load(t.Context()); err == nil || h != nil {
			t.Fatal("invalid migration source accepted")
		}
	}
	if h, err := source.Load(nil); err == nil || h != nil {
		t.Fatal("nil migration context accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if h, err := source.Load(ctx); !errors.Is(err, context.Canceled) || h != nil {
		t.Fatal("migration cancellation lost", err)
	}
}
