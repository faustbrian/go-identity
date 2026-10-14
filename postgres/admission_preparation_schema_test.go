package postgres

import (
	"context"
	"errors"
	"testing"
)

func TestAdmissionPreparationMigrationPreservesInstalledHistory(t *testing.T) {
	base := PreparationMigrationSource{Base: MigrationSource{}, Version: 10}
	old, err := base.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	source := AdmissionPreparationMigrationSource{Base: base, Version: 11}
	history, err := source.Load(context.Background())
	if err != nil || len(history) != 11 || history[10].DownSQL() != "" {
		t.Fatal("missing forward admission history", err)
	}
	for i := range old {
		if old[i] != history[i] {
			t.Fatal("installed preparation history rewritten")
		}
	}
	history[0] = history[10]
	again, err := source.Load(context.Background())
	if err != nil || again[0] != old[0] {
		t.Fatal("caller mutated source history", err)
	}
	for _, bad := range []AdmissionPreparationMigrationSource{{}, {Base: base, Version: 10}} {
		if h, err := bad.Load(context.Background()); err == nil || h != nil {
			t.Fatal("invalid admission migration accepted")
		}
	}
	if h, err := source.Load(nil); err == nil || h != nil {
		t.Fatal("nil migration context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if h, err := source.Load(ctx); !errors.Is(err, context.Canceled) || h != nil {
		t.Fatal("migration cancellation lost", err)
	}
}
