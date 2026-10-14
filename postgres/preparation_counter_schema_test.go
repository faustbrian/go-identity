package postgres

import (
	"context"
	"errors"
	"testing"
)

func TestCounterPreparationMigrationPreservesInstalledHistory(t *testing.T) {
	base := AdmissionPreparationMigrationSource{Base: PreparationMigrationSource{Base: MigrationSource{}, Version: 10}, Version: 11}
	old, err := base.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	source := CounterPreparationMigrationSource{Base: base, Version: 12}
	history, err := source.Load(context.Background())
	if err != nil || len(history) != 12 || history[11].DownSQL() != "" {
		t.Fatal("missing forward counter history", err)
	}
	for i := range old {
		if old[i] != history[i] {
			t.Fatal("installed preparation history rewritten")
		}
	}
	history[0] = history[11]
	again, err := source.Load(context.Background())
	if err != nil || again[0] != old[0] {
		t.Fatal("caller mutated source history", err)
	}
	for _, bad := range []CounterPreparationMigrationSource{{}, {Base: base, Version: 11}} {
		if h, err := bad.Load(context.Background()); err == nil || h != nil {
			t.Fatal("invalid counter migration accepted")
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
