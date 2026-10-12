package mfapostgres

import (
	"context"
	"testing"
)

func TestTOTPFactorMigrationHistoryAndBounds(t *testing.T) {
	base := ContinuationMigrationSource{Base: MigrationSource{Version: 1}, Version: 2}
	history, err := (TOTPFactorMigrationSource{Base: base, Version: 3}).Load(context.Background())
	if err != nil || len(history) != 3 {
		t.Fatal("factor history not append-only", err)
	}
	before, err := base.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for i := range before {
		if history[i].UpSQL() != before[i].UpSQL() || history[i].Version() != before[i].Version() {
			t.Fatal("existing history changed")
		}
	}
	for _, source := range []TOTPFactorMigrationSource{{}, {Base: base, Version: 2}, {Base: base, Version: 0}} {
		if _, err := source.Load(context.Background()); err == nil {
			t.Fatal("invalid history accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (TOTPFactorMigrationSource{Base: base, Version: 3}).Load(ctx); err == nil {
		t.Fatal("cancellation ignored")
	}
}
