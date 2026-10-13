package mfapostgres

import (
	"context"
	"testing"
)

func TestFactorManagementMigrationPreservesOriginalHistory(t *testing.T) {
	base := FactorVerificationMigrationSource{Base: MigrationSource{Version: 1}, Version: 2}
	before, err := base.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	history, err := (FactorManagementMigrationSource{Base: base, Version: 3}).Load(t.Context())
	if err != nil || len(history) != len(before)+1 {
		t.Fatal("management history not append-only", err)
	}
	for i := range before {
		if history[i] != before[i] {
			t.Fatal("existing factor or proof history rewritten")
		}
	}
	for _, source := range []FactorManagementMigrationSource{{}, {Base: base, Version: 2}} {
		if _, err := source.Load(t.Context()); err == nil {
			t.Fatal("missing/conflicting migration ownership accepted")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := (FactorManagementMigrationSource{Base: base, Version: 3}).Load(ctx); err == nil {
		t.Fatal("cancellation ignored")
	}
}
