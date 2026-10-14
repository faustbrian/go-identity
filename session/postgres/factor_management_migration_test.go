package postgres

import (
	"context"
	"testing"
)

func TestFactorUpdateSessionMigrationRequiresExactOwnership(t *testing.T) {
	for _, source := range []MFAFactorUpdateSessionMigrationSource{{}, {Schema: "unsafe;schema", Version: 2}, {Schema: "session_store", Version: 0}} {
		if _, err := source.Load(t.Context()); err == nil {
			t.Fatal("invalid factor-management session migration accepted")
		}
	}
	source := MFAFactorUpdateSessionMigrationSource{Schema: "session_store", Version: 2}
	steps, err := source.Load(t.Context())
	if err != nil || len(steps) != 1 || steps[0].Version() != 2 {
		t.Fatal("owned extension unavailable", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := source.Load(ctx); err == nil {
		t.Fatal("migration ignored cancellation")
	}
}
