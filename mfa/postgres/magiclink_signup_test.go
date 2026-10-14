package mfapostgres

import (
	"context"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestMagicLinkSignupMigrationPreservesFactorHistory(t *testing.T) {
	ctx := context.Background()
	base := MigrationSource{Version: 1}
	original, err := base.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	source := MagicLinkSignupMigrationSource{Base: base, Version: 2}
	history, err := source.Load(ctx)
	if err != nil || len(history) != 2 || history[0].UpSQL() != original[0].UpSQL() || history[1].Version() != 2 || history[1].DownSQL() != "" {
		t.Fatal("additive magic-link factor provenance unavailable", err)
	}
	for _, s := range []MagicLinkSignupMigrationSource{{}, {Base: base, Version: 1}, {Base: (*MigrationSource)(nil), Version: 2}, {Base: base, Version: migrations.Version(^uint64(0))}} {
		if history, err := s.Load(ctx); err == nil || history != nil {
			t.Fatal("invalid history accepted")
		}
	}
	if _, err := source.Load(nil); err == nil {
		t.Fatal("nil context accepted")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := source.Load(cancelled); err != context.Canceled {
		t.Fatal("cancellation not preserved", err)
	}
}
