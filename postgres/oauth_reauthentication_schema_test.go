package postgres

import (
	"context"
	"errors"
	"math"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestOAuthReauthenticationMigrationPreservesInstalledHistory(t *testing.T) {
	base := CounterPreparationMigrationSource{Base: AdmissionPreparationMigrationSource{Base: PreparationMigrationSource{Base: MigrationSource{}, Version: 10}, Version: 11}, Version: 12}
	old, err := base.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	source := OAuthReauthenticationMigrationSource{Base: base, Version: 13}
	history, err := source.Load(t.Context())
	if err != nil || len(history) != len(old)+1 || history[len(old)].DownSQL() != "" {
		t.Fatal("missing forward OAuth history", err)
	}
	for i := range old {
		if history[i] != old[i] {
			t.Fatal("installed migration changed")
		}
	}
	history[0] = history[len(old)]
	again, err := source.Load(t.Context())
	if err != nil || again[0] != old[0] {
		t.Fatal("caller mutated installed history", err)
	}
	for _, invalid := range []OAuthReauthenticationMigrationSource{{}, {Base: base}, {Base: base, Version: 12}, {Base: base, Version: migrations.Version(math.MaxInt64) + 1}} {
		if history, err := invalid.Load(t.Context()); err == nil || history != nil {
			t.Fatal("invalid forward migration accepted")
		}
	}
	if history, err := source.Load(nil); err == nil || history != nil {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if history, err := source.Load(ctx); !errors.Is(err, context.Canceled) || history != nil {
		t.Fatal("cancelled migration returned partial history")
	}
}
