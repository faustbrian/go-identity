package postgres

import (
	"context"
	"errors"
	"testing"
)

func TestAnonymousIdentityMigrationPreservesPredecessorsAndDeniesIncompleteHistory(t *testing.T) {
	base := IdentifierNormalizationMigrationSource{Base: IdentifierMutationMigrationSource{Base: MigrationSource{}, Version: 10}, Version: 11}
	original, err := base.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	selected := AnonymousIdentityMigrationSource{Base: base, Version: 12}
	history, err := selected.Load(t.Context())
	if err != nil || len(history) != len(original)+1 {
		t.Fatal("missing forward history", err)
	}
	for n := range original {
		if history[n].Version() != original[n].Version() || history[n].Name() != original[n].Name() || history[n].UpSQL() != original[n].UpSQL() || history[n].DownSQL() != original[n].DownSQL() {
			t.Fatal("anonymous namespace changed an installed predecessor")
		}
	}
	if history[len(history)-1].DownSQL() != "" {
		t.Fatal("destructive anonymous migration rollback offered")
	}
	history[0] = history[len(history)-1]
	retained, err := selected.Load(t.Context())
	if err != nil || retained[0].Version() != original[0].Version() {
		t.Fatal("caller mutation changed source history", err)
	}
	for _, invalid := range []AnonymousIdentityMigrationSource{
		{}, {Base: MigrationSource{}, Version: 12}, {Base: base}, {Base: base, Version: 11},
		{Base: IdentifierMutationMigrationSource{Base: MigrationSource{}, Version: 10}, Version: 12},
		{Base: IdentifierNormalizationMigrationSource{Base: MigrationSource{}, Version: 10}, Version: 12},
	} {
		if got, err := invalid.Load(t.Context()); err == nil || got != nil {
			t.Fatal("incomplete history admitted")
		}
	}
	if _, err := selected.Load(nil); err == nil {
		t.Fatal("nil context admitted")
	}
	ctx, stop := context.WithCancel(context.Background())
	stop()
	if got, err := selected.Load(ctx); !errors.Is(err, context.Canceled) || got != nil {
		t.Fatal("cancellation lost", err)
	}
}
