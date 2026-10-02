package postgres

import (
	"context"
	"errors"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestMigrationSourceImmutableAndForwardOnly(t *testing.T) {
	var source migrations.Source = MigrationSource{}
	first, err := source.Load(context.Background())
	if err != nil || len(first) != 1 {
		t.Fatal("missing complete migration history")
	}
	if first[0].Version() != 1 || first[0].DownSQL() != "" || first[0].TransactionMode() != migrations.TransactionModeDefault {
		t.Fatal("unsafe migration contract")
	}
	original := first[0]
	first[0] = migrations.Migration{}
	second, err := source.Load(context.Background())
	if err != nil || second[0] != original {
		t.Fatal("caller mutated history")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if result, err := source.Load(ctx); !errors.Is(err, context.Canceled) || result != nil {
		t.Fatal("cancelled source disclosed partial history")
	}
	if result, err := source.Load(nil); err == nil || result != nil {
		t.Fatal("nil migration context admitted")
	}
}
