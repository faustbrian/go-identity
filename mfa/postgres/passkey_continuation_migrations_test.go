package mfapostgres

import (
	"context"
	"errors"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestPasskeyContinuationMigrationPreservesHistoryAndRequiresOrderedBase(t *testing.T) {
	ctx := t.Context()
	base := ContinuationMigrationSource{Base: MigrationSource{Version: 1}, Version: 2}
	prior, err := base.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	source := PasskeyContinuationMigrationSource{Base: base, Version: 3}
	history, err := source.Load(ctx)
	if err != nil || len(history) != len(prior)+1 {
		t.Fatal("valid forward continuation extension denied", err)
	}
	for i := range prior {
		if history[i].UpSQL() != prior[i].UpSQL() || history[i].Version() != prior[i].Version() {
			t.Fatal("installed migration changed")
		}
	}
	for _, bad := range []PasskeyContinuationMigrationSource{{}, {Base: base, Version: 2}, {Base: base, Version: migrations.Version(^uint64(0))}} {
		if _, err := bad.Load(ctx); err == nil {
			t.Fatal("invalid or unordered migration source accepted")
		}
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if _, err := source.Load(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled migration loaded", err)
	}
	if _, err := source.Load(nilPasskeyContinuationContextForTest()); err == nil {
		t.Fatal("nil migration context accepted")
	}
}

func nilPasskeyContinuationContextForTest() context.Context { return nil }
