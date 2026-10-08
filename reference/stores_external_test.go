package reference_test

import (
	"context"
	"errors"
	"testing"

	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/risk"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestUnconfiguredStoreCompositionCannotGrantAdmission(t *testing.T) {
	stores, err := reference.ComposeStores(reference.StoreConfiguration{}, reference.ReferenceDependencies{})
	if !errors.Is(err, risk.ErrInvalidPolicy) {
		t.Fatal("incomplete deployment configuration must be rejected")
	}
	if counter, err := stores.RecoverVelocity(context.Background(), "tenant"); err == nil || counter != nil {
		t.Fatal("invalid composition granted counter admission")
	}
	if err := stores.Close(context.Background()); err != nil {
		t.Fatal("zero ownership must permit cleanup")
	}
}

func TestUnconfiguredCompositionCannotExportMigrationHistory(t *testing.T) {
	var stores reference.StoreSet
	var source migrations.Source = stores.MigrationSource()
	if history, err := source.Load(context.Background()); err == nil || len(history) != 0 {
		t.Fatal("invalid composition exported migration authority")
	}
}
