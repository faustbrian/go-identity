package reference_test

import (
	"context"
	"testing"

	"github.com/faustbrian/go-identity/reference"
)

func TestReferenceMigrationCheckRequiresConstructedOwner(t *testing.T) {
	var stores reference.StoreSet
	for _, ctx := range []context.Context{nil, context.Background()} {
		result, err := stores.ReferenceMigrationCheck(ctx, reference.ReferenceMigrationCheckRequest{Modules: []reference.ModuleID{"identity/postgres"}})
		if err == nil || len(result.Statuses) != 0 {
			t.Fatal("zero migration owner returned compatibility")
		}
	}
}
