package reference_test

import (
	"context"
	"testing"

	"github.com/faustbrian/go-identity/reference"
)

func TestReferenceMigrationPlanRequiresConstructedOwner(t *testing.T) {
	var stores reference.StoreSet
	for _, ctx := range []context.Context{nil, context.Background()} {
		result, err := stores.ReferenceMigrationPlan(ctx, reference.ReferenceMigrationPlanRequest{Modules: []reference.ModuleID{"identity/postgres"}})
		if err == nil || result.Plan.Digest != ([32]byte{}) {
			t.Fatal("zero owner returned a usable migration plan")
		}
	}
}
