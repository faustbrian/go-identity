package reference_test

import (
	"context"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/reference"
)

func TestReferenceMigrationApplyRequiresConstructedOwner(t *testing.T) {
	key, err := identity.NewIdempotencyKey([]byte("migration-retry"))
	if err != nil {
		t.Fatal(err)
	}
	var stores reference.StoreSet
	for _, ctx := range []context.Context{nil, context.Background()} {
		result, err := stores.ReferenceMigrationApply(ctx, reference.ReferenceMigrationApplyRequest{CommandID: "migration_command_0001", IdempotencyKey: key})
		if err == nil || result.Result.State() != 0 {
			t.Fatal("zero owner admitted migration", err)
		}
	}
}
