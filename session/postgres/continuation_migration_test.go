package postgres

import (
	"context"
	"errors"
	"math"
	"testing"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestContinuationMigrationRejectsInvalidOwnership(t *testing.T) {
	var invalid identity.InvalidInputError
	for _, source := range []CredentialContinuationMigrationSource{{}, {Schema: "public", Version: 15}, {Schema: "identity", Version: 15}, {Schema: "session_store"}, {Schema: "session_store", Version: migrations.Version(math.MaxInt64) + 1}} {
		if _, err := source.Load(context.Background()); !errors.As(err, &invalid) {
			t.Fatal("invalid ownership accepted", err)
		}
	}
	source := CredentialContinuationMigrationSource{Schema: "session_store", Version: 15}
	if _, err := source.Load(nil); !errors.As(err, &invalid) {
		t.Fatal("nil context accepted", err)
	}
	ctx, stop := context.WithCancel(context.Background())
	stop()
	if _, err := source.Load(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
}
