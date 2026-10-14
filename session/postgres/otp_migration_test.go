package postgres

import (
	"context"
	"errors"
	"math"
	"testing"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestOTPMigrationRejectsInvalidOwnershipAndPreservesCancellation(t *testing.T) {
	var invalid identity.InvalidInputError
	for _, source := range []OTPMigrationSource{{}, {Schema: "public", Version: 14}, {Schema: "identity", Version: 14}, {Schema: "session_store"}, {Schema: "session_store", Version: migrations.Version(math.MaxInt64) + 1}} {
		if _, err := source.Load(context.Background()); !errors.As(err, &invalid) {
			t.Fatal("invalid migration ownership accepted", err)
		}
	}
	source := OTPMigrationSource{Schema: "session_store", Version: 14}
	if _, err := source.Load(nil); !errors.As(err, &invalid) {
		t.Fatal("nil context accepted", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := source.Load(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
}
