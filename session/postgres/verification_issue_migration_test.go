package postgres

import (
	"context"
	"errors"
	"math"
	"testing"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestVerificationSigninMigrationOwnership(t *testing.T) {
	var invalid identity.InvalidInputError
	for _, source := range []EmailVerificationSigninMigrationSource{{}, {Schema: "public", Version: 19}, {Schema: "identity", Version: 19}, {Schema: "session_store"}, {Schema: "session_store", Version: migrations.Version(math.MaxInt64) + 1}} {
		if _, err := source.Load(context.Background()); !errors.As(err, &invalid) {
			t.Fatal("invalid migration owner admitted", err)
		}
	}
	source := EmailVerificationSigninMigrationSource{Schema: "session_store", Version: 19}
	if _, err := source.Load(nil); !errors.As(err, &invalid) {
		t.Fatal("nil context admitted", err)
	}
	ctx, stop := context.WithCancel(context.Background())
	stop()
	if _, err := source.Load(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
}
