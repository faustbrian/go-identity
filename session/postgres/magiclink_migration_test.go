package postgres

import (
	"context"
	"errors"
	"math"
	"testing"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestMagicLinkMigrationRejectsInvalidOwnershipAndPreservesCancellation(t *testing.T) {
	var invalid identity.InvalidInputError
	for _, s := range []MagicLinkMigrationSource{{}, {Schema: "public", Version: 16}, {Schema: "identity", Version: 16}, {Schema: "session_store"}, {Schema: "session_store", Version: migrations.Version(math.MaxInt64) + 1}} {
		if _, err := s.Load(context.Background()); !errors.As(err, &invalid) {
			t.Fatal("invalid migration owner accepted", err)
		}
	}
	s := MagicLinkMigrationSource{Schema: "session_store", Version: 16}
	if _, err := s.Load(nil); !errors.As(err, &invalid) {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Load(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("lost cancellation", err)
	}
}
