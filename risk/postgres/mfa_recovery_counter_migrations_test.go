package postgres

import (
	"context"
	"errors"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestMFARecoveryCounterMigrationInputAndCancellation(t *testing.T) {
	s := MFARecoveryCounterMigrationSource{Schema: "risk_store", Version: 67}
	history, err := s.Load(context.Background())
	if err != nil || len(history) != 1 {
		t.Fatal("forward recovery history unavailable", err)
	}
	for _, bad := range []MFARecoveryCounterMigrationSource{{}, {Schema: "public", Version: 67}, {Schema: "identity", Version: 67}, {Schema: "risk_store", Version: ^migrations.Version(0)}} {
		if got, err := bad.Load(context.Background()); err == nil || got != nil {
			t.Fatal("invalid history accepted")
		}
	}
	if got, err := s.Load(nil); err == nil || got != nil {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := s.Load(ctx); !errors.Is(err, context.Canceled) || got != nil {
		t.Fatal("cancellation lost", err)
	}
}
