package postgres

import (
	"context"
	"errors"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestMFAOTPCompletionCounterMigrationInputAndCancellation(t *testing.T) {
	s := MFAOTPCompletionCounterMigrationSource{Schema: "risk_store", Version: 69}
	if got, err := s.Load(context.Background()); err != nil || len(got) != 1 {
		t.Fatal("OTP completion history unavailable", err)
	}
	for _, bad := range []MFAOTPCompletionCounterMigrationSource{{}, {Schema: "public", Version: 69}, {Schema: "identity", Version: 69}, {Schema: "risk_store", Version: ^migrations.Version(0)}} {
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
