package postgres

import (
	"context"
	"errors"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestMFAOTPRecordMigrationInputAndCancellation(t *testing.T) {
	s := MFAOTPRecordMigrationSource{Schema: "sessions", Version: 50}
	if history, err := s.Load(context.Background()); err != nil || len(history) != 1 {
		t.Fatal("selected OTP record migration unavailable", err)
	}
	for _, bad := range []MFAOTPRecordMigrationSource{{}, {Schema: "public", Version: 50}, {Schema: "sessions", Version: ^migrations.Version(0)}} {
		if history, err := bad.Load(context.Background()); err == nil || history != nil {
			t.Fatal("invalid migration accepted")
		}
	}
	if _, err := s.Load(nil); err == nil {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if history, err := s.Load(ctx); !errors.Is(err, context.Canceled) || history != nil {
		t.Fatal("cancellation lost", err)
	}
}
