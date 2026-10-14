package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestPreAuthReleaseRequiresLiveNoncommitInvocation(t *testing.T) {
	err := ReleasePreAuth(context.Background(), kernel.OTPReleaseWork{}, nil,
		Config{Schema: "session_store", MaximumDuration: time.Second}, testPreAuth(t, time.Now().UTC()))
	var forbidden identity.ForbiddenError
	if !errors.As(err, &forbidden) {
		t.Fatal("zero release handle granted authority", err)
	}
}

func TestPreAuthReleasePreservesCallerCancellation(t *testing.T) {
	ctx, stop := context.WithCancel(context.Background())
	stop()
	err := ReleasePreAuth(ctx, kernel.OTPReleaseWork{}, nil,
		Config{Schema: "session_store", MaximumDuration: time.Second}, testPreAuth(t, time.Now().UTC()))
	var canceled identity.CancelledError
	if !errors.As(err, &canceled) {
		t.Fatalf("caller cancellation misclassified: %T", err)
	}
}

func TestPreAuthReleaseMigrationIsForwardOnly(t *testing.T) {
	s := PreAuthReleaseMigrationSource{Schema: "session_store", Version: 12}
	history, err := s.Load(context.Background())
	if err != nil || len(history) != 1 || history[0].Version() != 12 || history[0].DownSQL() != "" || history[0].TransactionMode() != migrations.TransactionModeDefault {
		t.Fatal("release migration not forward-only", err)
	}
	for _, bad := range []PreAuthReleaseMigrationSource{{}, {Schema: "public", Version: 12}, {Schema: "session_store", Version: ^migrations.Version(0)}} {
		if h, err := bad.Load(context.Background()); err == nil || h != nil {
			t.Fatal("invalid allocation accepted")
		}
	}
	if h, err := s.Load(nil); err == nil || h != nil {
		t.Fatal("nil context accepted")
	}
	ctx, stop := context.WithCancel(context.Background())
	stop()
	if h, err := s.Load(ctx); !errors.Is(err, context.Canceled) || h != nil {
		t.Fatal("cancellation ignored")
	}
}
