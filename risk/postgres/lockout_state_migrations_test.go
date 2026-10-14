package postgres

import (
	"context"
	"errors"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
)

func lockoutStateHistory() LockoutStateMigrationSource {
	return LockoutStateMigrationSource{Base: LockoutMigrationSource{Base: CounterMigrationSource{Base: ReservationMigrationSource{Base: IssuanceIDMigrationSource{Base: MigrationSource{Schema: "risk_store", Version: 20}, Version: 21}, Version: 22}, Version: 23}, Version: 24}, Version: 25}
}

func TestLockoutStateMigrationPreservesInstalledHistory(t *testing.T) {
	s := lockoutStateHistory()
	original, err := s.Base.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	history, err := s.Load(context.Background())
	if err != nil || len(history) != len(original)+1 {
		t.Fatal("forward history", err)
	}
	for i, m := range original {
		if history[i] != m {
			t.Fatal("installed migration changed")
		}
	}
	last := history[len(original)]
	if last.Version() != 25 || last.DownSQL() != "" || last.TransactionMode() != migrations.TransactionModeDefault {
		t.Fatal("invalid state migration")
	}
	history[len(original)] = migrations.Migration{}
	again, err := s.Load(context.Background())
	if err != nil || again[len(original)] != last {
		t.Fatal("caller-owned history corrupted source", err)
	}
	for _, version := range []migrations.Version{0, 23, 24, ^migrations.Version(0)} {
		s.Version = version
		if h, err := s.Load(context.Background()); err == nil || h != nil {
			t.Fatal("invalid permanent version accepted")
		}
	}
	s = lockoutStateHistory()
	if h, err := s.Load(nil); err == nil || h != nil {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if h, err := s.Load(ctx); !errors.Is(err, context.Canceled) || h != nil {
		t.Fatal("cancelled load", err)
	}
}
