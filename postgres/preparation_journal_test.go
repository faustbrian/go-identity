package postgres

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPreparationRejectsUnownedAndUnboundedInputs(t *testing.T) {
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	for _, ctx := range []context.Context{nil, context.Background(), ctx} {
		if _, err := reservePreparationJournal(ctx, nil, claimRequest{}, claimNew, [16]byte{1}, time.Second); err == nil {
			t.Fatal("invalid reserve admitted")
		}
		if err := startJournalPreparation(ctx, nil, claimRequest{}, journalReservation{}, [16]byte{1}); err == nil {
			t.Fatal("invalid start admitted")
		}
		for _, wire := range [][]byte{nil, {1}, make([]byte, maximumPreparationCiphertext+1)} {
			if err := retainJournalPreparation(ctx, nil, claimRequest{}, journalReservation{}, [16]byte{1}, wire); err == nil {
				t.Fatal("invalid retention admitted")
			}
		}
	}
}

func TestPreparationMigrationRetainsOriginalHistory(t *testing.T) {
	s := PreparationMigrationSource{Base: MigrationSource{}, Version: 10}
	base, err := s.Base.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	history, err := s.Load(context.Background())
	if err != nil || len(history) != len(base)+1 {
		t.Fatal("missing forward history", err)
	}
	for i := range base {
		if base[i] != history[i] {
			t.Fatal("rewrote installed history")
		}
	}
	last := history[len(base)]
	if last.DownSQL() != "" {
		t.Fatal("destructive down migration")
	}
	history[0] = last
	again, err := s.Load(context.Background())
	if err != nil || again[0] != base[0] {
		t.Fatal("caller modified retained history")
	}
	for _, bad := range []PreparationMigrationSource{{}, {Base: MigrationSource{}, Version: 9}} {
		if h, err := bad.Load(context.Background()); err == nil || h != nil {
			t.Fatal("invalid migration accepted")
		}
	}
	if h, err := s.Load(nil); err == nil || h != nil {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if h, err := s.Load(ctx); !errors.Is(err, context.Canceled) || h != nil {
		t.Fatal("cancellation replaced", err)
	}
}
