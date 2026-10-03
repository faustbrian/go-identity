package postgres

import (
	"context"
	"errors"
	migrations "github.com/faustbrian/go-migrations/v3"
	"testing"
)

func TestVelocityReplayMigrationPreservesHistory(t *testing.T) {
	base := VelocityIntegrityMigrationSource{Base: VelocityIntentMigrationSource{Base: VelocityMigrationSource{Base: CounterMigrationSource{Base: ReservationMigrationSource{Base: IssuanceIDMigrationSource{Base: MigrationSource{Schema: "risk_store", Version: 20}, Version: 21}, Version: 22}, Version: 23}, Version: 24}, Version: 25}, Version: 26}
	original, err := base.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	s := VelocityReplayMigrationSource{Base: base, Version: 27}
	h, err := s.Load(context.Background())
	if err != nil || len(h) != len(original)+1 || h[len(original)].Version() != 27 || h[len(original)].DownSQL() != "" || h[len(original)].TransactionMode() != migrations.TransactionModeDefault {
		t.Fatal("invalid forward history", err)
	}
	for i, m := range original {
		if h[i] != m {
			t.Fatal("installed history rewritten")
		}
	}
	h[len(original)] = migrations.Migration{}
	again, err := s.Load(context.Background())
	if err != nil || again[len(original)].Version() != 27 {
		t.Fatal("history aliases caller", err)
	}
	for _, version := range []migrations.Version{0, 25, 26, ^migrations.Version(0)} {
		if h, err := (VelocityReplayMigrationSource{Base: base, Version: version}).Load(context.Background()); err == nil || h != nil {
			t.Fatal("invalid allocation accepted")
		}
	}
	if h, err := s.Load(nil); err == nil || h != nil {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if h, err := s.Load(ctx); !errors.Is(err, context.Canceled) || h != nil {
		t.Fatal("cancellation lost", err)
	}
}
