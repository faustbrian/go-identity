package postgres

import (
	"context"
	"errors"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestVelocityPublicationMigrationPreservesHistory(t *testing.T) {
	base := VelocityCoverageMigrationSource{Base: VelocityAppliedMigrationSource{Base: VelocityReplayMigrationSource{Base: VelocityIntegrityMigrationSource{Base: VelocityIntentMigrationSource{Base: VelocityMigrationSource{Base: CounterMigrationSource{Base: ReservationMigrationSource{Base: IssuanceIDMigrationSource{Base: MigrationSource{Schema: "risk_store", Version: 20}, Version: 21}, Version: 22}, Version: 23}, Version: 24}, Version: 25}, Version: 26}, Version: 27}, Version: 28}, Version: 29}
	original, err := base.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	s := VelocityPublicationMigrationSource{Base: base, Version: 30}
	h, err := s.Load(context.Background())
	if err != nil || len(h) != len(original)+1 || h[len(original)].Version() != 30 || h[len(original)].DownSQL() != "" || h[len(original)].TransactionMode() != migrations.TransactionModeDefault {
		t.Fatal("invalid forward history", err)
	}
	for i, m := range original {
		if h[i] != m {
			t.Fatal("installed history rewritten")
		}
	}
	h[len(original)] = migrations.Migration{}
	again, err := s.Load(context.Background())
	if err != nil || again[len(original)].Version() != 30 {
		t.Fatal("history aliases caller", err)
	}
	for _, version := range []migrations.Version{0, 29, ^migrations.Version(0)} {
		if h, err := (VelocityPublicationMigrationSource{Base: base, Version: version}).Load(context.Background()); err == nil || h != nil {
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
