package postgres

import (
	"context"
	"errors"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestVelocityMigrationPreservesHistory(t *testing.T) {
	base := CounterMigrationSource{Base: ReservationMigrationSource{Base: IssuanceIDMigrationSource{Base: MigrationSource{Schema: "risk_store", Version: 20}, Version: 21}, Version: 22}, Version: 23}
	original, err := base.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	s := VelocityMigrationSource{Base: base, Version: 24}
	h, err := s.Load(context.Background())
	if err != nil || len(h) != 5 || h[4].Version() != 24 || h[4].DownSQL() != "" || h[4].TransactionMode() != migrations.TransactionModeDefault {
		t.Fatal("invalid forward history", err)
	}
	for i, m := range original {
		if h[i] != m {
			t.Fatal("installed migration rewritten")
		}
	}
	h[4] = migrations.Migration{}
	again, err := s.Load(context.Background())
	if err != nil || again[4].Version() != 24 {
		t.Fatal("history aliases caller slice", err)
	}
	for _, version := range []migrations.Version{0, 20, 23, ^migrations.Version(0)} {
		if h, err := (VelocityMigrationSource{Base: base, Version: version}).Load(context.Background()); err == nil || h != nil {
			t.Fatal("unsafe allocation admitted")
		}
	}
	if h, err := s.Load(nil); err == nil || h != nil {
		t.Fatal("nil context admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if h, err := s.Load(ctx); !errors.Is(err, context.Canceled) || h != nil {
		t.Fatal("cancellation lost")
	}
	invalid := s
	invalid.Base.Base.Base.Base.Schema = "public"
	if h, err := invalid.Load(context.Background()); err == nil || h != nil {
		t.Fatal("invalid base accepted")
	}
}
