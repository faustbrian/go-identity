package postgres

import (
	"context"
	"errors"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestMigrationOwnsForwardAtomicHistory(t *testing.T) {
	s := MigrationSource{Schema: "identity_risk", Version: 20}
	h, err := s.Load(context.Background())
	if err != nil || len(h) != 1 || h[0].Version() != 20 || h[0].DownSQL() != "" || h[0].TransactionMode() != migrations.TransactionModeDefault {
		t.Fatal("missing forward atomic history", err)
	}
	original := h[0]
	h[0] = migrations.Migration{}
	h, err = s.Load(context.Background())
	if err != nil || h[0] != original {
		t.Fatal("caller changed retained migration")
	}
	for _, bad := range []MigrationSource{{}, {Schema: "public", Version: 20}, {Schema: "identity", Version: 20}, {Schema: "information_schema", Version: 20}, {Schema: "pg_store", Version: 20}, {Schema: "1store", Version: 20}, {Schema: "store\";DROP SCHEMA identity", Version: 20}, {Schema: "risk", Version: ^migrations.Version(0)}} {
		if h, err := bad.Load(context.Background()); err == nil || h != nil {
			t.Fatal("unsafe allocation admitted")
		}
	}
	if h, err := s.Load(nil); err == nil || h != nil {
		t.Fatal("nil context admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if h, err := s.Load(ctx); !errors.Is(err, context.Canceled) || h != nil {
		t.Fatal("lost cancellation")
	}
}

func TestIssuanceIdentityMigrationPreservesOriginalHistory(t *testing.T) {
	base := MigrationSource{Schema: "risk_store", Version: 20}
	original, err := base.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	s := IssuanceIDMigrationSource{Base: base, Version: 21}
	h, err := s.Load(context.Background())
	if err != nil || len(h) != 2 || h[0] != original[0] || h[1].Version() != 21 || h[1].DownSQL() != "" || h[1].TransactionMode() != migrations.TransactionModeDefault {
		t.Fatal("initial history rewritten", err)
	}
	for _, bad := range []IssuanceIDMigrationSource{{}, {Base: base, Version: 20}, {Base: base, Version: 19}, {Base: base, Version: ^migrations.Version(0)}, {Base: MigrationSource{Schema: "public", Version: 20}, Version: 21}} {
		if h, err := bad.Load(context.Background()); err == nil || h != nil {
			t.Fatal("invalid forward allocation")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if h, err := s.Load(ctx); !errors.Is(err, context.Canceled) || h != nil {
		t.Fatal("lost cancellation")
	}
}

func TestReservationMigrationPreservesPermanentHistory(t *testing.T) {
	base := IssuanceIDMigrationSource{Base: MigrationSource{Schema: "risk_store", Version: 20}, Version: 21}
	original, err := base.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	s := ReservationMigrationSource{Base: base, Version: 22}
	history, err := s.Load(context.Background())
	if err != nil || len(history) != 3 || history[0] != original[0] || history[1] != original[1] || history[2].Version() != 22 || history[2].DownSQL() != "" || history[2].TransactionMode() != migrations.TransactionModeDefault {
		t.Fatal("reservation upgrade rewrote installed history", err)
	}
	for _, version := range []migrations.Version{0, 20, 21, ^migrations.Version(0)} {
		if h, err := (ReservationMigrationSource{Base: base, Version: version}).Load(context.Background()); err == nil || h != nil {
			t.Fatal("invalid permanent allocation admitted")
		}
	}
	if h, err := s.Load(nil); err == nil || h != nil {
		t.Fatal("nil context admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if h, err := s.Load(ctx); !errors.Is(err, context.Canceled) || h != nil {
		t.Fatal("lost cancellation")
	}
}
