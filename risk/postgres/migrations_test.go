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
