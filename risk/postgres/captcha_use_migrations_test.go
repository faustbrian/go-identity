package postgres

import (
	"context"
	"errors"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestCaptchaUseMigrationAllocation(t *testing.T) {
	s := CaptchaUseMigrationSource{Schema: "risk_store", Version: 42}
	h, err := s.Load(context.Background())
	if err != nil || len(h) != 1 || h[0].Version() != 42 || h[0].DownSQL() != "" || h[0].TransactionMode() != migrations.TransactionModeDefault {
		t.Fatal("missing atomic forward consuming upgrade", err)
	}
	original := h[0]
	h[0] = migrations.Migration{}
	h, err = s.Load(context.Background())
	if err != nil || len(h) != 1 || h[0] != original {
		t.Fatal("caller changed owned migration", err)
	}
	for _, bad := range []CaptchaUseMigrationSource{{}, {Schema: "public", Version: 42}, {Schema: "identity", Version: 42}, {Schema: "pg_store", Version: 42}, {Schema: "risk_store", Version: ^migrations.Version(0)}} {
		if h, err := bad.Load(context.Background()); err == nil || h != nil {
			t.Fatal("invalid consuming allocation admitted")
		}
	}
	if h, err := s.Load(nil); err == nil || h != nil {
		t.Fatal("nil context admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if h, err := s.Load(ctx); !errors.Is(err, context.Canceled) || h != nil {
		t.Fatal("lost cancellation", err)
	}
}
