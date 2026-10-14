package postgres

import (
	"context"
	"errors"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// Native CAPTCHA installation is independently selected after the existing
// risk namespace, not coupled to phone/counter/lockout bootstrap histories.
func TestCaptchaMigrationOwnsSeparateForwardAllocation(t *testing.T) {
	s := CaptchaMigrationSource{Schema: "risk_store", Version: 40}
	h, err := s.Load(context.Background())
	if err != nil || len(h) != 1 || h[0].Version() != 40 || h[0].DownSQL() != "" || h[0].TransactionMode() != migrations.TransactionModeDefault {
		t.Fatal("missing independent atomic CAPTCHA migration", err)
	}
	original := h[0]
	h[0] = migrations.Migration{}
	h, err = s.Load(context.Background())
	if err != nil || h[0] != original {
		t.Fatal("caller changed owned migration")
	}
	for _, bad := range []CaptchaMigrationSource{{}, {Schema: "public", Version: 40}, {Schema: "identity", Version: 40}, {Schema: "pg_store", Version: 40}, {Schema: "risk_store", Version: ^migrations.Version(0)}} {
		if h, err := bad.Load(context.Background()); err == nil || h != nil {
			t.Fatal("invalid allocation admitted")
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
