package mfapostgres

import (
	"context"
	"testing"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestPasskeySignupRequiresActualCreation(t *testing.T) {
	if err := InitializePasskeySignup(context.Background(), kernel.Work{}, nil, identity.Command{}); err == nil {
		t.Fatal("zero Work initialized factors")
	}
	if state, err := RequirePasskeySignupFactors(context.Background(), kernel.Work{}, nil, identity.Command{}); err == nil || state.Version() != 0 {
		t.Fatal("zero Work supplied empty-factor assurance")
	}
}

func TestPasskeySignupMigrationRetainsPredecessors(t *testing.T) {
	ctx := context.Background()
	base := UsernameSignupMigrationSource{Base: MagicLinkSignupMigrationSource{Base: MigrationSource{Version: 1}, Version: 2}, Version: 3}
	previous, err := base.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	source := PasskeySignupMigrationSource{Base: base, Version: 4}
	history, err := source.Load(ctx)
	if err != nil || len(history) != len(previous)+1 {
		t.Fatal("additive signup factor history", err)
	}
	for i, old := range previous {
		if history[i].Version() != old.Version() || history[i].UpSQL() != old.UpSQL() || history[i].DownSQL() != old.DownSQL() {
			t.Fatal("predecessor factor history rewritten")
		}
	}
	if history[len(previous)].Version() != 4 || history[len(previous)].DownSQL() != "" {
		t.Fatal("unsafe migration version/downgrade")
	}
	for _, bad := range []PasskeySignupMigrationSource{{}, {Base: base}, {Base: base, Version: 3}, {Base: (*MigrationSource)(nil), Version: 4}, {Base: base, Version: migrations.Version(^uint64(0))}} {
		if history, err := bad.Load(ctx); err == nil || history != nil {
			t.Fatal("invalid factor suffix admitted")
		}
	}
	if _, err := source.Load(nil); err == nil {
		t.Fatal("nil context admitted")
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if _, err := source.Load(cancelled); err != context.Canceled {
		t.Fatal("cancellation lost", err)
	}
}
