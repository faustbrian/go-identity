package postgres

import (
	"context"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestMagicLinkRegistrationHistoryPreservesPasswordBranches(t *testing.T) {
	base := PasswordSignupAcceptanceMigrationSource{Base: PasswordRegistrationMigrationSource{Base: MigrationSource{}, Version: 10}, Version: 11}
	old, err := base.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	source := MagicLinkRegistrationMigrationSource{Base: base, Version: 12}
	history, err := source.Load(context.Background())
	if err != nil || len(history) != len(old)+1 {
		t.Fatal("passwordless registration suffix missing", err)
	}
	for i := range old {
		if old[i].Version() != history[i].Version() || old[i].UpSQL() != history[i].UpSQL() || old[i].DownSQL() != history[i].DownSQL() {
			t.Fatal("existing registration history rewritten")
		}
	}
	if history[len(old)].Version() != 12 || history[len(old)].DownSQL() != "" {
		t.Fatal("passwordless registration downgrade or version")
	}
	for _, bad := range []MagicLinkRegistrationMigrationSource{{}, {Base: base}, {Base: base, Version: 11}, {Base: base, Version: migrations.Version(^uint64(0))}} {
		if _, err := bad.Load(context.Background()); err == nil {
			t.Fatal("invalid suffix admitted")
		}
	}
	if _, err := source.Load(nil); err == nil {
		t.Fatal("nil context admitted")
	}
	ctx, stop := context.WithCancel(context.Background())
	stop()
	if _, err := source.Load(ctx); err != context.Canceled {
		t.Fatal("cancellation lost", err)
	}
}
