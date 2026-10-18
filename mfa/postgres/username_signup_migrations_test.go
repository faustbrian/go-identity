package mfapostgres_test

import (
	"context"
	"testing"

	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestUsernameSignupMigrationPreservesFactorHistory(t *testing.T) {
	for _, magic := range []bool{false, true} {
		var base migrations.Source = mfapg.MigrationSource{Version: 1}
		if magic {
			base = mfapg.MagicLinkSignupMigrationSource{Base: base, Version: 2}
		}
		before, err := base.Load(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		source := mfapg.UsernameSignupMigrationSource{Base: base, Version: 3}
		history, err := source.Load(context.Background())
		if err != nil || len(history) != len(before)+1 || history[len(before)].DownSQL() != "" {
			t.Fatal("missing forward-only factor history", err)
		}
		for i, old := range before {
			if history[i].Version() != old.Version() || history[i].UpSQL() != old.UpSQL() || history[i].DownSQL() != old.DownSQL() {
				t.Fatal("installed factor history changed")
			}
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := source.Load(ctx); err != context.Canceled {
			t.Fatal("cancellation lost")
		}
		for _, invalid := range []mfapg.UsernameSignupMigrationSource{{}, {Base: base}, {Base: base, Version: 1}, {Base: base, Version: migrations.Version(^uint64(0))}} {
			if _, err := invalid.Load(context.Background()); err == nil {
				t.Fatal("invalid history admitted")
			}
		}
	}
}
