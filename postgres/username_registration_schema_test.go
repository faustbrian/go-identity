package postgres

import (
	"context"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestUsernameRegistrationMigrationPreservesSelectedHistory(t *testing.T) {
	for _, magic := range []bool{false, true} {
		var base migrations.Source = PasswordSignupAcceptanceMigrationSource{Base: PasswordRegistrationMigrationSource{Base: MigrationSource{}, Version: 10}, Version: 11}
		if magic {
			base = MagicLinkRegistrationMigrationSource{Base: base, Version: 12}
		}
		base = EmailVerificationMigrationSource{Base: base, Version: 13}
		old, err := base.Load(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		source := UsernameRegistrationMigrationSource{Base: base, Version: 14}
		history, err := source.Load(context.Background())
		if err != nil || len(history) != len(old)+1 || history[len(old)].DownSQL() != "" {
			t.Fatal("username forward history missing", err)
		}
		for i, previous := range old {
			if history[i].Version() != previous.Version() || history[i].UpSQL() != previous.UpSQL() || history[i].DownSQL() != previous.DownSQL() {
				t.Fatal("username extension rewrote installed history")
			}
		}
		for _, invalid := range []UsernameRegistrationMigrationSource{{}, {Base: base}, {Base: base, Version: 13}, {Base: base, Version: migrations.Version(^uint64(0))}} {
			if _, err := invalid.Load(context.Background()); err == nil {
				t.Fatal("invalid history accepted")
			}
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := source.Load(ctx); err != context.Canceled {
			t.Fatal("cancellation lost")
		}
	}
}
