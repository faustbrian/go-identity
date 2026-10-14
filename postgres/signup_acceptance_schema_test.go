package postgres

import (
	"context"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestSignupAcceptanceMigrationPreservesCreationHistory(t *testing.T) {
	ctx := context.Background()
	base := PasswordRegistrationMigrationSource{Base: MigrationSource{}, Version: 10}
	original, err := base.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	source := PasswordSignupAcceptanceMigrationSource{Base: base, Version: 11}
	history, err := source.Load(ctx)
	if err != nil || len(history) != len(original)+1 || history[len(original)].Version() != 11 || history[len(original)].DownSQL() != "" {
		t.Fatal("forward migration incomplete", err)
	}
	for i := range original {
		if history[i].UpSQL() != original[i].UpSQL() || history[i].Version() != original[i].Version() {
			t.Fatal("original creation history rewritten")
		}
	}
	for _, invalid := range []PasswordSignupAcceptanceMigrationSource{{}, {Base: base}, {Base: base, Version: 10}, {Base: base, Version: migrations.Version(^uint64(0))}} {
		if _, err := invalid.Load(ctx); err == nil {
			t.Fatal("invalid acceptance history admitted")
		}
	}
	if _, err := source.Load(nil); err == nil {
		t.Fatal("nil context admitted")
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if _, err := source.Load(cancelled); err != context.Canceled {
		t.Fatal("earlier cancellation lost")
	}
}
