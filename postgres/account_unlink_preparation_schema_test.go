package postgres

import (
	"context"
	"errors"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
)

func unlinkPreparationMigrationBase() migrations.Source {
	preparation := AccountLinkPreparationMigrationSource{Base: CounterPreparationMigrationSource{Base: AdmissionPreparationMigrationSource{Base: PreparationMigrationSource{Base: MigrationSource{}, Version: 10}, Version: 11}, Version: 12}, Version: 13}
	rp := OAuthRPPreparationErasureMigrationSource{Base: preparation, Version: 14}
	links := AccountLinkPreparationErasureMigrationSource{Base: rp, Version: 15}
	return AccountLinkPreparationErasureValidationMigrationSource{Base: links, Version: 16}
}

func TestAccountUnlinkPreparationMigrationsPreserveEveryInstalledPrefix(t *testing.T) {
	base := unlinkPreparationMigrationBase()
	installed, err := base.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	expansion := AccountUnlinkPreparationMigrationSource{Base: base, Version: 17}
	validation := AccountUnlinkPreparationValidationMigrationSource{Base: expansion, Version: 18}
	for index, source := range []migrations.Source{expansion, validation} {
		history, err := source.Load(t.Context())
		if err != nil || len(history) != len(installed)+index+1 {
			t.Fatal("unlink preparation expansion/validation missing", err)
		}
		for i, old := range installed {
			if history[i] != old {
				t.Fatal("unlink extension rewrote published command/link/RP history")
			}
		}
		for _, next := range history[len(installed):] {
			if next.DownSQL() != "" {
				t.Fatal("unlink rollback would destroy retained preparation history")
			}
		}
		history[0] = history[len(installed)]
		again, err := source.Load(t.Context())
		if err != nil || again[0] != installed[0] {
			t.Fatal("caller mutated original migration history", err)
		}
		if out, err := source.Load(nil); err == nil || out != nil {
			t.Fatal("nil migration context admitted")
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if out, err := source.Load(ctx); !errors.Is(err, context.Canceled) || out != nil {
			t.Fatal("migration source lost cancellation", err)
		}
	}
	for _, source := range []migrations.Source{
		AccountUnlinkPreparationMigrationSource{},
		AccountUnlinkPreparationMigrationSource{Base: base, Version: 16},
		AccountUnlinkPreparationValidationMigrationSource{},
		AccountUnlinkPreparationValidationMigrationSource{Base: expansion, Version: 17},
	} {
		if out, err := source.Load(t.Context()); err == nil || out != nil {
			t.Fatal("invalid unlink preparation migration admitted")
		}
	}
}
