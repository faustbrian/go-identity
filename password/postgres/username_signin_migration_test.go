package passwordpostgres

import (
	"context"
	"errors"
	"testing"

	password "github.com/faustbrian/go-identity/password"
	migrations "github.com/faustbrian/go-migrations/v3"
)

type usernameSigninNilSource struct{}

func (s *usernameSigninNilSource) Load(context.Context) ([]migrations.Migration, error) {
	if s == nil {
		panic("typed nil source invoked")
	}
	return nil, nil
}

func TestUsernameSigninMigrationRejectsTypedNilSource(t *testing.T) {
	var source *usernameSigninNilSource
	if history, err := (UsernameSigninMigrationSource{Base: source, Version: 9}).Load(context.Background()); !errors.Is(err, password.ErrPasswordWork) || history != nil {
		t.Fatal("typed nil migration owner accepted", err)
	}
}

func TestUsernameSigninMigrationPreservesHistoryAndCancellation(t *testing.T) {
	base, err := (MigrationSource{}).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	source := UsernameSigninMigrationSource{Base: MigrationSource{}, Version: 9}
	history, err := source.Load(context.Background())
	if err != nil || len(history) != len(base)+1 {
		t.Fatal("username signin suffix missing", err)
	}
	for index, original := range base {
		if history[index] != original {
			t.Fatal("username signin rewrote installed migration history")
		}
	}
	if history[len(base)].Version() != 9 || history[len(base)].DownSQL() != "" {
		t.Fatal("username signin suffix is destructive or misallocated")
	}
	for _, version := range []migrations.Version{0, 8, ^migrations.Version(0)} {
		if history, err := (UsernameSigninMigrationSource{Base: MigrationSource{}, Version: version}).Load(context.Background()); err == nil || history != nil {
			t.Fatal("invalid suffix allocation admitted")
		}
	}
	if history, err := source.Load(nil); err == nil || history != nil {
		t.Fatal("nil context admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if history, err := source.Load(ctx); !errors.Is(err, context.Canceled) || history != nil {
		t.Fatal("migration cancellation lost", err)
	}
}
