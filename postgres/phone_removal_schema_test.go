package postgres

import (
	"context"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestPhoneRemovalCascadeMigrationPreservesInstalledHistory(t *testing.T) {
	base := IdentifierRemovalCascadeMigrationSource{Base: StatusMigrationSource{Base: MigrationSource{}, Version: 10}, Version: 11}
	before, err := base.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got, err := (PhoneRemovalCascadeMigrationSource{Base: base, Version: 12}).Load(context.Background())
	if err != nil || len(got) != len(before)+1 {
		t.Fatal("missing native phone-removal cascade successor", err)
	}
	for n := range before {
		if before[n].Version() != got[n].Version() || before[n].Checksum() != got[n].Checksum() {
			t.Fatal("installed migration identity changed")
		}
	}
	if got[len(got)-1].DownSQL() != "" {
		t.Fatal("destructive rollback offered")
	}
	for _, source := range []migrations.Source{nil, MigrationSource{}, StatusMigrationSource{Base: MigrationSource{}, Version: 10}} {
		if _, err := (PhoneRemovalCascadeMigrationSource{Base: source, Version: 12}).Load(context.Background()); err == nil {
			t.Fatal("missing native predecessor admitted")
		}
	}
}
