package postgres

import (
	"context"
	"testing"
)

func TestPhoneChangeCascadeMigrationPreservesInstalledHistory(t *testing.T) {
	base := PhoneRemovalCascadeMigrationSource{Base: IdentifierRemovalCascadeMigrationSource{Base: StatusMigrationSource{Base: MigrationSource{}, Version: 10}, Version: 11}, Version: 12}
	original, err := base.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	history, err := (PhoneChangeCascadeMigrationSource{Base: base, Version: 13}).Load(context.Background())
	if err != nil || len(history) != len(original)+1 {
		t.Fatal("missing forward phone replacement support", err)
	}
	for n := range original {
		if history[n].UpSQL() != original[n].UpSQL() || history[n].Version() != original[n].Version() || history[n].Name() != original[n].Name() {
			t.Fatal("replacement rewrote installed history")
		}
	}
	if history[len(history)-1].DownSQL() != "" {
		t.Fatal("destructive cascade rollback offered")
	}
	for _, bad := range []PhoneChangeCascadeMigrationSource{{Base: MigrationSource{}, Version: 13}, {Base: base, Version: 12}, {Version: 13}} {
		if _, err := bad.Load(context.Background()); err == nil {
			t.Fatal("missing prerequisite or invalid ordering admitted")
		}
	}
}
