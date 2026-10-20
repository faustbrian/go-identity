package passwordpostgres

import (
	"context"
	"errors"
	"testing"

	password "github.com/faustbrian/go-identity/password"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestPhoneMFASigninMigrationPreservesHistory(t *testing.T) {
	ctx := context.Background()
	for _, username := range []bool{false, true} {
		var base migrations.Source = MigrationSource{}
		if username {
			base = UsernameMFAMigrationSource{Base: base, Version: 9}
		}
		original, err := base.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		source := PhoneMFASigninMigrationSource{Base: base, Version: 10, UsernameMFA: username}
		history, err := source.Load(ctx)
		if err != nil || len(history) != len(original)+1 {
			t.Fatal("phone MFA suffix missing", err)
		}
		for j, before := range original {
			if history[j] != before {
				t.Fatal("phone MFA changed installed migration history")
			}
		}
		if history[len(original)].Version() != 10 || history[len(original)].DownSQL() != "" {
			t.Fatal("phone MFA suffix allocation or reversibility changed")
		}
		if history, err := source.Load(nil); err == nil || history != nil {
			t.Fatal("phone MFA source accepted nil context")
		}
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if history, err := source.Load(canceled); !errors.Is(err, context.Canceled) || history != nil {
			t.Fatal("phone MFA source lost cancellation", err)
		}
	}
	var typedNil *usernameSigninNilSource
	for _, source := range []PhoneMFASigninMigrationSource{
		{}, {Base: typedNil, Version: 9}, {Base: MigrationSource{}, Version: 8},
		{Base: MigrationSource{}, Version: ^migrations.Version(0)},
	} {
		if history, err := source.Load(ctx); !errors.Is(err, password.ErrPasswordWork) || history != nil {
			t.Fatal("invalid phone MFA forward allocation admitted", err)
		}
	}
}
