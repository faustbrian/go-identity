package passwordpostgres

import (
	"context"
	"errors"
	"testing"

	password "github.com/faustbrian/go-identity/password"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestPasskeyProofMigrationPreservesInstalledHistory(t *testing.T) {
	base := ActionReauthenticationMigrationSource{Base: EmailReauthenticationMigrationSource{}, Version: 70}
	for _, selected := range []migrations.Source{base, AnonymousUpgradeReauthenticationMigrationSource{Base: OrganizationLifecycleReauthenticationMigrationSource{Base: PhoneReauthenticationMigrationSource{Base: base, Version: 71}, Version: 72}, Version: 73}} {
		before, err := selected.Load(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		source := PasskeyReauthenticationMigrationSource{Base: selected, Version: 74}
		history, err := source.Load(t.Context())
		if err != nil || len(history) != len(before)+1 {
			t.Fatal("forward passkey consumption history unavailable", err)
		}
		for n := range before {
			if history[n] != before[n] {
				t.Fatal("installed signed-proof history was rewritten")
			}
		}
		if history[len(before)].DownSQL() != "" {
			t.Fatal("destructive proof-use rollback offered")
		}
		if rows, err := source.Load(nil); err == nil || rows != nil {
			t.Fatal("nil migration context admitted")
		}
		canceled, cancel := context.WithCancel(t.Context())
		cancel()
		if rows, err := source.Load(canceled); !errors.Is(err, context.Canceled) || rows != nil {
			t.Fatal("migration cancellation lost", err)
		}
	}
	for _, source := range []PasskeyReauthenticationMigrationSource{{}, {Base: base}, {Base: base, Version: 70}, {Base: base, Version: ^migrations.Version(0)}, {Base: EmailReauthenticationMigrationSource{}, Version: 74}} {
		if rows, err := source.Load(t.Context()); !errors.Is(err, password.ErrPasswordWork) || rows != nil {
			t.Fatal("invalid passkey history returned partial migrations", err)
		}
	}
}

func TestPasskeyManagementProofMigrationPreservesInstalledHistory(t *testing.T) {
	base := PasskeyReauthenticationMigrationSource{Base: ActionReauthenticationMigrationSource{Base: EmailReauthenticationMigrationSource{}, Version: 70}, Version: 74}
	before, err := base.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	source := PasskeyManagementReauthenticationMigrationSource{Base: base, Version: 75}
	history, err := source.Load(t.Context())
	if err != nil || len(history) != len(before)+1 {
		t.Fatal("forward credential-update proof history unavailable", err)
	}
	for n := range before {
		if history[n] != before[n] {
			t.Fatal("installed enrollment proof history was rewritten")
		}
	}
	if history[len(before)].DownSQL() != "" {
		t.Fatal("destructive proof-use rollback offered")
	}
	if rows, err := source.Load(nil); err == nil || rows != nil {
		t.Fatal("nil migration context admitted")
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if rows, err := source.Load(canceled); !errors.Is(err, context.Canceled) || rows != nil {
		t.Fatal("migration cancellation lost", err)
	}
	for _, invalid := range []PasskeyManagementReauthenticationMigrationSource{{}, {Base: base}, {Base: base, Version: 74}, {Base: base, Version: ^migrations.Version(0)}, {Base: EmailReauthenticationMigrationSource{}, Version: 75}, {Base: base.Base, Version: 75}} {
		if rows, err := invalid.Load(t.Context()); !errors.Is(err, password.ErrPasswordWork) || rows != nil {
			t.Fatal("invalid management history returned partial migrations", err)
		}
	}
}
