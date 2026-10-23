package postgres

import (
	"context"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestAnonymousExpiryDisposalPreservesInstalledHistory(t *testing.T) {
	base := AnonymousDisposalMigrationSource{Base: AnonymousIdentityMigrationSource{Base: IdentifierNormalizationMigrationSource{Base: IdentifierMutationMigrationSource{Base: CredentialMigrationSource{Base: StatusMigrationSource{Base: MigrationSource{}, Version: 10}, Version: 11}, Version: 12}, Version: 13}, Version: 14}, Version: 15}
	for _, predecessor := range []migrations.Source{base, AnonymousUpgradeDisposalMigrationSource{Base: base, Version: 16}} {
		old, err := predecessor.Load(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		source := AnonymousExpiryDisposalMigrationSource{Base: predecessor, Version: 17}
		got, err := source.Load(t.Context())
		if err != nil || len(got) != len(old)+1 {
			t.Fatal("forward expiry history missing", err)
		}
		for n := range old {
			if old[n].Checksum() != got[n].Checksum() || old[n].Name() != got[n].Name() || old[n].Version() != got[n].Version() {
				t.Fatal("installed predecessor rewritten")
			}
		}
		if got[len(got)-1].DownSQL() != "" {
			t.Fatal("destructive downgrade offered")
		}
		if _, err := (AnonymousUpgradeDisposalMigrationSource{Base: source, Version: 18}).Load(t.Context()); err == nil {
			t.Fatal("later purpose extension could drop expiry support")
		}
	}
	for _, invalid := range []AnonymousExpiryDisposalMigrationSource{{}, {Base: base}, {Base: base, Version: 15}, {Base: MigrationSource{}, Version: 17}} {
		if out, err := invalid.Load(t.Context()); err == nil || out != nil {
			t.Fatal("invalid predecessor admitted")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := (AnonymousExpiryDisposalMigrationSource{Base: base, Version: 17}).Load(ctx); err != context.Canceled {
		t.Fatal("cancellation lost", err)
	}
}
