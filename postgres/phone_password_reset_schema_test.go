package postgres

import (
	"context"
	"errors"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestPhonePasswordResetMigrationPreservesInstalledResetHistory(t *testing.T) {
	base := CredentialResetMigrationSource{Base: CredentialReplacementMigrationSource{Base: CredentialMigrationSource{Base: StatusMigrationSource{Base: MigrationSource{}, Version: 12}, Version: 13}, Version: 14}, Version: 15}
	before, err := base.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	source := PhonePasswordResetMigrationSource{Base: base, Version: 16}
	after, err := source.Load(context.Background())
	if err != nil || len(after) != len(before)+1 {
		t.Fatal("phone reset forward history unavailable", err)
	}
	for i := range before {
		if before[i].Checksum() != after[i].Checksum() || before[i].Version() != after[i].Version() {
			t.Fatal("phone extension rewrote installed reset history")
		}
	}
	if after[len(after)-1].DownSQL() != "" {
		t.Fatal("phone reset extension permits destructive downgrade")
	}
	// Returned history must not alias a later Load result.
	after[0] = after[len(after)-1]
	again, err := source.Load(context.Background())
	if err != nil || again[0].Checksum() != before[0].Checksum() {
		t.Fatal("caller changed retained predecessor history", err)
	}
	for _, invalid := range []PhonePasswordResetMigrationSource{{}, {Base: base}, {Base: base, Version: 15}, {Base: base, Version: migrations.Version(^uint64(0))}} {
		if result, err := invalid.Load(context.Background()); err == nil || result != nil {
			t.Fatal("invalid extension returned partial history")
		}
	}
	if result, err := source.Load(nil); err == nil || result != nil {
		t.Fatal("nil context returned partial history")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if result, err := source.Load(ctx); !errors.Is(err, context.Canceled) || result != nil {
		t.Fatal("cancellation lost while composing forward history", err)
	}
}
