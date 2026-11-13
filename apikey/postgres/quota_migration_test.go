package postgres

import (
	"context"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestQuotaMigrationRejectsInvalidAndDoesNotRewriteBase(t *testing.T) {
	base, err := (MigrationSource{Version: 1}).Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	quota, err := (QuotaMigrationSource{Version: 2}).Load(t.Context())
	if err != nil || len(quota) != 1 || quota[0].Version() != 2 {
		t.Fatal("optional quota migration", err)
	}
	again, err := (MigrationSource{Version: 1}).Load(t.Context())
	if err != nil || base[0].Checksum() != again[0].Checksum() {
		t.Fatal("quota rewrote published base history", err)
	}
	for _, v := range []migrations.Version{0, ^migrations.Version(0)} {
		if _, err := (QuotaMigrationSource{Version: v}).Load(t.Context()); err == nil {
			t.Fatal("invalid quota migration version")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := (QuotaMigrationSource{Version: 2}).Load(ctx); err == nil {
		t.Fatal("canceled migration")
	}
}
