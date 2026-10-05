package postgres

import (
	"context"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestPrivacyAllocationMigrationAndUnownedWork(t *testing.T) {
	base := StatusMigrationSource{Base: MigrationSource{}, Version: 10}
	before, err := base.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	source := PrivacyExportMigrationSource{Base: base, Version: 11}
	after, err := source.Load(context.Background())
	if err != nil || len(after) != len(before)+1 {
		t.Fatal("missing privacy authority history", err)
	}
	for i, m := range before {
		if after[i].Checksum() != m.Checksum() {
			t.Fatal("old migration rewritten")
		}
	}
	if after[len(after)-1].DownSQL() != "" {
		t.Fatal("privacy authority supports destructive down")
	}
	for _, s := range []PrivacyExportMigrationSource{{}, {Base: base, Version: 10}} {
		if _, err := s.Load(context.Background()); err == nil {
			t.Fatal("invalid migration accepted")
		}
	}
	if _, err := allocatePrivacyExport(context.Background(), Work{}, identity.PrivacyExportRequestCommand{}); err == nil {
		t.Fatal("unowned Work allocated authority")
	}
}
