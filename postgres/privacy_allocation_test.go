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

func TestPrivacyAllocationJobMigrationPreservesAppliedHistory(t *testing.T) {
	base := PrivacyExportMigrationSource{Base: StatusMigrationSource{Base: MigrationSource{}, Version: 10}, Version: 11}
	before, err := base.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	source := PrivacyExportJobMigrationSource{Base: base, Version: 12}
	after, err := source.Load(context.Background())
	if err != nil || len(after) != len(before)+1 {
		t.Fatal("missing job migration", err)
	}
	for i, m := range before {
		if after[i].Checksum() != m.Checksum() {
			t.Fatal("applied privacy history changed")
		}
	}
	if after[len(after)-1].DownSQL() != "" {
		t.Fatal("snapshot retention has destructive down")
	}
	for _, bad := range []PrivacyExportJobMigrationSource{{}, {Base: base, Version: 11}} {
		if _, err := bad.Load(context.Background()); err == nil {
			t.Fatal("invalid job migration accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := source.Load(ctx); err != context.Canceled {
		t.Fatal("cancelled migration continued", err)
	}
	if _, err := source.Load(nil); err == nil {
		t.Fatal("nil context accepted")
	}
}
