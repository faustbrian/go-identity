package passwordpostgres

import (
	"context"
	"testing"
)

func TestPhoneRemovalProofMigrationPreservesOriginalUseHistory(t *testing.T) {
	base := PhoneReauthenticationMigrationSource{Base: ActionReauthenticationMigrationSource{Base: EmailReauthenticationMigrationSource{}, Version: 70}, Version: 71}
	before, err := base.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got, err := (PhoneRemovalReauthenticationMigrationSource{Base: base, Version: 72}).Load(context.Background())
	if err != nil || len(got) != len(before)+1 {
		t.Fatal("missing forward removal-proof support", err)
	}
	for n := range before {
		if before[n].Checksum() != got[n].Checksum() || before[n].Version() != got[n].Version() {
			t.Fatal("installed phone or password proof history rewritten")
		}
	}
	if got[len(got)-1].DownSQL() != "" {
		t.Fatal("destructive proof rollback offered")
	}
	if _, err := (PhoneRemovalReauthenticationMigrationSource{Base: EmailReauthenticationMigrationSource{}, Version: 72}).Load(context.Background()); err == nil {
		t.Fatal("missing original action/phone proof history accepted")
	}
}
