package passwordpostgres

import (
	"context"
	"errors"
	"testing"
)

func TestPhoneChangeProofMigrationPreservesInstalledHistory(t *testing.T) {
	phone := PhoneReauthenticationMigrationSource{Base: ActionReauthenticationMigrationSource{Base: EmailReauthenticationMigrationSource{}, Version: 70}, Version: 71}
	removal := PhoneRemovalReauthenticationMigrationSource{Base: phone, Version: 72}
	for _, base := range []struct {
		name   string
		source PhoneRemovalReauthenticationMigrationSource
	}{
		{"with-removal", removal},
	} {
		t.Run(base.name, func(t *testing.T) {
			before, err := base.source.Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			got, err := (PhoneChangeReauthenticationMigrationSource{Base: base.source, Version: 73}).Load(context.Background())
			if err != nil || len(got) != len(before)+1 {
				t.Fatal("missing forward change-proof history", err)
			}
			for n := range before {
				if before[n].Checksum() != got[n].Checksum() || before[n].Version() != got[n].Version() {
					t.Fatal("installed proof history changed")
				}
			}
			if got[len(got)-1].DownSQL() != "" {
				t.Fatal("destructive proof rollback offered")
			}
		})
	}
	// Change does not require selecting the separate removal workflow.
	if _, err := (PhoneChangeReauthenticationMigrationSource{Base: phone, Version: 72}).Load(context.Background()); err != nil {
		t.Fatal("change required unrelated removal history", err)
	}
	if _, err := (PhoneChangeReauthenticationMigrationSource{Base: EmailReauthenticationMigrationSource{}, Version: 73}).Load(context.Background()); err == nil {
		t.Fatal("missing original phone proof history accepted")
	}
	if _, err := (PhoneChangeReauthenticationMigrationSource{Base: removal, Version: 72}).Load(context.Background()); err == nil {
		t.Fatal("non-successor change history accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (PhoneChangeReauthenticationMigrationSource{Base: removal, Version: 73}).Load(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled history did not preserve cancellation", err)
	}
}
