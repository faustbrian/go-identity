package postgres

import (
	"context"
	"errors"
	"testing"
)

func TestAnonymousDisposalHistoryRequiresCreationAndLegalHold(t *testing.T) {
	base := AnonymousIdentityMigrationSource{Base: IdentifierNormalizationMigrationSource{Base: IdentifierMutationMigrationSource{Base: CredentialMigrationSource{Base: StatusMigrationSource{Base: MigrationSource{}, Version: 10}, Version: 11}, Version: 12}, Version: 13}, Version: 14}
	old, err := base.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	s := AnonymousDisposalMigrationSource{Base: base, Version: 15}
	got, err := s.Load(t.Context())
	if err != nil || len(got) != len(old)+1 {
		t.Fatal("disposal history missing", err)
	}
	for n := range old {
		if old[n].Version() != got[n].Version() || old[n].Name() != got[n].Name() || old[n].UpSQL() != got[n].UpSQL() || old[n].DownSQL() != got[n].DownSQL() {
			t.Fatal("populated predecessor changed")
		}
	}
	if got[len(got)-1].DownSQL() != "" {
		t.Fatal("destructive downgrade offered")
	}
	noHold := AnonymousIdentityMigrationSource{Base: IdentifierNormalizationMigrationSource{Base: IdentifierMutationMigrationSource{Base: MigrationSource{}, Version: 10}, Version: 11}, Version: 12}
	for _, bad := range []AnonymousDisposalMigrationSource{{}, {Base: base}, {Base: base, Version: 14}, {Base: MigrationSource{}, Version: 15}, {Base: noHold, Version: 15}} {
		if out, err := bad.Load(t.Context()); err == nil || out != nil {
			t.Fatal("incomplete creation/hold history admitted")
		}
	}
	ctx, stop := context.WithCancel(context.Background())
	stop()
	if _, err := s.Load(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("migration cancellation lost", err)
	}
}
