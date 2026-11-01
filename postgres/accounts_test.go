package postgres

import (
	"context"
	"errors"
	"math"
	"testing"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestAccountReadsRejectInvalidRuntime(t *testing.T) {
	for _, repo := range []*Repository{nil, {}} {
		if out, err := repo.ListAccounts(context.Background(), identity.AccountQuery{TenantID: "tenant", UserID: "user", MaximumAccounts: 100}); err == nil || out.User.ID != "" || out.Accounts != nil {
			t.Fatal("invalid runtime returned account state")
		}
		if out, err := repo.GetAccountLinkState(context.Background(), identity.AccountLinkQuery{}); err == nil || out.Access.User.ID != "" || out.Access.Accounts != nil {
			t.Fatal("invalid runtime returned link authority")
		}
	}
}

func TestAccountMigrationPreservesInstalledHistory(t *testing.T) {
	ctx := context.Background()
	base := CredentialMigrationSource{Base: StatusMigrationSource{Base: MigrationSource{}, Version: 10}, Version: 11}
	history, err := base.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	source := AccountMigrationSource{Base: base, Version: 12}
	got, err := source.Load(ctx)
	if err != nil || len(got) != len(history)+1 {
		t.Fatal("forward history missing", err)
	}
	for i := range history {
		if got[i].Version() != history[i].Version() || got[i].Checksum() != history[i].Checksum() {
			t.Fatal("installed migration changed")
		}
	}
	got[0] = got[len(got)-1]
	again, err := source.Load(ctx)
	if err != nil || again[0].Checksum() != history[0].Checksum() {
		t.Fatal("returned history aliases subsequent load", err)
	}
	var typedNil *CredentialMigrationSource
	for _, invalid := range []AccountMigrationSource{{}, {Base: typedNil, Version: 12}, {Base: base}, {Base: base, Version: 11}, {Base: base, Version: migrations.Version(math.MaxUint64)}} {
		if out, err := invalid.Load(ctx); err == nil || out != nil {
			t.Fatal("invalid history returned migrations")
		}
	}
	if out, err := source.Load(nil); err == nil || out != nil {
		t.Fatal("nil migration context admitted")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if out, err := source.Load(cancelled); !errors.Is(err, context.Canceled) || out != nil {
		t.Fatal("migration cancellation lost", err)
	}
}

func TestAccountVersionsRejectNoncanonicalStorage(t *testing.T) {
	for _, raw := range []string{"", "0", "01", "+1", "1.0", "-1", "18446744073709551616"} {
		var unavailable identity.UnavailableError
		if v, err := parseAccountVersion(raw); v != 0 || !errors.As(err, &unavailable) {
			t.Fatal("invalid stored security epoch admitted")
		}
	}
}
