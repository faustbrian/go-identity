package postgres

import (
	"context"
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestSSOOIDCSubjectAvailabilityRejectsUnownedRepository(t *testing.T) {
	q := ProviderSigninAccountQuery{TenantID: "tenant", Provider: "sso.oidc.v1.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", Issuer: "https://issuer.example", Subject: "subject"}
	for _, repository := range []*Repository{nil, {}} {
		var input identity.InvalidInputError
		if available, err := repository.SSOOIDCSubjectAvailable(context.Background(), q); available || !errors.As(err, &input) {
			t.Fatal("unowned repository returned availability")
		}
	}
}

func ssoOIDCSubjectMigrationBase() migrations.Source {
	return AccountMigrationSource{Base: CredentialMigrationSource{Base: StatusMigrationSource{Base: MigrationSource{}, Version: 10}, Version: 11}, Version: 12}
}

func TestSSOOIDCSubjectAvailabilityMigrationPreservesHistory(t *testing.T) {
	ctx := context.Background()
	base := ssoOIDCSubjectMigrationBase()
	before, err := base.Load(ctx)
	if err != nil {
		t.Fatal("account history fixture")
	}
	source := SSOOIDCSubjectAvailabilityMigrationSource{Base: base, Version: 13}
	after, err := source.Load(ctx)
	if err != nil || len(after) != len(before)+1 {
		t.Fatal("subject availability history unavailable")
	}
	for i := range before {
		if before[i] != after[i] {
			t.Fatal("installed account migration changed")
		}
	}
	index := after[len(before)]
	if index.Version() != 13 || index.TransactionMode() != migrations.TransactionModeNone || index.DownSQL() != "" {
		t.Fatal("retired subject index is not concurrent forward-only history")
	}
	after[0] = migrations.Migration{}
	reloaded, err := source.Load(ctx)
	if err != nil || reloaded[0] != before[0] {
		t.Fatal("migration history aliases caller-owned storage")
	}
	for _, invalid := range []SSOOIDCSubjectAvailabilityMigrationSource{{}, {Base: base}, {Base: base, Version: 12}, {Base: base, Version: migrations.Version(^uint64(0))}} {
		var input identity.InvalidInputError
		if history, err := invalid.Load(ctx); history != nil || !errors.As(err, &input) {
			t.Fatal("invalid subject migration returned partial history")
		}
	}
	if history, err := source.Load(nil); history != nil || err == nil {
		t.Fatal("nil context returned migration history")
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if history, err := source.Load(cancelled); history != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("migration lost caller cancellation")
	}
}
