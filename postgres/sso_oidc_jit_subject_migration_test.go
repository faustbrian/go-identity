package postgres

import (
	"context"
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestSSOOIDCSubjectAvailabilityOfflineMigrationPreservesPublishedHistory(t *testing.T) {
	ctx := context.Background()
	base := ssoOIDCSubjectMigrationBase()
	prefix, err := base.Load(ctx)
	if err != nil {
		t.Fatal("account history fixture", err)
	}
	source := SSOOIDCSubjectAvailabilityMigrationSource{Base: base, Version: 13}
	native, err := source.Load(ctx)
	if err != nil {
		t.Fatal("published concurrent history", err)
	}
	const publishedSQL = `CREATE INDEX CONCURRENTLY identity_accounts_retired_subject ON identity.accounts(tenant_id,subject_key) WHERE NOT linked;`
	published, err := migrations.NewMigration(13, "identity_sso_oidc_retired_subject", migrations.TransactionModeNone, publishedSQL, "")
	if err != nil || native[len(prefix)] != published {
		t.Fatal("published concurrent bytes, mode or checksum changed", err)
	}

	offline, err := source.LoadOffline(ctx)
	if err != nil || len(offline) != len(prefix)+1 {
		t.Fatal("offline history unavailable", err)
	}
	const offlineSQL = "SET LOCAL lock_timeout = '5s';\nCREATE INDEX identity_accounts_retired_subject ON identity.accounts(tenant_id,subject_key) WHERE NOT linked;"
	expected, err := migrations.NewMigration(13, "identity_sso_oidc_retired_subject", migrations.TransactionModeDefault, offlineSQL, "")
	if err != nil || offline[len(prefix)] != expected {
		t.Fatal("offline mode changed the non-unique retired index or lock budget", err)
	}
	if offline[len(prefix)].Checksum() == published.Checksum() {
		t.Fatal("different installation modes cannot share an installed checksum")
	}
	for i := range prefix {
		if native[i] != prefix[i] || offline[i] != prefix[i] {
			t.Fatal("offline selection rewrote an installed predecessor")
		}
	}
	offline[0] = migrations.Migration{}
	reloaded, err := source.LoadOffline(ctx)
	if err != nil || reloaded[0] != prefix[0] || native[0] != prefix[0] {
		t.Fatal("offline history aliases caller-owned storage", err)
	}
	nativeAgain, err := source.Load(ctx)
	if err != nil || nativeAgain[len(prefix)] != published {
		t.Fatal("offline loading changed later concurrent history", err)
	}
}

func TestSSOOIDCSubjectAvailabilityOfflineMigrationReusesValidation(t *testing.T) {
	base := ssoOIDCSubjectMigrationBase()
	for _, source := range []SSOOIDCSubjectAvailabilityMigrationSource{{}, {Base: base}, {Base: base, Version: 12}, {Base: base, Version: migrations.Version(^uint64(0))}} {
		var input identity.InvalidInputError
		if history, err := source.LoadOffline(context.Background()); history != nil || !errors.As(err, &input) {
			t.Fatal("invalid offline source returned partial history", err)
		}
	}
	source := SSOOIDCSubjectAvailabilityMigrationSource{Base: base, Version: 13}
	var input identity.InvalidInputError
	if history, err := source.LoadOffline(nil); history != nil || !errors.As(err, &input) {
		t.Fatal("nil context returned offline history", err)
	}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	if history, err := source.LoadOffline(cancelled); history != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("offline loading lost caller cancellation", err)
	}
}
