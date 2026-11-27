package postgres

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestProxyTransactionMigrationSource(t *testing.T) {
	source := ProxyTransactionMigrationSource{Schema: "oauth_proxy", Version: 101}
	history, err := source.Load(context.Background())
	if err != nil || len(history) != 1 {
		t.Fatal("load additive proxy custody migration", err)
	}
	if history[0].Version() != 101 || history[0].DownSQL() != "" || history[0].UpSQL() == "" {
		t.Fatal("proxy custody must retain its allocated version and have no destructive downgrade")
	}
	if !strings.Contains(history[0].UpSQL(), `CREATE TABLE "oauth_proxy".proxy_transactions(`) {
		t.Fatal("proxy custody did not select its dedicated validated namespace")
	}
	again, err := source.Load(context.Background())
	if err != nil || len(again) != 1 || again[0].UpSQL() != history[0].UpSQL() {
		t.Fatal("immutable migration source changed across loads", err)
	}
}

func TestProxyTransactionMigrationRejectsInvalidConfiguration(t *testing.T) {
	for _, schema := range []string{"", "identity", "public", "information_schema", "pg_proxy", "Upper", "oauth;drop", strings.Repeat("a", 64)} {
		t.Run(schema, func(t *testing.T) {
			_, err := (ProxyTransactionMigrationSource{Schema: schema, Version: 101}).Load(context.Background())
			var invalid identity.InvalidInputError
			if !errors.As(err, &invalid) || invalid.Field != "oauth_proxy_transaction_migration" {
				t.Fatalf("invalid namespace was not configuration-rejected: %T", err)
			}
		})
	}
	for _, version := range []migrations.Version{0, migrations.Version(math.MaxInt64) + 1} {
		_, err := (ProxyTransactionMigrationSource{Schema: "oauth_proxy", Version: version}).Load(context.Background())
		var invalid identity.InvalidInputError
		if !errors.As(err, &invalid) {
			t.Fatalf("invalid history version was not rejected: %T", err)
		}
	}
	if _, err := (ProxyTransactionMigrationSource{Schema: "oauth_proxy", Version: 101}).Load(nil); err == nil {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (ProxyTransactionMigrationSource{Schema: "oauth_proxy", Version: 101}).Load(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("migration source lost cancellation", err)
	}
}
