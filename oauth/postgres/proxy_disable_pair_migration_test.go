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

func TestProxyDisablePairMigrationValidatesInputs(t *testing.T) {
	for _, tt := range []struct {
		name    string
		ctx     context.Context
		schema  string
		version migrations.Version
	}{
		{"nil context", nil, "oauth_rp", 103},
		{"empty schema", t.Context(), "", 103},
		{"identity schema", t.Context(), "identity", 103},
		{"public schema", t.Context(), "public", 103},
		{"audit schema", t.Context(), "audit", 103},
		{"information schema", t.Context(), "information_schema", 103},
		{"postgres schema", t.Context(), "pg_oauth", 103},
		{"uppercase schema", t.Context(), "OAuth", 103},
		{"leading digit", t.Context(), "1oauth", 103},
		{"leading underscore", t.Context(), "_oauth", 103},
		{"punctuated schema", t.Context(), "oauth-rp", 103},
		{"oversized schema", t.Context(), strings.Repeat("a", 64), 103},
		{"zero version", t.Context(), "oauth_rp", 0},
		{"oversized version", t.Context(), "oauth_rp", migrations.Version(math.MaxInt64) + 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			history, err := (ProxyDisablePairMigrationSource{Schema: tt.schema, Version: tt.version}).Load(tt.ctx)
			var invalid identity.InvalidInputError
			if len(history) != 0 || !errors.As(err, &invalid) || invalid.Field != "oauth_proxy_disable_pair_migration" {
				t.Fatalf("invalid migration input returned %v, %v", history, err)
			}
		})
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	history, err := (ProxyDisablePairMigrationSource{Schema: "oauth_rp", Version: 103}).Load(ctx)
	if len(history) != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled load returned %v, %v", history, err)
	}

	for _, schema := range []string{"a", "oauth_rp", strings.Repeat("a", 63)} {
		history, err := (ProxyDisablePairMigrationSource{Schema: schema, Version: migrations.Version(math.MaxInt64)}).Load(t.Context())
		if err != nil || len(history) != 1 || history[0].Version() != migrations.Version(math.MaxInt64) {
			t.Fatalf("valid schema/version boundary %q rejected: %v", schema, err)
		}
	}
}

func TestProxyDisablePairMigrationIsAdditiveAndForwardOnly(t *testing.T) {
	history, err := (ProxyDisablePairMigrationSource{Schema: "oauth_pair_owner", Version: 103}).Load(t.Context())
	if err != nil || len(history) != 1 {
		t.Fatal("expected one independent migration", err)
	}
	migration := history[0]
	if migration.Version() != 103 || migration.Name() != "identity_oauth_proxy_disable_pair" ||
		migration.TransactionMode() != migrations.TransactionModeDefault || migration.DownSQL() != "" {
		t.Fatal("pair migration changed its forward-only transaction contract")
	}

	sql := migration.UpSQL()
	if !strings.HasPrefix(sql, "SET LOCAL lock_timeout = '5s';\n") ||
		strings.Count(sql, "CREATE TABLE ") != 1 || strings.Count(sql, ";") != 2 || strings.Contains(sql, "@schema@") {
		t.Fatal("pair migration must only set a bounded lock wait and create one table")
	}
	for _, fragment := range []string{
		`CREATE TABLE "oauth_pair_owner".provider_disable_proxy_pairs (`,
		`tenant_id identity.directory_id NOT NULL`,
		`source_command_id text COLLATE "C" NOT NULL CHECK(source_command_id ~ '^[A-Za-z0-9_-]{22}$')`,
		`cascade_id text COLLATE "C" NOT NULL CHECK(cascade_id ~ '^[A-Za-z0-9_-]{22}$')`,
		`generation bigint NOT NULL CHECK(generation>0)`,
		`production_schema text COLLATE "C" NOT NULL CHECK(production_schema ~ '^[a-z][a-z0-9_]{0,62}$'`,
		`production_schema NOT IN ('identity','public','audit','information_schema') AND production_schema !~ '^pg_'`,
		`preview_schema text COLLATE "C" NOT NULL CHECK(preview_schema ~ '^[a-z][a-z0-9_]{0,62}$'`,
		`preview_schema NOT IN ('identity','public','audit','information_schema') AND preview_schema !~ '^pg_'`,
		`production_deployment text COLLATE "C" NOT NULL CHECK(production_deployment ~ '^[a-z0-9_-]{1,128}$')`,
		`preview_deployment text COLLATE "C" NOT NULL CHECK(preview_deployment ~ '^[a-z0-9_-]{1,128}$'`,
		`preview_deployment<>production_deployment`,
		`acknowledged_at timestamptz CHECK(acknowledged_at IS NULL OR isfinite(acknowledged_at))`,
		`PRIMARY KEY(tenant_id,source_command_id)`,
	} {
		if !strings.Contains(sql, fragment) {
			t.Fatalf("pair migration is missing its DDL contract: %s", fragment)
		}
	}
	for _, forbidden := range []string{"ALTER ", "LOCK ", "REFERENCES ", "INSERT ", "UPDATE ", "DELETE ", "DEFAULT ", "CREATE INDEX ", "CREATE TRIGGER ", "CREATE FUNCTION "} {
		if strings.Contains(sql, forbidden) {
			t.Fatalf("pair migration contains non-additive or implicit state: %s", forbidden)
		}
	}
}
