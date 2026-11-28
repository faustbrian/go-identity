package postgres

import (
	"strings"
	"testing"

	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestProxyCustodyWriteFenceMigrationIsOptIn(t *testing.T) {
	ctx := t.Context()
	for _, tc := range []struct {
		name, custody, fence string
		kind                 kernel.OAuthProxyRetirementKind
	}{
		{"production", "proxy_transactions", "proxy_production_write_fences", kernel.OAuthProxyRetireProduction},
		{"preview", "proxy_preview_bindings", "proxy_preview_write_fences", kernel.OAuthProxyRetirePreview},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const schema = "oauth_fence_test"
			sources := []migrations.Source{
				ProxyCustodyWriteFenceMigrationSource{Schema: schema, Version: 51, Kind: tc.kind},
				ProxyCustodyWriteFenceActivationSource{Schema: schema, Version: 52, Kind: tc.kind},
			}
			for i, source := range sources {
				history, err := source.Load(ctx)
				if err != nil || len(history) != 1 || history[0].Version() != migrations.Version(51+i) || history[0].DownSQL() != "" {
					t.Fatal("fence expansion and activation must be separately installable and forward-only", err)
				}
				sql := history[0].UpSQL()
				if !strings.Contains(sql, tc.custody) || !strings.Contains(sql, tc.fence) {
					t.Fatal("migration did not bind its selected native storage")
				}
				if strings.Contains(sql, "CREATE CONSTRAINT TRIGGER") != (i == 1) {
					t.Fatal("only explicit activation may require marked writers")
				}
			}
		})
	}
	for _, bad := range []migrations.Source{
		ProxyCustodyWriteFenceMigrationSource{Schema: "audit", Version: 1, Kind: kernel.OAuthProxyRetirePreview},
		ProxyCustodyWriteFenceActivationSource{Schema: "oauth_fence_test", Version: 0, Kind: kernel.OAuthProxyRetirePreview},
		ProxyCustodyWriteFenceMigrationSource{Schema: "oauth_fence_test", Version: 1},
	} {
		if _, err := bad.Load(ctx); err == nil {
			t.Fatal("invalid migration owner was accepted")
		}
	}
}
