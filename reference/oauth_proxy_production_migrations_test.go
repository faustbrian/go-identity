package reference_test

import (
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/reference"
)

func TestOAuthProxyProductionMigrationSelectionIsOfflineAndBounded(t *testing.T) {
	pool, production := oauthProxyProductionConfiguration(t)
	c := reference.OAuthProxyProductionMigrationConfiguration{
		Schema: production.Native.Schema, GlobalAuthorityID: production.Native.GlobalAuthorityID,
		TenantID: production.Start.Preview.TenantID, Timeout: time.Second,
	}
	for _, change := range []func(*reference.OAuthProxyProductionMigrationConfiguration){
		func(c *reference.OAuthProxyProductionMigrationConfiguration) { c.TenantID = "" },
		func(c *reference.OAuthProxyProductionMigrationConfiguration) { c.Timeout = 0 },
		func(c *reference.OAuthProxyProductionMigrationConfiguration) { c.Schema = "audit" },
		func(c *reference.OAuthProxyProductionMigrationConfiguration) { c.Schema = strings.Repeat("a", 64) },
		func(c *reference.OAuthProxyProductionMigrationConfiguration) { c.HTTPRiskSchema = c.Schema },
		func(c *reference.OAuthProxyProductionMigrationConfiguration) { c.HTTPRiskSchema = "public" },
	} {
		invalid := c
		change(&invalid)
		if _, err := reference.NewOAuthProxyProductionMigrations(pool, invalid); err == nil {
			t.Fatal("invalid or overlapping schema selection succeeded")
		}
	}
	selected, err := reference.NewOAuthProxyProductionMigrations(pool, c)
	if err != nil {
		t.Fatal("construct standalone migration selection without contacting PostgreSQL", err)
	}
	if err := selected.Close(t.Context()); err != nil {
		t.Fatal("close standalone migration selection", err)
	}
	if _, err := selected.Check(t.Context()); err == nil {
		t.Fatal("closed operator owner accepted a fresh operation")
	}
}
