package postgres

import (
	"strings"
	"testing"
)

func TestProxyRetirementDrainMigrationIsAdditive(t *testing.T) {
	history, err := (ProxyRetirementDrainMigrationSource{Schema: "oauth_rp", Version: 94}).Load(t.Context())
	if err != nil || len(history) != 1 || history[0].Version() != 94 || history[0].DownSQL() != "" {
		t.Fatal("drain must have one optional forward migration", err)
	}
	sql := history[0].UpSQL()
	if !strings.Contains(sql, "PRIMARY KEY(tenant_id,cascade_id,generation,role,deployment)") || strings.Contains(sql, "ALTER TABLE") {
		t.Fatal("the migration must only create a generation-scoped checkpoint store")
	}
	if _, err := (ProxyRetirementDrainMigrationSource{Schema: "audit", Version: 94}).Load(t.Context()); err == nil {
		t.Fatal("accepted a reserved namespace")
	}
}
