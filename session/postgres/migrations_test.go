package postgres

import (
	"context"
	"errors"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestMigrationHistoryOwnsExplicitSchemaAndVersion(t *testing.T) {
	// Existing callers may use positional literals; the install source must keep
	// its original two-field contract as new migrations are added.
	source := MigrationSource{"identity_session", 10}
	first, err := source.Load(context.Background())
	if err != nil || len(first) != 1 || first[0].Version() != 10 || first[0].DownSQL() != "" || first[0].TransactionMode() != migrations.TransactionModeDefault {
		t.Fatal("missing forward atomic session install", err)
	}
	original := first[0]
	first[0] = migrations.Migration{}
	second, err := source.Load(context.Background())
	if err != nil || second[0] != original {
		t.Fatal("history aliases caller memory")
	}
	for _, bad := range []MigrationSource{{}, {Schema: "public", Version: 10}, {Schema: "identity", Version: 10}, {Schema: "bad\";DROP SCHEMA identity", Version: 10}, {Schema: "identity_session"}, {Schema: "session_store", Version: ^migrations.Version(0)}, {Schema: "pg_invalid", Version: 10}, {Schema: "1invalid", Version: 10}} {
		if rows, err := bad.Load(context.Background()); err == nil || rows != nil {
			t.Fatal("unsafe source accepted")
		}
	}
	if rows, err := source.Load(nil); err == nil || rows != nil {
		t.Fatal("nil context accepted")
	}
	upgraded, err := (RevocationMigrationSource{Base: source, Version: 11}).Load(context.Background())
	if err != nil || len(upgraded) != 2 || upgraded[0] != original || upgraded[1].Version() != 11 || upgraded[1].DownSQL() != "" {
		t.Fatal("forward install rewrote historical allocation", err)
	}
	for _, v := range []migrations.Version{0, 9, 10, ^migrations.Version(0)} {
		if history, err := (RevocationMigrationSource{Base: source, Version: v}).Load(context.Background()); err == nil || history != nil {
			t.Fatal("invalid mutation allocation admitted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if rows, err := source.Load(ctx); !errors.Is(err, context.Canceled) || rows != nil {
		t.Fatal("cancellation lost")
	}
	upgrade := RevocationMigrationSource{Base: source, Version: 11}
	if rows, err := upgrade.Load(ctx); !errors.Is(err, context.Canceled) || rows != nil {
		t.Fatal("upgrade cancellation lost")
	}
	if rows, err := upgrade.Load(nil); err == nil || rows != nil {
		t.Fatal("upgrade nil context accepted")
	}
	if rows, err := (RevocationMigrationSource{Version: 11}).Load(context.Background()); err == nil || rows != nil {
		t.Fatal("invalid base install admitted")
	}
}
