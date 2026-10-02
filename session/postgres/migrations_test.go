package postgres

import (
	"context"
	"errors"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestMigrationHistoryOwnsExplicitSchemaAndVersion(t *testing.T) {
	source := MigrationSource{Schema: "identity_session", Version: 10}
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
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if rows, err := source.Load(ctx); !errors.Is(err, context.Canceled) || rows != nil {
		t.Fatal("cancellation lost")
	}
}
