package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"testing"

	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestOwnedListRejectsIncompleteComposition(t *testing.T) {
	if service, err := NewListService(nil, ListServiceConfig{}); service != nil || err == nil {
		t.Fatal("incomplete list composition admitted")
	}
	var zero *Repository
	if page, err := zero.ReadSessionPage(context.Background(), session.SessionPageQuery{}); err == nil || len(page.Entries) != 0 {
		t.Fatal("zero page reader admitted")
	}
	var _ session.SessionPageReader = (*Repository)(nil)
}

func TestOwnedListConfigurationCannotDiscloseSecrets(t *testing.T) {
	c := ListServiceConfig{}
	if got := fmt.Sprintf("%#v", c); got != "postgres.ListServiceConfig(redacted)" {
		t.Fatal("configuration disclosure")
	}
	if _, err := json.Marshal(c); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("configuration export admitted")
	}
}

func TestListMigrationRejectsInvalidAllocationsAndCancellation(t *testing.T) {
	for _, source := range []ListMigrationSource{{}, {Schema: "public", Version: 19}, {Schema: "session_store", Version: migrations.Version(math.MaxInt64) + 1}} {
		if rows, err := source.Load(context.Background()); err == nil || rows != nil {
			t.Fatal("invalid migration allocation")
		}
	}
	source := ListMigrationSource{Schema: "session_store", Version: 19}
	if rows, err := source.Load(nil); err == nil || rows != nil {
		t.Fatal("nil context")
	}
	ctx, stop := context.WithCancel(context.Background())
	stop()
	if rows, err := source.Load(ctx); !errors.Is(err, context.Canceled) || rows != nil {
		t.Fatal("migration cancellation")
	}
	if rows, err := source.Load(context.Background()); err != nil || len(rows) != 1 {
		t.Fatal("owned migration", err)
	}
}
