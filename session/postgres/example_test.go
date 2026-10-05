package postgres_test

import (
	"context"
	"fmt"

	"github.com/faustbrian/go-identity/session/postgres"
)

func ExampleMigrationSource_Load() {
	// The owned composition allocates this immutable version after kernel history.
	source := postgres.MigrationSource{Schema: "identity_session", Version: 10}
	history, err := source.Load(context.Background())
	if err != nil {
		panic(err)
	}
	// Loading does not connect, create a ledger or execute SQL.
	fmt.Println(len(history), history[0].Version(), history[0].DownSQL() == "")
	// Output: 1 10 true
}

func ExampleSessionAuthorityKeys() {
	keys, err := postgres.SessionAuthorityKeys("tenant-a", "user-a", "family-a", "session-a")
	if err != nil {
		panic(err)
	}
	// Do not log the correlation keys. Derivation alone proves no authority.
	fmt.Println(keys.Family != keys.Session)
	// Output: true
}
