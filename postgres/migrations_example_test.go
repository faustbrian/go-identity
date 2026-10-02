package postgres_test

import (
	"context"
	"fmt"

	identitydb "github.com/faustbrian/go-identity/postgres"
)

func ExampleMigrationSource_Load() {
	history, err := (identitydb.MigrationSource{}).Load(context.Background())
	if err != nil {
		panic(err)
	}
	fmt.Println(history[0].Version(), history[0].Name(), history[0].DownSQL() == "")
	// Output: 1 identity_users true
}
