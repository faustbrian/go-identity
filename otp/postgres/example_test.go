package postgres_test

import (
	"context"
	"fmt"

	otppostgres "github.com/faustbrian/go-identity/otp/postgres"
)

func ExampleMigrationSource() {
	// Permanently allocate this version after the kernel and all other sources.
	history, err := (otppostgres.MigrationSource{Schema: "otp_store", Version: 100}).Load(context.Background())
	if err != nil {
		panic("invalid migration configuration")
	}
	// Pass this history to the composition's go-migrations source/runner.
	fmt.Println(len(history), history[0].Version())
	// Output: 1 100
}
