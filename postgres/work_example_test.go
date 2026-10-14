package postgres_test

import (
	"context"
	"fmt"

	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

// A separately owned enlisted adapter uses only the public restricted surface.
func currentWorkVersion(ctx context.Context, work identitypostgres.Work) (string, error) {
	scope, err := work.Scope()
	if err != nil {
		return "", err
	}
	rows, err := work.Query(ctx, `SELECT version::text FROM identity.users WHERE tenant_id=$1 AND user_id=$2`, string(scope.TenantID), string(scope.UserID))
	if err != nil {
		return "", err
	}
	defer rows.Close()
	if !rows.Next() {
		return "", rows.Err()
	}
	var version string
	if err := rows.Scan(&version); err != nil {
		return "", err
	}
	return version, nil
}

func ExampleWork() {
	// Application code cannot create valid Work: its future Coordinator owns
	// issuance. This verifies the safe zero contract, not complete composition.
	_, err := currentWorkVersion(context.Background(), identitypostgres.Work{})
	fmt.Println(err != nil)
	// Output: true
}
