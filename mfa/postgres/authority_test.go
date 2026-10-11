package mfapostgres_test

import (
	"context"
	"testing"

	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestAuthorityRequiresActualProtectedInvocation(t *testing.T) {
	for _, ctx := range []context.Context{nil, context.Background()} {
		if err := mfapg.InitializeSignup(ctx, kernel.Work{}, nil, identity.Command{}, "user"); err == nil {
			t.Fatal("factor absence initialized outside genuine account creation")
		}
		s, err := mfapg.RequireEmailRecovery(ctx, kernel.Work{}, nil, identity.Command{}, "user", 0)
		if err == nil || s.Version() != 0 {
			t.Fatal("unknown factor state admitted outside protected reset")
		}
		s, err = mfapg.RequireEmailRecoveryPreparation(ctx, kernel.Work{}, nil, identity.Command{}, "user", 1)
		if err == nil || s.Version() != 0 {
			t.Fatal("factor preparation admitted an unscoped invocation")
		}
	}
}
