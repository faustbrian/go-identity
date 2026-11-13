package mfapostgres

import (
	"context"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestOAuthSigninFactorsRejectUnownedInvocation(t *testing.T) {
	for _, ctx := range []context.Context{nil, context.Background()} {
		if state, err := ReadOAuthSigninFactors(ctx, nil, "tenant", "user", time.Second); err == nil || state.Version() != 0 {
			t.Fatal("missing primary inferred no enrolled factors")
		}
		if state, err := RequireOAuthSigninFactors(ctx, kernel.Work{}, nil, identity.Command{}, 1); err == nil || state.Version() != 0 {
			t.Fatal("unowned callback supplied factor authority")
		}
	}
}
