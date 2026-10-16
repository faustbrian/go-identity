package mfapostgres

import (
	"context"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestVerificationSigninAuthorityRequiresPrimaryAndExactInvocation(t *testing.T) {
	for _, ctx := range []context.Context{nil, context.Background()} {
		if _, err := ReadEmailVerificationSigninFactors(ctx, nil, "tenant", "user", time.Second); err == nil {
			t.Fatal("missing primary inferred no MFA")
		}
		if _, err := RequireEmailVerificationSigninFactors(ctx, kernel.Work{}, nil, identity.Command{}, 1); err == nil {
			t.Fatal("missing protected invocation supplied factor admission")
		}
	}
}
