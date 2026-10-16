package mfapostgres

import (
	"context"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestEmailOTPAuthorityRejectsMissingPrimaryAndInvocation(t *testing.T) {
	for _, ctx := range []context.Context{nil, context.Background()} {
		if _, err := ReadEmailOTPFactors(ctx, nil, "tenant", "user", time.Second); err == nil {
			t.Fatal("missing native primary inferred empty MFA")
		}
		if _, err := RequireEmailOTPFactors(ctx, kernel.Work{}, nil, identity.Command{}, 1); err == nil {
			t.Fatal("missing exact owner invocation supplied factor admission")
		}
	}
}
