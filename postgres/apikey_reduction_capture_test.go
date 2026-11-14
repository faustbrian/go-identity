package postgres

import (
	"context"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestAPIKeyPermissionReductionCaptureRejectsZeroOwner(t *testing.T) {
	for _, owner := range []*Coordinator{nil, {}} {
		for _, ctx := range []context.Context{nil, context.Background()} {
			result, fingerprint, err := owner.ExecutePreparedAPIKeyPermissionReduction(ctx, identity.Command{}, CommandPlan{})
			if err == nil || result != (identity.CommandResult{}) || fingerprint != ([32]byte{}) {
				t.Fatal("unowned reduction minted recovery commitment")
			}
		}
	}
}
