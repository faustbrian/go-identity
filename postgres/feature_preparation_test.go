package postgres

import (
	"context"
	identity "github.com/faustbrian/go-identity"
	"testing"
)

func TestPreparedFeatureRejectsUnownedInputs(t *testing.T) {
	for _, c := range []*Coordinator{nil, {}} {
		for _, ctx := range []context.Context{nil, context.Background()} {
			result, err := c.ExecutePreparedFeature(ctx, identity.Command{}, CommandPlan{})
			if err == nil || result.Outcome != identity.CommitOutcomeInvalid {
				t.Fatal("unowned preparation executed")
			}
		}
	}
}
