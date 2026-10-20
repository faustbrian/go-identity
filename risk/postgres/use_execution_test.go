package postgres

import (
	"context"
	"testing"

	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

func TestNativeRiskExecutionRejectsUnownedHandles(t *testing.T) {
	r, _, _, _ := completionUseFixture(t)
	for _, repository := range []*Repository{nil, {}, r} {
		participant, ok := any(repository).(identitypostgres.RiskExecutionContributor)
		if !ok {
			t.Fatal("native risk owner cannot execute all consuming phases")
		}
		for _, ctx := range []context.Context{nil, context.Background()} {
			if err := participant.CheckRiskEvidence(ctx, identitypostgres.RiskApplyWork{}); err == nil {
				t.Fatal("unowned risk apply authority accepted")
			}
			if err := participant.FinalizeRiskEvidence(ctx, identitypostgres.RiskFinalizeWork{}); err == nil {
				t.Fatal("unowned risk finalize authority accepted")
			}
		}
	}
}
