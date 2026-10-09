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

func TestPreparationFinalDeclarationConservesCounterScope(t *testing.T) {
	_, _, plan := featurePlanFixture(t)
	plan.SubjectType = "session"
	plan.CommandCounters = &CommandCounterPlan{PolicyVersion: 3, Fingerprint: [32]byte{3}}
	if !preparationFinalDeclaration(plan, plan) {
		t.Fatal("matching counter declaration rejected")
	}
	for _, change := range []func(*CommandPlan){
		func(p *CommandPlan) { p.CommandCounters = nil },
		func(p *CommandPlan) { p.CommandCounters.PolicyVersion++ },
		func(p *CommandPlan) { p.CommandCounters.Fingerprint[0]++ },
		func(p *CommandPlan) { p.RiskEvidence = &RiskEvidencePlan{} },
		func(p *CommandPlan) { p.OTP = &OTPAttemptPlan{} },
	} {
		final := plan
		counter := *plan.CommandCounters
		final.CommandCounters = &counter
		change(&final)
		if preparationFinalDeclaration(plan, final) {
			t.Fatal("final plan changed protected scope")
		}
	}
	without := plan
	without.CommandCounters = nil
	if preparationFinalDeclaration(without, plan) {
		t.Fatal("generated plan introduced an uncharged counter")
	}
}
