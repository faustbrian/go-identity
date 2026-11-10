package postgres

import (
	"context"
	"testing"
)

// This is an invocation-state test, not proof of durable capability consumption
// or complete OAuth signin. The native consumer must prove those real owners.
func TestOAuthSigninConsumptionRequiresProtectedConsumedInvocation(t *testing.T) {
	b, plan := oauthSigninConsumptionPlanFixture(t)
	owner := &oauthSigninAccountParticipant{}
	for _, mode := range []string{"current", "not-consumed", "finalized", "returned", "not-apply", "foreign-owner", "missing-proof", "closed"} {
		t.Run(mode, func(t *testing.T) {
			frozen := &admittedKernelPlan{binding: b, feature: plan.Feature, lifecycle: plan.Lifecycle, fingerprint: [32]byte{7}, capability: plan.Capability}
			reservation := &reservationState{plan: frozen, journal: journalReservation{generation: 1}}
			w := Work{state: &workState{ctx: context.Background(), binding: b, generation: 1, feature: plan.Feature, lifecycle: &workLifecycle{plan: *plan.Lifecycle}, featureInvocation: owner, featureApplying: true, oauthSigninStage: oauthSigninStateConsumed, execution: &domainExecution{reservation: reservation}}}
			candidate := owner
			switch mode {
			case "not-consumed":
				w.state.oauthSigninStage = oauthSigninStateAbsent
			case "finalized":
				w.state.oauthSigninStage = oauthSigninStateFinalized
			case "returned":
				w.state.featureInvocation = nil
			case "not-apply":
				w.state.featureApplying = false
			case "foreign-owner":
				candidate = &oauthSigninAccountParticipant{}
			case "missing-proof":
				frozen.capability = nil
			case "closed":
				w.state.closed = true
			}
			got, err := w.OAuthSigninConsumption(candidate)
			if mode != "current" {
				if err == nil || got != (CapabilityReservationBinding{}) {
					t.Fatal("unowned phase acquired consumed callback state")
				}
				return
			}
			if err != nil || got.Command != b || got.Plan != *plan.Capability || got.Generation != 1 || got.Fingerprint != ([32]byte{7}) {
				t.Fatal("original consumed state lost", err)
			}
			got.Plan.ReplayDigest[0]++
			if *frozen.capability != *plan.Capability {
				t.Fatal("returned copy changed original proof")
			}
		})
	}
}
