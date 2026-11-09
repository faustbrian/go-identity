package postgres

import (
	"context"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestAccountLinkRecoveryScopeRequiresAttachedPlanAndExactInvocationOwner(t *testing.T) {
	for _, mode := range []string{"attached", "unattached", "ordinary", "foreign-owner", "foreign-entry", "returned", "closed"} {
		t.Run(mode, func(t *testing.T) {
			_, work, _ := accountLinkStateExecutionFixture(t)
			plan := work.state.execution.reservation.plan
			owner := plan.accountLink.contributor.(AccountLinkContributor)
			state := &recoveryWorkState{work: work, plan: plan, entry: *plan.accountLink, active: true}
			input := owner
			switch mode {
			case "unattached":
				plan.capability = nil
			case "ordinary":
				plan.accountLinkState = nil
			case "foreign-owner":
				input = &accountLinkOwnerProbe{}
			case "foreign-entry":
				state.entry = plan.contributors[1]
			case "returned":
				state.active = false
			case "closed":
				work.state.closed = true
			}
			h := RecoveryWork{state: state}
			binding, original, final, err := h.AccountLinkScope(input)
			if mode != "attached" {
				if err == nil || binding != (identity.CommandBinding{}) || original != (CapabilityPlan{}) || final != (CapabilityPlan{}) {
					t.Fatal("incomplete or foreign invocation disclosed attached metadata")
				}
				return
			}
			if err != nil || binding != work.state.binding || original != *plan.accountLinkState || final != *plan.capability {
				t.Fatal("exact owner lost original attached metadata", err)
			}
			original.ReplayDigest[0]++
			final.ProofFingerprint[0]++
			_, again, attached, err := h.AccountLinkScope(owner)
			if err != nil || again != *plan.accountLinkState || attached != *plan.capability {
				t.Fatal("returned metadata aliases the admitted plan")
			}
			state.active = false
			if _, _, _, err := h.AccountLinkScope(owner); err == nil {
				t.Fatal("returned invocation retained metadata access")
			}
		})
	}
	if _, _, _, err := (RecoveryWork{}).AccountLinkScope(nil); err == nil {
		t.Fatal("zero recovery handle exposed attached metadata")
	}
}

func TestAccountLinkCleanupScopeRequiresExactInvocationOwner(t *testing.T) {
	for _, mode := range []string{"original-owner", "foreign-owner", "returned", "closed"} {
		t.Run(mode, func(t *testing.T) {
			_, work, _ := accountLinkStateExecutionFixture(t)
			owner := &accountLinkCleanupScopeProbe{}
			state := &accountLinkCleanupInvocation{work: work, owner: owner, binding: work.state.binding, state: *work.state.execution.reservation.plan.accountLinkState, active: true}
			var input AccountLinkCleanupContributor = owner
			switch mode {
			case "foreign-owner":
				input = &accountLinkCleanupScopeProbe{}
			case "returned":
				state.active = false
			case "closed":
				work.state.closed = true
			}
			h := AccountLinkCleanupWork{state: state}
			binding, original, err := h.Scope(input)
			if mode != "original-owner" {
				if err == nil || binding != (identity.CommandBinding{}) || original != (CapabilityPlan{}) {
					t.Fatal("foreign/returned cleanup handle exposed custody")
				}
				return
			}
			if err != nil || binding != work.state.binding || original != state.state {
				t.Fatal("historical cleanup required callback or current proof custody", err)
			}
			state.active = false
			if _, _, err := h.Scope(owner); err == nil {
				t.Fatal("returned cleanup scope retained access")
			}
		})
	}
}

type accountLinkCleanupScopeProbe struct{ preparedAccountLinkOwnerProbe }

func (*accountLinkCleanupScopeProbe) CleanupAccountLink(context.Context, AccountLinkCleanupWork) error {
	return nil
}
