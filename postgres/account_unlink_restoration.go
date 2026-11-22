package postgres

import (
	"bytes"
	"slices"

	identity "github.com/faustbrian/go-identity"
)

// Only the authenticated child declaration may be added. Original owner,
// lifecycle, audit and counter policy stay frozen through the same codec used
// by the journal. Digest itself is derived, not a competing authority.
func sameAccountUnlinkDeclaration(b identity.CommandBinding, original, final CommandPlan) bool {
	if original.Capability != nil || final.Capability == nil || original.AccountLinkState != nil || final.AccountLinkState != nil {
		return false
	}
	final.Capability = nil
	fp := [32]byte{1}
	before, err := encodeKernelPlan(b, fp, original)
	after, other := encodeKernelPlan(b, fp, final)
	return err == nil && other == nil && bytes.Equal(before, after)
}

// Restore authenticates the original owner's encrypted output before reaching
// this structural attachment check. The generated command gets its own keyed
// execution claim, never replaces the original journal claim, and cannot widen
// the original password authority interval or change protected intent/counters.
// Current password/session/factor/risk checks still run in the final mutation.
func (c *Coordinator) prepareRestoredAccountUnlink(original, generated identity.Command, declaration, final CommandPlan) (claimRequest, CommandPlan, error) {
	fail := func() (claimRequest, CommandPlan, error) {
		return claimRequest{}, CommandPlan{}, invalidPreparation()
	}
	_, admitted, _, err := c.prepareAccountUnlinkPreparation(original, declaration)
	if err != nil {
		return fail()
	}
	input, _, _ := original.AccountUnlinkPreparationInput()
	if !sameAccountUnlinkRestoredIntent(original, generated) || !sameAccountUnlinkDeclaration(input.Binding, admitted.snapshot(), final) {
		return fail()
	}
	q, owned, _, err := c.prepareAccountUnlink(input.Binding, generated, final)
	if err != nil {
		return fail()
	}
	return q, owned, nil
}

func sameAccountUnlinkRestoredIntent(original, generated identity.Command) bool {
	input, _, ok := original.AccountUnlinkPreparationInput()
	spec, counters, issued := generated.AccountUnlinkCounterCommand()
	if !ok || !issued || spec.Binding != input.Binding || spec.Change != input.Change || spec.SessionID != input.SessionID || spec.SessionVersion != input.SessionVersion || spec.RevokeProvider != input.RevokeProvider {
		return false
	}
	if counters.Network != input.Counters.Network || !counters.PreparedAt.Equal(input.Counters.PreparedAt) || !slices.Equal(counters.KeyVersions, input.Counters.KeyVersions) {
		return false
	}
	proof := spec.Proof.Payload()
	primary := input.Primary.Proof
	return !proof.IssuedAt.Before(primary.IssuedAt) && !proof.ExpiresAt.After(primary.ExpiresAt)
}

// Original journal identity and generated execution intent are deliberately
// different. Only a retained, issuer-attached unlink can select the second
// claim; absent or inconsistent custody must not fall back to original metadata.
func accountUnlinkExecutionRequest(r *reservationState) (claimRequest, error) {
	if r == nil || r.plan == nil || r.plan.accountUnlink == nil || r.plan.capability == nil || r.request.source == nil {
		return claimRequest{}, invalidPreparation()
	}
	if r.executionRequest == nil {
		_, _, issued := r.request.source.AccountUnlinkCounterCommand()
		if !issued || r.preparation != nil {
			return claimRequest{}, invalidPreparation()
		}
		return r.request, nil
	}
	if r.preparation == nil || r.preparation.generation == 0 || r.preparation.generation > r.journal.generation || len(r.preparation.ciphertext) == 0 || len(r.preparation.ciphertext) > maximumPreparationCiphertext || r.executionRequest.source == nil {
		return claimRequest{}, invalidPreparation()
	}
	if _, ok := r.plan.accountUnlink.contributor.(AccountUnlinkPreparationContributor); !ok {
		return claimRequest{}, invalidPreparation()
	}
	original, generated := *r.request.source, *r.executionRequest.source
	spec, _, _ := generated.AccountUnlinkCounterCommand()
	if !sameAccountUnlinkRestoredIntent(original, generated) || spec.Binding != r.plan.binding || !accountUnlinkProofPlan(spec, r.plan.snapshot()) {
		return claimRequest{}, invalidPreparation()
	}
	if !bytes.Equal(r.request.safeFields, r.executionRequest.safeFields) || bytes.Equal(r.request.canonical, r.executionRequest.canonical) {
		return claimRequest{}, invalidPreparation()
	}
	return *r.executionRequest, nil
}
