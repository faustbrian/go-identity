package postgres

import (
	"bytes"
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// ApplyAccountUnlink applies the closed typed unlink transition only through
// this exact enlisted repository's generation-bound Work. Its result remains
// provisional: only Coordinator.Commit can acknowledge durability. Native
// credential/factor/session policy, proof consumption and encrypted provider
// token cleanup must be supplied by the actual registered unlink owner, never
// by a caller-authored eligibility projection. No provider network call runs.
// Repeated, mixed, foreign or changed intent poisons Work and returns no result.
// This method does not independently enable the profile in Coordinator.Begin.
func (r *Repository) ApplyAccountUnlink(ctx context.Context, w Work, command identity.Command) (identity.CommandResult, error) {
	zero := identity.CommandResult{}
	if r == nil || r.read == nil || ctx == nil {
		return zero, invalidWork()
	}
	if err := w.usable(); err != nil {
		return zero, err
	}
	fail := func(err error) (identity.CommandResult, error) { return zero, w.fail(w.state.ctx, err) }
	if w.state.execution == nil || w.state.accountUnlink != nil || w.state.accountLink != nil || w.state.creation != nil || w.state.profile != nil || w.state.update != nil || w.state.status != nil || w.state.identifier != nil || w.state.feature != nil {
		return fail(invalidWork())
	}
	c := w.state.execution.coordinator
	reservation := w.state.execution.reservation
	if !c.owns(w) || reservation.plan == nil || reservation.plan.accountUnlink == nil || reservation.plan.belongsTo(c.registry) != nil || w.state.generation == 0 {
		return fail(invalidWork())
	}
	p := reservation.plan
	spec, _, ok := command.AccountUnlinkCounterCommand()
	if !ok || spec.Binding != w.state.binding || len(p.contributors) != 6 || p.contributors[0].contributor != r || p.capability == nil || spec.RevokeProvider {
		return fail(invalidWork())
	}
	q, err := prepareClaim(command, c.keys.retained[c.keys.current])
	expected, expectedErr := accountUnlinkExecutionRequest(reservation)
	if err != nil || expectedErr != nil || !bytes.Equal(q.canonical, expected.canonical) {
		return fail(identity.ConflictError{})
	}
	owner := p.accountUnlink.contributor.(AccountUnlinkContributor)
	if err := validateAccountUnlink(owner, command, p.snapshot()); err != nil {
		return fail(err)
	}
	if _, err := c.runAccountUnlinkPhase(ctx, w, command, accountUnlinkCheck, nil); err != nil {
		return zero, err
	}
	if err := c.checkCommandCounters(ctx, w, command); err != nil {
		return zero, err
	}
	state, _, err := lockAccountUnlinkState(ctx, w, spec.Change)
	if err != nil {
		return zero, err
	}
	state.Access.Methods, err = c.runAccountUnlinkPhase(ctx, w, command, accountUnlinkEligibility, state.Access.Methods)
	if err != nil {
		return zero, err
	}
	// Eligibility can wait on another owner. Check expiry with primary time
	// after that wait, not with the earlier snapshot-lock clock sample.
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return zero, err
	}
	if !accountUnlinkProofCurrent(spec, now) {
		return fail(identity.ForbiddenError{})
	}
	next, err := identity.ApplyAccountUnlink(state, spec.Change, now)
	if err != nil {
		return fail(err)
	}
	if err := c.runCapabilityExecution(ctx, w, false); err != nil {
		return zero, err
	}
	if _, err := c.runAccountUnlinkPhase(ctx, w, command, accountUnlinkPersist, nil); err != nil {
		return zero, err
	}
	if err := persistAccountUnlinkMutation(ctx, w, spec.Change, next); err != nil {
		return zero, err
	}
	progress := w.state.accountUnlink
	progress.user = next.Access.User
	progress.receipt = identity.AccountUnlinkReceipt{AccountID: next.Removed.ID,
		ExpectedAccountVersion: spec.Change.ExpectedAccountVersion, ExpectedSocialLinkVersion: spec.Change.ExpectedSocialLinkVersion,
		ExpectedCredentialVersion: spec.Change.ExpectedCredentialVersion, TombstoneVersion: next.TombstoneVersion,
		SocialLinkVersion: next.SocialLinkVersion, CredentialVersion: next.CredentialVersion,
		InvalidatesCredential: next.InvalidatesCredential, ProviderOutcome: identity.ProviderRevocationNotRequested}
	progress.stage = accountUnlinkApplied
	original := command
	w.state.counterCommand = &original
	records, err := accountUnlinkMutationAudits(ctx, p, now, "committed")
	if err != nil {
		return fail(err)
	}
	for i, record := range records {
		if err := w.StageAudit(p.audits[i].EventIndex, record); err != nil {
			return zero, err
		}
	}
	if err := w.StageLifecycle(p.lifecycle.EventIndex, now); err != nil {
		return zero, err
	}
	receipt := progress.receipt
	result := identity.CommandResult{Binding: spec.Binding, Outcome: identity.CommitOutcomeCommitted,
		User: progress.user, ExpectedVersion: spec.Change.ExpectedUserVersion, Unlink: &receipt, AuditEventID: records[0].ID()}
	if result.Validate() != nil {
		return fail(invalidWork())
	}
	return result, nil
}

func accountUnlinkProofCurrent(spec identity.AccountUnlinkCommand, now time.Time) bool {
	proof := spec.Proof.Payload()
	return !now.IsZero() && !now.Before(proof.IssuedAt) && !now.Before(proof.NotBefore) && now.Before(proof.ExpiresAt)
}

func matchesAccountUnlinkResult(w Work, result identity.CommandResult) bool {
	owned := w.state.accountUnlink
	if owned == nil || owned.stage != accountUnlinkApplied || owned.active {
		return false
	}
	if w.state.accountLink != nil || w.state.creation != nil || w.state.profile != nil || w.state.update != nil || w.state.status != nil || w.state.identifier != nil || w.state.feature != nil {
		return false
	}
	if result.Binding != w.state.binding || result.User != owned.user || owned.user.Version <= 1 {
		return false
	}
	return result.Unlink != nil && *result.Unlink == owned.receipt && result.ExpectedVersion == owned.user.Version-1
}
