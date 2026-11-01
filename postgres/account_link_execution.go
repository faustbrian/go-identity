package postgres

import (
	"bytes"
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// The only account writer remains the kernel. Native provider effects and
// one-use consumption are provisional in this same original transaction.
func (r *Repository) applyAccountLink(ctx context.Context, w Work, command identity.Command) (identity.CommandResult, error) {
	fail := func(err error) (identity.CommandResult, error) {
		return identity.CommandResult{}, w.fail(w.state.ctx, err)
	}
	if err := w.usable(); err != nil {
		return identity.CommandResult{}, err
	}
	if ctx == nil || r == nil || r.read == nil || w.state.execution == nil || w.state.accountLink != nil || w.state.creation != nil || w.state.profile != nil || w.state.update != nil || w.state.status != nil || w.state.identifier != nil || w.state.feature != nil {
		return fail(invalidWork())
	}
	c := w.state.execution.coordinator
	reservation := w.state.execution.reservation
	if !c.owns(w) || reservation.plan == nil || reservation.plan.accountLink == nil || reservation.plan.belongsTo(c.registry) != nil || w.state.generation == 0 {
		return fail(invalidWork())
	}
	p := reservation.plan
	spec, _, ok := command.AccountLinkCounterCommand()
	if !ok || spec.Binding != w.state.binding || len(p.contributors) != 6 || p.contributors[0].contributor != r {
		return fail(invalidWork())
	}
	q, err := prepareClaim(command, c.keys.retained[c.keys.current])
	if err != nil || !bytes.Equal(q.canonical, reservation.request.canonical) {
		return fail(identity.ConflictError{})
	}
	if err = validateAccountLink(p.accountLink.contributor.(AccountLinkContributor), command, p.snapshot()); err != nil {
		return fail(err)
	}
	if err = c.runAccountLinkPhase(ctx, w, command, accountLinkCheck); err != nil {
		return identity.CommandResult{}, err
	}
	if err = c.checkCommandCounters(ctx, w, command); err != nil {
		return identity.CommandResult{}, err
	}
	state, now, err := lockAccountLinkState(ctx, w, spec.Change)
	if err != nil {
		return identity.CommandResult{}, err
	}
	if !accountLinkProofCurrent(spec, now) {
		return fail(identity.ForbiddenError{})
	}
	mutation, err := identity.ApplyAccountLink(state, spec.Change, now)
	if err != nil {
		return fail(err)
	}
	if err = c.runCapabilityExecution(ctx, w, false); err != nil {
		return identity.CommandResult{}, err
	}
	if err = c.runAccountLinkPhase(ctx, w, command, accountLinkPersist); err != nil {
		return identity.CommandResult{}, err
	}
	if err = persistAccountLinkMutation(ctx, w, spec.Change, mutation); err != nil {
		return identity.CommandResult{}, err
	}
	progress := w.state.accountLink
	progress.user = mutation.Access.User
	progress.receipt = identity.AccountLinkReceipt{AccountID: mutation.Account.ID, Mode: spec.Change.Mode,
		ExpectedAccountVersion: spec.Change.ExpectedAccountVersion, ExpectedSocialLinkVersion: spec.Change.ExpectedSocialLinkVersion,
		ExpectedCredentialVersion: spec.Change.ExpectedCredentialVersion, AccountVersion: mutation.Account.Version,
		SocialLinkVersion: mutation.SocialLinkVersion, CredentialVersion: mutation.CredentialVersion, AddsCredential: mutation.AddsCredential}
	progress.applied = true
	original := command
	w.state.counterCommand = &original
	record, err := kernelMutationAudit(ctx, spec.Binding, spec.Change.ExpectedAccountVersion, now, "committed")
	if err != nil {
		return fail(err)
	}
	if err = w.StageAudit(p.audits[0].EventIndex, record); err != nil {
		return identity.CommandResult{}, err
	}
	if err = w.StageLifecycle(p.lifecycle.EventIndex, now); err != nil {
		return identity.CommandResult{}, err
	}
	receipt := progress.receipt
	result := identity.CommandResult{Binding: spec.Binding, Outcome: identity.CommitOutcomeCommitted, User: progress.user, ExpectedVersion: spec.Change.ExpectedUserVersion, Link: &receipt, AuditEventID: record.ID()}
	if result.Validate() != nil {
		return fail(invalidWork())
	}
	return result, nil
}

func accountLinkProofCurrent(spec identity.AccountLinkCommand, now time.Time) bool {
	proof := spec.Proof.Payload()
	return !now.IsZero() && !now.Before(proof.IssuedAt) && !now.Before(proof.NotBefore) && now.Before(proof.ExpiresAt)
}

func (c *Coordinator) finalizeAccountLink(w Work) error {
	if !c.owns(w) {
		return invalidWork()
	}
	p := w.state.execution.reservation.plan
	if p.accountLink == nil {
		return nil
	}
	progress := w.state.accountLink
	if progress == nil || !progress.initial || !progress.persisted || !progress.applied || progress.final || progress.finalized {
		return w.fail(w.state.ctx, invalidWork())
	}
	if err := c.runAccountLinkPhase(w.state.ctx, w, progress.command, accountLinkFinalCheck); err != nil {
		return err
	}
	if err := c.runAccountLinkPhase(w.state.ctx, w, progress.command, accountLinkFinalize); err != nil {
		return err
	}
	if err := c.runCapabilityExecution(w.state.ctx, w, true); err != nil {
		return err
	}
	// Provider/capability finalization may wait past the original counter
	// evidence interval. Recheck that same charge after these effects, never
	// replace it with a new preparation timestamp or another allowance.
	if err := c.checkCommandCounters(w.state.ctx, w, progress.command); err != nil {
		return err
	}
	spec, _, ok := progress.command.AccountLinkCounterCommand()
	now, err := w.DatabaseTime(w.state.ctx)
	if err != nil {
		return err
	}
	if !ok || !accountLinkProofCurrent(spec, now) {
		return w.fail(w.state.ctx, identity.ForbiddenError{})
	}
	return nil
}

// A pending journal is never reconstructed as successful from current rows.
// Only absence for a new record or its unchanged unlink tombstone supplies
// negative domain evidence; every other participant must independently agree.
func recoverAccountLink(ctx context.Context, h RecoveryWork) (RecoveryStatus, error) {
	b, err := h.Scope()
	if err != nil || h.state.plan.lifecycle == nil || !accountLinkBinding(b) {
		return RecoveryUnknown, invalidWork()
	}
	before := h.state.plan.lifecycle.BeforeVersion
	rows, err := h.Query(ctx, `SELECT EXISTS(SELECT 1 FROM identity.accounts WHERE tenant_id=$1 AND account_id=$2),
EXISTS(SELECT 1 FROM identity.accounts WHERE tenant_id=$1 AND account_id=$2 AND user_id=$3 AND version=$4::numeric AND NOT linked)`, string(b.TenantID), b.RecordID, string(b.UserID), before)
	if err != nil {
		return RecoveryUnknown, err
	}
	defer rows.Close()
	var exists, unchanged bool
	if !rows.Next() || rows.Scan(&exists, &unchanged) != nil || rows.Next() || rows.Err() != nil {
		return RecoveryUnknown, identity.UnavailableError{}
	}
	if before == 0 && !exists || before > 0 && exists && unchanged {
		return RecoveryNotCommitted, nil
	}
	return RecoveryUnknown, nil
}
