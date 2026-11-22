package postgres

import (
	"bytes"
	"context"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

// SSOOIDCPreparationRefusalContributor is limited to the exact registered
// enterprise OIDC callback owner. Restore authenticates the original command
// and generation's fresh encrypted refusal outside Work, without exchange or
// renewing authority. It returns false only for non-refusal output. Cleanup
// runs in fenced Work with FeatureScope to erase the original RP custody. It
// cannot apply a sign-in, consume state, issue credentials or close Work.
type SSOOIDCPreparationRefusalContributor interface {
	FeatureAdmissionPreparationContributor
	RestoreSSOOIDCPreparationRefusal(context.Context, identity.Command, uint64, []byte) (bool, error)
	CleanupSSOOIDCPreparationRefusal(context.Context, Work) error
}

// SSOOAuth2PreparationRefusalContributor is limited to the exact registered
// enterprise OAuth 2.0 callback owner. Restore authenticates the original
// command and fresh generation's encrypted output outside Work and returns
// false only for non-refusal output. It must not exchange, perform I/O or renew
// authority. Cleanup borrows fenced Work with FeatureScope to erase the original
// RP custody, never to apply sign-in, consume state, issue credentials or close
// Work. Cleanup, denial audit, original one-use reservation release and terminal
// receipt commit together; errors preserve an unknown outcome without retrying
// external work. Both methods obey cancellation and use invocation-local state.
type SSOOAuth2PreparationRefusalContributor interface {
	FeatureAdmissionPreparationContributor
	RestoreSSOOAuth2PreparationRefusal(context.Context, identity.Command, uint64, []byte) (bool, error)
	CleanupSSOOAuth2PreparationRefusal(context.Context, Work) error
}

func (c *Coordinator) finishSSOPreparationRefusal(ctx context.Context, original identity.Command, q claimRequest, plan *admittedKernelPlan, journal journalReservation, owner [16]byte, participant FeaturePreparationContributor, wire []byte) (identity.CommandResult, bool, error) {
	binding := plan.binding
	unknown := func() (identity.CommandResult, bool, error) {
		return featureOutcome(binding, q.feature, identity.CommitOutcomeUnknown, 0), true, identity.UnknownCommitError{CommandID: binding.CommandID}
	}
	var restore func(context.Context, identity.Command, uint64, []byte) (bool, error)
	var cleanup func(context.Context, Work) error
	var descriptor ContributorDescriptor
	switch {
	case ssoOIDCCallbackClaim(q):
		refusalOwner, ok := participant.(SSOOIDCPreparationRefusalContributor)
		if !ok {
			return identity.CommandResult{}, false, nil
		}
		restore = refusalOwner.RestoreSSOOIDCPreparationRefusal
		cleanup = refusalOwner.CleanupSSOOIDCPreparationRefusal
		descriptor = ssoOIDCSigninDescriptor()
	case ssoOAuth2CallbackClaim(q):
		refusalOwner, ok := participant.(SSOOAuth2PreparationRefusalContributor)
		if !ok {
			return identity.CommandResult{}, false, nil
		}
		restore = refusalOwner.RestoreSSOOAuth2PreparationRefusal
		cleanup = refusalOwner.CleanupSSOOAuth2PreparationRefusal
		descriptor = ssoOAuth2SigninDescriptor()
	default:
		return identity.CommandResult{}, false, nil
	}
	if plan.feature == nil || plan.feature.Contributor != descriptor || plan.feature.Operation != *q.feature || !providerSigninPreparation(plan.snapshot()) {
		return unknown()
	}
	entry, err := c.registry.selectFeatureOperation(*plan.feature)
	if err != nil || !sameParticipant(entry.contributor, participant) {
		return unknown()
	}
	refused, err := restore(ctx, original, journal.generation, bytes.Clone(wire))
	if err != nil || ctx.Err() != nil {
		return unknown()
	}
	if !refused {
		return identity.CommandResult{}, false, nil
	}

	tx, err := c.pool.Raw().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return unknown()
	}
	defer rollbackPreparation(tx)
	fence, err := beginJournal(ctx, tx, q, c.keys, journal, owner)
	if err != nil {
		return unknown()
	}
	// This verifies the exact started generation and no final attachment. Do
	// not commit this checkpoint separately: otherwise a crash would strand a
	// known refusal after the original capability expires and cannot rebind.
	if err := retainJournalPreparation(ctx, tx, q, journal, owner, wire); err != nil {
		return unknown()
	}
	plan, err = c.freezePreparationDeclaration(ctx, tx, q, plan, original)
	if err != nil {
		return unknown()
	}
	w, err := newWork(ctx, tx, binding, q, fence)
	if err != nil {
		return unknown()
	}
	defer invalidateWork(w)
	w.state.registry = c.registry.state
	w.state.execution = &domainExecution{coordinator: c, reservation: &reservationState{coordinator: c, request: q, plan: plan, journal: journal, owner: owner}, ctx: ctx}
	if err := plan.bindWork(w); err != nil {
		return unknown()
	}
	if err := configureKernelWork(ctx, w); err != nil {
		return unknown()
	}
	if err := c.auditSSOPreparationRefusal(ctx, w, plan); err != nil {
		return unknown()
	}
	w.state.featureInvocation = participant
	err = cleanup(ctx, w)
	w.state.featureInvocation = nil
	if err != nil {
		return unknown()
	}
	// No final attachment under these locks means no domain Begin could have
	// run. Release only the original reserved generation, never a fresh grant.
	if err := c.releaseCapabilityAfterRollback(ctx, w, plan, journal); err != nil {
		return unknown()
	}
	if w.usable() != nil || w.state.rows != nil {
		return unknown()
	}
	result := featureOutcome(binding, q.feature, identity.CommitOutcomeNotCommitted, 0)
	if err := terminalizeJournal(w.state.ctx, tx, q, journal, owner, result, "denied"); err != nil {
		return unknown()
	}
	if err := c.commitPreparation(w.state.ctx, tx); err != nil {
		return unknown()
	}
	return result, true, identity.ForbiddenError{}
}

func (c *Coordinator) auditSSOPreparationRefusal(ctx context.Context, w Work, plan *admittedKernelPlan) error {
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	records, err := featureMutationAudits(ctx, plan, now, "denied")
	if err != nil {
		return err
	}
	for i, record := range records {
		if err := w.StageAudit(plan.audits[i].EventIndex, record); err != nil {
			return err
		}
	}
	return c.persistAuditPhase(w)
}
