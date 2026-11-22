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

func (c *Coordinator) finishSSOOIDCPreparationRefusal(ctx context.Context, original identity.Command, q claimRequest, plan *admittedKernelPlan, journal journalReservation, owner [16]byte, participant SSOOIDCPreparationRefusalContributor, wire []byte) (identity.CommandResult, bool, error) {
	binding := plan.binding
	unknown := func() (identity.CommandResult, bool, error) {
		return featureOutcome(binding, q.feature, identity.CommitOutcomeUnknown, 0), true, identity.UnknownCommitError{CommandID: binding.CommandID}
	}
	refused, err := participant.RestoreSSOOIDCPreparationRefusal(ctx, original, journal.generation, bytes.Clone(wire))
	if err != nil || ctx.Err() != nil {
		return unknown()
	}
	if !refused {
		return identity.CommandResult{}, false, nil
	}
	if plan.feature == nil || plan.feature.Contributor != ssoOIDCSigninDescriptor() || plan.capability == nil || !ssoOIDCCallbackClaim(q) {
		return unknown()
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
	if err := c.auditSSOOIDCRefusal(ctx, w, plan); err != nil {
		return unknown()
	}
	w.state.featureInvocation = participant
	err = participant.CleanupSSOOIDCPreparationRefusal(ctx, w)
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

func (c *Coordinator) auditSSOOIDCRefusal(ctx context.Context, w Work, plan *admittedKernelPlan) error {
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
