package postgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

// This result exists only after the coordinator acknowledges the transaction
// containing both the failure audit and terminal receipt. It is not a
// participant error or evidence about an uncertain commit.
type preparationAttachmentDenied struct{ result identity.CommandResult }

func (preparationAttachmentDenied) Error() string { return "preparation attachment denied" }

// The caller has proved there was no previous final attachment and rolled back
// every provisional reservation in its savepoint. Nothing from this command
// reached domain execution, and no participant release is authorized or needed.
func (c *Coordinator) denyPreparationAttachment(ctx context.Context, tx pgx.Tx, q claimRequest, p *admittedKernelPlan, j journalReservation, owner [16]byte) (identity.CommandResult, error) {
	fence, err := beginJournal(ctx, tx, q, c.keys, j, owner)
	if err != nil {
		return identity.CommandResult{}, err
	}
	w, err := newWork(ctx, tx, p.binding, q, fence)
	if err != nil {
		return identity.CommandResult{}, err
	}
	defer invalidateWork(w)
	w.state.registry = c.registry.state
	w.state.execution = &domainExecution{coordinator: c, reservation: &reservationState{coordinator: c, request: q, plan: p, journal: j, owner: owner}, ctx: ctx}
	if err := p.bindWork(w); err != nil {
		return identity.CommandResult{}, err
	}
	if err := configureKernelWork(ctx, w); err != nil {
		return identity.CommandResult{}, err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return identity.CommandResult{}, err
	}
	records, err := featureMutationAudits(ctx, p, now, "conflict")
	if err != nil {
		return identity.CommandResult{}, err
	}
	for i, record := range records {
		if err := w.StageAudit(p.audits[i].EventIndex, record); err != nil {
			return identity.CommandResult{}, err
		}
	}
	if err := c.persistAuditPhase(w); err != nil {
		return identity.CommandResult{}, err
	}
	if w.state.rows != nil || w.usable() != nil {
		return identity.CommandResult{}, invalidWork()
	}
	result := featureOutcome(p.binding, q.feature, identity.CommitOutcomeNotCommitted, 0)
	if err := terminalizeJournal(ctx, tx, q, j, owner, result, "conflict"); err != nil {
		return identity.CommandResult{}, err
	}
	return result, nil
}
