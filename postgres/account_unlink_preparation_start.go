package postgres

import (
	"context"
	"errors"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

// The existing journal and protected counter owner atomically acknowledge the
// original unlink start. No issuer or password consumption runs in this phase.
// Generation remains outside SQL and requires the returned acknowledged owner;
// even a committed start with a lost acknowledgement grants no such custody.
func (c *Coordinator) startAccountUnlinkPreparation(ctx context.Context, original identity.Command, q claimRequest, p *admittedKernelPlan, phase AccountUnlinkPreparationContributor, owner [16]byte) (r preparationReservation, result identity.CommandResult, err error) {
	if p == nil || p.accountUnlink == nil || p.capability != nil || !sameParticipant(p.accountUnlink.contributor, phase) {
		return r, result, invalidPreparation()
	}
	tx, err := c.pool.Raw().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return r, result, readFailure(ctx, err)
	}
	defer func() {
		if failure := rollbackPreparation(tx); failure != nil && !errors.Is(failure, pgx.ErrTxClosed) {
			r, result, err = preparationReservation{}, identity.CommandResult{Binding: p.binding, Outcome: identity.CommitOutcomeUnknown}, identity.UnknownCommitError{CommandID: p.binding.CommandID}
		}
	}()
	disposition, err := lockCommandClaim(ctx, tx, q, c.keys)
	if err != nil {
		return r, result, err
	}
	if disposition == claimConflict {
		return r, identity.CommandResult{Binding: p.binding, Outcome: identity.CommitOutcomeConflict}, identity.ConflictError{}
	}
	r, err = reservePreparationJournal(ctx, tx, q, disposition, owner, c.leaseDuration, 6)
	if err != nil {
		return r, result, err
	}
	p, err = c.freezePreparationDeclaration(ctx, tx, q, p, original)
	if err != nil {
		return preparationReservation{}, result, err
	}
	if r.journal.disposition != journalOwned {
		result = identity.CommandResult{Binding: p.binding, Outcome: identity.CommitOutcomeInProgress, RetryAfter: r.journal.retryAfter}
		if r.journal.result != nil {
			result = *r.journal.result
		}
		return r, result, nil
	}
	if r.generate {
		if err := c.admitAccountUnlinkPreparation(ctx, tx, original, q, p, phase, r.journal, owner); err != nil {
			return preparationReservation{}, result, err
		}
	}
	denied, err := c.reserveCommandCounters(ctx, tx, original, q, p, r.journal, owner)
	if err != nil {
		return preparationReservation{}, result, err
	}
	if denied {
		if _, err := c.freezePlanMode(ctx, tx, p.binding, q, claimNew, p.snapshot(), true); err != nil {
			return preparationReservation{}, result, err
		}
	} else if r.generate {
		if err := startJournalPreparation(ctx, tx, q, r.journal, owner); err != nil {
			return preparationReservation{}, result, err
		}
	}
	if err := c.commitPreparation(ctx, tx); err != nil {
		return preparationReservation{}, identity.CommandResult{Binding: p.binding, Outcome: identity.CommitOutcomeUnknown}, identity.UnknownCommitError{CommandID: p.binding.CommandID}
	}
	if denied {
		return preparationReservation{}, identity.CommandResult{Binding: p.binding, Outcome: identity.CommitOutcomeNotCommitted}, identity.ForbiddenError{}
	}
	return r, identity.CommandResult{Binding: p.binding, Outcome: identity.CommitOutcomeInProgress, RetryAfter: c.leaseDuration}, nil
}

func (c *Coordinator) admitAccountUnlinkPreparation(ctx context.Context, tx pgx.Tx, original identity.Command, q claimRequest, p *admittedKernelPlan, phase AccountUnlinkPreparationContributor, journal journalReservation, owner [16]byte) (err error) {
	fence, err := beginJournal(ctx, tx, q, c.keys, journal, owner)
	if err != nil {
		return err
	}
	w, err := newWork(ctx, tx, p.binding, q, fence)
	if err != nil {
		return err
	}
	w.state.registry = c.registry.state
	w.state.execution = &domainExecution{coordinator: c, reservation: &reservationState{coordinator: c, request: q, plan: p, journal: journal, owner: owner}, ctx: ctx}
	invocation := &accountUnlinkPreparationInvocation{work: w, owner: phase, original: original, active: true}
	defer func() {
		invocation.active, invocation.original = false, identity.Command{}
		invalidateWork(w)
		if recover() != nil {
			err = identity.UnavailableError{}
		}
	}()
	if err := p.bindWork(w); err != nil {
		return err
	}
	if err := configureKernelWork(ctx, w); err != nil {
		return err
	}
	if err := phase.AdmitAccountUnlinkPreparation(ctx, AccountUnlinkPreparationWork{state: invocation}, original); err != nil {
		_, _, _, safe := abortClassification(err)
		return safe
	}
	if w.state.rows != nil || w.usable() != nil {
		return invalidWork()
	}
	return nil
}
