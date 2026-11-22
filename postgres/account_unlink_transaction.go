package postgres

import (
	"bytes"
	"context"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
)

// Only the retained original preparation can enter protected execution. A
// separately reserved signed child does not establish password-proof custody.
func preparedAccountUnlinkReservation(r *reservationState) bool {
	if r == nil || r.plan == nil || r.plan.accountUnlink == nil || r.executionRequest == nil || r.preparation == nil {
		return false
	}
	_, err := accountUnlinkExecutionRequest(r)
	return err == nil
}

// Preparation, domain mutation and recovery retain the same coordinator and
// original command. This bridge creates no transaction or receipt authority.
func (c *Coordinator) executeAccountUnlinkReservation(ctx context.Context, repository *Repository, reservation Reservation, command identity.Command) (result identity.CommandResult, err error) {
	r := reservation.state
	if ctx == nil || c == nil || repository == nil || !preparedAccountUnlinkReservation(r) || r.coordinator != c || r.plan.belongsTo(c.registry) != nil || len(r.plan.contributors) != 6 || r.plan.contributors[0].contributor != repository {
		return result, invalidPreparation()
	}
	spec, _, ok := command.AccountUnlinkCounterCommand()
	actual, err := prepareClaim(command, c.keys.retained[c.keys.current])
	expected, expectedErr := accountUnlinkExecutionRequest(r)
	if !ok || err != nil || expectedErr != nil || spec.Binding != r.plan.binding || !bytes.Equal(actual.canonical, expected.canonical) {
		return result, invalidPreparation()
	}
	bounded, cancel := context.WithTimeout(ctx, c.maximumDuration)
	defer cancel()
	var work Work
	defer func() {
		panicked := recover() != nil
		if work.state != nil && !work.state.closed {
			result, err = c.Abort(work, identity.UnavailableError{})
		}
		if panicked {
			cleanup, stop := context.WithTimeout(context.Background(), c.maximumDuration)
			defer stop()
			result, err = c.recoverCommandReceipt(cleanup, creationRecoveryQuery(spec.Binding))
		}
		result, err = coreCreationReceipt(result, err)
	}()
	work, err = c.Begin(bounded, reservation)
	if err != nil {
		return result, err
	}
	now, err := work.DatabaseTime(bounded)
	if err != nil {
		return c.Abort(work, err)
	}
	work.state.execution.composedAbortAudits = make(map[string][]audit.Record, 5)
	for _, class := range []string{"denied", "conflict", "cancelled", "deadline-exceeded", "dependency-failure"} {
		records, err := accountUnlinkMutationAudits(bounded, r.plan, now, class)
		if err != nil {
			return c.Abort(work, err)
		}
		work.state.execution.composedAbortAudits[class] = records
	}
	result, err = repository.ApplyAccountUnlink(bounded, work, command)
	if err != nil {
		return c.Abort(work, err)
	}
	return c.Commit(work, result)
}

func (c *Coordinator) finalizeAccountUnlink(w Work) error {
	if !c.owns(w) {
		return invalidWork()
	}
	if w.state.execution.reservation.plan.accountUnlink == nil {
		return nil
	}
	progress := w.state.accountUnlink
	if progress == nil || progress.stage != accountUnlinkApplied || progress.active {
		return w.fail(w.state.ctx, invalidWork())
	}
	if _, err := c.runAccountUnlinkPhase(w.state.ctx, w, progress.command, accountUnlinkFinalCheck, nil); err != nil {
		return err
	}
	if _, err := c.runAccountUnlinkPhase(w.state.ctx, w, progress.command, accountUnlinkFinalize, nil); err != nil {
		return err
	}
	if err := c.runCapabilityExecution(w.state.ctx, w, true); err != nil {
		return err
	}
	// All final effects may wait. Recheck the same allowance and original
	// child expiry afterward; neither preparation nor a new charge renews them.
	if err := c.checkCommandCounters(w.state.ctx, w, progress.command); err != nil {
		return err
	}
	spec, _, ok := progress.command.AccountUnlinkCounterCommand()
	now, err := w.DatabaseTime(w.state.ctx)
	if err != nil {
		return err
	}
	if !ok || !accountUnlinkProofCurrent(spec, now) {
		return w.fail(w.state.ctx, identity.ForbiddenError{})
	}
	return nil
}
