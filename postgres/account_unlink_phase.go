package postgres

import (
	"bytes"
	"context"
	"slices"

	identity "github.com/faustbrian/go-identity"
)

// One stage owns ordering; a contributor cannot supply or advance this state.
// Invocation activity is a separate synchronous borrow, not a commit state.
type accountUnlinkStage uint8

const (
	accountUnlinkUnchecked accountUnlinkStage = iota
	accountUnlinkChecked
	accountUnlinkEligible
	accountUnlinkPersisted
	accountUnlinkApplied
	accountUnlinkFinallyChecked
	accountUnlinkFinalized
)

type accountUnlinkProgress struct {
	command identity.Command
	user    identity.User
	receipt identity.AccountUnlinkReceipt
	stage   accountUnlinkStage
	active  bool
}

func accountUnlinkPhaseStages(phase accountUnlinkPhase) (accountUnlinkStage, accountUnlinkStage, bool) {
	switch phase {
	case accountUnlinkCheck:
		return accountUnlinkUnchecked, accountUnlinkChecked, true
	case accountUnlinkEligibility:
		return accountUnlinkChecked, accountUnlinkEligible, true
	case accountUnlinkPersist:
		return accountUnlinkEligible, accountUnlinkPersisted, true
	case accountUnlinkFinalCheck:
		return accountUnlinkApplied, accountUnlinkFinallyChecked, true
	case accountUnlinkFinalize:
		return accountUnlinkFinallyChecked, accountUnlinkFinalized, true
	default:
		return 0, 0, false
	}
}

// Eligibility receives copied kernel facts. A trusted credential owner may
// establish Usable, but cannot replace a record, omit a disabled method, change
// expiry or invent a credential. Last-access policy remains the root transition.
func ownedAccountUnlinkEligibility(before, after []identity.LoginMethod) ([]identity.LoginMethod, error) {
	if len(before) > 128 || len(before) != len(after) {
		return nil, invalidWork()
	}
	for i, original := range before {
		observed := after[i]
		original.Usable, observed.Usable = false, false
		if original != observed {
			return nil, invalidWork()
		}
	}
	return slices.Clone(after), nil
}

func (c *Coordinator) runAccountUnlinkPhase(ctx context.Context, w Work, command identity.Command, phase accountUnlinkPhase, methods []identity.LoginMethod) (eligible []identity.LoginMethod, err error) {
	if !c.owns(w) {
		return nil, invalidWork()
	}
	if err = w.usable(); err != nil {
		return nil, err
	}
	if ctx == nil {
		return nil, w.fail(w.state.ctx, invalidWork())
	}
	if err = ctx.Err(); err != nil {
		return nil, w.fail(ctx, err)
	}
	r := w.state.execution.reservation
	p := r.plan
	spec, _, ok := command.AccountUnlinkCounterCommand()
	if !ok || p == nil || p.accountUnlink == nil || spec.Binding != p.binding || spec.Binding != w.state.binding {
		return nil, w.fail(ctx, invalidPlan())
	}
	q, err := prepareClaim(command, c.keys.retained[c.keys.current])
	expected, expectedErr := accountUnlinkExecutionRequest(r)
	if err != nil || expectedErr != nil || !bytes.Equal(q.canonical, expected.canonical) {
		return nil, w.fail(ctx, identity.ConflictError{})
	}
	owner, ok := p.accountUnlink.contributor.(AccountUnlinkContributor)
	if !ok || !sameParticipant(owner, owner) || validateAccountUnlink(owner, command, p.snapshot()) != nil {
		return nil, w.fail(ctx, invalidPlan())
	}
	before, after, valid := accountUnlinkPhaseStages(phase)
	if !valid || phase != accountUnlinkEligibility && len(methods) != 0 || len(methods) > 128 {
		return nil, w.fail(ctx, invalidWork())
	}
	progress := w.state.accountUnlink
	if phase == accountUnlinkCheck {
		if progress != nil {
			return nil, w.fail(ctx, invalidWork())
		}
		progress = &accountUnlinkProgress{command: command}
		w.state.accountUnlink = progress
	}
	if progress == nil || progress.active || progress.stage != before {
		return nil, w.fail(ctx, invalidWork())
	}
	progress.active = true
	invocation := &accountUnlinkInvocation{work: w, participant: owner, command: spec, phase: phase, active: true}
	defer func() {
		invocation.active, progress.active = false, false
		if recover() != nil {
			eligible, err = nil, w.fail(ctx, identity.UnavailableError{})
		}
	}()
	handle := AccountUnlinkWork{state: invocation}
	switch phase {
	case accountUnlinkCheck, accountUnlinkFinalCheck:
		err = owner.CheckAccountUnlink(ctx, handle)
	case accountUnlinkEligibility:
		original := slices.Clone(methods)
		eligible, err = owner.EligibleAccountUnlinkMethods(ctx, handle, slices.Clone(original))
		if err == nil {
			eligible, err = ownedAccountUnlinkEligibility(original, eligible)
		}
	case accountUnlinkPersist:
		err = owner.PersistAccountUnlink(ctx, handle)
	case accountUnlinkFinalize:
		err = owner.FinalizeAccountUnlink(ctx, handle)
	}
	if err != nil {
		_, _, _, safe := abortClassification(err)
		return nil, w.fail(ctx, safe)
	}
	if err = ctx.Err(); err != nil {
		return nil, w.fail(ctx, err)
	}
	if w.state.rows != nil {
		return nil, w.fail(ctx, invalidWork())
	}
	if err = w.usable(); err != nil {
		return nil, err
	}
	progress.stage = after
	return eligible, nil
}
