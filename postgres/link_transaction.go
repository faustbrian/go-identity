package postgres

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"sync/atomic"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
)

// PreparedAccountLink is a one-use final-execution handoff from the existing
// coordinator. It owns no open transaction, pool, goroutine or second journal.
// Copies share one-use state. Intent exposes neutral values only; terminal
// observations expose no execution handle. Retry through PrepareLink, never by
// reusing a spent handoff. Earlier preparation deadlines remain binding.
type PreparedAccountLink struct{ state *preparedAccountLinkState }

type preparedAccountLinkState struct {
	owner        *AccountLinkUnitOfWork
	reservation  Reservation
	command      identity.LinkCommand
	participants identity.LinkParticipants
	writer       *accountLinkWriter
	deadline     time.Time
	started      atomic.Bool
	observed     identity.LinkResult
}

var _ identity.LinkUnitOfWork = PreparedAccountLink{}

// Intent returns immutable original intent and the injected actual native
// writer selection. No SQL authority or bound writer escapes this projection.
func (p PreparedAccountLink) Intent() (identity.LinkCommand, identity.LinkParticipants, bool) {
	if p.state == nil || p.state.reservation.state == nil {
		return identity.LinkCommand{}, identity.LinkParticipants{}, false
	}
	return p.state.command, p.state.participants, true
}

// Observation returns an owned original durable observation only when the
// preparation resolved without a new execution handoff. Unknown is not success.
func (p PreparedAccountLink) Observation() (identity.CommandResult, bool) {
	if p.state == nil {
		return identity.CommandResult{}, false
	}
	return p.state.observed.Receipt()
}

func observedAccountLink(r identity.CommandResult) (PreparedAccountLink, error) {
	out, err := identity.NewObservedLinkResult(r)
	if err != nil {
		return PreparedAccountLink{}, err
	}
	return PreparedAccountLink{&preparedAccountLinkState{observed: out}}, nil
}

func neutralLinkOwners(owners []ContributorDescriptor) []identity.LinkContributor {
	out := make([]identity.LinkContributor, len(owners))
	for i, owner := range owners {
		out[i] = identity.LinkContributor{Owner: owner.Owner, ContractID: owner.ContractID, Version: uint64(owner.Version)}
	}
	return out
}

func (o *AccountLinkUnitOfWork) reservedLink(ctx context.Context, reservation Reservation, command identity.Command) (PreparedAccountLink, error) {
	if ctx == nil || o == nil || o.coordinator == nil || o.repository == nil || reservation.state == nil || reservation.state.coordinator != o.coordinator || reservation.state.plan == nil || reservation.state.plan.belongsTo(o.coordinator.registry) != nil {
		return PreparedAccountLink{}, invalidPreparation()
	}
	spec, _, ok := command.AccountLinkCounterCommand()
	if !ok || spec.Binding != reservation.state.plan.binding {
		return PreparedAccountLink{}, invalidPreparation()
	}
	owners := neutralLinkOwners(reservation.state.plan.snapshot().Contributors)
	intent, err := identity.NewLinkCommand(command, identity.LinkPreserveExistingAccess, owners)
	if err != nil {
		return PreparedAccountLink{}, err
	}
	writer := &accountLinkWriter{repository: o.repository}
	participants, err := identity.NewLinkParticipants(writer, owners)
	if err != nil {
		return PreparedAccountLink{}, err
	}
	deadline := time.Now().Add(o.coordinator.maximumDuration)
	if original, ok := ctx.Deadline(); ok && original.Before(deadline) {
		deadline = original
	}
	return PreparedAccountLink{&preparedAccountLinkState{owner: o, reservation: reservation, command: intent, participants: participants, writer: writer, deadline: deadline}}, nil
}

func (p PreparedAccountLink) matches(command identity.LinkCommand, participants identity.LinkParticipants) bool {
	s := p.state
	if s == nil || s.owner == nil || s.owner.coordinator == nil || s.reservation.state == nil || command.FinalAccessPolicy() != identity.LinkPreserveExistingAccess || !slices.Equal(command.Contributors(), s.command.Contributors()) || !slices.Equal(participants.Contributors(), s.command.Contributors()) {
		return false
	}
	writer, ok := participants.Linker().(*accountLinkWriter)
	if !ok || writer == nil || writer != s.writer || writer.work.state != nil || writer.repository != s.owner.repository {
		return false
	}
	actual, ok := command.Command()
	if !ok {
		return false
	}
	expected, ok := s.command.Command()
	if !ok {
		return false
	}
	c := s.owner.coordinator
	left, e := prepareClaim(actual, c.keys.retained[c.keys.current])
	right, other := prepareClaim(expected, c.keys.retained[c.keys.current])
	return e == nil && other == nil && bytes.Equal(left.canonical, right.canonical)
}

// WithinLink validates the exact original command, fixed access policy and
// registered owner selection, then binds a private invocation-local authoritative
// writer. It begins/finalizes/commits through the existing coordinator only.
// The writer returns application, not commitment; all required participant
// effects and original-time checks precede durable observation. Concurrent or
// repeated use of the same handoff denies without another transaction.
func (p PreparedAccountLink) WithinLink(ctx context.Context, command identity.LinkCommand, participants identity.LinkParticipants) (out identity.LinkResult, err error) {
	if ctx == nil || !p.matches(command, participants) {
		return out, invalidPreparation()
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	s := p.state
	bounded, stop := context.WithDeadline(ctx, s.deadline)
	defer stop()
	if err := bounded.Err(); err != nil {
		return out, err
	}
	if !s.started.CompareAndSwap(false, true) {
		return out, identity.ConflictError{}
	}
	c := s.owner.coordinator
	original, _ := command.Command()
	spec, _, _ := original.AccountLinkCounterCommand()
	result := identity.CommandResult{Binding: spec.Binding, Outcome: identity.CommitOutcomeUnknown}
	var work Work
	defer func() {
		panicked := recover() != nil
		if work.state != nil && !work.state.closed {
			result, err = c.Abort(work, identity.UnavailableError{})
		}
		if panicked {
			cleanup, cancel := context.WithTimeout(context.Background(), c.maximumDuration)
			defer cancel()
			result, err = c.recoverCommandReceipt(cleanup, creationRecoveryQuery(spec.Binding))
		}
		result, err = coreCreationReceipt(result, err)
		var shape error
		out, shape = identity.NewObservedLinkResult(result)
		if shape != nil {
			out = identity.LinkResult{}
			if err == nil {
				err = shape
			}
		}
	}()
	work, err = c.Begin(bounded, s.reservation)
	if err != nil {
		return out, err
	}
	now, e := work.DatabaseTime(bounded)
	if e != nil {
		result, err = c.Abort(work, e)
		return out, err
	}
	work.state.execution.composedAbortAudits = make(map[string][]audit.Record, 5)
	for _, class := range []string{"denied", "conflict", "cancelled", "deadline-exceeded", "dependency-failure"} {
		records, e := accountLinkMutationAudits(bounded, s.reservation.state.plan, now, class)
		if e != nil {
			result, err = c.Abort(work, e)
			return out, err
		}
		work.state.execution.composedAbortAudits[class] = records
	}
	// Bind a fresh receiver, not the shared selection returned by Intent. No
	// caller, provider callback or command/context can obtain this Work binding.
	writer := &accountLinkWriter{repository: s.writer.repository, work: work}
	defer func() { writer.work = Work{} }()
	applied, e := writer.ApplyLink(bounded, command)
	if e != nil {
		result, err = c.Abort(work, e)
		return out, err
	}
	application, ok := applied.Application()
	if !ok || application.Binding != spec.Binding {
		result, err = c.Abort(work, invalidWork())
		return out, err
	}
	link := application.Link
	result, err = c.Commit(work, identity.CommandResult{Binding: application.Binding, Outcome: identity.CommitOutcomeCommitted, User: application.User, ExpectedVersion: application.ExpectedVersion, Link: &link, AuditEventID: application.AuditEventID})
	return out, err
}

// The shared selection has no Work. WithinLink makes the only bound receiver,
// retains it privately and invalidates it before returning to its caller.
type accountLinkWriter struct {
	repository *Repository
	work       Work
}

var _ identity.AuthoritativeLinker = (*accountLinkWriter)(nil)

// Format omits reservation, original proof, source and database correlation.
func (PreparedAccountLink) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.PreparedAccountLink(redacted)"))
}

// MarshalJSON refuses export of one-use execution custody.
func (PreparedAccountLink) MarshalJSON() ([]byte, error) { return nil, invalidPreparation() }

// MarshalText refuses export of one-use execution custody as text.
func (PreparedAccountLink) MarshalText() ([]byte, error) { return nil, invalidPreparation() }
