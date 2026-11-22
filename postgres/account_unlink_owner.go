package postgres

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// AccountUnlinkUnitOfWorkConfig pins the positive audit-retention policy.
// Zero is invalid; configuration is immutable after construction.
type AccountUnlinkUnitOfWorkConfig struct{ RetentionPolicyVersion uint64 }

// AccountUnlinkUnitOfWork prepares the original fresh-authorized unlink through
// the existing coordinator. It owns no transaction engine, pool or goroutine.
// Use the ready handoff behind the root prepared unlink service and the genuine
// native password/provider/session owner, never caller-authored eligibility.
// Independent calls may overlap; each returned handoff is single-use.
type AccountUnlinkUnitOfWork struct {
	coordinator *Coordinator
	repository  *Repository
	provider    AccountUnlinkPreparationContributor
	retention   uint64
}

// NewAccountUnlinkUnitOfWork validates the exact enlisted repository, unlink
// preparation owner and staged issuer without IO. PrepareUnlink admits the full
// closed declaration, including capability, counters, audit and lifecycle owners,
// before any SQL or generation. Pools remain caller-owned.
func NewAccountUnlinkUnitOfWork(c *Coordinator, r *Repository, config AccountUnlinkUnitOfWorkConfig) (*AccountUnlinkUnitOfWork, error) {
	if c == nil || c.pool == nil || c.pool.Raw() == nil || c.registry == nil || c.registry.state == nil || r == nil || r.read == nil || config.RetentionPolicyVersion == 0 {
		return nil, coordinatorError()
	}
	if _, err := c.accountLinkPreparationIssuer(); err != nil {
		return nil, invalidPreparation()
	}
	o := &AccountUnlinkUnitOfWork{coordinator: c, repository: r, retention: config.RetentionPolicyVersion}
	registeredRepository := false
	for _, entry := range c.registry.state.entries {
		if entry.descriptor == r.Descriptor() && entry.contributor == r {
			registeredRepository = true
		}
		if entry.descriptor == accountUnlinkOwnerDescriptor() {
			owner, ok := entry.contributor.(AccountUnlinkPreparationContributor)
			if !ok || !sameParticipant(owner, owner) || o.provider != nil {
				return nil, invalidPreparation()
			}
			o.provider = owner
		}
	}
	if !registeredRepository || o.provider == nil {
		return nil, invalidPreparation()
	}
	return o, nil
}

// PrepareUnlink acknowledges original admission/counters before generating the
// issuer checkpoint outside SQL, then retains, restores and atomically attaches
// its exact one-use child. No ready execution escapes an uncertain acknowledgement.
// Copies and retries never sign again or extend original proof/evidence expiry.
// Terminal replay returns only Observation; pending uncertainty is not success.
// The native owner must supply authenticated restoration and all final effects.
func (o *AccountUnlinkUnitOfWork) PrepareUnlink(ctx context.Context, original identity.Command, declaration CommandPlan) (next PreparedAccountUnlink, err error) {
	if ctx == nil || o == nil || o.coordinator == nil || o.repository == nil {
		return next, invalidPreparation()
	}
	c := o.coordinator
	bounded, cancel := context.WithTimeout(ctx, c.maximumDuration)
	defer cancel()
	q, admitted, phase, err := c.prepareAccountUnlinkPreparation(original, declaration)
	if err != nil || !sameParticipant(phase, o.provider) || admitted.audits[0].RetentionPolicyVersion != o.retention {
		return next, invalidPreparation()
	}
	b := admitted.binding
	unknown := func() (PreparedAccountUnlink, error) {
		out, _ := o.observedUnlink(identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeUnknown})
		return out, identity.UnknownCommitError{CommandID: b.CommandID}
	}
	defer func() {
		if recover() != nil {
			next, err = unknown()
		}
	}()
	var owner [16]byte
	if _, err := rand.Read(owner[:]); err != nil || owner == ([16]byte{}) {
		return next, identity.UnavailableError{}
	}
	r, result, err := c.startAccountUnlinkPreparation(bounded, original, q, admitted, phase, owner)
	if err != nil || r.journal.disposition != journalOwned {
		if result.Validate() == nil {
			observed, shape := o.observedUnlink(result)
			if shape != nil {
				return next, shape
			}
			return observed, err
		}
		return next, err
	}
	wire := r.output
	if r.generate {
		wire, err = phase.GenerateAccountUnlinkPreparation(bounded, original, r.journal.generation)
		if err != nil || bounded.Err() != nil || len(wire) == 0 || len(wire) > maximumPreparationCiphertext {
			return unknown()
		}
		wire = bytes.Clone(wire)
		if err := c.retainFeaturePreparation(bounded, q, r.journal, owner, wire); err != nil {
			return unknown()
		}
		r.outputGeneration = r.journal.generation
	}
	generated, final, issuance, err := phase.RestoreAccountUnlinkPreparation(bounded, original, r.outputGeneration, bytes.Clone(wire))
	if err != nil || bounded.Err() != nil {
		return unknown()
	}
	execution, final, err := c.prepareRestoredAccountUnlink(original, generated, admitted.snapshot(), final)
	if err != nil {
		return unknown()
	}
	reservation, err := c.attachAccountUnlinkPreparation(bounded, q, execution, final, issuance, r, owner, wire)
	if err != nil {
		return unknown()
	}
	deadline, _ := bounded.Deadline()
	return PreparedAccountUnlink{&preparedAccountUnlinkState{owner: o, reservation: reservation, command: generated, binding: b, deadline: deadline}}, nil
}

// PreparedAccountUnlink is one native prepared execution or one original durable
// observation. It owns no open transaction or bearer-transfer authority. Copies
// share the reservation's single-use guard. Retry via PrepareUnlink, not a spent
// handle. Core remains responsible for current policy, eligibility and redaction.
type PreparedAccountUnlink struct{ state *preparedAccountUnlinkState }

type preparedAccountUnlinkState struct {
	owner       *AccountUnlinkUnitOfWork
	reservation Reservation
	command     identity.Command
	binding     identity.CommandBinding
	deadline    time.Time
	observed    *identity.CommandResult
}

var _ identity.PreparedAccountUnlinkUnitOfWork = PreparedAccountUnlink{}

func (o *AccountUnlinkUnitOfWork) observedUnlink(result identity.CommandResult) (PreparedAccountUnlink, error) {
	if result.Validate() != nil || !accountUnlinkBinding(result.Binding) {
		return PreparedAccountUnlink{}, invalidPreparation()
	}
	result = cloneUnlinkObservation(result)
	return PreparedAccountUnlink{&preparedAccountUnlinkState{owner: o, binding: result.Binding, observed: &result}}, nil
}

// RecoveryHandle creates a scoped read/reconciliation handoff with no
// execution capability. Use it behind AccountUnlinkService so authorization
// and redaction precede primary recovery. No IO runs here.
func (o *AccountUnlinkUnitOfWork) RecoveryHandle(binding identity.CommandBinding) (PreparedAccountUnlink, error) {
	if o == nil || o.coordinator == nil || !accountUnlinkBinding(binding) {
		return PreparedAccountUnlink{}, invalidPreparation()
	}
	if (identity.CommandResult{Binding: binding, Outcome: identity.CommitOutcomeNotCommitted}).Validate() != nil {
		return PreparedAccountUnlink{}, invalidPreparation()
	}
	return PreparedAccountUnlink{state: &preparedAccountUnlinkState{owner: o, binding: binding}}, nil
}

func cloneUnlinkObservation(result identity.CommandResult) identity.CommandResult {
	if result.Unlink != nil {
		receipt := *result.Unlink
		result.Unlink = &receipt
	}
	return result
}

// Intent returns an immutable exact issued intent only for a ready, unspent
// handoff. It conveys no raw token or independent authentication authority.
func (p PreparedAccountUnlink) Intent() (identity.AccountUnlinkCommand, bool) {
	if p.state == nil || p.state.owner == nil || p.state.reservation.state == nil || p.state.reservation.state.started.Load() || !preparedAccountUnlinkReservation(p.state.reservation.state) {
		return identity.AccountUnlinkCommand{}, false
	}
	spec, _, ok := p.state.command.AccountUnlinkCounterCommand()
	return spec, ok
}

// Observation returns an owned historical receipt only when preparation did
// not grant execution. Pending/Unknown never implies commitment or continuation.
func (p PreparedAccountUnlink) Observation() (identity.CommandResult, bool) {
	if p.state == nil || p.state.observed == nil {
		return identity.CommandResult{}, false
	}
	return cloneUnlinkObservation(*p.state.observed), true
}

// VerifyPreparedAccountUnlink matches the exact grant/intent to the native
// owner's authenticated restoration. It performs no IO, signature replacement,
// proof consumption or freshness renewal. Unrelated or spent custody denies.
func (p PreparedAccountUnlink) VerifyPreparedAccountUnlink(ctx context.Context, spec identity.AccountUnlinkCommand) error {
	if ctx == nil {
		return invalidPreparation()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	expected, ok := p.Intent()
	if !ok || p.state.deadline.IsZero() || !time.Now().Before(p.state.deadline) {
		return invalidPreparation()
	}
	actual, err := identity.NewAccountUnlinkCommand(spec)
	wanted, other := identity.NewAccountUnlinkCommand(expected)
	if err != nil || other != nil {
		return invalidPreparation()
	}
	c := p.state.owner.coordinator
	left, err := prepareClaim(actual, c.keys.retained[c.keys.current])
	right, other := prepareClaim(wanted, c.keys.retained[c.keys.current])
	if err != nil || other != nil || !bytes.Equal(left.canonical, right.canonical) {
		return identity.ForbiddenError{}
	}
	return nil
}

// Execute accepts only this handoff's exact bare command from core admission,
// then uses its frozen counter-bearing command in the sole native transaction.
func (p PreparedAccountUnlink) Execute(ctx context.Context, command identity.Command) (identity.CommandResult, error) {
	spec, ok := command.UnlinkAccount()
	if !ok || p.VerifyPreparedAccountUnlink(ctx, spec) != nil {
		return identity.CommandResult{}, invalidPreparation()
	}
	s := p.state
	bounded, cancel := context.WithDeadline(ctx, s.deadline)
	defer cancel()
	return s.owner.coordinator.executeAccountUnlinkReservation(bounded, s.owner.repository, s.reservation, s.command)
}

// Recover reads only the exact original scoped primary observation. Current
// application authorization/redaction still belongs to the root service.
func (p PreparedAccountUnlink) Recover(ctx context.Context, q identity.RecoveryQuery) (identity.CommandResult, error) {
	if ctx == nil || p.state == nil || p.state.owner == nil || q != creationRecoveryQuery(p.state.binding) {
		return identity.CommandResult{}, invalidPreparation()
	}
	c := p.state.owner.coordinator
	bounded, cancel := context.WithTimeout(ctx, c.maximumDuration)
	defer cancel()
	result, err := c.recoverCommandReceipt(bounded, q)
	return coreCreationReceipt(result, err)
}

// Format hides original command, proof and runtime dependencies.
func (AccountUnlinkUnitOfWork) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.AccountUnlinkUnitOfWork(redacted)"))
}

// MarshalJSON rejects runtime composition export.
func (AccountUnlinkUnitOfWork) MarshalJSON() ([]byte, error) { return nil, invalidPreparation() }

// Format hides retained proof, ciphertext, receipt and transaction correlation.
func (PreparedAccountUnlink) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.PreparedAccountUnlink(redacted)"))
}

// MarshalJSON rejects prepared authority export.
func (PreparedAccountUnlink) MarshalJSON() ([]byte, error) { return nil, invalidPreparation() }

// MarshalText rejects implicit text and map-key export.
func (PreparedAccountUnlink) MarshalText() ([]byte, error) { return nil, invalidPreparation() }
