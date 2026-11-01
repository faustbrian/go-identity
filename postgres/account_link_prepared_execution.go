package postgres

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

// ExecutePrepared runs original explicit-self OAuth link input through the
// existing command journal. The native owner supplies the exact declaration;
// consumers must use its supported workflow, not author one themselves.
// Original state reservation, counters and the start marker commit before
// Generate may decrypt PKCE, exchange or sign. An unacknowledged start never
// permits generation. Retained ciphertext resumes under its original generation;
// neither retry nor takeover replaces original intent or re-exchanges a code.
//
// Attachment persists and reserves the one matching final signed grant through
// the actual registered issuer/consumer in one transaction. That issuance is a
// prerequisite, not evidence of account commitment. The final six-owner plan
// consumes both original state and final grant with account/audit/lifecycle
// effects. Final current checks and conservative recovery remain mandatory.
// Matching terminal replay returns its original receipt without restoration.
// Earlier deadlines win; uncertain durable outcomes reveal no partial result.
func (o *AccountLinkUnitOfWork) ExecutePrepared(ctx context.Context, original identity.Command, declaration CommandPlan) (result identity.CommandResult, err error) {
	if o == nil || o.coordinator == nil || o.repository == nil || ctx == nil {
		return result, coordinatorError()
	}
	c := o.coordinator
	if _, err := c.accountLinkPreparationIssuer(); err != nil {
		return result, invalidPreparation()
	}
	bounded, cancel := context.WithTimeout(ctx, c.maximumDuration)
	defer cancel()
	q, admitted, phase, err := c.prepareAccountLinkPreparation(original, declaration)
	if err != nil || !sameParticipant(phase, o.provider) || admitted.audits[0].RetentionPolicyVersion != o.retention {
		return result, invalidPreparation()
	}
	b := admitted.binding
	defer func() {
		if recover() != nil {
			result, err = identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeUnknown}, identity.UnknownCommitError{CommandID: b.CommandID}
		}
		result, err = coreCreationReceipt(result, err)
	}()
	var owner [16]byte
	if _, err := rand.Read(owner[:]); err != nil || owner == ([16]byte{}) {
		return result, identity.UnavailableError{}
	}
	r, result, err := c.startAccountLinkPreparation(bounded, original, q, admitted, phase, owner)
	if err != nil || r.journal.disposition != journalOwned {
		return result, err
	}
	unknown := func() (identity.CommandResult, error) {
		return identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeUnknown}, identity.UnknownCommitError{CommandID: b.CommandID}
	}
	wire := r.output
	if r.generate {
		wire, err = phase.GenerateAccountLinkPreparation(bounded, original, r.journal.generation)
		if err != nil || bounded.Err() != nil || len(wire) == 0 || len(wire) > maximumPreparationCiphertext {
			return unknown()
		}
		wire = bytes.Clone(wire)
		if err := c.retainFeaturePreparation(bounded, q, r.journal, owner, wire); err != nil {
			return unknown()
		}
		r.outputGeneration = r.journal.generation
	}
	generated, final, issuance, err := phase.RestoreAccountLinkPreparation(bounded, original, r.outputGeneration, bytes.Clone(wire))
	if err != nil || bounded.Err() != nil || !sameAccountLinkDeclaration(b, admitted.snapshot(), final) {
		return unknown()
	}
	execution, snapshot, err := c.prepareRestoredAccountLink(generated, final)
	if err != nil {
		return unknown()
	}
	reservation, err := c.attachAccountLinkPreparation(bounded, q, execution, snapshot, issuance, r, owner, wire)
	if err != nil {
		return unknown()
	}
	return o.executeReservation(bounded, reservation, generated)
}

// Preparation must not discover a missing persistence owner only after an
// irreversible provider exchange. Ordinary already-issued linking retains its
// six-owner composition; only this opt-in route additionally requires an issuer.
func (c *Coordinator) accountLinkPreparationIssuer() (CapabilityIssuanceContributor, error) {
	if c == nil || c.registry == nil || c.registry.state == nil {
		return nil, invalidPreparation()
	}
	entries, err := c.registry.selectContributors([]ContributorDescriptor{{Owner: "capability/postgres", ContractID: "capability.issuance", Version: 1}})
	if err != nil || len(entries) != 1 {
		return nil, invalidPreparation()
	}
	issuer, ok := entries[0].contributor.(CapabilityIssuanceContributor)
	if !ok || !sameParticipant(issuer, issuer) {
		return nil, invalidPreparation()
	}
	return issuer, nil
}

// Compare every frozen declaration field through the existing canonical codec;
// only the newly authenticated final grant is added after exchange.
func sameAccountLinkDeclaration(b identity.CommandBinding, original, final CommandPlan) bool {
	if original.AccountLinkState == nil || original.Capability != nil || final.Capability == nil || final.AccountLinkState == nil || final.Capability.ExpiresAt.After(original.AccountLinkState.ExpiresAt) {
		return false
	}
	final.Capability = nil
	fp := [32]byte{1}
	before, e := encodeKernelPlan(b, fp, original)
	after, other := encodeKernelPlan(b, fp, final)
	return e == nil && other == nil && bytes.Equal(before, after)
}

func (c *Coordinator) prepareRestoredAccountLink(command identity.Command, final CommandPlan) (claimRequest, CommandPlan, error) {
	fail := func() (claimRequest, CommandPlan, error) { return claimRequest{}, CommandPlan{}, invalidPreparation() }
	s, _, ok := command.AccountLinkCounterCommand()
	if !ok || !accountLinkBinding(s.Binding) || final.AccountLinkState == nil || !accountLinkProofPlan(s, final) {
		return fail()
	}
	q, err := prepareClaim(command, c.keys.retained[c.keys.current])
	if err != nil || !validClaim(q, c.keys) {
		return fail()
	}
	fp := claimFingerprint(c.keys.retained[c.keys.current], q.canonical)
	wire, err := encodeKernelPlan(s.Binding, fp, final)
	if err != nil {
		return fail()
	}
	owned, err := decodeKernelPlan(s.Binding, fp, wire)
	if err != nil {
		return fail()
	}
	p, err := c.registry.admitKernelPlan(s.Binding, fp, owned)
	if err != nil || p.accountLink == nil || validateCommandCounters(counterAdmissionParticipant(p), command, *p.counters) != nil || validateAccountLink(p.accountLink.contributor.(AccountLinkContributor), command, p.snapshot()) != nil {
		return fail()
	}
	return q, owned, nil
}

func (c *Coordinator) startAccountLinkPreparation(ctx context.Context, original identity.Command, q claimRequest, p *admittedKernelPlan, phase AccountLinkPreparationContributor, owner [16]byte) (r preparationReservation, result identity.CommandResult, err error) {
	tx, err := c.pool.Raw().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return r, result, readFailure(ctx, err)
	}
	defer func() {
		if e := rollbackPreparation(tx); e != nil && !errors.Is(e, pgx.ErrTxClosed) {
			r, result, err = preparationReservation{}, identity.CommandResult{Binding: p.binding, Outcome: identity.CommitOutcomeUnknown}, identity.UnknownCommitError{CommandID: p.binding.CommandID}
		}
	}()
	d, err := lockCommandClaim(ctx, tx, q, c.keys)
	if err != nil {
		return r, result, err
	}
	if d == claimConflict {
		return r, identity.CommandResult{Binding: p.binding, Outcome: identity.CommitOutcomeConflict}, identity.ConflictError{}
	}
	r, err = reservePreparationJournal(ctx, tx, q, d, owner, c.leaseDuration, 5)
	if err != nil {
		return r, result, err
	}
	p, err = c.freezePreparationCounters(ctx, tx, q, p, original)
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
		if err := c.admitAccountLinkPreparation(ctx, tx, original, q, p, phase, r.journal, owner); err != nil {
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
	} else {
		if err := c.reserveCapabilityInput(ctx, tx, q, p, r.journal, owner, capabilityOriginalAccountLinkState); err != nil {
			return preparationReservation{}, result, err
		}
		if r.generate {
			if err := startJournalPreparation(ctx, tx, q, r.journal, owner); err != nil {
				return preparationReservation{}, result, err
			}
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

func (c *Coordinator) admitAccountLinkPreparation(ctx context.Context, tx pgx.Tx, original identity.Command, q claimRequest, p *admittedKernelPlan, phase AccountLinkPreparationContributor, j journalReservation, owner [16]byte) (err error) {
	fence, err := beginJournal(ctx, tx, q, c.keys, j, owner)
	if err != nil {
		return err
	}
	w, err := newWork(ctx, tx, p.binding, q, fence)
	if err != nil {
		return err
	}
	w.state.registry = c.registry.state
	w.state.execution = &domainExecution{coordinator: c, reservation: &reservationState{coordinator: c, request: q, plan: p, journal: j, owner: owner}, ctx: ctx}
	s := &accountLinkPreparationInvocation{work: w, owner: phase, original: original, active: true}
	defer func() {
		s.active, s.original = false, identity.Command{}
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
	if err := phase.AdmitAccountLinkPreparation(ctx, AccountLinkPreparationWork{state: s}, original); err != nil {
		_, _, _, safe := abortClassification(err)
		return safe
	}
	if w.state.rows != nil || w.usable() != nil {
		return invalidWork()
	}
	return nil
}

func (c *Coordinator) attachAccountLinkPreparation(ctx context.Context, original, generated claimRequest, final CommandPlan, issuance CapabilityIssuancePlan, r preparationReservation, owner [16]byte, wire []byte) (Reservation, error) {
	tx, err := c.pool.Raw().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Reservation{}, readFailure(ctx, err)
	}
	defer rollbackPreparation(tx)
	fence, err := beginJournal(ctx, tx, original, c.keys, r.journal, owner)
	if err != nil {
		return Reservation{}, err
	}
	id, _ := base64.RawURLEncoding.DecodeString(string(original.commandID))
	var stored, previousPlan []byte
	var generation string
	if err := tx.QueryRow(ctx, `SELECT preparation_ciphertext,preparation_ciphertext_generation::text,command_plan FROM identity.commands WHERE command_id=$1 AND tenant_id=$2 AND purpose=$3`, id, string(original.tenant), original.purpose).Scan(&stored, &generation, &previousPlan); err != nil {
		return Reservation{}, readFailure(ctx, err)
	}
	if !bytes.Equal(stored, wire) || !preparationGeneration(generation, r.outputGeneration) || generated.source == nil {
		return Reservation{}, invalidPreparation()
	}
	spec, _, ok := generated.source.AccountLinkCounterCommand()
	if !ok {
		return Reservation{}, invalidPreparation()
	}
	d := claimReplay
	if previousPlan == nil {
		d = claimNew
	}
	p, err := c.freezePlan(ctx, tx, spec.Binding, original, d, final)
	if err != nil {
		return Reservation{}, err
	}
	state := &reservationState{coordinator: c, request: original, executionRequest: &generated, plan: p, journal: r.journal, owner: owner, preparation: &retainedFeaturePreparation{ciphertext: bytes.Clone(wire), generation: r.outputGeneration}}
	if _, err := accountLinkExecutionRequest(state); err != nil {
		return Reservation{}, err
	}
	if !validCapabilityIssuancePlan(&issuance) || len(issuance.Grants) != 1 || issuance.RegistrationUserID != "" || issuance.ResetRecipientUserID != "" || issuance.MagicLinkRecipientUserID != "" || issuance.MFAContinuationUserID != "" || issuance.Grants[0] != *p.capability {
		return Reservation{}, invalidPreparation()
	}
	journal := r.journal
	if previousPlan == nil {
		// The issuer's positive row proves this preparation prerequisite only.
		// Do not freeze it among the final domain recovery participants: that
		// would mistake successful issuance for an account link that rolled back.
		if err := c.issueAccountLinkAttachment(ctx, tx, state, fence, issuance, spec); err != nil {
			return Reservation{}, err
		}
		journal.previousGeneration = 0
	}
	// Original state was already reserved/rebound by the acknowledged start.
	// Only the post-exchange final input is new here; never reserve state twice.
	if err := c.reserveCapability(ctx, tx, original, p, journal, owner); err != nil {
		return Reservation{}, err
	}
	if err := c.commitPreparation(ctx, tx); err != nil {
		return Reservation{}, err
	}
	return Reservation{state: state}, nil
}

func (c *Coordinator) issueAccountLinkAttachment(ctx context.Context, tx pgx.Tx, r *reservationState, fence journalWorkFence, issuance CapabilityIssuancePlan, spec identity.AccountLinkCommand) error {
	entries, err := c.registry.selectContributors([]ContributorDescriptor{issuance.Contributor})
	if err != nil || len(entries) != 1 || validateIssuanceContributor(spec.Binding, &issuance, entries) != nil {
		return invalidPreparation()
	}
	issuer, ok := entries[0].contributor.(CapabilityIssuanceContributor)
	if !ok {
		return invalidPreparation()
	}
	plan := *r.plan
	plan.contributors = append(append([]registeredContributor(nil), r.plan.contributors...), entries[0])
	plan.issuance = cloneCapabilityIssuancePlan(&issuance)
	// Keep temporary issuance custody distinct without copying the final
	// reservation's atomic single-use Begin state.
	attachment := &reservationState{coordinator: r.coordinator, request: r.request, executionRequest: r.executionRequest, preparation: r.preparation, plan: &plan, journal: r.journal, owner: r.owner}
	w, err := newWork(ctx, tx, spec.Binding, r.request, fence)
	if err != nil {
		return err
	}
	defer invalidateWork(w)
	w.state.registry = c.registry.state
	w.state.execution = &domainExecution{coordinator: c, reservation: attachment, ctx: ctx}
	if err := plan.bindWork(w); err != nil {
		return err
	}
	if err := configureKernelWork(ctx, w); err != nil {
		return err
	}
	if err := w.StageCapabilityIssuanceFor(issuer, 0, spec.Proof); err != nil {
		return err
	}
	return c.persistCapabilityIssuance(w)
}
