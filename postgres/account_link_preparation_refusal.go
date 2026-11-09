package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"strconv"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

// AccountLinkPreparationRefusal is an authenticated definitive provider refusal
// decoded by the registered preparation owner. Its exact original binding,
// state and retained output generation must match the locked journal. The zero
// value means this is not a refusal variant; it grants no terminal authority.
// Consumers cannot submit this value to execute or settle a command.
type AccountLinkPreparationRefusal struct {
	Binding    identity.CommandBinding
	State      CapabilityPlan
	Generation uint64
}

// Format suppresses original command and state correlations.
func (AccountLinkPreparationRefusal) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.AccountLinkPreparationRefusal(redacted)"))
}

// MarshalJSON rejects serialization of participant evidence.
func (AccountLinkPreparationRefusal) MarshalJSON() ([]byte, error) { return nil, invalidPreparation() }

// AccountLinkPreparationRefusalContributor optionally decodes a closed refusal
// variant on the SAME registered preparation owner. Legacy successful-output
// restoration is unchanged. Decode must authenticate the original RP metadata,
// state and generation, and on ordinary retry its original input commitment.
// Historical invocations have metadata only, never live callback/proof custody.
// A zero result with nil error denotes non-refusal output; corrupt marked
// refusals return an error. No SQL, exchange, signing, expiry renewal or side
// effects are permitted. The coordinator alone selects immutable retained bytes
// and establishes noncommit and terminal cleanup under its existing fence.
type AccountLinkPreparationRefusalContributor interface {
	AccountLinkPreparationContributor
	RestoreAccountLinkPreparationRefusal(context.Context, identity.CommandBinding, CapabilityPlan, uint64, []byte) (AccountLinkPreparationRefusal, error)
}

func decodeAccountLinkRefusal(ctx context.Context, p *admittedKernelPlan, generation uint64, wire []byte) (AccountLinkPreparationRefusal, error) {
	if p == nil || p.accountLink == nil || p.accountLinkState == nil || p.capability != nil || generation == 0 || len(wire) == 0 || len(wire) > maximumPreparationCiphertext {
		return AccountLinkPreparationRefusal{}, invalidPreparation()
	}
	owner, ok := p.accountLink.contributor.(AccountLinkPreparationRefusalContributor)
	if !ok {
		return AccountLinkPreparationRefusal{}, nil
	}
	refusal, err := owner.RestoreAccountLinkPreparationRefusal(ctx, p.binding, *p.accountLinkState, generation, bytes.Clone(wire))
	if err != nil {
		return AccountLinkPreparationRefusal{}, err
	}
	if refusal == (AccountLinkPreparationRefusal{}) {
		return refusal, nil
	}
	if refusal.Binding != p.binding || refusal.State != *p.accountLinkState || refusal.Generation != generation {
		return AccountLinkPreparationRefusal{}, invalidPreparation()
	}
	if _, ok := p.accountLink.contributor.(AccountLinkCleanupContributor); !ok {
		return AccountLinkPreparationRefusal{}, invalidPreparation()
	}
	return refusal, nil
}

// Called under the claim/journal locks, before any takeover. Missing output,
// unmarked success output and legacy owners are not negative exchange evidence.
func retainedAccountLinkRefusal(ctx context.Context, tx pgx.Tx, p *admittedKernelPlan) (AccountLinkPreparationRefusal, error) {
	id, _ := base64.RawURLEncoding.DecodeString(string(p.binding.CommandID))
	var wire []byte
	var generation *string
	err := tx.QueryRow(ctx, `SELECT CASE WHEN octet_length(preparation_ciphertext) BETWEEN 1 AND $4 THEN preparation_ciphertext END,preparation_ciphertext_generation::text
FROM identity.commands WHERE command_id=$1 AND tenant_id=$2 AND purpose=$3 AND state='pending' AND command_plan IS NULL AND preparation_profile=5`, id, string(p.binding.TenantID), p.binding.OperationID, maximumPreparationCiphertext).Scan(&wire, &generation)
	if err != nil {
		return AccountLinkPreparationRefusal{}, readFailure(ctx, err)
	}
	if wire == nil && generation == nil {
		return AccountLinkPreparationRefusal{}, nil
	}
	if generation == nil {
		return AccountLinkPreparationRefusal{}, invalidPreparation()
	}
	n, err := strconv.ParseUint(*generation, 10, 64)
	if err != nil || !preparationGeneration(*generation, n) {
		return AccountLinkPreparationRefusal{}, invalidPreparation()
	}
	return decodeAccountLinkRefusal(ctx, p, n, wire)
}

// A retained definitive refusal plus an absent final attachment proves that no
// domain Begin was possible. The acknowledged original state remains reserved.
// Finish through the same fenced cleanup/audit/release/receipt phases as Abort,
// without issuing a final Grant or pretending that release consumed state.
func (c *Coordinator) finishAccountLinkRefusal(ctx context.Context, q claimRequest, p *admittedKernelPlan, r preparationReservation, owner [16]byte, wire []byte) (result identity.CommandResult, handled bool, err error) {
	refusal, err := decodeAccountLinkRefusal(ctx, p, r.outputGeneration, wire)
	if err != nil {
		return result, true, err
	}
	if refusal == (AccountLinkPreparationRefusal{}) {
		return result, false, nil
	}
	unknown := identity.CommandResult{Binding: p.binding, Outcome: identity.CommitOutcomeUnknown}
	tx, err := c.pool.Raw().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return unknown, true, readFailure(ctx, err)
	}
	defer rollbackPreparation(tx)
	fence, err := beginJournal(ctx, tx, q, c.keys, r.journal, owner)
	if err != nil {
		return unknown, true, err
	}
	retained, err := retainedAccountLinkRefusal(ctx, tx, p)
	if err != nil || retained != refusal {
		return unknown, true, invalidPreparation()
	}
	w, err := newWork(ctx, tx, p.binding, q, fence)
	if err != nil {
		return unknown, true, err
	}
	defer invalidateWork(w)
	w.state.registry = c.registry.state
	w.state.execution = &domainExecution{coordinator: c, reservation: &reservationState{coordinator: c, request: q, plan: p, journal: r.journal, owner: owner}, ctx: ctx}
	if err := p.bindWork(w); err != nil {
		return unknown, true, err
	}
	if err := configureKernelWork(ctx, w); err != nil {
		return unknown, true, err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return unknown, true, err
	}
	records, err := accountLinkMutationAudits(ctx, p, now, "denied")
	if err != nil {
		return unknown, true, err
	}
	for i, record := range records {
		if err := w.StageAudit(p.audits[i].EventIndex, record); err != nil {
			return unknown, true, err
		}
	}
	if err := c.persistAuditPhase(w); err != nil {
		return unknown, true, err
	}
	if err := c.cleanupPreparedAccountLink(ctx, w); err != nil {
		return unknown, true, err
	}
	// No final attachment exists under these locks: Begin explicitly rejects
	// this state-only reservation. That is definitive local noncommit evidence,
	// allowing the canonical live-generation release without a fake domain run.
	if err := c.releaseCapabilityAfterRollback(ctx, w, p, r.journal); err != nil {
		return unknown, true, err
	}
	if w.usable() != nil || w.state.rows != nil {
		return unknown, true, invalidWork()
	}
	result = identity.CommandResult{Binding: p.binding, Outcome: identity.CommitOutcomeNotCommitted}
	if err := terminalizeJournal(ctx, tx, q, r.journal, owner, result, "denied"); err != nil {
		return unknown, true, err
	}
	if err := tx.Commit(ctx); err != nil {
		return unknown, true, readFailure(ctx, err)
	}
	return result, true, identity.ForbiddenError{}
}
