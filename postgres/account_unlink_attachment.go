package postgres

import (
	"bytes"
	"context"
	"encoding/base64"

	"github.com/jackc/pgx/v5"
)

// Attachment is another phase of the existing original command, not a second
// execution/recovery owner. Only its retained issued child may be attached;
// successful issuer persistence must never prove the account mutation committed.
func (c *Coordinator) attachAccountUnlinkPreparation(ctx context.Context, original, generated claimRequest, final CommandPlan, issuance CapabilityIssuancePlan, r preparationReservation, owner [16]byte, wire []byte) (Reservation, error) {
	if original.source == nil || generated.source == nil || len(wire) == 0 || len(wire) > maximumPreparationCiphertext {
		return Reservation{}, invalidPreparation()
	}
	input, _, originalOK := original.source.AccountUnlinkPreparationInput()
	spec, _, issued := generated.source.AccountUnlinkCounterCommand()
	if !originalOK || !issued || spec.Binding != input.Binding || !sameAccountUnlinkRestoredIntent(*original.source, *generated.source) {
		return Reservation{}, invalidPreparation()
	}
	tx, err := c.pool.Raw().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Reservation{}, readFailure(ctx, err)
	}
	defer rollbackPreparation(tx)
	fence, err := beginJournal(ctx, tx, original, c.keys, r.journal, owner)
	if err != nil {
		return Reservation{}, err
	}
	raw, _ := base64.RawURLEncoding.DecodeString(string(original.commandID))
	var stored, declaration, previousPlan, fingerprint []byte
	var generation string
	if err := tx.QueryRow(ctx, `SELECT j.preparation_ciphertext,j.preparation_ciphertext_generation::text,j.preparation_declaration,j.command_plan,c.fingerprint
FROM identity.commands j JOIN identity.identity_command_id_claims c USING(command_id)
WHERE j.command_id=$1 AND j.tenant_id=$2 AND j.purpose=$3 AND j.preparation_profile=6`, raw, string(original.tenant), original.purpose).Scan(&stored, &generation, &declaration, &previousPlan, &fingerprint); err != nil {
		return Reservation{}, readFailure(ctx, err)
	}
	if !bytes.Equal(stored, wire) || !preparationGeneration(generation, r.outputGeneration) || len(fingerprint) != 32 {
		return Reservation{}, invalidPreparation()
	}
	// Recheck the actual stored original declaration rather than trusting an
	// in-memory plan retained across generation or a competing takeover.
	declared, err := decodeKernelPlan(spec.Binding, [32]byte(fingerprint), declaration)
	if err != nil || !sameAccountUnlinkDeclaration(spec.Binding, declared, final) {
		return Reservation{}, invalidPreparation()
	}
	disposition := claimReplay
	if previousPlan == nil {
		disposition = claimNew
	}
	p, err := c.freezePlan(ctx, tx, spec.Binding, original, disposition, final)
	if err != nil {
		return Reservation{}, err
	}
	state := &reservationState{coordinator: c, request: original, executionRequest: &generated, plan: p, journal: r.journal, owner: owner, preparation: &retainedFeaturePreparation{ciphertext: bytes.Clone(wire), generation: r.outputGeneration}}
	if _, err := accountUnlinkExecutionRequest(state); err != nil {
		return Reservation{}, err
	}
	if !validCapabilityIssuancePlan(&issuance) || len(issuance.Grants) != 1 || issuance.RegistrationUserID != "" || issuance.ResetRecipientUserID != "" || issuance.MagicLinkRecipientUserID != "" || issuance.MFAContinuationUserID != "" || issuance.Grants[0] != *p.capability {
		return Reservation{}, invalidPreparation()
	}
	journal := r.journal
	if previousPlan == nil {
		if err := c.issuePreparedAccountCapability(ctx, tx, state, fence, issuance, spec.Binding, spec.Proof); err != nil {
			return Reservation{}, err
		}
		journal.previousGeneration = 0
	}
	if err := c.reserveCapability(ctx, tx, original, p, journal, owner); err != nil {
		return Reservation{}, err
	}
	if err := c.commitPreparation(ctx, tx); err != nil {
		return Reservation{}, err
	}
	return Reservation{state: state}, nil
}
