package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

// Freeze the complete code-free declaration in the existing journal before any
// charge. It is distinct from the generated final plan, whose audit/delivery
// custody can depend on output. Retained claim keys, not the current key, bind
// charge provenance across process restart and key rotation.
func (c *Coordinator) freezePreparationCounters(ctx context.Context, tx pgx.Tx, q claimRequest, p *admittedKernelPlan, command identity.Command) (*admittedKernelPlan, error) {
	id, _ := base64.RawURLEncoding.DecodeString(string(q.commandID))
	var fingerprint, stored []byte
	if err := tx.QueryRow(ctx, `SELECT c.fingerprint,j.preparation_declaration FROM identity.identity_command_id_claims c JOIN identity.commands j USING(command_id) WHERE c.command_id=$1 AND j.tenant_id=$2 AND j.purpose=$3 FOR UPDATE OF j`, id, string(q.tenant), q.purpose).Scan(&fingerprint, &stored); err != nil {
		return nil, readFailure(ctx, err)
	}
	if len(fingerprint) != 32 {
		return nil, identity.UnavailableError{}
	}
	retained := [32]byte(fingerprint)
	declaration := p.snapshot()
	wire, err := encodeFeaturePlan(p.binding, retained, declaration)
	if err != nil || len(wire) > 65536 {
		return nil, invalidPreparation()
	}
	declaration.Digest = sha256.Sum256(wire)
	if declaration.MFACompletion != nil && declaration.OTP != nil && validMFACompletionPlan(p.binding, declaration) {
		spec, ok := command.Feature()
		if !ok {
			return nil, invalidPreparation()
		}
		wire, err = encodeMFAOTPPreparation(spec, retained, declaration)
		if err != nil {
			return nil, err
		}
	}
	if stored == nil {
		tag, err := tx.Exec(ctx, `UPDATE identity.commands SET preparation_declaration=$4 WHERE command_id=$1 AND tenant_id=$2 AND purpose=$3 AND preparation_profile IN (3,4) AND preparation_declaration IS NULL AND preparation_started_generation IS NULL`, id, string(q.tenant), q.purpose, wire)
		if err != nil {
			return nil, readFailure(ctx, err)
		}
		if tag.RowsAffected() != 1 {
			return nil, identity.ConflictError{}
		}
	} else if !bytes.Equal(stored, wire) {
		return nil, identity.ConflictError{}
	}
	// This remains the original code-free declaration, not generated issuance.
	return c.registry.admitFeaturePlanMode(p.binding, retained, declaration, true)
}
