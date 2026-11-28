package impersonationpostgres

import (
	"context"
	"strconv"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/impersonation"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

const stopProofInsertSQL = `INSERT INTO identity_impersonation.stop_proofs
 (tenant_id,grant_id,activation_command_id,csrf_key,csrf_digest)
 VALUES($1,$2,$3,$4::text::bigint,$5)`
const stopProofSelectSQL = `SELECT activation_command_id,csrf_key::text,csrf_digest
 FROM identity_impersonation.stop_proofs WHERE tenant_id=$1 AND grant_id=$2`

// A stop proof belongs to the originally issued child (version 3), even
// when authenticating its already-terminal metadata-only replay.
func stopProofBinding(tenant identity.TenantID, grant impersonation.GrantID) session.CSRFBinding {
	return session.CSRFBinding{TenantID: tenant, SessionID: "impersonation:" + string(grant), SessionVersion: 3}
}

func newStopProof(tenant identity.TenantID, grant impersonation.GrantID, key session.CSRFKey) (session.CSRFToken, session.CSRFStateSpec, error) {
	if !validStoredGrantKey(tenant, grant) {
		return session.CSRFToken{}, session.CSRFStateSpec{}, impersonation.ErrInvalidInput
	}
	token, err := session.NewCSRFToken()
	if err != nil {
		return session.CSRFToken{}, session.CSRFStateSpec{}, err
	}
	proof, err := token.Digest(key, stopProofBinding(tenant, grant))
	if err != nil {
		return session.CSRFToken{}, session.CSRFStateSpec{}, err
	}
	spec, err := proof.Bindings()
	return token, spec, err
}

func stopProofInsertArgs(row activationRecord, proof session.CSRFStateSpec) []any {
	return []any{string(row.tenant), string(row.grantID), string(row.commandID), strconv.FormatUint(uint64(proof.KeyVersion), 10), proof.Digest[:]}
}

func storeStopProof(ctx context.Context, w kernel.Work, row activationRecord, proof session.CSRFStateSpec) error {
	if proof.Binding != stopProofBinding(row.tenant, row.grantID) {
		return invalidStorageInput()
	}
	if _, err := session.NewCSRFState(proof); err != nil {
		return invalidStorageInput()
	}
	count, err := w.Exec(ctx, stopProofInsertSQL, stopProofInsertArgs(row, proof)...)
	if err != nil {
		return err
	}
	if count != 1 {
		return impersonation.ErrConflict
	}
	return nil
}

func loadStopProof(ctx context.Context, rows storedGrantRows, row activationRecord) (session.CSRFStateSpec, error) {
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return session.CSRFStateSpec{}, storageReadError(ctx)
		}
		return session.CSRFStateSpec{}, identity.ForbiddenError{}
	}
	var command, key string
	var digest []byte
	if err := rows.Scan(&command, &key, &digest); err != nil || rows.Next() || rows.Err() != nil ||
		command != string(row.commandID) || len(digest) != 32 {
		return session.CSRFStateSpec{}, storageReadError(ctx)
	}
	version, err := strconv.ParseUint(key, 10, 32)
	if err != nil || version == 0 || strconv.FormatUint(version, 10) != key {
		return session.CSRFStateSpec{}, storageReadError(ctx)
	}
	spec := session.CSRFStateSpec{Binding: stopProofBinding(row.tenant, row.grantID), KeyVersion: uint32(version)}
	copy(spec.Digest[:], digest)
	if _, err := session.NewCSRFState(spec); err != nil {
		return session.CSRFStateSpec{}, storageReadError(ctx)
	}
	return spec, nil
}

func checkStopProof(proof session.CSRFStateSpec, token session.CSRFToken, key session.CSRFKey) error {
	state, err := session.NewCSRFState(proof)
	if err != nil || state.Check(proof.Binding, token, key) != nil {
		return identity.ForbiddenError{}
	}
	return nil
}
