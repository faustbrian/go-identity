package postgres

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

type claimDisposition uint8

const (
	claimInvalid claimDisposition = iota
	claimNew
	claimReplay
	claimConflict
)

// These are coordinator-private prepared inputs, not caller fingerprint or
// transaction extension points. The owned command codec will supply canonical
// CBOR and safe collision fields; raw canonical commands are never persisted.
// The coordinator snapshots these bounded inputs before opening a transaction.
type claimRequest struct {
	commandID             identity.CommandID
	tenant                identity.TenantID
	purpose               string
	canonical, safeFields []byte
	// Only the owned typed codec populates source. Replays must regenerate its
	// secret digests under the stored key, not the newest issuance key.
	source *identity.Command
}
type claimKeys struct {
	current  uint32
	retained map[uint32][32]byte
}

// lockCommandClaim is the first private admission step, not ReserveCommand.
// It never begins, commits, rolls back or grants domain mutation authority.
// The sole coordinator must atomically create a scoped pending row and reserve
// all declared participants before committing a claimNew outcome. Errors here
// do not establish rollback; the coordinator owns closure and unknown handling.
func lockCommandClaim(ctx context.Context, tx pgx.Tx, q claimRequest, keys claimKeys) (claimDisposition, error) {
	if ctx == nil || tx == nil || !validClaim(q, keys) {
		return claimInvalid, identity.InvalidInputError{Field: "command_claim"}
	}
	if _, ok := ctx.Deadline(); !ok {
		return claimInvalid, identity.InvalidInputError{Field: "command_claim_context"}
	}
	if err := ctx.Err(); err != nil {
		return claimInvalid, readFailure(ctx, err)
	}
	id, _ := base64.RawURLEncoding.DecodeString(string(q.commandID))
	digest := claimFingerprint(keys.retained[keys.current], q.canonical)
	inserted, err := tx.Exec(ctx, `INSERT INTO identity.identity_command_id_claims
(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields)
VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(command_id) DO NOTHING`, id, string(q.tenant), q.purpose, digest[:], int64(keys.current), q.safeFields)
	if err != nil {
		return claimInvalid, readFailure(ctx, err)
	}
	var tenant, purpose *string
	var keyVersion *int64
	var fingerprint, safe []byte
	var retired bool
	err = tx.QueryRow(ctx, `SELECT tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields,retired
FROM identity.identity_command_id_claims WHERE command_id=$1 FOR UPDATE`, id).Scan(&tenant, &purpose, &fingerprint, &keyVersion, &safe, &retired)
	if err != nil {
		if ctx.Err() != nil {
			return claimInvalid, readFailure(ctx, ctx.Err())
		}
		return claimInvalid, identity.UnavailableError{}
	}
	if retired {
		return claimConflict, nil
	}
	if tenant == nil || purpose == nil || keyVersion == nil || *keyVersion < 1 || *keyVersion > 4294967295 || len(fingerprint) != 32 || len(safe) == 0 {
		return claimInvalid, identity.UnavailableError{}
	}
	if *tenant != string(q.tenant) || *purpose != q.purpose || !bytes.Equal(safe, q.safeFields) {
		return claimConflict, nil
	}
	key, ok := keys.retained[uint32(*keyVersion)]
	if !ok {
		return claimInvalid, identity.UnavailableError{}
	}
	canonical := q.canonical
	if q.source != nil {
		prepared, err := prepareClaim(*q.source, key)
		if err != nil {
			return claimInvalid, err
		}
		canonical = prepared.canonical
	}
	expected := claimFingerprint(key, canonical)
	if !hmac.Equal(fingerprint, expected[:]) {
		return claimConflict, nil
	}
	if inserted.RowsAffected() == 1 {
		return claimNew, nil
	}
	var exists bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM identity.commands
WHERE command_id=$1 AND tenant_id=$2 AND purpose=$3)`, id, string(q.tenant), q.purpose).Scan(&exists)
	if err != nil {
		return claimInvalid, readFailure(ctx, err)
	}
	if !exists {
		return claimInvalid, identity.UnavailableError{}
	}
	return claimReplay, nil
}

func validClaim(q claimRequest, keys claimKeys) bool {
	if _, err := identity.ParseCommandID(string(q.commandID)); err != nil {
		return false
	}
	if (identity.User{ID: "claim-input", TenantID: q.tenant, Status: identity.StatusActive, Version: 1}).Validate(q.tenant) != nil {
		return false
	}
	if len(q.purpose) == 0 || len(q.purpose) > 128 || len(q.canonical) == 0 || len(q.canonical) > 1<<20 || len(q.safeFields) == 0 || len(q.safeFields) > 65536 {
		return false
	}
	for i, b := range []byte(q.purpose) {
		if b >= 'a' && b <= 'z' {
			continue
		}
		if i == 0 || !(b >= '0' && b <= '9' || b == '.' || b == '_' || b == ':' || b == '/' || b == '-') {
			return false
		}
	}
	if keys.current == 0 || len(keys.retained) == 0 || len(keys.retained) > 32 {
		return false
	}
	if _, ok := keys.retained[keys.current]; !ok {
		return false
	}
	for version, key := range keys.retained {
		if version == 0 || key == ([32]byte{}) {
			return false
		}
	}
	return true
}

func claimFingerprint(key [32]byte, canonical []byte) [32]byte {
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write(canonical)
	var result [32]byte
	copy(result[:], mac.Sum(nil))
	return result
}
