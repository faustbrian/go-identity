package passwordpostgres

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"

	auth "github.com/faustbrian/go-authentication/v2"
	password "github.com/faustbrian/go-identity/password"
)

const maximumReauthenticationRecordBytes = 32768

var _ auth.ReauthenticationSource = (*Repository)(nil)

// Reauthentication reads the immutable original signed password verification
// by its globally unique proof ID. Only an original coordinator command marked
// committed is visible; pending, aborted and absent records return the same
// ErrInvalidProof without any partial data. Earlier caller deadlines win over
// Config.MaximumDuration. Corrupt/oversized records, missing schema and primary
// failures return redacted password.ErrPasswordWork; cancellation is preserved.
// It never checks current owners, authenticates the signature, renews freshness,
// consumes a proof, issues a session or creates missing state. Authentication's
// configured evidence-key validator owns signature and exact-use validation;
// protected workflows still require current primary checks and atomic one-use
// finalization. Borrowed pool ownership and concurrent-use rules match Repository.
func (r *Repository) Reauthentication(ctx context.Context, id auth.ProofID) (auth.SignedReauthenticationRecord, error) {
	if ctx == nil || !r.configuredWriter() || !validReauthenticationID(id) {
		return auth.SignedReauthenticationRecord{}, password.ErrPasswordWork
	}
	bounded, cancel := context.WithTimeout(ctx, r.maximumDuration)
	defer cancel()
	if err := bounded.Err(); err != nil {
		return auth.SignedReauthenticationRecord{}, err
	}
	rows, err := r.pool.Raw().Query(bounded, `SELECT p.tenant_id,p.user_id,
CASE WHEN octet_length(p.record)<=$2 THEN p.record ELSE ''::bytea END
FROM identity_password.reauthentication_records p
JOIN identity.commands c USING(tenant_id,purpose,command_id)
WHERE p.proof_id=$1 AND c.state='committed' LIMIT 2`, string(id), maximumReauthenticationRecordBytes)
	if err != nil {
		return auth.SignedReauthenticationRecord{}, readerFailure(bounded)
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil || bounded.Err() != nil {
			return auth.SignedReauthenticationRecord{}, readerFailure(bounded)
		}
		return auth.SignedReauthenticationRecord{}, auth.ErrInvalidProof
	}
	var tenant, user string
	var payload []byte
	if err := rows.Scan(&tenant, &user, &payload); err != nil {
		return auth.SignedReauthenticationRecord{}, readerFailure(bounded)
	}
	if rows.Next() || rows.Err() != nil {
		return auth.SignedReauthenticationRecord{}, readerFailure(bounded)
	}
	if err := bounded.Err(); err != nil {
		return auth.SignedReauthenticationRecord{}, err
	}
	raw, err := decodeReauthenticationRecord(id, tenant, user, payload)
	if canceled := bounded.Err(); canceled != nil {
		return auth.SignedReauthenticationRecord{}, canceled
	}
	return raw, err
}

func validReauthenticationID(id auth.ProofID) bool {
	if len(id) < 22 || len(id) > 128 {
		return false
	}
	for i := range len(id) {
		if id[i] < 33 || id[i] > 126 {
			return false
		}
	}
	return true
}

// One representation retains the upstream record, signature and nanosecond
// timestamps exactly. Native issuance will write it only through the original
// Work; there is intentionally no public setter or consumer-written store port.
func encodeReauthenticationRecord(r auth.SignedReauthenticationRecord) ([]byte, error) {
	if !validReauthenticationID(r.Proof.Proof.ID) || r.Proof.Proof.Method != "password" || r.Proof.Proof.Assurance != auth.AssuranceSingleFactor || len(r.Signature) != ed25519.SignatureSize {
		return nil, password.ErrPasswordWork
	}
	if _, err := r.SigningBytes(); err != nil {
		return nil, password.ErrPasswordWork
	}
	encoded, err := json.Marshal(r)
	if err != nil || len(encoded) > maximumReauthenticationRecordBytes {
		return nil, password.ErrPasswordWork
	}
	return encoded, nil
}

func decodeReauthenticationRecord(id auth.ProofID, tenant, user string, payload []byte) (auth.SignedReauthenticationRecord, error) {
	bad := func() (auth.SignedReauthenticationRecord, error) {
		return auth.SignedReauthenticationRecord{}, password.ErrPasswordWork
	}
	if len(payload) == 0 || len(payload) > maximumReauthenticationRecordBytes || !validReauthenticationID(id) {
		return bad()
	}
	var r auth.SignedReauthenticationRecord
	d := json.NewDecoder(bytes.NewReader(payload))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF || r.Proof.Proof.ID != id || r.Proof.Proof.Tenant != tenant || r.Proof.Proof.Subject != user {
		return bad()
	}
	canonical, err := encodeReauthenticationRecord(r)
	// Canonical bytes additionally reject duplicate names, aliased field names,
	// ignored union data and trailing JSON; json.Unmarshal alone cannot do so.
	if err != nil || !bytes.Equal(canonical, payload) {
		return bad()
	}
	return r, nil
}
