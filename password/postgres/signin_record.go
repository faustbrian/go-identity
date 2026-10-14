package passwordpostgres

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"

	auth "github.com/faustbrian/go-authentication"
	password "github.com/faustbrian/go-identity/password"
)

const maximumSigninRecordBytes = 32768

var _ auth.SignInSource = (*Repository)(nil)

// SignInAuthentication reads the immutable signed original password signin by
// exact proof ID from the primary. Only a committed original password-signin
// command is visible; missing, pending and aborted observations uniformly return
// authentication.ErrInvalidProof with zero data. The earlier caller deadline
// bounds Config.MaximumDuration. Corrupt or unavailable storage is redacted
// password.ErrPasswordWork; cancellation is preserved. Payloads are bounded in
// SQL before transfer and decoded with closed canonical framing.
//
// This reader is not authentication, a session workflow or current authorization.
// It preserves signature, credential/proof versions and original timestamps,
// never renewing, signing, consuming or creating a record. The configured
// authentication authority owns signature, issuer, audience, purpose and expiry
// validation; protected issuance still owns current checks and atomic one-time
// use. Pool ownership and concurrent-call semantics match Repository. No public
// setter exists: the owning signin workflow must persist originals through its
// sole coordinator after successful password authentication.
func (r *Repository) SignInAuthentication(ctx context.Context, id auth.ProofID) (auth.SignedSignInRecord, error) {
	if ctx == nil || !r.configuredWriter() || !validReauthenticationID(id) {
		return auth.SignedSignInRecord{}, password.ErrPasswordWork
	}
	bounded, cancel := context.WithTimeout(ctx, r.maximumDuration)
	defer cancel()
	if err := bounded.Err(); err != nil {
		return auth.SignedSignInRecord{}, err
	}
	rows, err := r.pool.Raw().Query(bounded, `SELECT p.tenant_id,p.user_id,
CASE WHEN octet_length(p.record)<=$2 THEN p.record ELSE ''::bytea END
FROM identity_password.signin_records p
JOIN identity.commands c USING(tenant_id,purpose,command_id)
WHERE p.proof_id=$1 AND p.purpose='identity.password.signin' AND c.state='committed' LIMIT 2`, string(id), maximumSigninRecordBytes)
	if err != nil {
		return auth.SignedSignInRecord{}, readerFailure(bounded)
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil || bounded.Err() != nil {
			return auth.SignedSignInRecord{}, readerFailure(bounded)
		}
		return auth.SignedSignInRecord{}, auth.ErrInvalidProof
	}
	var tenant, user string
	var payload []byte
	if err := rows.Scan(&tenant, &user, &payload); err != nil {
		return auth.SignedSignInRecord{}, readerFailure(bounded)
	}
	if rows.Next() || rows.Err() != nil {
		return auth.SignedSignInRecord{}, readerFailure(bounded)
	}
	if err := bounded.Err(); err != nil {
		return auth.SignedSignInRecord{}, err
	}
	result, err := decodeSigninRecord(id, tenant, user, payload)
	if canceled := bounded.Err(); canceled != nil {
		return auth.SignedSignInRecord{}, canceled
	}
	return result, err
}

// Upstream signing framing is the single structural authority. Canonical storage
// retains the complete original, including its signature; verification belongs
// to the configured authentication owner, not this codec or a second engine.
func encodeSigninRecord(r auth.SignedSignInRecord) ([]byte, error) {
	if !validReauthenticationID(r.Proof.ID) || r.Proof.Method != "password" || r.Proof.Assurance != auth.AssuranceSingleFactor || len(r.Signature) != ed25519.SignatureSize {
		return nil, password.ErrPasswordWork
	}
	if _, err := r.SigningBytes(); err != nil {
		return nil, password.ErrPasswordWork
	}
	payload, err := json.Marshal(r)
	if err != nil || len(payload) > maximumSigninRecordBytes {
		return nil, password.ErrPasswordWork
	}
	return payload, nil
}

func decodeSigninRecord(id auth.ProofID, tenant, user string, payload []byte) (auth.SignedSignInRecord, error) {
	bad := func() (auth.SignedSignInRecord, error) { return auth.SignedSignInRecord{}, password.ErrPasswordWork }
	if len(payload) == 0 || len(payload) > maximumSigninRecordBytes || !validReauthenticationID(id) {
		return bad()
	}
	var r auth.SignedSignInRecord
	d := json.NewDecoder(bytes.NewReader(payload))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF || r.Proof.ID != id || r.Proof.Tenant != tenant || r.Proof.Subject != user {
		return bad()
	}
	canonical, err := encodeSigninRecord(r)
	// Re-encoding equality rejects duplicates, case aliases and ignored input,
	// which encoding/json's decoder would otherwise accept even with closed fields.
	if err != nil || !bytes.Equal(canonical, payload) {
		return bad()
	}
	return r, nil
}
