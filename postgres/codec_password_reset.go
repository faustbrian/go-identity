package postgres

import identity "github.com/faustbrian/go-identity"

func passwordResetOperation(op identity.FeatureOperation) bool {
	return op.Owner == "identity/password" && op.OperationID == "identity.password.reset-complete"
}

// Bind original submitted custody before validity/admission so retained-key
// journal replay does not acquire new meaning when the token expires. This
// neither transfers the proof nor admits it as a grant or one-time reservation.
func encodePasswordResetCustody(c identity.Command, key [32]byte, payload map[string][]byte) error {
	hash, proof, ok := c.PasswordResetCustody()
	if !ok {
		return codecError()
	}
	secret := []byte(hash)
	digest, err := commandSecret(key, "password-reset-hash", secret, 16384)
	clear(secret)
	if err != nil {
		return codecError()
	}
	proofDigest, err := proof.CommandDigest(key, "password-reset-proof", 4096)
	if err != nil {
		return codecError()
	}
	payload["password-reset-hash"] = cborBytes(digest)
	payload["password-reset-proof"] = cborBytes(proofDigest[:])
	return nil
}
