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

// Original raw input and generated verifier occupy separate domains under the
// existing claim owner. This binds bytes exactly without retaining plaintext.
func encodePasswordResetInputCustody(c identity.Command, key [32]byte, payload map[string][]byte) error {
	password, proof, ok := c.PasswordResetInputCustody()
	if !ok {
		return codecError()
	}
	var digest []byte
	err := password.Use(func(raw []byte) error {
		if len(raw) == 0 {
			return codecError()
		}
		var err error
		digest, err = commandSecret(key, "password-reset-input-password", raw, 1<<20)
		return err
	})
	if err != nil {
		return codecError()
	}
	proofDigest, err := proof.CommandDigest(key, "password-reset-input-proof", 4096)
	if err != nil {
		return codecError()
	}
	payload["password-reset-input-password"] = cborBytes(digest)
	payload["password-reset-input-proof"] = cborBytes(proofDigest[:])
	return nil
}
