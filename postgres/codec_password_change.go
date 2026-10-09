package postgres

import identity "github.com/faustbrian/go-identity"

// Every original custody value belongs to the command fingerprint, not to the
// safe collision scope or raw journal. Signature/current-session validation and
// atomic consumption remain the native password phase's responsibility.
func encodePasswordChangeCustody(c identity.Command, key [32]byte, payload map[string][]byte) error {
	hash, bearer, proof, ok := c.PasswordChangeCustody()
	if !ok {
		return codecError()
	}
	p := proof.Proof
	// Signed native records use years 1..9999. Bound before Unix conversion so
	// an out-of-profile caller literal cannot wrap into another original instant.
	issuedYear, expiryYear := p.IssuedAt.UTC().Year(), p.ExpiresAt.UTC().Year()
	if issuedYear < 1 || issuedYear > 9999 || expiryYear < 1 || expiryYear > 9999 {
		return codecError()
	}
	encoded := cborMap(map[string][]byte{
		"id": cborText(string(p.ID)), "tenant": cborText(p.Tenant), "subject": cborText(p.Subject),
		"method": cborText(p.Method), "assurance": cborUint(uint64(p.Assurance)),
		"purpose": cborText(string(p.Purpose)), "audience": cborText(p.Audience),
		"issued_seconds": cborInt(p.IssuedAt.Unix()), "issued_nanoseconds": cborUint(uint64(p.IssuedAt.Nanosecond())),
		"expiry_seconds": cborInt(p.ExpiresAt.Unix()), "expiry_nanoseconds": cborUint(uint64(p.ExpiresAt.Nanosecond())),
		"session_id": cborText(proof.SessionID), "session_version": cborUint(proof.SessionVersion), "action": cborText(proof.Action),
	})
	defer clear(encoded)
	for _, input := range []struct {
		path    string
		value   []byte
		maximum int
	}{
		{"password-change-hash", []byte(hash), 16384},
		{"password-change-session", []byte(bearer.Token()), 86},
		{"password-change-proof", encoded, 8192},
	} {
		digest, err := commandSecret(key, input.path, input.value, input.maximum)
		clear(input.value)
		if err != nil {
			return err
		}
		payload[input.path] = cborBytes(digest)
	}
	return nil
}
