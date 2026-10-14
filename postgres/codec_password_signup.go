package postgres

import identity "github.com/faustbrian/go-identity"

// Signup binds the exact prepared verifier and original pre-auth cookie, not a
// verifier-store digest or admitted flow projection. This is command identity;
// the native participant still owns password policy and bearer admission.
func encodePasswordSignupCustody(c identity.Command, key [32]byte, payload map[string][]byte) error {
	hash, cookie, ok := c.PasswordSignupCustody()
	if !ok {
		return codecError()
	}
	secret := []byte(hash)
	hashDigest, err := commandSecret(key, "password-signup-hash", secret, 16384)
	clear(secret)
	if err != nil {
		return codecError()
	}
	secret = []byte(cookie.Token())
	cookieDigest, err := commandSecret(key, "password-signup-cookie", secret, 86)
	clear(secret)
	if err != nil {
		return codecError()
	}
	payload["password-signup-hash"] = cborBytes(hashDigest)
	payload["password-signup-cookie"] = cborBytes(cookieDigest)
	return nil
}
