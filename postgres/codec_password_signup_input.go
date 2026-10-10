package postgres

import identity "github.com/faustbrian/go-identity"

// Original input and generated verifier have distinct secret domains under the
// same retained-key claim owner. No secondary fingerprint or journal is used.
func encodePasswordSignupInputCustody(c identity.Command, key [32]byte, payload map[string][]byte) error {
	password, cookie, ok := c.PasswordSignupInputCustody()
	if !ok {
		return codecError()
	}
	var passwordDigest []byte
	err := password.Use(func(raw []byte) error {
		if len(raw) == 0 {
			return codecError()
		}
		var err error
		passwordDigest, err = commandSecret(key, "password-signup-input-password", raw, 1<<20)
		return err
	})
	if err != nil {
		return codecError()
	}
	secret := []byte(cookie.Token())
	cookieDigest, err := commandSecret(key, "password-signup-input-cookie", secret, 86)
	clear(secret)
	if err != nil {
		return codecError()
	}
	payload["password-signup-input-password"] = cborBytes(passwordDigest)
	payload["password-signup-input-cookie"] = cborBytes(cookieDigest)
	return nil
}
