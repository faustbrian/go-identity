package postgres

import identity "github.com/faustbrian/go-identity"

// An operation name alone does not select this custody profile: other already
// registered signin schemas (including consuming CAPTCHA) retain their mapping.
func passwordSigninOperation(op identity.FeatureOperation) bool {
	profile := op.Owner == "identity/password" && op.OperationID == "identity.password.signin" && op.SchemaID == "password-signin" || op.Owner == "identity/username" && op.OperationID == "identity.username.signin" && op.SchemaID == "username-signin" || op.Owner == "identity/phone" && op.OperationID == "identity.phone.password-signin" && op.SchemaID == "phone-password-signin"
	return profile && op.SchemaVersion == 1 && op.RecordRequirement == identity.FeatureRecordOmitted && op.SubjectRequirement <= identity.FeatureSubjectAnonymousFlow
}

// Original signin custody participates in retained-key command identity without
// becoming durable authority. The native password participant still owns actual
// comparison, pre-auth admission and same-transaction session/policy effects.
func encodePasswordSigninCustody(c identity.Command, key [32]byte, payload map[string][]byte) error {
	password, cookie, ok := c.PasswordSigninCustody()
	if !ok {
		return codecError()
	}
	var passwordDigest []byte
	err := password.Use(func(raw []byte) error {
		if len(raw) == 0 {
			return codecError()
		}
		var err error
		passwordDigest, err = commandSecret(key, "password-signin-password", raw, 1<<20)
		return err
	})
	if err != nil {
		return codecError()
	}
	// The cookie temporary is cleared synchronously. Password.Use owns and
	// clears its borrow on every return; no raw bytes enter payload or scope.
	secret := []byte(cookie.Token())
	cookieDigest, err := commandSecret(key, "password-signin-cookie", secret, 86)
	clear(secret)
	if err != nil {
		return codecError()
	}
	payload["password-signin-password"] = cborBytes(passwordDigest)
	payload["password-signin-cookie"] = cborBytes(cookieDigest)
	return nil
}
