package identity

import authentication "github.com/faustbrian/go-authentication"

// NewFeatureOneTimeCodeCommand freezes structural feature intent and one opaque
// submitted code for a trusted native adapter. Code bytes never enter FeatureValue
// or FeatureCommandSpec, and Feature returns only the code-free metadata. This
// carries custody, not successful verification, authorization or one-time use.
// The owning feature validates its exact schema, scope and code profile; the
// sole durable coordinator binds the secret in its keyed command fingerprint.
// Unsupported one-time profiles must be rejected before durable admission.
//
// The constructor validates nonzero code through a discarded bounded digest
// with a public validation-only key, never a stored verifier or authority key.
// It accepts no request-selected digest. Existing structural bounds, defensive
// copying and errors are identical to NewFeatureCommand; zero code returns
// InvalidInputError. It performs no IO or callbacks and is safe for immutable
// concurrent reads. Command copies retain the secret; discard every copy on a
// terminal outcome and retain only code-free recovery metadata on ambiguity.
// Go cannot guarantee complete erasure of immutable secret storage.
func NewFeatureOneTimeCodeCommand(spec FeatureCommandSpec, code authentication.OneTimeCode) (Command, error) {
	c, err := NewFeatureCommand(spec)
	if err != nil {
		return Command{}, err
	}
	if _, err := code.CommandDigest([32]byte{1}, "identity.command.validation"); err != nil {
		return Command{}, invalidFeatureCommand()
	}
	c.feature.code = &code
	return c, nil
}

// OneTimeCode borrows opaque code custody only for trusted fingerprinting and
// counted primary verification. False and zero code are returned for ordinary,
// zero, kernel and mixed commands. It does not verify, consume or grant a proof.
// Returned copies remain immutable; discard them after use. No secret bytes,
// persisted digest or conversion accessor is exposed. No IO or state changes.
func (c Command) OneTimeCode() (authentication.OneTimeCode, bool) {
	if c.feature == nil || c.feature.code == nil {
		return authentication.OneTimeCode{}, false
	}
	if _, ok := c.Feature(); !ok {
		return authentication.OneTimeCode{}, false
	}
	return *c.feature.code, true
}
