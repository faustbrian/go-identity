package identity

import "strings"

// NewFeaturePasswordHashCommand freezes existing-password change metadata and
// an encoded hash in separate opaque custody. Hash transport is 1..16384 visible
// ASCII bytes, preserved exactly, never normalized. These are storage transport
// bounds only: the password owner must independently parse the reviewed encoding
// under its primitive limits, enforce HIBP/reuse/reauthentication/session policy,
// and bind the actual hash into the sole coordinator's keyed command intent.
// This function does not hash, verify, validate an algorithm or grant authority.
//
// Only identity/password's record-required identity.password.change profile is
// admitted. Unsupported signup/reset/rehash profiles and mixed OTP/bearer custody
// are not inferred. Invalid input returns zero Command and redacted InvalidInput.
// The legacy Feature accessor deliberately rejects this variant, preventing
// older coordinators from dropping material from command fingerprints. A native
// owner must explicitly select PasswordHashFeature and PasswordHash together.
// Construction performs no IO/callbacks and starts no goroutines. Command copies
// retain immutable verifier material; discard all copies after bounded use. Go
// cannot guarantee erasure of immutable strings. Never pass a plaintext password.
func NewFeaturePasswordHashCommand(spec FeatureCommandSpec, encodedHash string) (Command, error) {
	if !passwordHashOperation(spec.Operation) || !validPasswordHashTransport(encodedHash) {
		return Command{}, invalidFeatureCommand()
	}
	c, err := NewFeatureCommand(spec)
	if err != nil {
		return Command{}, err
	}
	frozen := strings.Clone(encodedHash)
	// A closure prevents fmt's unsupported-verb/private-wrapper reflection
	// fallback from walking a private string field and disclosing its contents.
	c.feature.passwordHash = func() string { return frozen }
	return c, nil
}

func validPasswordHashTransport(hash string) bool {
	if len(hash) == 0 || len(hash) > 16384 {
		return false
	}
	for i := range len(hash) {
		if hash[i] < '!' || hash[i] > '~' {
			return false
		}
	}
	return true
}

func passwordHashOperation(op FeatureOperation) bool {
	return op.Owner == "identity/password" && op.OperationID == "identity.password.change" && op.RecordRequirement == FeatureRecordRequired
}

func (c Command) validPasswordHashVariant() bool {
	return c.validFeatureVariant() && c.feature.passwordHash != nil && c.feature.passwordChange == nil && c.feature.passwordSignin == nil && c.feature.passwordSignup == nil && c.feature.code == nil && c.feature.preAuthCookie == nil && c.feature.sessionToken == nil && passwordHashOperation(c.feature.spec.Operation)
}

// PasswordHashFeature returns owned hash-free metadata only for the explicit
// password-hash variant. Zero, ordinary, kernel, unsupported and mixed commands
// deny. Projection mutation cannot change retained intent. No IO or callback
// runs. This accessor does not admit execution, validate hash policy or prove
// authorization. Native mapping must also bind the separately borrowed hash.
func (c Command) PasswordHashFeature() (FeatureCommandSpec, bool) {
	if !c.validPasswordHashVariant() {
		return FeatureCommandSpec{}, false
	}
	return cloneFeatureSpec(c.feature.spec), true
}

// PasswordHash explicitly borrows the original encoded verifier for bounded
// native fingerprinting, primitive parsing and driver persistence. Zero,
// ordinary, kernel, unsupported and mixed commands return empty/false. Never
// log, serialize, persist in the kernel journal or expose the borrowed string
// in a response; hash storage belongs only to the password adapter. This grants
// no password verification, proof, current authority or transaction ownership.
// Immutable concurrent reads are safe; discard borrowed strings after use.
func (c Command) PasswordHash() (string, bool) {
	if !c.validPasswordHashVariant() {
		return "", false
	}
	return c.feature.passwordHash(), true
}
