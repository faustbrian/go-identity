package identity

import authentication "github.com/faustbrian/go-authentication/v2"

// NewFeatureRecoveryCodePreAuthCommand freezes a distinct recovery-code
// submission and its original canonical browser cookie for a trusted adapter.
// Neither secret enters scalar Feature metadata. Construction validates syntax
// only; the native owner must authenticate the original primary/continuation,
// compare the digest and burn the code with session effects in one transaction.
// This never coerces recovery material to OTP or grants factor assurance.
//
// Zero code, malformed cookie or invalid bounded spec returns zero Command and
// redacted InvalidInputError. Validation uses a discarded public-key digest,
// never a stored verifier. No IO, clocks or caller callbacks run. Immutable
// copies share secret custody and are safe for concurrent reads; discard every
// copy on terminal outcomes. Durable recovery uses secret-free metadata. Go
// cannot guarantee complete erasure of immutable credential storage.
func NewFeatureRecoveryCodePreAuthCommand(spec FeatureCommandSpec, code authentication.RecoveryCode, cookie authentication.BearerCredential) (Command, error) {
	frozen, err := freezeFeaturePreAuthCookie(cookie)
	if err != nil {
		return Command{}, err
	}
	c, err := NewFeatureCommand(spec)
	if err != nil {
		return Command{}, err
	}
	if _, err := code.KeyedDigest([32]byte{1}, []byte("identity.command.recovery.validation")); err != nil {
		return Command{}, invalidFeatureCommand()
	}
	c.feature.recovery, c.feature.preAuthCookie = &code, &frozen
	return c, nil
}

// RecoveryCode lends the exact opaque submitted recovery input to its trusted
// native fingerprint/comparison owner. It does not verify, consume or disclose
// a plaintext code. Zero, ordinary, OTP and mixed commands return zero/false.
// Copies remain immutable; discard after bounded use and never persist them.
func (c Command) RecoveryCode() (authentication.RecoveryCode, bool) {
	if c.feature == nil || c.feature.recovery == nil {
		return authentication.RecoveryCode{}, false
	}
	if _, ok := c.Feature(); !ok {
		return authentication.RecoveryCode{}, false
	}
	return *c.feature.recovery, true
}
