package identity

import (
	"strings"

	"github.com/faustbrian/go-capability/v2"
)

// NewFeaturePasswordResetCommand retains prepared replacement verifier material
// and the original upstream capability proof for a trusted native reset owner.
// Only identity/password's identity.password.reset-complete, password-reset-complete
// v1, record-required, user-targeted descriptor is supported. Hash transport is
// 1..16384 visible ASCII bytes, unchanged; proof transport is 32..4096 canonical
// bytes observed through upstream ValidateBounds. Invalid input returns a zero
// Command and redacted InvalidInputError without transferring the proof.
//
// This is structural custody, not signature validation, current account/factor
// authority, HIBP/hash policy, issuance provenance or permission to execute. The
// native owner must bind both original values into its keyed intent and reserve,
// mutate credentials, apply session effects and finalize capability use in one
// recoverable transaction. Existing execution paths reject this variant.
//
// Metadata and verifier are frozen; proof copies retain upstream shared lifetime
// semantics. Transfer through any alias invalidates all aliases. A successful
// bounds observation is not a liveness lease. No token bytes are copied, exposed,
// verified or transferred here. Construction performs no IO, callbacks or clock
// reads. Concurrent reads and upstream transfers are safe; callers must discard
// all secret-bearing copies after bounded use. Never pass a plaintext password.
func NewFeaturePasswordResetCommand(spec FeatureCommandSpec, encodedHash string, proof capability.Proof) (Command, error) {
	if !passwordResetOperation(spec.Operation) || !validPasswordHashTransport(encodedHash) || proof.ValidateBounds(32, 4096) != nil {
		return Command{}, invalidFeatureCommand()
	}
	c, err := NewFeatureCommand(spec)
	if err != nil {
		return Command{}, err
	}
	hash := strings.Clone(encodedHash)
	// Closure custody also prevents unsupported private-wrapper fmt reflection
	// from traversing verifier bytes or upstream private token storage.
	c.feature.passwordReset = func() (string, capability.Proof) { return hash, proof }
	return c, nil
}

func passwordResetOperation(op FeatureOperation) bool {
	return op.Owner == "identity/password" && op.OperationID == "identity.password.reset-complete" && op.SchemaID == "password-reset-complete" && op.SchemaVersion == 1 && op.RecordRequirement == FeatureRecordRequired && op.SubjectRequirement == FeatureSubjectUser
}

func (c Command) validPasswordResetVariant() bool {
	return c.validFeatureVariant() && c.feature.passwordReset != nil && passwordResetOperation(c.feature.spec.Operation)
}

// PasswordResetFeature returns an independently owned verifier/proof-free
// projection only for reset custody. Zero, mixed and other variants deny.
// Metadata survives proof transfer but grants no execution/recovery authority.
// Mutation of returned fields cannot change retained intent. No IO runs.
func (c Command) PasswordResetFeature() (FeatureCommandSpec, bool) {
	if !c.validPasswordResetVariant() {
		return FeatureCommandSpec{}, false
	}
	return cloneFeatureSpec(c.feature.spec), true
}

// PasswordResetCustody borrows the exact replacement verifier and original
// upstream proof together for bounded native fingerprinting and validation.
// Presence is structural, not current proof validity: aliases share terminal
// Transfer and the native owner must fail closed when verification denies.
// Zero, mixed and other variants return zero values and false. Never serialize,
// log or persist this pair in a command journal, recovery record or response.
// Verifier storage belongs only to the password adapter; immutable Go strings
// cannot be completely erased. No IO, transfer or consumption occurs here.
func (c Command) PasswordResetCustody() (string, capability.Proof, bool) {
	if !c.validPasswordResetVariant() {
		return "", capability.Proof{}, false
	}
	hash, proof := c.feature.passwordReset()
	return hash, proof, true
}
