package identity

import (
	"github.com/faustbrian/go-capability"
	primitive "github.com/faustbrian/go-password"
)

// NewFeaturePasswordResetInputCommand freezes original password-reset input
// before a replacement verifier exists. It admits only the exact user-targeted
// password-reset-complete v1 descriptor. The password is 1..1 MiB and proof
// transport is 32..4096 canonical bytes; workflow policy may narrow both.
// No bytes are copied, normalized, hashed, verified or consumed. Construction
// grants no issuance provenance, current recovery authority or execution.
//
// This variant is preparation-only. The existing journal binds original borrowed
// password/proof custody before acknowledged, admission-gated generation. Only
// NewFeaturePasswordResetCommand selects the generated verifier for execution.
// Callers must keep both owners alive during bounded use and destroy their
// password afterward. Copies share terminal Secret destruction and upstream
// Proof transfer. Structural presence is not a liveness lease. No IO, callbacks,
// clocks or goroutines run; errors return zero and redacted InvalidInputError.
func NewFeaturePasswordResetInputCommand(spec FeatureCommandSpec, password primitive.Secret, proof capability.Proof) (Command, error) {
	if !passwordResetOperation(spec.Operation) || password.Len() == 0 || password.Len() > 1<<20 || proof.ValidateBounds(32, 4096) != nil {
		return Command{}, invalidFeatureCommand()
	}
	c, err := NewFeatureCommand(spec)
	if err != nil {
		return Command{}, err
	}
	c.feature.passwordResetInput = func() (primitive.Secret, capability.Proof) { return password, proof }
	return c, nil
}

func (c Command) validPasswordResetInputVariant() bool {
	return c.validFeatureVariant() && c.feature.passwordResetInput != nil && passwordResetOperation(c.feature.spec.Operation)
}

// PasswordResetInputFeature returns independently owned secret-free metadata
// for original reset preparation only. Zero, mixed and generated variants deny.
// Metadata survives owner destruction/transfer but grants no authority.
func (c Command) PasswordResetInputFeature() (FeatureCommandSpec, bool) {
	if !c.validPasswordResetInputVariant() {
		return FeatureCommandSpec{}, false
	}
	return cloneFeatureSpec(c.feature.spec), true
}

// PasswordResetInputCustody borrows the original Secret and proof together.
// Copies retain shared terminal owner lifetimes; recheck on every bounded use.
// Never serialize, log or persist this pair. Presence is not authentication or
// permission to hash, reserve or consume. Zero and other variants deny.
func (c Command) PasswordResetInputCustody() (primitive.Secret, capability.Proof, bool) {
	if !c.validPasswordResetInputVariant() {
		return primitive.Secret{}, capability.Proof{}, false
	}
	p, proof := c.feature.passwordResetInput()
	return p, proof, true
}
