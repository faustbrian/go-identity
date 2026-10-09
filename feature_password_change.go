package identity

import (
	"time"

	"github.com/faustbrian/go-authentication"
)

// NewFeaturePasswordChangeCommand freezes existing-password change metadata,
// encoded hash, original session bearer and the sole upstream reauthentication
// proof together. Only identity/password's record-required password-change v1
// profile is admitted. Hash and bearer transport bounds are those documented
// by NewFeaturePasswordHashCommand and NewFeatureSessionCommand. Proof structure
// uses upstream authentication validation at its original issuance instant;
// tenant, subject and protected action must match the command and the proof
// purpose must be identity.password.verify. Original versions and nanoseconds
// are retained, not rounded or renewed. No current clock is sampled.
//
// Construction grants no authentication or mutation authority: the native
// password owner must reverify the signed original proof, current source session,
// hash/HIBP/reuse policy and consume the proof atomically with the mutation and
// session effects. This transport does not verify a signature or consume a proof.
// Existing feature, hash-only and session accessors reject this disjoint variant;
// a native executor must explicitly bind all PasswordChangeCustody values into
// its keyed intent before admitting execution or recovery. Existing executors
// remain closed to it. Invalid input returns zero Command and redacted error.
//
// Construction is bounded and pure, with no IO, callbacks or goroutines. Do not
// mutate inputs concurrently with construction. Copies are immutable and safe
// for concurrent reads; discard all secret-bearing copies after bounded use.
// Go cannot guarantee immutable string erasure. Never supply plaintext passwords.
func NewFeaturePasswordChangeCommand(spec FeatureCommandSpec, encodedHash string, bearer authentication.BearerCredential, proof authentication.ReauthenticationProof) (Command, error) {
	if !passwordChangeOperation(spec.Operation) || proof.Proof.Purpose != "identity.password.verify" {
		return Command{}, invalidFeatureCommand()
	}
	// Use the upstream structural contract rather than a second proof validator.
	// This historical instant deliberately establishes no current freshness.
	if proof.Validate(authentication.ReauthenticationUse{
		ProofUse:  authentication.ProofUse{Tenant: string(spec.Binding.TenantID), Subject: string(spec.Binding.UserID), Purpose: "identity.password.verify", Audience: proof.Proof.Audience, Now: proof.Proof.IssuedAt},
		SessionID: proof.SessionID, SessionVersion: proof.SessionVersion, Action: spec.Operation.OperationID, MaximumAge: 24 * time.Hour,
	}) != nil {
		return Command{}, invalidFeatureCommand()
	}
	frozenProof, err := authentication.NewProof(authentication.ProofSpec(proof.Proof))
	if err != nil {
		return Command{}, invalidFeatureCommand()
	}
	proof.Proof = frozenProof
	// The remaining immutable string fields are value copies. Their bytes cannot
	// be changed by subsequent assignment to the caller-owned proof projection.
	hashCommand, err := NewFeaturePasswordHashCommand(spec, encodedHash)
	if err != nil {
		return Command{}, err
	}
	bearerCommand, err := NewFeatureSessionCommand(spec, bearer)
	if err != nil {
		return Command{}, err
	}
	hash := hashCommand.feature.passwordHash()
	token := *bearerCommand.feature.sessionToken
	hashCommand.feature.passwordHash = nil
	// Closure custody prevents fmt reflection on private wrapper fields from
	// traversing raw verifier, bearer or proof material.
	hashCommand.feature.passwordChange = func() (string, authentication.BearerCredential, authentication.ReauthenticationProof) {
		return hash, token, proof
	}
	return hashCommand, nil
}

func passwordChangeOperation(op FeatureOperation) bool {
	return passwordHashOperation(op) && op.SchemaID == "password-change" && op.SchemaVersion == 1
}

func (c Command) validPasswordChangeVariant() bool {
	return c.validFeatureVariant() && c.feature.passwordChange != nil && c.feature.passwordHash == nil && c.feature.code == nil && c.feature.preAuthCookie == nil && c.feature.sessionToken == nil && passwordChangeOperation(c.feature.spec.Operation)
}

// PasswordChangeFeature returns owned hash/bearer/proof-free command metadata
// only for the authenticated password-change custody variant. Zero, mixed and
// every other variant return false. Mutating a projection cannot alter intent.
// This does not grant execution or authority; the native executor must also
// select and exhaustively bind PasswordChangeCustody. No IO or callbacks run.
func (c Command) PasswordChangeFeature() (FeatureCommandSpec, bool) {
	if !c.validPasswordChangeVariant() {
		return FeatureCommandSpec{}, false
	}
	return cloneFeatureSpec(c.feature.spec), true
}

// PasswordChangeCustody borrows the original hash, opaque source bearer and
// upstream proof together for trusted native fingerprinting and validation.
// Zero, mixed and other variants return empty values and false. Returned proof
// is a caller-owned value: assignment cannot change retained custody. Never
// serialize/log these values or put them in the journal or public responses.
// Borrowing grants no signed provenance, freshness, consumption or transaction
// authority. Immutable concurrent reads are safe; discard copies after use.
func (c Command) PasswordChangeCustody() (string, authentication.BearerCredential, authentication.ReauthenticationProof, bool) {
	if !c.validPasswordChangeVariant() {
		return "", authentication.BearerCredential{}, authentication.ReauthenticationProof{}, false
	}
	hash, bearer, proof := c.feature.passwordChange()
	return hash, bearer, proof, true
}
