package passwordpostgres

import (
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	primitive "github.com/faustbrian/go-password/v2"
)

// Original must come from authenticated durable issuance custody. Grant must
// be verified from this command's borrowed proof, and consumption must be the
// real issuer's preparation for that exact command and retained replay version.
// These inputs are private native-phase dependencies, never client metadata.
// This closes signed-scope/material composition, not current recovery admission:
// original identifier/factors/risk must still be fenced inside the sole Work.
// No hashing, SQL, transfer, consumption, renewal or secret retention occurs.
// ExpectedUserVersion is aggregate CAS, not the signed user security epoch.
// The kernel checks that CAS against current storage; the native workflow must
// separately fence original.UserAuthorityVersion through its directory admission.
func passwordResetOriginalMaterial(c identity.Command, policy primitive.Policy, profile password.ResetProfile, original password.ResetGrantSpec, grant capability.Grant, consumption kernel.CapabilityPlan, now time.Time) (kernel.CredentialResetIntent, primitive.EncodedHash, error) {
	i, hash, err := passwordResetMaterial(c, policy)
	if err != nil {
		return kernel.CredentialResetIntent{}, primitive.EncodedHash{}, err
	}
	if err := passwordResetOriginalIntent(i, profile, original, grant, consumption, now); err != nil {
		return kernel.CredentialResetIntent{}, primitive.EncodedHash{}, err
	}
	return i, hash, nil
}

func passwordResetOriginalIntent(i kernel.CredentialResetIntent, profile password.ResetProfile, original password.ResetGrantSpec, grant capability.Grant, consumption kernel.CapabilityPlan, now time.Time) error {
	payload := grant.Payload()
	r := i.Replacement
	if profile.Authorize(grant, original, now) != nil || r.Credential.TenantID != original.TenantID || r.Credential.UserID != original.UserID || r.Credential.ID != original.CredentialID || r.Credential.Version != original.CredentialVersion || r.ExpectedAuthorityVersion != original.CredentialAuthorityVersion || consumption.Purpose != "identity.password.reset-complete" || consumption.CapabilityID != payload.ID || consumption.ProofFingerprint == ([32]byte{}) || consumption.ProofFingerprint != grant.EnvelopeDigest() || consumption.ReplayKeyVersion == 0 || consumption.ReplayDigest == ([32]byte{}) || consumption.MaxUses != 1 || !consumption.ExpiresAt.Equal(original.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	return nil
}
