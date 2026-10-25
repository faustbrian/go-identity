package mfapostgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// PersistPasskeyContinuation stores the original pending TOTP-only challenge
// during its registered native UV assertion owner's protected Apply. The owner
// must first prove the genuine assertion and original browser in this Work.
// Frozen child scope, original primary identity and current enrolled factor
// generation must agree. This neither authenticates an assertion nor issues a
// capability/session. Duplicate insertion never resets attempts or expiry;
// propagate every error to the sole coordinator for atomic rollback.
func PersistPasskeyContinuation(ctx context.Context, w kernel.Work, owner kernel.PasskeyMFAChallengeContributor, command identity.Command, c mfa.PartialAuthContinuation) error {
	if ctx == nil || owner == nil {
		return invalidAuthority()
	}
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return err
	}
	challenge, err := w.PasskeyMFAChallenge(owner)
	if err != nil {
		return err
	}
	b, fingerprint, generation, err := w.FeatureCommandIdentity(owner)
	if err != nil {
		return err
	}
	if !passkeyContinuationMatches(c, b, challenge) {
		return identity.ForbiddenError{}
	}
	if err := RequirePasskeySigninFactors(ctx, w, owner, command, b.UserID, challenge.FactorVersion); err != nil {
		return err
	}
	return persistContinuation(ctx, w, c, b, fingerprint, generation)
}

func passkeyContinuationMatches(c mfa.PartialAuthContinuation, b identity.CommandBinding, challenge kernel.MFAContinuationPlan) bool {
	s, err := c.Bindings()
	if err != nil || s.PasskeyCommandID != b.CommandID || s.VerificationCommandID != "" || len(s.AllowedMethods) != 1 || s.AllowedMethods[0] != "totp" {
		return false
	}
	digest, err := c.ScopeDigest()
	return err == nil && s.State == mfa.Pending && s.Version == 1 && s.ID == mfa.ContinuationID(challenge.ID) && s.SubjectID == identity.SubjectID(challenge.UserID) && s.SubjectID == identity.SubjectID(b.UserID) && s.TenantID == b.TenantID && string(s.PrimaryProofID) == string(b.CommandID) && digest == challenge.ScopeDigest && s.PolicyVersion == challenge.PolicyVersion && s.FactorVersion == challenge.FactorVersion && s.IssuedAt.Equal(challenge.IssuedAt) && s.ExpiresAt.Equal(challenge.ExpiresAt)
}
