package mfapostgres

import (
	"context"
	"encoding/base64"
	"strconv"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// PersistMagicLinkContinuation stores one original challenge only during the
// exact native owner's protected Apply, after same-Work primary consumption.
// Frozen child scope, primary identity/expiry and enrolled factor generation
// must match. It starts no transaction, issues no capability/session and stores
// no bearer or factor secret. Return every error to the coordinator; all effects
// still depend on its final authority checks, child issuance and sole commit.
// Duplicate insertion denies instead of renewing lifetime or resetting attempts.
func PersistMagicLinkContinuation(ctx context.Context, w kernel.Work, owner kernel.MagicLinkMFAChallengeContributor, command identity.Command, c mfa.PartialAuthContinuation) error {
	if ctx == nil || owner == nil {
		return invalidAuthority()
	}
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return err
	}
	challenge, err := w.MagicLinkMFAChallenge(owner)
	if err != nil {
		return err
	}
	parent, err := w.MagicLinkConsumption(owner)
	if err != nil {
		return err
	}
	s, err := c.Bindings()
	if err != nil {
		return invalidAuthority()
	}
	if !legacyPrimaryContinuationOrigin(s) {
		return identity.ForbiddenError{}
	}
	digest, err := c.ScopeDigest()
	if err != nil || s.State != mfa.Pending || s.Version != 1 || s.ID != mfa.ContinuationID(challenge.ID) || s.SubjectID != identity.SubjectID(challenge.UserID) || s.TenantID != parent.Command.TenantID || string(s.SourcePreAuthID) != parent.Command.AnonymousFlowID || string(s.PrimaryProofID) != parent.Plan.CapabilityID || s.PrimaryProofDigest != parent.Plan.ProofFingerprint || !s.PrimaryProofExpiresAt.Equal(parent.Plan.ExpiresAt) || digest != challenge.ScopeDigest || s.PolicyVersion != challenge.PolicyVersion || s.FactorVersion != challenge.FactorVersion || !s.IssuedAt.Equal(challenge.IssuedAt) || !s.ExpiresAt.Equal(challenge.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	return persistContinuation(ctx, w, c, parent.Command, parent.Fingerprint, parent.Generation)
}

// PersistPasswordContinuation stores the original pending password-first
// challenge only within its comparison owner's exact protected Apply. The
// password owner must validate and persist its non-final signed primary in the
// same Work before calling this operation. This function neither compares a
// password nor issues a capability/session. It binds the frozen child scope and
// active factor generation; all errors must propagate to the sole coordinator.
// Duplicate insertion denies without resetting attempts or extending expiry.
func PersistPasswordContinuation(ctx context.Context, w kernel.Work, owner kernel.PasswordMFAChallengeContributor, command identity.Command, c mfa.PartialAuthContinuation) error {
	if ctx == nil || owner == nil {
		return invalidAuthority()
	}
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return err
	}
	challenge, err := w.PasswordMFAChallenge(owner)
	if err != nil {
		return err
	}
	b, fingerprint, generation, err := w.FeatureCommandIdentity(owner)
	if err != nil {
		return err
	}
	s, err := c.Bindings()
	if err != nil {
		return invalidAuthority()
	}
	if !legacyPrimaryContinuationOrigin(s) {
		return identity.ForbiddenError{}
	}
	digest, err := c.ScopeDigest()
	if err != nil || (b.OperationID != "identity.password.signin" && b.OperationID != "identity.username.signin" && b.OperationID != "identity.phone.password-signin") || s.State != mfa.Pending || s.Version != 1 || s.ID != mfa.ContinuationID(challenge.ID) || s.SubjectID != identity.SubjectID(challenge.UserID) || s.TenantID != b.TenantID || string(s.SourcePreAuthID) != b.AnonymousFlowID || string(s.PrimaryProofID) != string(b.CommandID) || digest != challenge.ScopeDigest || s.PolicyVersion != challenge.PolicyVersion || s.FactorVersion != challenge.FactorVersion || !s.IssuedAt.Equal(challenge.IssuedAt) || !s.ExpiresAt.Equal(challenge.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	return persistContinuation(ctx, w, c, b, fingerprint, generation)
}

// PersistEmailVerificationContinuation stores the original pending challenge
// after separately committed verification, only in its exact native owner's
// protected Apply. The owner must authenticate its parent and original browser
// before this call. Full immutable scope, subject and current factor generation
// must match; no parent consumption, password evidence or session is invented.
// Duplicate insertion denies without resetting attempts or expiry. Every error
// must abort the sole Work with its child issuance, audit and lifecycle effects.
func PersistEmailVerificationContinuation(ctx context.Context, w kernel.Work, owner kernel.EmailVerificationMFAChallengeContributor, command identity.Command, c mfa.PartialAuthContinuation) error {
	if ctx == nil || owner == nil {
		return invalidAuthority()
	}
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return err
	}
	challenge, err := w.EmailVerificationMFAChallenge(owner)
	if err != nil {
		return err
	}
	b, fingerprint, generation, err := w.FeatureCommandIdentity(owner)
	if err != nil {
		return err
	}
	s, err := c.Bindings()
	if err != nil {
		return invalidAuthority()
	}
	if string(s.VerificationCommandID) != b.RecordID {
		return identity.ForbiddenError{}
	}
	digest, err := c.ScopeDigest()
	if err != nil || s.State != mfa.Pending || s.Version != 1 || s.ID != mfa.ContinuationID(challenge.ID) || s.SubjectID != identity.SubjectID(b.UserID) || s.SubjectID != identity.SubjectID(challenge.UserID) || s.TenantID != b.TenantID || digest != challenge.ScopeDigest || s.PolicyVersion != challenge.PolicyVersion || s.FactorVersion != challenge.FactorVersion || !s.IssuedAt.Equal(challenge.IssuedAt) || !s.ExpiresAt.Equal(challenge.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	return persistContinuation(ctx, w, c, b, fingerprint, generation)
}

// Password and magic-link owners must not adopt a newer primary-origin profile
// merely because its subject and primary ID happen to fit their legacy scope.
func legacyPrimaryContinuationOrigin(s mfa.ContinuationSpec) bool {
	return s.VerificationCommandID == "" && s.PasskeyCommandID == ""
}

func persistContinuation(ctx context.Context, w kernel.Work, c mfa.PartialAuthContinuation, b identity.CommandBinding, fingerprint [32]byte, generation uint64) error {
	s, err := c.Bindings()
	if err != nil {
		return invalidAuthority()
	}
	digest, err := c.ScopeDigest()
	if err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if err = c.RequirePending(now); err != nil {
		return err
	}
	wire, err := encodeContinuationScope(c)
	if err != nil {
		return err
	}
	defer clear(wire)
	commandID, err := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	if err != nil || len(commandID) != 16 {
		return invalidAuthority()
	}
	// A missing/empty/stale authority cannot become an enrolled challenge. The
	// native owner additionally fences the actual methods and current policy.
	rows, err := w.Query(ctx, `SELECT version::text,active_factors FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id=$2 FOR UPDATE`, string(s.TenantID), string(s.SubjectID))
	if err != nil {
		return identity.UnavailableError{}
	}
	var factorVersion string
	var active int32
	matched := rows.Next() && rows.Scan(&factorVersion, &active) == nil && !rows.Next() && rows.Err() == nil
	rows.Close()
	if !matched || factorVersion != strconv.FormatUint(s.FactorVersion, 10) || active <= 0 || active > 64 {
		return identity.ForbiddenError{}
	}
	count, err := w.Exec(ctx, `INSERT INTO identity_mfa.continuations(tenant_id,continuation_id,user_id,source_preauth_id,origin_command_id,origin_purpose,origin_fingerprint,origin_generation,scope_digest,original_scope,state,version,max_attempts,attempts_remaining,issued_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8::numeric,$9,$10,1,1,$11,$12,$13,$14)`, string(s.TenantID), string(s.ID), string(s.SubjectID), string(s.SourcePreAuthID), commandID, b.OperationID, fingerprint[:], strconv.FormatUint(generation, 10), digest[:], wire, int32(s.MaxAttempts), int32(s.AttemptsRemaining), s.IssuedAt, s.ExpiresAt)
	if err != nil {
		return identity.UnavailableError{}
	}
	if count != 1 {
		return identity.ConflictError{}
	}
	return nil
}
