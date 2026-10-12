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
	digest, err := c.ScopeDigest()
	if err != nil || s.State != mfa.Pending || s.Version != 1 || s.ID != mfa.ContinuationID(challenge.ID) || s.SubjectID != identity.SubjectID(challenge.UserID) || s.TenantID != parent.Command.TenantID || string(s.SourcePreAuthID) != parent.Command.AnonymousFlowID || string(s.PrimaryProofID) != parent.Plan.CapabilityID || s.PrimaryProofDigest != parent.Plan.ProofFingerprint || !s.PrimaryProofExpiresAt.Equal(parent.Plan.ExpiresAt) || digest != challenge.ScopeDigest || s.PolicyVersion != challenge.PolicyVersion || s.FactorVersion != challenge.FactorVersion || !s.IssuedAt.Equal(challenge.IssuedAt) || !s.ExpiresAt.Equal(challenge.ExpiresAt) {
		return identity.ForbiddenError{}
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
	commandID, err := base64.RawURLEncoding.DecodeString(string(parent.Command.CommandID))
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
	count, err := w.Exec(ctx, `INSERT INTO identity_mfa.continuations(tenant_id,continuation_id,user_id,source_preauth_id,origin_command_id,origin_purpose,origin_fingerprint,origin_generation,scope_digest,original_scope,state,version,max_attempts,attempts_remaining,issued_at,expires_at) VALUES($1,$2,$3,$4,$5,'identity.magic-link.consume',$6,$7::numeric,$8,$9,1,1,$10,$11,$12,$13)`, string(s.TenantID), string(s.ID), string(s.SubjectID), string(s.SourcePreAuthID), commandID, parent.Fingerprint[:], strconv.FormatUint(parent.Generation, 10), digest[:], wire, int32(s.MaxAttempts), int32(s.AttemptsRemaining), s.IssuedAt, s.ExpiresAt)
	if err != nil {
		return identity.UnavailableError{}
	}
	if count != 1 {
		return identity.ConflictError{}
	}
	return nil
}
