package mfapostgres

import (
	"context"
	"encoding/base64"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
)

// RecoverMagicLinkChallenge compares durable original continuation evidence
// with the exact frozen native challenge. It reads only through the sole
// coordinator's recovery Work. Mutable attempt/state updates do not renew or
// erase original issuance evidence. It cannot return credentials or authorize
// a factor/session. Missing rows contribute no committed effect; only the
// coordinator's complete participant set can establish transaction rollback.
// Corrupt evidence remains unknown. Original continuation records are retained
// authority evidence and must not be pruned without a retained outcome owner.
func RecoverMagicLinkChallenge(ctx context.Context, w kernel.RecoveryWork, owner kernel.MagicLinkMFAChallengeContributor) (kernel.RecoveryStatus, error) {
	m, err := w.MagicLinkMFAChallenge(owner)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	b, _, _, err := w.FeatureScope(owner)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	id, err := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	if err != nil {
		return kernel.RecoveryUnknown, invalidAuthority()
	}
	rows, err := w.Query(ctx, `SELECT c.original_scope,c.max_attempts FROM identity_mfa.continuations c JOIN identity.identity_command_id_claims k ON k.command_id=c.origin_command_id AND k.tenant_id=c.tenant_id AND k.purpose=c.origin_purpose JOIN identity.commands j ON j.command_id=c.origin_command_id AND j.tenant_id=c.tenant_id AND j.purpose=c.origin_purpose WHERE c.tenant_id=$1 AND c.continuation_id=$2 AND c.origin_command_id=$3 AND c.source_preauth_id=$4 AND c.origin_purpose='identity.magic-link.consume' AND c.origin_fingerprint=k.fingerprint AND c.origin_generation<=j.generation`, string(b.TenantID), string(m.ID), id, b.AnonymousFlowID)
	if err != nil {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return kernel.RecoveryUnknown, identity.UnavailableError{}
		}
		return kernel.RecoveryNotCommitted, nil
	}
	var wire []byte
	var attempts uint32
	if rows.Scan(&wire, &attempts) != nil || rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	c, err := decodeContinuationScope(wire, m.ScopeDigest, mfa.Pending, 1, attempts)
	if err != nil {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	s, err := c.Bindings()
	if err != nil || identity.CommandID(s.ID) != m.ID || identity.UserID(s.SubjectID) != m.UserID || s.PolicyVersion != m.PolicyVersion || s.FactorVersion != m.FactorVersion || !s.IssuedAt.Equal(m.IssuedAt) || !s.ExpiresAt.Equal(m.ExpiresAt) {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	return kernel.RecoveryCommitted, ctx.Err()
}

// ReadMagicLinkChallengeOutcome classifies a previously authorized committed
// native receipt without exposing subject, factor or proof metadata. The caller
// must first obtain the receipt through the coordinator's current result-access
// policy. It is historical outcome metadata, never authentication permission.
// This bounded primary read owns no pool lifetime, mutation or provider callback.
func ReadMagicLinkChallengeOutcome(ctx context.Context, pool *database.Pool, r identity.CommandResult, maximum time.Duration) (bool, error) {
	if ctx == nil || pool == nil || pool.Raw() == nil || r.Validate() != nil || r.Outcome != identity.CommitOutcomeCommitted || r.Binding.OperationID != "identity.magic-link.consume" || r.Binding.UserID != "" || r.Binding.AnonymousFlowID == "" || maximum <= 0 || maximum > 5*time.Second {
		return false, invalidAuthority()
	}
	id, err := base64.RawURLEncoding.DecodeString(string(r.Binding.CommandID))
	if err != nil {
		return false, invalidAuthority()
	}
	bounded, stop := context.WithTimeout(ctx, maximum)
	defer stop()
	var found bool
	err = pool.Raw().QueryRow(bounded, `SELECT EXISTS(SELECT 1 FROM identity_mfa.continuations c JOIN identity.identity_command_id_claims k ON k.command_id=c.origin_command_id AND k.tenant_id=c.tenant_id AND k.purpose=c.origin_purpose WHERE c.tenant_id=$1 AND c.source_preauth_id=$2 AND c.origin_command_id=$3 AND c.origin_purpose='identity.magic-link.consume' AND c.origin_fingerprint=k.fingerprint)`, string(r.Binding.TenantID), r.Binding.AnonymousFlowID, id).Scan(&found)
	if err != nil {
		return false, identity.UnavailableError{}
	}
	return found, bounded.Err()
}
