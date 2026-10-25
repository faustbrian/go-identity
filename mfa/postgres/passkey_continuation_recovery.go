package mfapostgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/jackc/pgx/v5"
)

// RecoverPasskeyContinuation compares retained MFA-owned evidence with the
// exact registered native passkey owner's original challenge in recovery Work.
// It grants no assertion, factor, session or credential-disclosure permission.
// Completed, revoked and expired challenges retain their original commitment
// evidence; recovery never resets state, attempts or expiry. Missing evidence
// votes only for this participant's noncommit; the sole coordinator must still
// reconcile every participant. Conflicting or corrupt evidence stays Unknown.
// Original rows must not be pruned without a retained outcome owner. No pool,
// transaction, callback, goroutine or rows are retained beyond this invocation.
func RecoverPasskeyContinuation(ctx context.Context, w kernel.RecoveryWork, owner kernel.PasskeyMFAChallengeContributor) (kernel.RecoveryStatus, error) {
	if ctx == nil {
		return kernel.RecoveryUnknown, invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return kernel.RecoveryUnknown, err
	}
	challenge, err := w.PasskeyMFAChallenge(owner)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	b, _, _, err := w.FeatureScope(owner)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	return recoverPasskeyContinuation(ctx, recoveryWorkStore(w.Query, nil).sql.query, b, challenge)
}

func recoverPasskeyContinuation(ctx context.Context, query func(context.Context, string, []any, ...any) error, b identity.CommandBinding, challenge kernel.MFAContinuationPlan) (kernel.RecoveryStatus, error) {
	if ctx == nil || query == nil {
		return kernel.RecoveryUnknown, invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return kernel.RecoveryUnknown, err
	}
	id, err := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	if err != nil || len(id) != 16 {
		return kernel.RecoveryUnknown, invalidAuthority()
	}
	var child, user, source string
	var digest, wire []byte
	var attempts uint32
	var issued, expires time.Time
	var original bool
	// Read by the unique original command, not expected child/digest predicates:
	// a conflicting row is Unknown, never misleading evidence of no effect.
	err = query(ctx, `SELECT c.continuation_id,c.user_id,c.source_preauth_id,c.scope_digest,c.original_scope,c.max_attempts,c.issued_at,c.expires_at,
COALESCE(c.origin_fingerprint=k.fingerprint AND c.origin_generation<=j.generation,false)
FROM identity_mfa.continuations c
LEFT JOIN identity.identity_command_id_claims k ON k.command_id=c.origin_command_id AND k.tenant_id=c.tenant_id AND k.purpose=c.origin_purpose
LEFT JOIN identity.commands j ON j.command_id=c.origin_command_id AND j.tenant_id=c.tenant_id AND j.purpose=c.origin_purpose
WHERE c.tenant_id=$1 AND c.origin_purpose='identity.passkey.signin-verify' AND c.origin_command_id=$2`, []any{string(b.TenantID), id}, &child, &user, &source, &digest, &wire, &attempts, &issued, &expires, &original)
	defer clear(wire)
	if err != nil {
		if ctx.Err() != nil {
			return kernel.RecoveryUnknown, ctx.Err()
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return kernel.RecoveryNotCommitted, nil
		}
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	if !original || child != string(challenge.ID) || user != string(challenge.UserID) || !bytes.Equal(digest, challenge.ScopeDigest[:]) || !issued.Equal(challenge.IssuedAt) || !expires.Equal(challenge.ExpiresAt) {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	// Stored original_scope is the immutable pending projection. Current terminal
	// or attempt state is intentionally irrelevant to historical commitment.
	c, err := decodeContinuationScope(wire, challenge.ScopeDigest, mfa.Pending, 1, attempts)
	if err != nil || !passkeyContinuationMatches(c, b, challenge) {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	s, _ := c.Bindings()
	if source != string(s.SourcePreAuthID) {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	if err := ctx.Err(); err != nil {
		return kernel.RecoveryUnknown, err
	}
	return kernel.RecoveryCommitted, nil
}
