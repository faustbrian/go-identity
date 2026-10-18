package mfapostgres

import (
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
)

// ReadEmailVerificationMFAFactors reads known current primary factor state for
// explicitly selected verification-origin MFA. Unlike the unchanged known-empty
// profile, enrolled state may select a challenge, never a session. Missing or
// corrupt authority denies; no absence is inferred or initialized. The native
// owner must fence the same generation in Work. Pool is borrowed; maximum is
// 1ms..5s and earlier cancellation wins. No callback or goroutine is owned.
func ReadEmailVerificationMFAFactors(ctx context.Context, pool *database.Pool, tenant identity.TenantID, user identity.UserID, maximum time.Duration) (mfa.FactorAuthority, error) {
	return readPrimaryFactorState(ctx, pool, tenant, user, maximum)
}

// RequireEmailVerificationTOTPChallenge locks the unchanged enrolled factor
// generation for the exact native verification challenge owner, in preparation,
// Apply or final admission. A genuine confirmed TOTP secret must exist. Other
// methods cannot substitute for it, and this reader grants no possession,
// challenge, factor attempt or session authority. Locks share the sole Work;
// propagate every error. No transaction, provider or callback is started.
func RequireEmailVerificationTOTPChallenge(ctx context.Context, w kernel.Work, owner kernel.EmailVerificationMFAChallengeContributor, command identity.Command, version uint64) error {
	if ctx == nil || owner == nil || version == 0 {
		return invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s, ok := command.Feature()
	b, f, life, err := w.FeatureScope(owner)
	op := identity.FeatureOperation{Owner: "identity/email", OperationID: "identity.email.verification-signin", SchemaID: "email-verification-signin", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	if err != nil || !ok || s.Binding != b || s.Operation != op || f.Operation != op || f.Contributor != (kernel.ContributorDescriptor{Owner: "identity/email/postgres", ContractID: "identity.email", Version: 1}) || life.EventType != "mfa.challenge.created.v1" || life.BeforeVersion != 0 || life.AfterVersion != 1 {
		return invalidAuthority()
	}
	state, err := readFactorAuthority(ctx, w, b, b.UserID, version)
	if err != nil {
		return err
	}
	if state.RequireEmailRecovery(b.TenantID, b.UserID) == nil {
		return identity.ForbiddenError{}
	}
	present, err := passwordSigninFactorPresent(ctx, w, `SELECT factor_id FROM identity_mfa.totp_factors WHERE tenant_id=$1 AND user_id=$2 AND state=2 AND confirmed_at IS NOT NULL AND encrypted_secret IS NOT NULL LIMIT 1`, b.TenantID, b.UserID)
	if err != nil {
		return err
	}
	if !present {
		return identity.ForbiddenError{}
	}
	return ctx.Err()
}
