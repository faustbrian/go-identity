package mfapostgres

import (
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
)

// ReadEmailVerificationSigninFactors reads known-empty primary factor state for
// the explicitly selected post-registration-verification signin profile. Missing,
// enrolled or corrupt state denies without initializing or inferring absence.
// This is preliminary metadata, not authentication or a freshness lease. Fence
// the same generation with RequireEmailVerificationSigninFactors in protected
// Work. The borrowed pool is never closed; duration is 1ms..5s and earlier
// cancellation wins. No callbacks, transactions, retries or goroutines are owned.
func ReadEmailVerificationSigninFactors(ctx context.Context, pool *database.Pool, tenant identity.TenantID, user identity.UserID, maximum time.Duration) (mfa.FactorAuthority, error) {
	return readKnownEmptyPrimary(ctx, pool, tenant, user, maximum)
}

// RequireEmailVerificationSigninFactors locks the unchanged known-empty factor
// generation only for the exact email-owned post-verification signin command.
// Apply and final commit admission must both check it; errors abort Work. The
// lock lasts until the sole coordinator closes Work. Other email verification,
// password, OTP and magic-link profiles cannot select this fence. No proof,
// session or authentication authority is produced or renewed.
func RequireEmailVerificationSigninFactors(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, expectedVersion uint64) (mfa.FactorAuthority, error) {
	if ctx == nil || owner == nil || expectedVersion == 0 {
		return mfa.FactorAuthority{}, invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return mfa.FactorAuthority{}, err
	}
	s, ok := command.Feature()
	b, f, life, err := w.FeatureScope(owner)
	op := identity.FeatureOperation{Owner: "identity/email", OperationID: "identity.email.verification-signin", SchemaID: "email-verification-signin", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	if err != nil || !ok || s.Binding != b || s.Operation != op || f.Operation != op || f.Contributor != (kernel.ContributorDescriptor{Owner: "identity/email/postgres", ContractID: "identity.email", Version: 1}) || life.EventType != "session.created.v1" || life.BeforeVersion != 0 || life.AfterVersion != 1 {
		return mfa.FactorAuthority{}, invalidAuthority()
	}
	return readKnownEmptyFactors(ctx, w, b, b.UserID, expectedVersion)
}
