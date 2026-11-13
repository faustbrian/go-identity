package mfapostgres

import (
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
)

// ReadOAuthSigninFactors observes the existing provider account's known-empty
// MFA generation before the native signin owner freezes its callback command.
// Missing, enrolled or corrupt state denies without initializing it. This is
// preliminary metadata, not provider authentication or a positive validity lease.
// Preserve the observed version and fence it with RequireOAuthSigninFactors in
// Apply and final checks. The borrowed primary pool and 1ms..5s duration retain
// existing cancellation bounds; no transaction, retry or goroutine is started.
func ReadOAuthSigninFactors(ctx context.Context, pool *database.Pool, tenant identity.TenantID, user identity.UserID, maximumDuration time.Duration) (mfa.FactorAuthority, error) {
	return readKnownEmptyPrimary(ctx, pool, tenant, user, maximumDuration)
}

// RequireOAuthSigninFactors locks the original known-empty MFA generation for
// the native existing-account signin callback's selected provider account. The
// kernel first fences that exact account and original Apply/final-check command
// instance; anonymous flow, service actor and replay identity remain unchanged.
// A caller cannot supply a different user or borrow linking/password custody.
// Locks remain with the sole coordinator through commit or rollback. Propagate
// every error to abort Work. This creates no proof, session, factor state or
// renewed freshness and never substitutes for provider or browser verification.
func RequireOAuthSigninFactors(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, expectedVersion uint64) (mfa.FactorAuthority, error) {
	if ctx == nil || owner == nil || expectedVersion == 0 {
		return mfa.FactorAuthority{}, invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return mfa.FactorAuthority{}, err
	}
	if _, err := w.RequireOAuthSigninProviderAccount(ctx, owner, command); err != nil {
		return mfa.FactorAuthority{}, err
	}
	account, err := kernel.OAuthSigninAccount(command)
	if err != nil {
		return mfa.FactorAuthority{}, err
	}
	feature, _ := command.Feature()
	return readKnownEmptyFactors(ctx, w, feature.Binding, account.Account.UserID, expectedVersion)
}
