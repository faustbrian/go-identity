package mfapostgres

import (
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
)

// ReadOAuthUnlinkFactors reads the native known-empty generation when
// admitting a new password-authorized self-unlink. This is preliminary
// metadata, not authentication or a freshness lease. Retain this generation
// on retries; do not replace it with another primary read.
func ReadOAuthUnlinkFactors(ctx context.Context, pool *database.Pool, tenant identity.TenantID, user identity.UserID, maximumDuration time.Duration) (mfa.FactorAuthority, error) {
	return readKnownEmptyPrimary(ctx, pool, tenant, user, maximumDuration)
}

// RequireOAuthUnlinkPreparationFactors locks the original known-empty
// generation in the exact owner's unlink preparation. The coordinator owns
// the lock. Missing, changed or enrolled state denies without initialization.
func RequireOAuthUnlinkPreparationFactors(ctx context.Context, w kernel.AccountUnlinkPreparationWork, owner kernel.AccountUnlinkPreparationContributor) (mfa.FactorAuthority, error) {
	if ctx == nil {
		return mfa.FactorAuthority{}, invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return mfa.FactorAuthority{}, err
	}
	intent, err := w.Command(owner)
	if err != nil {
		return mfa.FactorAuthority{}, err
	}
	return requireKnownEmptyFactorQuery(ctx, w.Query, intent.Binding, intent.FactorAuthorityVersion)
}

// RequireOAuthUnlinkFactors repeats the generation fence in the admitted
// unlink's initial and final checks, after the credential/session checks. Work
// supplies the original generation; the caller cannot replace it.
func RequireOAuthUnlinkFactors(ctx context.Context, w kernel.AccountUnlinkWork, owner kernel.AccountUnlinkPreparationContributor) (mfa.FactorAuthority, error) {
	if ctx == nil {
		return mfa.FactorAuthority{}, invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return mfa.FactorAuthority{}, err
	}
	generation, err := w.OriginalFactorAuthorityVersion(owner)
	if err != nil {
		return mfa.FactorAuthority{}, err
	}
	intent, _, err := w.Command(owner)
	if err != nil {
		return mfa.FactorAuthority{}, err
	}
	return requireKnownEmptyFactorQuery(ctx, w.Query, intent.Binding, generation)
}
