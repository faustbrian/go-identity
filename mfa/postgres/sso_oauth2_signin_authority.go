package mfapostgres

import (
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
)

// ReadSSOOAuth2SigninFactors observes the selected enterprise account's current
// known-empty MFA generation before the native owner freezes its callback.
// Missing, enrolled or corrupt state denies without initialization. This is
// preliminary metadata, not authentication or a validity lease. Preserve the
// generation and fence it with RequireSSOOAuth2SigninFactors in Apply and final
// checks. The pool is borrowed; maximumDuration is 1ms..5s, bounded by earlier
// cancellation. No transaction, retry, goroutine or authority is created.
func ReadSSOOAuth2SigninFactors(ctx context.Context, pool *database.Pool, tenant identity.TenantID, user identity.UserID, maximumDuration time.Duration) (mfa.FactorAuthority, error) {
	return readKnownEmptyPrimary(ctx, pool, tenant, user, maximumDuration)
}

// RequireSSOOAuth2SigninFactors locks the original known-empty MFA generation
// for the exact enterprise callback-selected account. The kernel first fences
// that SSO-owned account and the original registered Apply/final-check command;
// anonymous flow, service actor and replay scope remain unchanged. OIDC and social
// callbacks cannot borrow this authority. Locks belong to the sole coordinator
// until commit or rollback; every error must abort Work. This creates no proof,
// session, factor state or freshness and does not replace the SSO owner's
// provider/profile, organization, browser, subject or policy fences.
func RequireSSOOAuth2SigninFactors(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, expectedVersion uint64) (mfa.FactorAuthority, error) {
	if ctx == nil || owner == nil || expectedVersion == 0 {
		return mfa.FactorAuthority{}, invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return mfa.FactorAuthority{}, err
	}
	if _, err := w.RequireSSOOAuth2SigninProviderAccount(ctx, owner, command); err != nil {
		return mfa.FactorAuthority{}, err
	}
	account, err := kernel.SSOOAuth2SigninAccount(command)
	if err != nil {
		return mfa.FactorAuthority{}, err
	}
	feature, _ := command.Feature()
	return readKnownEmptyFactors(ctx, w, feature.Binding, account.Account.UserID, expectedVersion)
}
