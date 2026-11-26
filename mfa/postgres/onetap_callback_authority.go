package mfapostgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// RequireOneTapCallbackFactors locks the original known-empty MFA generation
// for the exact Google account selected by the native One Tap callback. The
// kernel first fences that linked account and the registered owner's original
// Apply/final-check command; its anonymous flow, service actor and replay scope
// remain unchanged. Observe the generation with ReadOAuthSigninFactors before
// freezing the command, then call this fence in Apply and final checks. Missing,
// enrolled or stale factor authority denies without initializing state.
//
// Locks belong to the sole coordinator until commit or rollback. Propagate
// every error to abort Work. Ordinary OAuth and SSO custody cannot substitute
// for One Tap custody. This creates no proof, session, factor state or renewed
// freshness and never replaces provider, browser or session-owner checks.
func RequireOneTapCallbackFactors(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, expectedVersion uint64) (mfa.FactorAuthority, error) {
	if ctx == nil || owner == nil || expectedVersion == 0 {
		return mfa.FactorAuthority{}, invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return mfa.FactorAuthority{}, err
	}
	if _, err := w.RequireOneTapCallbackAccount(ctx, owner, command); err != nil {
		return mfa.FactorAuthority{}, err
	}
	account, err := kernel.OneTapCallbackAccount(command)
	if err != nil {
		return mfa.FactorAuthority{}, err
	}
	feature, _ := command.Feature()
	return readKnownEmptyFactors(ctx, w, feature.Binding, account.Account.UserID, expectedVersion)
}
