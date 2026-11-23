package mfapostgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// RequireSSOSAMLIDPConfirmationFactors fences the original known-empty factor
// generation in the exact unsolicited confirmation Work. The selected account
// must still match the paired original command. It creates no factor state or
// freshness; return every error to abort the caller's original transaction.
func RequireSSOSAMLIDPConfirmationFactors(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, expectedVersion uint64) (mfa.FactorAuthority, error) {
	if ctx == nil || owner == nil || expectedVersion == 0 {
		return mfa.FactorAuthority{}, invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return mfa.FactorAuthority{}, err
	}
	if _, err := w.RequireSSOSAMLIDPConfirmationProviderAccount(ctx, owner, command); err != nil {
		return mfa.FactorAuthority{}, err
	}
	feature, _ := command.SAMLIDPConfirmationFeature()
	return readKnownEmptyFactors(ctx, w, feature.Binding, feature.Binding.UserID, expectedVersion)
}
