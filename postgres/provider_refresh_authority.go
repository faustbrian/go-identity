package postgres

import (
	"context"
	"math"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// AdvanceProviderRefreshAuthority advances the identity-owned social-link
// version for the exact current provider account. Only the registered native
// refresh participant can call it with its original command during Apply.
//
// The operation leaves the provider account identity and its login credential
// unchanged. OAuth still owns its encrypted token compare-and-set and all
// other security checks. Both owners must enlist in the same Work; a rollback
// of the vault or required effects also rolls back this change.
func (w Work) AdvanceProviderRefreshAuthority(ctx context.Context, owner FeatureExecutionContributor, command identity.Command, expected ProviderAccountAdmission) (uint64, error) {
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return 0, err
	}
	binding, feature, _, err := w.FeatureScope(owner)
	if err != nil {
		return 0, w.fail(ctx, err)
	}
	account := expected.Account
	if feature.Contributor != (ContributorDescriptor{Owner: "identity/oauth/postgres", ContractID: "identity.oauth.provider-refresh", Version: 1}) ||
		feature.Operation.Owner != "identity/oauth" || feature.Operation.OperationID != "identity.account.refresh-token" ||
		binding.ActorKind != authorization.SubjectUser || binding.ActorID != identity.ActorID(binding.UserID) ||
		binding.RecordID != string(account.ID) || expected.Credential.Credential.Owner != "identity/oauth" {
		return 0, w.fail(ctx, invalidWork())
	}
	if expected.SocialLinkVersion == 0 || expected.SocialLinkVersion == math.MaxUint64 ||
		!providerRefreshBindsAccountVersions(command, account.Version, expected.SocialLinkVersion) {
		return 0, w.fail(ctx, invalidWork())
	}
	if _, err := w.requireActiveProviderAccount(ctx, binding, expected); err != nil {
		return 0, err
	}

	// Refresh changes provider-token custody, not the linked login method.
	// Fence the same account and link versions under the retained Work locks.
	next := expected.SocialLinkVersion + 1
	n, err := w.Exec(ctx, advanceProviderRefreshAuthoritySQL,
		string(account.TenantID), string(account.UserID), string(account.ID), account.Provider, account.Issuer,
		account.Subject, account.Version, expected.SocialLinkVersion, next)
	if err != nil {
		return 0, err
	}
	if n != 1 {
		return 0, w.fail(ctx, identity.ConflictError{})
	}
	return next, nil
}

const advanceProviderRefreshAuthoritySQL = `UPDATE identity.accounts SET social_link_version=$9::numeric
 WHERE tenant_id=$1 AND user_id=$2 AND account_id=$3 AND provider=$4 AND issuer=$5 AND subject=$6
 AND version=$7::numeric AND social_link_version=$8::numeric AND linked`

func providerRefreshBindsAccountVersions(command identity.Command, accountVersion, socialLinkVersion uint64) bool {
	spec, ok := command.Feature()
	if !ok || accountVersion == 0 {
		return false
	}
	wantAccount := identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: accountVersion}
	wantLink := identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: socialLinkVersion}
	accountBound, linkBound := false, false
	for _, field := range spec.Fields {
		switch field.Name {
		case "provider-refresh.account-version":
			accountBound = field.Value.Kind == wantAccount.Kind && field.Value.Uint64 == wantAccount.Uint64
		case "provider-refresh.social-link-version":
			linkBound = field.Value.Kind == wantLink.Kind && field.Value.Uint64 == wantLink.Uint64
		}
	}
	return accountBound && linkBound
}
