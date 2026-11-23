package postgres

import (
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
)

const ssoSAMLIDPConfirmationAccountPrefix = "sso.saml.idp.account."

// SSOSAMLIDPConfirmationAccountFields freezes the original existing account
// and its authority versions for unsolicited confirmation. The values alone
// do not authenticate a provider, confirm a browser or renew authority.
func SSOSAMLIDPConfirmationAccountFields(account ProviderAccountAdmission) ([]identity.FeatureField, error) {
	if !validSAMLAccountProvider(account.Account.Provider) {
		return nil, invalidWork()
	}
	return signinAccountFields(account, ssoSAMLIDPConfirmationAccountPrefix, "sso")
}

// SSOSAMLIDPConfirmationAccount reconstructs the exact original account only
// from a paired confirmation command for the same tenant and linked user.
// It does not verify either submitted value or perform I/O.
func SSOSAMLIDPConfirmationAccount(command identity.Command) (ProviderAccountAdmission, error) {
	f, ok := command.SAMLIDPConfirmationFeature()
	if !ok || f.Operation != SSOSAMLIDPConfirmationOperation() || !validSSOSAMLIDPConfirmationBinding(f.Binding) {
		return ProviderAccountAdmission{}, invalidWork()
	}
	arrival, err := identity.ParseCommandID(f.Binding.RecordID)
	if err != nil || arrival == f.Binding.CommandID {
		return ProviderAccountAdmission{}, invalidWork()
	}
	account, err := signinAccountFromFields(f, ssoSAMLIDPConfirmationAccountPrefix, "sso",
		oauthSigninAccountPrefix, ssoOIDCSigninAccountPrefix, ssoOAuth2SigninAccountPrefix, ssoSAMLSigninAccountPrefix)
	if err != nil || account.Account.UserID != f.Binding.UserID || !validSAMLAccountProvider(account.Account.Provider) {
		return ProviderAccountAdmission{}, invalidWork()
	}
	return account, nil
}

// RequireSSOSAMLIDPConfirmationProviderAccount fences the original linked
// account in the exact native confirmation Apply or final check. It holds the
// current primary locks without creating or refreshing account authority. It
// does not verify browser intent, provider, organization or replay evidence.
func (w Work) RequireSSOSAMLIDPConfirmationProviderAccount(ctx context.Context, owner FeatureExecutionContributor, command identity.Command) (time.Time, error) {
	return w.requireSSOSigninProviderAccount(ctx, owner, command, SSOSAMLIDPConfirmationOperation(), SSOSAMLIDPConfirmationAccount)
}
