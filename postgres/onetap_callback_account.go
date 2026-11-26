package postgres

import (
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// OneTapCallbackAccount decodes the existing OAuth account snapshot fields
// only from the exact anonymous, browser-bound Google One Tap command. The
// native owner must obtain these fields from the verified Google issuer and
// subject and the primary linked-account lookup. An email is not an account
// selector. The snapshot does not convey provider proof or current authority.
func OneTapCallbackAccount(command identity.Command) (ProviderAccountAdmission, error) {
	f, ok := command.Feature()
	_, cookie := command.PreAuthCookie()
	_, code := command.OneTimeCode()
	_, recovery := command.RecoveryCode()
	_, bearer := command.SessionToken()
	if !ok || !cookie || code || recovery || bearer || f.Operation != OneTapCallbackOperation() || !validOneTapCallbackBinding(f.Binding) {
		return ProviderAccountAdmission{}, invalidWork()
	}
	a, err := signinAccountFromFields(f, oauthSigninAccountPrefix, "identity/oauth", ssoOIDCSigninAccountPrefix, ssoOAuth2SigninAccountPrefix, ssoSAMLSigninAccountPrefix)
	if err != nil || a.Account.Provider != "google" || a.Account.Issuer != "https://accounts.google.com" || a.Account.TenantID != f.Binding.TenantID {
		return ProviderAccountAdmission{}, invalidWork()
	}
	return a, nil
}

// RequireOneTapCallbackAccount keeps the exact original Google account,
// credential and link authority live through One Tap Apply and final commit.
// It reuses the primary account lock and post-lock clock, and never changes
// the command's anonymous flow/actor or grants session or replay authority.
func (w Work) RequireOneTapCallbackAccount(ctx context.Context, owner FeatureExecutionContributor, command identity.Command) (time.Time, error) {
	return w.requireProviderSigninCommandAccount(ctx, owner, command, OneTapCallbackOperation(), OneTapCallbackAccount)
}
