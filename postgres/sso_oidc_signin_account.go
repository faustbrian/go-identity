package postgres

import (
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
)

const ssoOIDCSigninAccountPrefix = "sso.oidc.signin.account."
const ssoOAuth2SigninAccountPrefix = "sso.oauth2.signin.account."

// SSOOIDCSigninAccountFields freezes an existing SSO-owned account and every
// independent identity epoch in the original enterprise callback intent. The
// trusted SSO owner first validates the assertion and configured namespaced
// provider. This records no proof, creates no link and renews no authority.
func SSOOIDCSigninAccountFields(a ProviderAccountAdmission) ([]identity.FeatureField, error) {
	return signinAccountFields(a, ssoOIDCSigninAccountPrefix, "sso")
}

// SSOOIDCSigninAccount decodes only the exact resource-bound enterprise callback
// with original preauth-cookie custody. It rejects social or mixed profiles,
// malformed account fields and foreign tenants. The result is an immutable
// observation, not authentication; provider/profile, organization, factor and
// policy authority remain with their owners and require primary fencing.
func SSOOIDCSigninAccount(command identity.Command) (ProviderAccountAdmission, error) {
	return ssoEnterpriseSigninAccount(command, ssoOIDCSigninOperation(), ssoOIDCSigninAccountPrefix, ssoOAuth2SigninAccountPrefix)
}

// SSOOAuth2SigninAccountFields freezes the exact OAuth-linked account selected
// by verified provider-subject evidence. These fields prove no current authority.
func SSOOAuth2SigninAccountFields(a ProviderAccountAdmission) ([]identity.FeatureField, error) {
	return signinAccountFields(a, ssoOAuth2SigninAccountPrefix, "sso")
}

// SSOOAuth2SigninAccount decodes only the native OAuth callback's original
// pre-authentication command and exact account snapshot, not session authority.
func SSOOAuth2SigninAccount(command identity.Command) (ProviderAccountAdmission, error) {
	return ssoEnterpriseSigninAccount(command, SSOOAuth2SigninOperation(), ssoOAuth2SigninAccountPrefix, ssoOIDCSigninAccountPrefix)
}

func ssoEnterpriseSigninAccount(command identity.Command, op identity.FeatureOperation, prefix, otherEnterprisePrefix string) (ProviderAccountAdmission, error) {
	f, ok := command.Feature()
	_, cookie := command.PreAuthCookie()
	_, code := command.OneTimeCode()
	_, recovery := command.RecoveryCode()
	_, bearer := command.SessionToken()
	if !ok || !cookie || code || recovery || bearer || f.Operation != op || !validEnterpriseSigninBinding(f.Binding, op) {
		return ProviderAccountAdmission{}, invalidWork()
	}
	return signinAccountFromFields(f, prefix, "sso", oauthSigninAccountPrefix, otherEnterprisePrefix)
}

// RequireSSOOIDCSigninProviderAccount fences only the exact registered native
// enterprise callback's original command during synchronous Apply or its final
// commit check. Invalid, foreign or stale authority poisons Work. Identity's
// existing user/credential/account/association locks and exclusive expiry checks
// remain held by the sole coordinator without changing anonymous command scope.
//
// This creates no identity, link, membership, session or transaction. The primary
// clock sample is not a lease; SSO must separately fence current organization,
// provider/profile, assertion, browser, policy and factor authority and consume
// its original one-use state in the same transaction.
func (w Work) RequireSSOOIDCSigninProviderAccount(ctx context.Context, owner FeatureExecutionContributor, command identity.Command) (time.Time, error) {
	return w.requireSSOSigninProviderAccount(ctx, owner, command, ssoOIDCSigninOperation(), SSOOIDCSigninAccount)
}

// RequireSSOOAuth2SigninProviderAccount fences the selected linked account in
// the original OAuth Apply or final check. It borrows the existing identity
// locks, preserves the anonymous invocation, and cannot refresh evidence or
// select an account from browser input.
func (w Work) RequireSSOOAuth2SigninProviderAccount(ctx context.Context, owner FeatureExecutionContributor, command identity.Command) (time.Time, error) {
	return w.requireSSOSigninProviderAccount(ctx, owner, command, SSOOAuth2SigninOperation(), SSOOAuth2SigninAccount)
}

func (w Work) requireSSOSigninProviderAccount(ctx context.Context, owner FeatureExecutionContributor, command identity.Command, op identity.FeatureOperation, decode func(identity.Command) (ProviderAccountAdmission, error)) (time.Time, error) {
	if err := w.usable(); err != nil {
		return time.Time{}, err
	}
	if ctx == nil {
		return time.Time{}, w.fail(w.state.ctx, invalidWork())
	}
	if err := ctx.Err(); err != nil {
		return time.Time{}, w.fail(ctx, err)
	}
	b, feature, life, err := w.FeatureScope(owner)
	if err != nil {
		return time.Time{}, w.fail(ctx, invalidWork())
	}
	if w.state.featureApplying {
		if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
			return time.Time{}, err
		}
	} else if w.state.featureCommitCommand == nil || *w.state.featureCommitCommand != command {
		return time.Time{}, w.fail(ctx, invalidWork())
	}
	expected, decodeErr := decode(command)
	spec, _ := command.Feature()
	profile, _ := providerSigninProfile(op)
	if decodeErr != nil || spec.Binding != b || feature.Operation != op || feature.Contributor != profile.Contrib || life != profile.Lifecycle {
		return time.Time{}, w.fail(ctx, invalidWork())
	}
	// Only the lookup selects this user. Audit, replay and every effect retain
	// the original enterprise anonymous-flow/transaction binding.
	b.UserID = expected.Account.UserID
	return w.requireActiveProviderAccount(ctx, b, expected)
}
