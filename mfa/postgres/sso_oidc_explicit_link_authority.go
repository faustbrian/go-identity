package mfapostgres

import (
	"context"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
)

// ReadSSOOIDCExplicitLinkFactors observes the existing member's known-empty
// MFA generation before the enterprise owner freezes original link intent.
// Missing, enrolled or corrupt state denies without initialization. Preserve
// this original generation and fence it in preparation, Apply and final checks.
// This is metadata, not authentication, session admission or a freshness lease.
// The pool is borrowed; maximumDuration is 1ms..5s, bounded by cancellation.
func ReadSSOOIDCExplicitLinkFactors(ctx context.Context, pool *database.Pool, tenant identity.TenantID, user identity.UserID, maximumDuration time.Duration) (mfa.FactorAuthority, error) {
	return readKnownEmptyPrimary(ctx, pool, tenant, user, maximumDuration)
}

// RequireSSOOIDCExplicitLinkFactors locks the original known-empty generation
// only for the exact native authenticated-member enterprise OIDC start or link
// callback. Call after account/session locks in preparation admission, Apply
// and final checks, propagating every error to abort. FeatureScope requires the
// original registered owner's active invocation; command must retain its exact
// frozen binding, operation and session-token custody. The enterprise owner
// separately conserves the original command and proves session freshness,
// consent, browser, provider and membership authority in the same Work.
// Locks remain with the sole coordinator until commit/abort. No transaction,
// factor state, proof, session or renewed freshness is created by this guard.
func RequireSSOOIDCExplicitLinkFactors(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, expectedVersion uint64) (mfa.FactorAuthority, error) {
	if ctx == nil || owner == nil || expectedVersion == 0 {
		return mfa.FactorAuthority{}, invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return mfa.FactorAuthority{}, err
	}
	binding, feature, life, err := w.FeatureScope(owner)
	if err != nil || ssoOIDCExplicitLinkFactorScope(command, binding, feature, life) != nil {
		return mfa.FactorAuthority{}, invalidAuthority()
	}
	return readKnownEmptyFactors(ctx, w, binding, binding.UserID, expectedVersion)
}

func ssoOIDCExplicitLinkFactorScope(command identity.Command, binding identity.CommandBinding, feature kernel.FeatureRegistration, life kernel.LifecyclePlan) error {
	spec, ok := command.Feature()
	_, session := command.SessionToken()
	_, code := command.OneTimeCode()
	_, recovery := command.RecoveryCode()
	if !ok || !session || code || recovery {
		return invalidAuthority()
	}
	if spec.Binding != binding || spec.Operation != feature.Operation || binding.ValidateFor(spec.Operation) != nil {
		return invalidAuthority()
	}
	if binding.ActorKind != authorization.SubjectUser || string(binding.ActorID) != string(binding.UserID) || binding.AnonymousFlowID != "" {
		return invalidAuthority()
	}
	switch spec.Operation {
	case kernel.SSOOIDCExplicitLinkStartOperation():
		if feature.Contributor == (kernel.ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.oidc-login-start", Version: 1}) && life == (kernel.LifecyclePlan{EventType: "oauth.rp_transaction.created.v1", AfterVersion: 1}) {
			return nil
		}
	case kernel.SSOOIDCExplicitLinkCallbackOperation():
		if feature.Contributor == (kernel.ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.oidc-login-callback", Version: 1}) && life == (kernel.LifecyclePlan{EventType: "enterprise_provider.account_linked.v1", BeforeVersion: 1, AfterVersion: 2}) {
			return nil
		}
	}
	return invalidAuthority()
}
