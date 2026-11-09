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

// ReadOAuthLinkFactors reads the explicit self-link subject's actual known-empty
// MFA generation before the native owner freezes original intent. The borrowed
// primary pool and 1ms..5s duration retain existing cancellation/resource bounds.
// Missing, enrolled or corrupt state denies; no state is initialized. Success is
// metadata, not authentication, session admission or a positive freshness lease.
// Preserve this generation and fence it in every protected linking phase.
func ReadOAuthLinkFactors(ctx context.Context, pool *database.Pool, tenant identity.TenantID, user identity.UserID, maximumDuration time.Duration) (mfa.FactorAuthority, error) {
	return readKnownEmptyPrimary(ctx, pool, tenant, user, maximumDuration)
}

// RequireOAuthLinkStartFactors locks the original known-empty generation only
// for the exact native explicit-self RP link-start profile. Call in preparation
// admission, Apply and final commit checks, after account/session locks. The
// original command must retain the same frozen binding and operation. The sole
// coordinator owns Work and the factor row lock until commit/abort. Return every
// error to abort; this creates no proof, session, transaction or renewed lease.
func RequireOAuthLinkStartFactors(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, original identity.Command, expectedVersion uint64) (mfa.FactorAuthority, error) {
	if ctx == nil || owner == nil || expectedVersion == 0 {
		return mfa.FactorAuthority{}, invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return mfa.FactorAuthority{}, err
	}
	s, ok := original.Feature()
	b, f, life, err := w.FeatureScope(owner)
	if err != nil || !ok || oauthLinkStartFactorScope(s, b, f, life) != nil {
		return mfa.FactorAuthority{}, invalidAuthority()
	}
	return readKnownEmptyFactors(ctx, w, b, b.UserID, expectedVersion)
}

func oauthLinkStartFactorScope(s identity.FeatureCommandSpec, b identity.CommandBinding, f kernel.FeatureRegistration, life kernel.LifecyclePlan) error {
	op := identity.FeatureOperation{Owner: "identity/oauth", OperationID: "identity.account.link-start", SchemaID: "identity.account.link-start.rp-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectUser}
	if s.Binding != b || s.Operation != op || f.Operation != op || b.ValidateFor(op) != nil || b.ActorKind != authorization.SubjectUser || string(b.ActorID) != string(b.UserID) || f.Contributor != (kernel.ContributorDescriptor{Owner: "identity/oauth/postgres", ContractID: "identity.oauth.rp-initiation", Version: 1}) || life != (kernel.LifecyclePlan{EventType: "oauth.rp_transaction.created.v1", AfterVersion: 1}) {
		return invalidAuthority()
	}
	return nil
}

// RequireOAuthLinkPreparationFactors fences the original known-empty factor
// generation during the native owner's canonical root explicit-self link
// preparation. Command verifies the sealed synchronous owner; reads and locks
// belong to its original Work, not a new transaction. Final link checks must
// repeat the fence because provider exchange runs outside this transaction.
// Missing, enrolled or changed authority denies without initializing state,
// adopting a generation, minting authentication or renewing original freshness.
func RequireOAuthLinkPreparationFactors(ctx context.Context, w kernel.AccountLinkPreparationWork, owner kernel.AccountLinkPreparationContributor, expectedVersion uint64) (mfa.FactorAuthority, error) {
	if ctx == nil || owner == nil || expectedVersion == 0 {
		return mfa.FactorAuthority{}, invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return mfa.FactorAuthority{}, err
	}
	s, err := w.Command(owner)
	if err != nil || oauthLinkFactorScope(s.Binding) != nil {
		return mfa.FactorAuthority{}, invalidAuthority()
	}
	return requireOAuthLinkFactorQuery(ctx, w.Query, s.Binding, expectedVersion)
}

// RequireOAuthLinkFactors fences the same original known-empty generation in
// initial and final native root explicit-self link checks. Call after canonical
// account/session locks and propagate every failure. Command enforces the exact
// sealed owner; the factor lock remains with the sole coordinator until Work
// closes. This does not authenticate provider proof, grant session admission,
// mutate factors, initialize missing state or refresh retained authority.
func RequireOAuthLinkFactors(ctx context.Context, w kernel.AccountLinkWork, owner kernel.AccountLinkContributor, expectedVersion uint64) (mfa.FactorAuthority, error) {
	if ctx == nil || owner == nil || expectedVersion == 0 {
		return mfa.FactorAuthority{}, invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return mfa.FactorAuthority{}, err
	}
	s, _, err := w.Command(owner)
	if err != nil || oauthLinkFactorScope(s.Binding) != nil {
		return mfa.FactorAuthority{}, invalidAuthority()
	}
	return requireOAuthLinkFactorQuery(ctx, w.Query, s.Binding, expectedVersion)
}

func oauthLinkFactorScope(b identity.CommandBinding) error {
	// Root account_link_plan.go fixes the admitted owner to identity/oauth/postgres,
	// identity.oauth.account-link v1; both sealed Command accessors require that
	// exact instance. Do not call contributor metadata under its transaction locks.
	// Implicit/admin linking cannot borrow password-session no-factor admission.
	if b.OperationID != "identity.account.link-token" || b.SchemaID != "identity-account" || b.SchemaVersion != 1 || b.LinkMode != identity.AccountLinkExplicit || b.ActorKind != authorization.SubjectUser || b.UserID == "" || string(b.ActorID) != string(b.UserID) || b.AnonymousFlowID != "" {
		return invalidAuthority()
	}
	return nil
}

func requireOAuthLinkFactorQuery(ctx context.Context, query factorAuthorityQuery, b identity.CommandBinding, expectedVersion uint64) (mfa.FactorAuthority, error) {
	state, err := readFactorAuthorityQuery(ctx, query, b, b.UserID, expectedVersion)
	if err != nil {
		return mfa.FactorAuthority{}, err
	}
	if err := state.RequireEmailRecovery(b.TenantID, b.UserID); err != nil {
		return mfa.FactorAuthority{}, err
	}
	return state, nil
}
