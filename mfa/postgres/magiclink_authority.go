package mfapostgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// RequireMagicLinkFactors locks the real MFA generation for the exact native
// anonymous magic-link owner in its active preparation/execution Work. Missing
// or enrolled state denies; this single-factor email path cannot bypass MFA.
// Request may select current known-empty state with expectedVersion zero;
// consume must match a positive generation authenticated by original issuance.
// Retain the returned version in original custody and recheck at final Work.
// This does not initialize, enroll or remove factors, authenticate a browser,
// consume a link or issue a session. Return every error to the coordinator.
func RequireMagicLinkFactors(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, user identity.UserID, expectedVersion uint64) (mfa.FactorAuthority, error) {
	if ctx == nil || owner == nil {
		return mfa.FactorAuthority{}, invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return mfa.FactorAuthority{}, err
	}
	spec, ok := command.Feature()
	b, f, _, err := w.FeatureScope(owner)
	request := b.OperationID == "identity.magic-link.request"
	consume := b.OperationID == "identity.magic-link.consume"
	if err != nil || !ok || b != spec.Binding || f.Operation != spec.Operation || f.Contributor != (kernel.ContributorDescriptor{Owner: "identity/magiclink/postgres", ContractID: "identity.magiclink", Version: 1}) || f.Operation.Owner != "identity/magiclink" || b.UserID != "" || b.AnonymousFlowID == "" || (!request && !consume) || consume && expectedVersion == 0 {
		return mfa.FactorAuthority{}, invalidAuthority()
	}
	if _, err := identity.ParseIdentifierID(string(user)); err != nil {
		return mfa.FactorAuthority{}, invalidAuthority()
	}
	return readKnownEmptyFactors(ctx, w, b, user, expectedVersion)
}

// ReadMagicLinkRequestFactors selects and locks actual factor generation for
// the explicitly MFA-enabled native request owner. It permits known enrolled
// state only to issue a primary email link, never a session or MFA proof. The
// consuming owner must independently fence this generation and require the
// enrolled second factor. Missing/foreign/stale state denies. Work retains the
// lock through commit; this starts no transaction, callback or retry.
func ReadMagicLinkRequestFactors(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, user identity.UserID, expectedVersion uint64) (mfa.FactorAuthority, error) {
	if ctx == nil || owner == nil {
		return mfa.FactorAuthority{}, invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return mfa.FactorAuthority{}, err
	}
	spec, ok := command.Feature()
	b, f, _, err := w.FeatureScope(owner)
	if err != nil || !ok || b != spec.Binding || f.Operation != spec.Operation || f.Contributor != (kernel.ContributorDescriptor{Owner: "identity/magiclink/postgres", ContractID: "identity.magiclink", Version: 1}) || f.Operation.Owner != "identity/magiclink" || b.UserID != "" || b.AnonymousFlowID == "" || b.OperationID != "identity.magic-link.request" {
		return mfa.FactorAuthority{}, invalidAuthority()
	}
	if _, err := identity.ParseIdentifierID(string(user)); err != nil {
		return mfa.FactorAuthority{}, invalidAuthority()
	}
	return readFactorAuthority(ctx, w, b, user, expectedVersion)
}
