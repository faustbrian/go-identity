package mfapostgres

import (
	"context"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// RequireManagedEmailFactors fences known empty MFA at its exact retained
// generation for the registered self-user email owner. It is valid during
// preparation, Apply and final checks, but grants no proof or mutation authority.
// Missing/enrolled/changed state denies; no initialization or absence inference
// occurs. The sole Work retains the primary factor lock until it closes.
func RequireManagedEmailFactors(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, expectedVersion uint64) (mfa.FactorAuthority, error) {
	if ctx == nil || owner == nil || expectedVersion == 0 {
		return mfa.FactorAuthority{}, invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return mfa.FactorAuthority{}, err
	}
	s, ok := command.Feature()
	b, f, _, err := w.FeatureScope(owner)
	if err != nil || !ok || s.Binding != b || s.Operation != f.Operation || f.Contributor != (kernel.ContributorDescriptor{Owner: "identity/email/postgres", ContractID: "identity.email", Version: 1}) {
		return mfa.FactorAuthority{}, invalidAuthority()
	}
	valid := f.Operation == (identity.FeatureOperation{Owner: "identity/email", OperationID: "identity.email.verification-confirm", SchemaID: "identity.email.verification-confirm.managed-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired})
	valid = valid || f.Operation == (identity.FeatureOperation{Owner: "identity/email", OperationID: "identity.email.change-confirm", SchemaID: "identity.email.change-confirm.managed-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired})
	if f.Operation == (identity.FeatureOperation{Owner: "identity/email", OperationID: "identity.email.verification-send", SchemaID: "identity.email.verification-send.resend-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}) {
		valid = b.ActorKind == authorization.SubjectUser && string(b.ActorID) == string(b.UserID)
	}
	for _, action := range []string{"identity.email.verification-send", "identity.email.change-request", "identity.email.address-remove"} {
		if f.Operation == (identity.FeatureOperation{Owner: "identity/email", OperationID: action, SchemaID: action + ".native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}) {
			valid = b.ActorKind == authorization.SubjectUser && string(b.ActorID) == string(b.UserID)
		}
	}
	if !valid {
		return mfa.FactorAuthority{}, invalidAuthority()
	}
	return readKnownEmptyFactors(ctx, w, b, b.UserID, expectedVersion)
}
