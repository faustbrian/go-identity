package mfapostgres

import (
	"context"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// RequireAdminSessionRevokeActorTOTPSessionFactor fences the administrator's
// original confirmed TOTP enrollment and factor generation in exact native
// administrator session-revoke Work. The factor belongs to the human command
// actor, including when that actor also owns the target session. The native
// session owner must bind the original authenticated session's factor, fence
// current actor primary and authorization, and check session possession, CSRF
// and freshness in the same Work. Propagate every error to abort. This guard
// grants no permission, renews no proof and does not revoke a session.
func RequireAdminSessionRevokeActorTOTPSessionFactor(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, actor identity.UserID, factorID string, expected TOTPSessionFactorState) error {
	if ctx == nil || expected.EnrollmentVersion == 0 || expected.AuthorityVersion == 0 {
		return invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	binding, registration, _, err := w.FeatureScope(owner)
	if err != nil || !adminSessionRevokeActorTOTPBindingMatches(binding, registration, actor) {
		return invalidAuthority()
	}
	if _, err := identity.ParseCommandID(factorID); err != nil {
		return invalidAuthority()
	}
	return requireTOTPSessionFactor(ctx, w, binding, actor, factorID, expected)
}

func adminSessionRevokeActorTOTPBindingMatches(binding identity.CommandBinding, registration kernel.FeatureRegistration, actor identity.UserID) bool {
	if actor == "" || binding.ActorKind != authorization.SubjectUser || identity.UserID(binding.ActorID) != actor {
		return false
	}
	if registration.Contributor != (kernel.ContributorDescriptor{Owner: "identity/session/postgres", ContractID: "identity.session.store", Version: 1}) {
		return false
	}
	operation := identity.FeatureOperation{
		Owner: "identity/session", OperationID: "identity.admin.session-revoke",
		SchemaID: "session-admin-revoke-one", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired,
	}
	return registration.Operation == operation && binding.ValidateFor(operation) == nil
}
