package mfapostgres

import (
	"context"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// RequireImpersonationActorTOTPSessionFactor fences the administrator's
// original confirmed TOTP enrollment and factor generation for a protected
// impersonation request or approval. The administrator is the command actor,
// not its target user. The native owner must bind the original authenticated
// session's factor, fence the actor's current primary and authorization before
// calling this guard, and check session possession, CSRF and freshness in the
// same Work. Propagate every error to abort; this grants no permission,
// renews no proof and does not activate an impersonation session.
func RequireImpersonationActorTOTPSessionFactor(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, actor identity.UserID, factorID string, expected TOTPSessionFactorState) error {
	if ctx == nil || expected.EnrollmentVersion == 0 || expected.AuthorityVersion == 0 {
		return invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	binding, registration, _, err := w.FeatureScope(owner)
	if err != nil || !impersonationActorTOTPBindingMatches(binding, registration, actor) {
		return invalidAuthority()
	}
	if _, err := identity.ParseCommandID(factorID); err != nil {
		return invalidAuthority()
	}
	return requireTOTPSessionFactor(ctx, w, binding, actor, factorID, expected)
}

func impersonationActorTOTPBindingMatches(binding identity.CommandBinding, registration kernel.FeatureRegistration, actor identity.UserID) bool {
	if actor == "" || binding.ActorKind != authorization.SubjectUser || identity.UserID(binding.ActorID) != actor || binding.UserID == actor {
		return false
	}
	if registration.Contributor != (kernel.ContributorDescriptor{Owner: "identity/impersonation/postgres", ContractID: "identity.impersonation", Version: 1}) {
		return false
	}
	var schema string
	switch binding.OperationID {
	case "identity.impersonation.request":
		schema = "impersonation-request"
	case "identity.impersonation.approve":
		schema = "impersonation-approve"
	default:
		return false
	}
	operation := identity.FeatureOperation{
		Owner: "identity/impersonation", OperationID: binding.OperationID,
		SchemaID: schema, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired,
	}
	return registration.Operation == operation && binding.ValidateFor(operation) == nil
}
