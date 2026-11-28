package postgres

import (
	"context"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// RequireActiveImpersonationRequester fences the original requester's account
// and authorization epochs during an exact approval. The Work actor remains the
// distinct approver; its UserID remains the target. Native approval owns policy,
// authenticating the approver and verifying that the requester comes from the
// exact locked grant and frozen original command. This narrow helper neither
// reauthenticates the requester nor transfers their authority to the approver.
func (w Work) RequireActiveImpersonationRequester(ctx context.Context, owner FeatureExecutionContributor, command identity.Command, expected identity.User, policy UserAuthorizationAdmission) error {
	if err := w.usable(); err != nil {
		return err
	}
	if ctx == nil {
		return w.fail(w.state.ctx, invalidWork())
	}
	if err := ctx.Err(); err != nil {
		return w.fail(ctx, err)
	}
	binding, registration, _, err := w.FeatureScope(owner)
	if err != nil || !impersonationRequesterMatches(binding, registration, command, expected, policy) {
		return w.fail(ctx, invalidWork())
	}
	original := w.state.featureApplyCommand
	if !w.state.featureApplying {
		original = w.state.featureCommitCommand
	}
	if original == nil || *original != command {
		return w.fail(ctx, invalidWork())
	}
	if err := w.requireActiveUserRecord(ctx, expected); err != nil {
		return err
	}
	// Change only the local authorization lookup key, never Work's binding.
	binding.UserID = expected.ID
	return w.requireActiveUserAuthorization(ctx, binding, policy)
}

func impersonationRequesterMatches(binding identity.CommandBinding, registration FeatureRegistration, command identity.Command, expected identity.User, policy UserAuthorizationAdmission) bool {
	const action = "identity.impersonation.approve"
	op := identity.FeatureOperation{Owner: "identity/impersonation", OperationID: action, SchemaID: "impersonation-approve", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	descriptor := ContributorDescriptor{Owner: "identity/impersonation/postgres", ContractID: "identity.impersonation", Version: 1}
	spec, ok := command.Feature()
	if !ok || registration.Operation != op || registration.Contributor != descriptor || spec.Operation != op || spec.Binding != binding || binding.ActorKind != authorization.SubjectUser {
		return false
	}
	if expected.Validate(binding.TenantID) != nil || expected.Status != identity.StatusActive || expected.ID == binding.UserID || expected.ID == identity.UserID(binding.ActorID) {
		return false
	}
	if policy.Scope.Validate() != nil || policy.Scope.TenantID != authorization.TenantID(binding.TenantID) || policy.Scope.SubjectID != authorization.SubjectID(expected.ID) || policy.Version == 0 {
		return false
	}
	var matched int
	for _, field := range spec.Fields {
		v := field.Value
		switch field.Name {
		case "impersonation.requester-id":
			if v.Kind == identity.FeatureText && v.Text == string(expected.ID) {
				matched++
			}
		case "impersonation.requester-version":
			if v.Kind == identity.FeatureUint64 && v.Uint64 == expected.Version {
				matched++
			}
		case "impersonation.requester-namespace":
			if v.Kind == identity.FeatureText && v.Text == policy.Scope.PolicyNamespace {
				matched++
			}
		case "impersonation.requester-authority":
			if v.Kind == identity.FeatureUint64 && v.Uint64 == policy.Version {
				matched++
			}
		}
	}
	return matched == 4
}
