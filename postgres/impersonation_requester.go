package postgres

import (
	"context"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// RequireActiveImpersonationRequester fences the original requester's account
// and authorization epochs during an exact approval. The Work actor remains the
// distinct approver on approval and is the original requester at exact start.
// UserID remains the target. The native feature owner authenticates the actor
// and binds the requester to the retained grant and original command. This
// helper neither authenticates anyone nor transfers their authority.
func (w Work) RequireActiveImpersonationRequester(ctx context.Context, owner FeatureExecutionContributor, command identity.Command, expected identity.User, policy UserAuthorizationAdmission) error {
	return w.requireImpersonationParticipant(ctx, owner, command, expected, policy, impersonationRequesterMatches)
}

// RequireActiveImpersonationApprover fences the original reviewer account and
// authorization epoch. During approval the reviewer must be the current actor;
// during start they must be distinct from actor and target. The caller owns
// exact retained approval proof and current eligibility policy. Only its live
// original Apply/final command may read or lock this participant.
func (w Work) RequireActiveImpersonationApprover(ctx context.Context, owner FeatureExecutionContributor, command identity.Command, expected identity.User, policy UserAuthorizationAdmission) error {
	return w.requireImpersonationParticipant(ctx, owner, command, expected, policy, impersonationApproverMatches)
}

type impersonationParticipantMatcher func(identity.CommandBinding, FeatureRegistration, identity.Command, identity.User, UserAuthorizationAdmission) bool

func (w Work) requireImpersonationParticipant(ctx context.Context, owner FeatureExecutionContributor, command identity.Command, expected identity.User, policy UserAuthorizationAdmission, matches impersonationParticipantMatcher) error {
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
	if err != nil || !matches(binding, registration, command, expected, policy) {
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
	mustBeActor := binding.OperationID == "identity.impersonation.start"
	return impersonationParticipantMatches(binding, registration, command, expected, policy, "impersonation.requester", mustBeActor)
}

func impersonationApproverMatches(binding identity.CommandBinding, registration FeatureRegistration, command identity.Command, expected identity.User, policy UserAuthorizationAdmission) bool {
	mustBeActor := binding.OperationID == "identity.impersonation.approve"
	return impersonationParticipantMatches(binding, registration, command, expected, policy, "impersonation.approver", mustBeActor)
}

func impersonationParticipantMatches(binding identity.CommandBinding, registration FeatureRegistration, command identity.Command, expected identity.User, policy UserAuthorizationAdmission, fieldPrefix string, mustBeActor bool) bool {
	var schema string
	switch binding.OperationID {
	case "identity.impersonation.approve":
		schema = "impersonation-approve"
	case "identity.impersonation.start":
		schema = "impersonation-start"
		grant, err := identity.ParseCommandID(binding.RecordID)
		if err != nil || grant == binding.CommandID {
			return false
		}
	default:
		return false
	}
	op := identity.FeatureOperation{Owner: "identity/impersonation", OperationID: binding.OperationID, SchemaID: schema, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	descriptor := ContributorDescriptor{Owner: "identity/impersonation/postgres", ContractID: "identity.impersonation", Version: 1}
	spec, ok := command.Feature()
	if !ok || registration.Operation != op || registration.Contributor != descriptor || spec.Operation != op || spec.Binding != binding || binding.ActorKind != authorization.SubjectUser {
		return false
	}
	isActor := expected.ID == identity.UserID(binding.ActorID)
	if expected.Validate(binding.TenantID) != nil || expected.Status != identity.StatusActive || expected.ID == binding.UserID || isActor != mustBeActor {
		return false
	}
	if policy.Scope.Validate() != nil || policy.Scope.TenantID != authorization.TenantID(binding.TenantID) || policy.Scope.SubjectID != authorization.SubjectID(expected.ID) || policy.Version == 0 {
		return false
	}
	var matched int
	for _, field := range spec.Fields {
		v := field.Value
		switch field.Name {
		case fieldPrefix + "-id":
			if v.Kind == identity.FeatureText && v.Text == string(expected.ID) {
				matched++
			}
		case fieldPrefix + "-version":
			if v.Kind == identity.FeatureUint64 && v.Uint64 == expected.Version {
				matched++
			}
		case fieldPrefix + "-namespace":
			if v.Kind == identity.FeatureText && v.Text == policy.Scope.PolicyNamespace {
				matched++
			}
		case fieldPrefix + "-authority":
			if v.Kind == identity.FeatureUint64 && v.Uint64 == policy.Version {
				matched++
			}
		}
	}
	return matched == 4
}
