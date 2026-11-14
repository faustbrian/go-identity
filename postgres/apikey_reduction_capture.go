package postgres

import (
	"context"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// ExecutePreparedAPIKeyPermissionReduction submits only the registered native
// service-account key-maintenance profile and returns its actual matched
// original claim fingerprint. The required record is the key being changed,
// distinct from the owning user and service actor. Other update schemas and
// human operations cannot select this output.
//
// The existing coordinator captures the commitment under its reservation lock,
// including a live lease, retained fingerprint-key rotation and uncertain
// acknowledgement. Never replace it with a prospective current-key hash. Zero
// means no matching claim was established. The commitment is correlation, not
// proof of commitment, permission or renewable validity; keep the exact original
// input for retries. Current native authorization, preparation, lifecycle and
// final-admission checks remain mandatory. No second transaction, journal or
// observation authority is introduced. Earlier caller deadlines win; the caller
// owns the coordinator's pool and registered dependencies throughout execution.
func (c *Coordinator) ExecutePreparedAPIKeyPermissionReduction(ctx context.Context, original identity.Command, declaration CommandPlan) (result identity.CommandResult, fingerprint [32]byte, err error) {
	op := identity.FeatureOperation{Owner: "identity/apikey", OperationID: "identity.apikey.update", SchemaID: "apikey-permission-reduction-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectUser}
	owner := ContributorDescriptor{Owner: "identity/apikey/postgres", ContractID: "identity.apikey", Version: 1}
	spec, ok := original.Feature()
	if ctx == nil || c == nil || c.admissionPolicy == nil || c.queryPolicy == nil || !ok || spec.Operation != op || spec.Binding.ValidateFor(op) != nil || spec.Binding.ActorKind != authorization.SubjectServiceAccount {
		return result, fingerprint, invalidPlan()
	}
	selected := declaration.Feature
	if selected == nil || selected.Contributor != owner || selected.Operation != op || declaration.APIKeyVerification != nil {
		return result, fingerprint, invalidPlan()
	}
	result, err = c.executePreparedFeatureCaptured(ctx, nil, original, declaration, &fingerprint)
	return result, fingerprint, err
}
