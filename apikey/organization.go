package apikey

import (
	"context"
	"fmt"
	"io"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// OrganizationCreateRequest explicitly selects organization ownership while
// retaining the actual manager's bearer authentication. OrganizationID is a
// target, not proof of membership or permission. The native owner must verify
// current membership, organization eligibility and every requested permission.
// The user-owned Create entry point cannot accept or silently ignore this type.
type OrganizationCreateRequest struct {
	CreateRequest
	OrganizationID OrganizationID
}

// Validate checks request shape only, never authentication or organization
// authority. Invalid input returns ErrInvalid without I/O or normalization.
func (r OrganizationCreateRequest) Validate() error {
	if r.CreateRequest.Validate() != nil || !scope(string(r.OrganizationID), 128) {
		return ErrInvalid
	}
	return nil
}

// OrganizationService is the explicitly selected organization extension of the
// native key service. Unselected adapters need not implement it. Rotate/revoke
// still target an existing key and must independently authorize its actual
// owner and current human; no creator-membership dependency is inferred.
type OrganizationService interface {
	Service
	CreateOrganization(context.Context, OrganizationCreateRequest) (IssuanceResult, error)
}

func organizationIssuanceOperation(operationID string) identity.FeatureOperation {
	schema := ""
	switch operationID {
	case "identity.apikey.create":
		schema = "apikey-create-organization-v1"
	case "identity.apikey.rotate":
		schema = "apikey-rotate-organization-v1"
	default:
		return identity.FeatureOperation{}
	}
	return identity.FeatureOperation{Owner: "identity/apikey", OperationID: operationID, SchemaID: schema, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func issuanceOwnerMatches(record Record, receipt identity.CommandResult) bool {
	owner, binding := record.Owner.spec, receipt.Binding
	if owner.TenantID != binding.TenantID {
		return false
	}
	if owner.Kind == OwnerUser {
		// Old user-owned profiles retain their existing compatibility. The new
		// exact organization schema may never be reinterpreted as a self key.
		return owner.UserID == binding.UserID && binding.SchemaID != "apikey-create-organization-v1" && binding.SchemaID != "apikey-rotate-organization-v1"
	}
	if owner.Kind != OwnerOrganization {
		return false
	}
	op := organizationIssuanceOperation(binding.OperationID)
	return op != (identity.FeatureOperation{}) && receipt.Feature.Operation == op && binding.ValidateFor(op) == nil && binding.ActorKind == authorization.SubjectUser && binding.UserID != "" && binding.ActorID == identity.ActorID(binding.UserID)
}

func (OrganizationCreateRequest) Format(s fmt.State, _ rune) {
	io.WriteString(s, "apikey.OrganizationCreateRequest(redacted)")
}
func (OrganizationCreateRequest) MarshalJSON() ([]byte, error) { return nil, ErrDisclosure }
