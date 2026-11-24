package postgres

import (
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
)

// Directory starts create a new generation record on every distinct command.
// Using that record as the resource would split one directory's abuse budget.
// Only this exact native profile replaces the usual record-bound dimension;
// the coordinator still binds the original generation in its command fingerprint.
func privilegedCounterResource(s identity.FeatureCommandSpec) (string, error) {
	if s.Operation.OperationID != "identity.sso.directory-sync-start" {
		return s.Binding.RecordID, nil
	}
	op := identity.FeatureOperation{Owner: "sso", OperationID: "identity.sso.directory-sync-start", SchemaID: "sso-directory-sync-start-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	if s.Operation != op || s.Binding.ValidateFor(op) != nil || s.Binding.ActorKind != authorization.SubjectUser || string(s.Binding.ActorID) != string(s.Binding.UserID) {
		return "", risk.ErrInvalidCounterCommand
	}
	var organizationID, sourceID, providerID string
	for _, field := range s.Fields {
		var target *string
		switch field.Name {
		case "directory.organization-id":
			target = &organizationID
		case "directory.source-id":
			target = &sourceID
		case "directory.provider-id":
			target = &providerID
		default:
			continue
		}
		if *target != "" || field.Value.Kind != identity.FeatureText {
			return "", risk.ErrInvalidCounterCommand
		}
		*target = field.Value.Text
	}
	return risk.DirectorySyncStartCounterResource(organizationID, sourceID, providerID)
}
