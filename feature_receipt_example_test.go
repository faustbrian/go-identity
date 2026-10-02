package identity_test

import (
	"fmt"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
)

func ExampleFeatureReceipt() {
	// A structural trusted-adapter projection, not issuance or commit evidence.
	r := identity.CommandResult{
		Binding: identity.CommandBinding{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", TenantID: "tenant-a", UserID: "user-a", ActorID: "actor-a", ActorKind: authorization.SubjectUser, OperationID: "identity.session.issue", RecordID: "session-a", PolicyID: "session-policy", PolicyVersion: 1, SchemaID: "session-issue", SchemaVersion: 1, CorrelationID: "correlation-a"},
		Outcome: identity.CommitOutcomeCommitted, AuditEventID: "audit-a",
		Feature: &identity.FeatureReceipt{Operation: identity.FeatureOperation{Owner: "identity/session", OperationID: "identity.session.issue", SchemaID: "session-issue", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}, AfterVersion: 1},
	}
	if r.Validate() != nil {
		panic("invalid example receipt")
	}
	fmt.Println(r.Feature.BeforeVersion, r.Feature.AfterVersion)
	// Output: 0 1
}
