package identity_test

import (
	"fmt"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func ExampleCommandBinding_ValidateFor() {
	// Compile-time composition descriptor, not an operation supplied by a client.
	operation := identity.FeatureOperation{
		Owner: "identity/session", OperationID: "identity.session.issue",
		SchemaID: "session-issue", SchemaVersion: 1,
		RecordRequirement: identity.FeatureRecordRequired,
	}
	binding := identity.CommandBinding{
		CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", TenantID: "tenant-a", UserID: "user-a",
		ActorID: "actor-a", ActorKind: authorization.SubjectUser,
		OperationID: "identity.session.issue", RecordID: "session-a",
		PolicyID: "session-policy", PolicyVersion: 1,
		SchemaID: "session-issue", SchemaVersion: 1, CorrelationID: "correlation-a",
	}
	fmt.Println(binding.ValidateFor(operation) == nil)
	binding.SchemaVersion++
	fmt.Println(binding.ValidateFor(operation) != nil)
	// Output:
	// true
	// true
}
