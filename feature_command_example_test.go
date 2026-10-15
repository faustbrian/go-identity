package identity_test

import (
	"fmt"
	"math"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func ExampleNewFeatureCommand() {
	// Trusted adapter mapping, not authentication, authorization or issuance.
	c, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{
		Operation: identity.FeatureOperation{Owner: "identity/session", OperationID: "identity.session.issue", SchemaID: "session-issue", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired},
		Binding: identity.CommandBinding{
			CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", TenantID: "tenant-a", UserID: "user-a",
			ActorID: "actor-a", ActorKind: authorization.SubjectUser,
			OperationID: "identity.session.issue", RecordID: "session-a",
			PolicyID: "session-policy", PolicyVersion: 1,
			SchemaID: "session-issue", SchemaVersion: 1, CorrelationID: "correlation-a",
		},
		Fields: []identity.FeatureField{{Name: "authority.user-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: math.MaxUint64}}},
	})
	if err != nil {
		panic("invalid example command")
	}
	projection, _ := c.Feature() // trusted mapping only; never log the projection
	fmt.Println(projection.Fields[0].Value.Uint64)
	fmt.Println(c)
	// Output:
	// 18446744073709551615
	// identity.Command(redacted)
}
