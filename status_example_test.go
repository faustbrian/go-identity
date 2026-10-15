package identity_test

import (
	"fmt"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func ExampleNewUserStatusCommand() {
	// Trusted composition authorizes and validates policy before sending this
	// immutable intent to the durable owner. Construction grants no authority.
	command, err := identity.NewUserStatusCommand(identity.UserStatusCommand{
		Binding: identity.CommandBinding{
			CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", TenantID: "tenant-a",
			UserID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", ActorID: "actor-a",
			ActorKind: authorization.SubjectUser, OperationID: "identity.user.suspend",
			PolicyID: "identity-policy", PolicyVersion: 1,
			SchemaID: "identity-lifecycle", SchemaVersion: 1, CorrelationID: "request-a",
		},
		ExpectedVersion: 12, ExpectedAuthorityVersion: 3, StatusPolicyVersion: 1,
		TargetStatus: identity.StatusSuspended, Reason: "abuse",
	})
	if err != nil {
		panic(err)
	}
	spec, ok := command.UserStatus()
	fmt.Println(ok, len(spec.RequiredConsumers()))
	fmt.Println(command)
	// Output:
	// true 12
	// identity.Command(redacted)
}
