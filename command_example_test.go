package identity_test

import (
	"fmt"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-identity"
)

func ExampleNewUserCreationCommand() {
	id, err := identity.NewCommandID()
	if err != nil {
		panic(err)
	}
	command, err := identity.NewUserCreationCommand(identity.CreateUserCommand{
		Binding: identity.CommandBinding{
			CommandID: id, TenantID: "tenant-example", UserID: "user-example",
			ActorID: "operator-example", ActorKind: authorization.SubjectServiceAccount,
			OperationID: "identity.user.create", PolicyID: "directory-policy", PolicyVersion: 1,
			SchemaID: "profile", SchemaVersion: 1, CorrelationID: string(id),
		}, Status: identity.StatusActive,
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("%#v\n", command)
	// Output: identity.Command(redacted)
}
