package identity_test

import (
	"fmt"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-identity"
)

func ExampleNewUserUpdateCommand() {
	id, err := identity.NewCommandID()
	if err != nil {
		panic(err)
	}
	command, err := identity.NewUserUpdateCommand(identity.UpdateUserCommand{
		Binding:         identity.CommandBinding{CommandID: id, TenantID: "tenant-example", UserID: "user-example", ActorID: "operator-example", ActorKind: authorization.SubjectServiceAccount, OperationID: "identity.user.update-admin", PolicyID: "directory-policy", PolicyVersion: 1, SchemaID: "profile", SchemaVersion: 1, CorrelationID: string(id)},
		ExpectedVersion: 2, Attributes: []identity.AttributeUpdate{{Name: "display_name", Value: identity.AttributeValue{Kind: identity.AttributeString, Scalar: identity.AttributeScalar{Kind: identity.AttributeString, String: "public-example"}}}},
	})
	if err != nil {
		panic(err)
	}
	// Construction validates structure, not policy or permission to execute.
	fmt.Printf("%#v\n", command)
	// Output: identity.Command(redacted)
}
