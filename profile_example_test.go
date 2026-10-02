package identity_test

import (
	"fmt"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
)

func ExampleNewProfileUpdateCommand() {
	command, err := identity.NewProfileUpdateCommand(identity.ProfileUpdateCommand{
		Binding:         identity.CommandBinding{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", TenantID: "tenant-a", UserID: "user-a", ActorID: "user-a", ActorKind: authorization.SubjectUser, OperationID: "identity.profile.update", PolicyID: "profile-policy", PolicyVersion: 1, SchemaID: "profile", SchemaVersion: 1, CorrelationID: "correlation-a"},
		ExpectedVersion: 2, Name: "example",
	})
	if err != nil {
		panic(err)
	}
	_, ok := command.UpdateProfile()
	fmt.Println(command, ok)
	// Output: identity.Command(redacted) true
}
