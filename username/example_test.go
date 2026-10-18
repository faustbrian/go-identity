package username_test

import (
	"context"
	"fmt"

	"github.com/faustbrian/go-identity/username"
)

func ExamplePolicy_Validate() {
	policy, err := username.NewPolicy(username.ReferencePolicySpec())
	if err != nil {
		panic(err)
	}
	name, err := policy.Validate(context.Background(), "Straße")
	if err != nil {
		panic(err)
	}
	// Deliberate sensitive persistence projection, not ordinary logging.
	record := name.Record()
	fmt.Println(record.Canonical, record.Display, record.ProfileVersion)
	fmt.Println(name)
	// Output:
	// strasse Straße 1
	// username(redacted)
}
