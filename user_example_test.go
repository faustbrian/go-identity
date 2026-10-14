package identity_test

import (
	"fmt"
	"time"

	"github.com/faustbrian/go-identity"
)

func ExampleUser_Validate() {
	user := identity.User{
		ID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", TenantID: "tenant-a",
		Status: identity.StatusActive, Version: 1,
	}
	fmt.Println(user.Validate("tenant-a"))
	fmt.Println(user.Validate("tenant-b"))
	// Output:
	// <nil>
	// identity: invalid input
}

func ExampleStatusPolicy_CheckTransition() {
	policy := identity.StatusPolicy{
		AllowedTransitions: []identity.StatusTransition{
			{From: identity.StatusActive, To: identity.StatusSuspended, ReasonRequired: true},
		},
		MaximumSuspension: 24 * time.Hour,
	}
	// This checks a proposed edge, not caller authorization or committed state.
	fmt.Println(policy.CheckTransition(identity.StatusActive, identity.StatusSuspended, true, time.Hour))
	fmt.Println(policy.CheckTransition(identity.StatusActive, identity.StatusSuspended, false, time.Hour))
	// Output:
	// <nil>
	// identity: invalid input
}
