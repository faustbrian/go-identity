package identity_test

import (
	"fmt"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func ExampleApplyIdentifierChange() {
	// The platform owner supplies locked primary state. This pure computation
	// does not authorize a caller, verify a challenge or commit durable state.
	state := identity.IdentifierState{
		User:             identity.User{ID: "user", TenantID: "tenant", Status: identity.StatusActive, Version: 1},
		AuthorityVersion: 1,
	}
	next, err := identity.ApplyIdentifierChange(state, identity.IdentifierChange{
		TenantID: "tenant", UserID: "user", ID: "email-record",
		Action: identity.IdentifierAttach, Kind: identity.IdentifierEmail,
		CanonicalValue: "person@example.test", DisplayValue: "Person@example.test",
		ExpectedUserVersion: 1, ExpectedAuthorityVersion: 1,
	}, time.Date(2026, 10, 2, 8, 0, 0, 0, time.UTC))
	if err != nil {
		panic(err)
	}
	fmt.Println(next.State.AuthorityVersion, next.State.Identifiers[0].Verified, next.State.Identifiers[0].Primary)
	// Output: 2 false false
}
