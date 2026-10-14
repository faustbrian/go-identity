package identity_test

import (
	"fmt"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func ExampleNewIdentifierProjection() {
	// A trusted feature has already authorized and read this consistent partition.
	observed := time.Date(2026, 10, 10, 19, 0, 0, 0, time.UTC)
	state := identity.IdentifierState{
		User:             identity.User{ID: "user-one", TenantID: "tenant-one", Status: identity.StatusActive, Version: 2},
		AuthorityVersion: 2,
		Identifiers: []identity.Identifier{{
			ID: "email-one", UserID: "user-one", Kind: identity.IdentifierEmail,
			CanonicalValue: "member@example.test", Verified: true, Version: 2,
		}},
		Verifications: []identity.Verification{{
			IdentifierID: "email-one", State: identity.VerificationVerified,
			VerifiedAt: observed.Add(-time.Minute), Version: 2,
		}},
	}
	projection, err := identity.NewIdentifierProjection(identity.IdentifierProjectionSpec{
		TenantID: "tenant-one", UserID: "user-one", IdentifierID: "email-one",
		State: state, ObservedAt: observed, Values: identity.IdentifierValuesOmitted,
	})
	if err != nil {
		panic(err)
	}
	metadata, err := projection.Bindings()
	if err != nil {
		panic(err)
	}
	_, _, hasValues := projection.Values()
	fmt.Println(metadata.Verified, metadata.IdentifierVersion, hasValues)
	// Output: true 2 false
}
