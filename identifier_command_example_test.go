package identity_test

import (
	"fmt"

	identity "github.com/faustbrian/go-identity"
)

func ExampleIdentifierIntentDigest() {
	digest, err := identity.IdentifierIntentDigest(identity.IdentifierChange{
		TenantID: "tenant-1", UserID: "user-1", Action: identity.IdentifierAttach,
		ID: "b", Kind: identity.IdentifierEmail, CanonicalValue: "two@example.test",
		ExpectedUserVersion: 4, ExpectedAuthorityVersion: 2,
	})
	// A digest binds intent. It is not a proof, bearer or safe tombstone.
	fmt.Println(err == nil, len(digest))
	// Output: true 32
}
