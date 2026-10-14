package identity_test

import (
	"fmt"

	"github.com/faustbrian/go-identity"
)

func ExampleNewCursor() {
	// A trusted repository records the scanned position in its retained snapshot.
	// The service authenticates/encrypts this value for wire continuation; it is
	// not a tenant permission, user identity or credential.
	cursor, err := identity.NewCursor("AQEBAQEBAQEBAQEBAQEBAQ", 10)
	if err != nil {
		panic(err)
	}
	fmt.Println(cursor.Position())
	// Output: 10
}
