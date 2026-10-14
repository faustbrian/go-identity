package identity_test

import (
	"fmt"

	"github.com/faustbrian/go-identity"
)

func ExampleParseSubjectID() {
	id, err := identity.ParseSubjectID("AAAAAAAAAAAAAAAAAAAAAQ")
	if err != nil {
		return
	}
	fmt.Println(identity.FormatSubjectID(id))
	// Output: AAAAAAAAAAAAAAAAAAAAAQ
}

func ExampleParsePreAuthTransactionID() {
	id, err := identity.ParsePreAuthTransactionID("AQAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		return
	}
	fmt.Println(identity.FormatPreAuthTransactionID(id))
	// Output: AQAAAAAAAAAAAAAAAAAAAA
}
