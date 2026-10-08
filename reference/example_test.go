package reference_test

import (
	"fmt"

	"github.com/faustbrian/go-identity/reference"
)

func ExampleComposeStores() {
	// Incomplete deployment resources never silently construct healthy stores.
	_, err := reference.ComposeStores(reference.StoreConfiguration{}, reference.ReferenceDependencies{})
	fmt.Println(err)
	// Output: risk: invalid policy
}
