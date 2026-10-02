package postgres_test

import (
	"fmt"

	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

// A separately owned adapter can implement the open interface without private
// symbols. This example describes registration only, not an executable phase.
type exampleContributor struct{}

func (exampleContributor) Descriptor() identitypostgres.ContributorDescriptor {
	return identitypostgres.ContributorDescriptor{Owner: "example/postgres", ContractID: "example.domain", Version: 1}
}

func ExampleNewContributorRegistry() {
	r, err := identitypostgres.NewContributorRegistry([]identitypostgres.Contributor{exampleContributor{}})
	if err != nil {
		panic(err)
	}
	d := r.Descriptors()[0]
	fmt.Println(d.Owner, d.ContractID, d.Version)
	// Output: example/postgres example.domain 1
}
