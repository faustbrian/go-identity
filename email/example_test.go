package email_test

import (
	"fmt"
	identifier "github.com/faustbrian/go-identifier"
	email "github.com/faustbrian/go-identity/email"
)

func ExampleAddressParser_Parse() {
	profile, err := identifier.NewNormalizationProfile(identifier.NormalizationProfileSpec{
		ID: "email-comparison", Version: 1, Unicode: identifier.UnicodeNormalizationNFC, MaximumBytes: 4096,
	})
	if err != nil {
		panic(err)
	}
	parser, err := email.NewAddressParser(email.AddressPolicy{MaximumBytes: 4096, Canonicalization: profile, PreserveDisplay: true})
	if err != nil {
		panic(err)
	}
	address, err := parser.Parse("User+tag@BÜCHER.example")
	if err != nil {
		panic(err)
	}
	// Explicitly exposing a deliberately non-user example, not ordinary logging.
	fmt.Println(address.Canonical().Record().Value)
	// Output: User+tag@xn--bcher-kva.example
}
