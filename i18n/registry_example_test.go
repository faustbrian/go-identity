package i18n_test

import (
	"fmt"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/i18n"
)

type deniedError struct{}

func (deniedError) Error() string                     { return "request denied" }
func (deniedError) ErrorIdentity() i18n.ErrorIdentity { return "example.denied" }
func (deniedError) SafeParameters() []i18n.SafeParameter {
	return []i18n.SafeParameter{{Name: "attempts", Value: identity.AttributeScalar{Kind: identity.AttributeInt64, Int64: 3}, Context: i18n.ParameterPlainText}}
}

func ExampleErrorRegistry_Resolve() {
	registry := i18n.NewErrorRegistry()
	err := registry.Register("example.denied", "signin.denied", i18n.ParameterSchema{Parameters: []i18n.ParameterSpec{{Name: "attempts", Kind: identity.AttributeInt64, Context: i18n.ParameterPlainText}}})
	if err != nil {
		panic(err)
	}
	if err := i18n.SealErrorRegistry(registry); err != nil {
		panic(err)
	}
	message, parameters, found := registry.Resolve(deniedError{})
	fmt.Println(message, parameters[0].Value.Int64, found)
	// Output: signin.denied 3 true
}
