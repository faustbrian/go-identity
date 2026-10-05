package i18n_test

import (
	"context"
	"fmt"
	"github.com/faustbrian/go-identity/i18n"
)

type resolverDeniedError struct{}

func (resolverDeniedError) Error() string                        { return "denied" }
func (resolverDeniedError) ErrorIdentity() i18n.ErrorIdentity    { return "example.denied" }
func (resolverDeniedError) SafeParameters() []i18n.SafeParameter { return nil }

func ExampleDefaultResolver_Resolve() {
	registry := i18n.NewErrorRegistry()
	if err := registry.Register("example.denied", "denied", i18n.ParameterSchema{}); err != nil {
		panic(err)
	}
	catalogs, err := i18n.NewCatalogStore([]i18n.Catalog{{Locale: "en", Version: 1, Messages: []i18n.Message{{ID: "denied", Template: "Denied"}}}, {Locale: "fi", Version: 1, Messages: []i18n.Message{{ID: "denied", Template: "Estetty"}}}})
	if err != nil {
		panic(err)
	}
	resolver, err := i18n.NewConfiguredResolver(i18n.ResolverConfig{Registry: registry, Catalogs: catalogs})
	if err != nil {
		panic(err)
	}
	result, err := resolver.Resolve(context.Background(), i18n.ResolveInput{Explicit: "fi-FI", Default: "en", Error: resolverDeniedError{}})
	if err != nil {
		panic(err)
	}
	fmt.Println(result.Code, result.Locale, result.Message)
	// Output: example.denied fi Estetty
}
