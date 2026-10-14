package i18n_test

import (
	"fmt"
	"github.com/faustbrian/go-identity/i18n"
)

func ExampleNewCatalog() {
	catalog, err := i18n.NewCatalog("fi-FI", []i18n.Message{{ID: "denied", Template: "Estetty"}})
	if err != nil {
		panic(err)
	}
	fmt.Println(catalog.Locale, catalog.Version, catalog.Messages[0].ID)
	// Output: fi-FI 1 denied
}
