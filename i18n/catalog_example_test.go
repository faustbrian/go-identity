package i18n_test

import (
	"context"
	"fmt"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/i18n"
)

func ExampleCatalogStore_Render() {
	store, err := i18n.NewCatalogStore([]i18n.Catalog{{Locale: "en", Version: 1, Messages: []i18n.Message{{ID: "attempts", Template: `{{value "count" "plain-text"}} {{plural "count" "one" "attempt" "other" "attempts"}}`, Placeholders: []i18n.ParameterSpec{{Name: "count", Kind: identity.AttributeInt64, Context: i18n.ParameterPlainText}}}}}})
	if err != nil {
		panic(err)
	}
	result, err := store.Render(context.Background(), "en", "attempts", []i18n.Parameter{{Name: "count", Value: identity.AttributeScalar{Kind: identity.AttributeInt64, Int64: 2}, Context: i18n.ParameterPlainText}})
	if err != nil {
		panic(err)
	}
	fmt.Println(result.Message)
	// Output: 2 attempts
}
