package i18n_test

import (
	"fmt"
	"github.com/faustbrian/go-identity/i18n"
)

func ExampleDefaultMatcher_Match() {
	locale, err := (i18n.DefaultMatcher{}).Match(i18n.MatchInput{
		Requested: []string{"fi-FI", "en;q=0.8"},
		Supported: []i18n.Locale{"en", "fi"}, Default: "en",
	})
	fmt.Println(locale, err)
	// Output: fi <nil>
}
