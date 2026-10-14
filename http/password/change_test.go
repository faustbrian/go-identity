package passwordhttp_test

import (
	"errors"
	"testing"

	identityhttp "github.com/faustbrian/go-identity/http"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
)

// Risk plan: original key/proof/secret/credential mapping; trusted session
// subject, original validity after rate/hooks, exact origin and CSRF channels;
// malformed input before IO, one native invocation, redacted ambiguous outcomes
// and no credential delivery. SQL atomic effects remain native-owned and need
// a composed real PostgreSQL check before claiming endpoint completion.
func TestPasswordChangeRejectsMissingComposition(t *testing.T) {
	if h, err := passwordhttp.NewChangeHandler(passwordhttp.ChangeConfig{}); h != nil || !errors.Is(err, identityhttp.ErrInvalidInput) {
		t.Fatal("unconfigured handler accepted")
	}
}
