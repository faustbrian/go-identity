package postgres

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/faustbrian/go-identity/session"
)

func TestOwnedSignOutRejectsIncompleteComposition(t *testing.T) {
	if service, err := NewSignOutService(nil, SignOutServiceConfig{}); service != nil || err == nil {
		t.Fatal("incomplete logout composition admitted")
	}
	var _ session.RevokeOneExecutor = (*RevokeOneExecutor)(nil)
}

func TestOwnedSignOutConfigurationCannotDiscloseSecrets(t *testing.T) {
	c := SignOutServiceConfig{}
	if got := fmt.Sprintf("%#v", c); got != "postgres.SignOutServiceConfig(redacted)" {
		t.Fatal("configuration disclosure")
	}
	if _, err := json.Marshal(c); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("configuration export admitted")
	}
}
