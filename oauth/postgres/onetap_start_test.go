package postgres_test

import (
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth/onetap"
	postgres "github.com/faustbrian/go-identity/oauth/postgres"
)

func TestOneTapNativeStartRejectsUnconfiguredRequests(t *testing.T) {
	var invalid identity.InvalidInputError
	owner, err := postgres.NewOneTapStartService(nil, postgres.OneTapStartConfig{})
	if owner != nil || !errors.As(err, &invalid) {
		t.Fatal("unconfigured startup selected a native One Tap owner")
	}
	for _, owner := range []*postgres.OneTapStartService{nil, new(postgres.OneTapStartService)} {
		result, err := owner.Start(t.Context(), onetap.BrowserStartRequest{})
		_, deliverable := result.Browser()
		if !errors.As(err, &invalid) || result.CommandID != "" || deliverable {
			t.Fatal("missing native owner or input returned a One Tap command or browser delivery")
		}
	}
}
