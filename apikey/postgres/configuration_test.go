package postgres_test

import (
	"errors"
	"testing"

	"github.com/faustbrian/go-identity/apikey"
	apikeypg "github.com/faustbrian/go-identity/apikey/postgres"
)

func TestConfigurationCheckRejectsAbsentService(t *testing.T) {
	for _, service := range []*apikeypg.Service{nil, {}} {
		if err := service.CheckConfiguration(t.Context(), "tenant"); !errors.Is(err, apikey.ErrInvalid) {
			t.Fatal("absent native configuration owner admitted", err)
		}
	}
}
