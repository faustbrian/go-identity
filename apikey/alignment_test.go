package apikey_test

import (
	"testing"
	"time"

	"github.com/faustbrian/go-identity/apikey"
)

func TestDurableKeyIdentityPreservesExistingCanonicalULID(t *testing.T) {
	const existing = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	id, err := apikey.ParseKeyID(existing)
	if err != nil || string(id) != existing {
		t.Fatal("existing identity replaced or rejected")
	}
	generated, err := apikey.NewKeyID()
	if err != nil || generated == "" || generated == id {
		t.Fatal("modern generation failed")
	}
}

func TestUnselectedMigrationStatesDenyAndShortSecureLifetimeIsAllowed(t *testing.T) {
	s := configuration(t).Spec()
	s.MaximumLifetime = time.Hour
	if _, err := apikey.NewConfiguration(s); err != nil {
		t.Error("secure short lifetime rejected")
	}
	s.MaximumLifetime = 90 * 24 * time.Hour
	for _, state := range []apikey.ConfigurationState{apikey.ConfigurationVerifyOnly, apikey.ConfigurationDeprecated} {
		s.State = state
		if _, err := apikey.NewConfiguration(s); err == nil {
			t.Error("unbounded unselected migration profile accepted")
		}
	}
}
