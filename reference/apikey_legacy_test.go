package reference

import (
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
)

func TestAPIKeyLegacyImportUsesExistingGuardedOwner(t *testing.T) {
	var handle *APIKeyService
	importer, ok := any(handle).(apikey.LegacyImporter)
	if !ok {
		t.Fatal("selected Reference API-key owner does not expose native digest-only import")
	}
	var unavailable identity.UnavailableError
	if _, err := importer.Import(t.Context(), apikey.ImportRequest{}); !errors.As(err, &unavailable) {
		t.Fatal("nil Reference owner did not reject import before native work")
	}
	for _, handle := range []*APIKeyService{{}, {state: &storeState{closed: true}}} {
		importer = any(handle).(apikey.LegacyImporter)
		if _, err := importer.Import(t.Context(), apikey.ImportRequest{Authentication: apikey.Authentication{TenantID: "tenant"}}); !errors.As(err, &unavailable) {
			t.Fatal("unselected or closed Reference owner reached native import")
		}
	}
}
