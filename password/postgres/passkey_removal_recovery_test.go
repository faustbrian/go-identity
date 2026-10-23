package passwordpostgres

import (
	"context"
	"encoding/json"
	"testing"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestPasskeyRemovalRecoveryRequiresNativeRequestAndCompletion(t *testing.T) {
	for _, service := range []*ResetService{nil, {}, {request: &resetRequestRuntime{}}} {
		if source, err := NewPasskeyRemovalRecoverySource(service); err == nil || source != nil {
			t.Fatal("missing native email recovery became passkey removal authority")
		}
	}
	for _, source := range []*PasskeyRemovalRecoverySource{nil, {}} {
		if source.PasskeyRemovalRecoveryIdentity() != ([32]byte{}) {
			t.Fatal("zero recovery source acquired configuration")
		}
		if err := source.CheckPasskeyRemovalRecovery(context.Background(), kernel.Work{}, nil, identity.Command{}); err == nil {
			t.Fatal("zero recovery owner admitted removal")
		}
	}
	if _, err := json.Marshal(PasskeyRemovalRecoverySource{}); err == nil {
		t.Fatal("recovery source implicitly exported configuration")
	}
}
