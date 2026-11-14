package postgres_test

import (
	"context"
	"testing"

	"github.com/faustbrian/go-identity/apikey"
	apikeypg "github.com/faustbrian/go-identity/apikey/postgres"
)

// The selected projection adapter requires real owned Store and AtomicVerifier
// sources. A shape-only placeholder cannot replace native permission maintenance.
var _ apikey.Store = (*apikeypg.PermissionReductionStore)(nil)

func TestPermissionReductionStoreRejectsMissingNativeOwner(t *testing.T) {
	if store, err := apikeypg.NewPermissionReductionStore(nil, apikeypg.PermissionReductionStoreConfig{TenantID: "tenant-a", UserID: "user-a", ActorID: "maintenance", ActorPolicyNamespace: "apikey-maintenance"}); err == nil || store != nil {
		t.Fatal("permission maintenance accepted an absent actual native source")
	}
	var source *apikeypg.PermissionReductionStore
	if out, err := source.ApplyPermissionReduction(context.Background(), apikey.PermissionReductionDecision{}); err == nil || out.Record != nil || out.ConfigurationAuthority != nil {
		t.Fatal("absent native owner accepted caller-supplied maintenance authority")
	}
	if out, err := source.ReconcilePermissionReduction(context.Background(), apikey.PermissionReductionReconcileQuery{}); err == nil || out.Record != nil || out.ConfigurationAuthority != nil {
		t.Fatal("absent native owner fabricated historical reduction commitment")
	}
}
