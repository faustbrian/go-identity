package reference

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
)

func TestAPIKeySelectionAndRetainedHandlesFailClosed(t *testing.T) {
	if owner, err := (FeatureSet{}).APIKeys(); err == nil || owner != nil {
		t.Fatal("zero graph exposed API-key owner")
	}
	for _, c := range []StoreConfiguration{{APIKey: &APIKeyConfiguration{}}, {HTTPAPIKey: &HTTPAPIKeyConfiguration{Create: true}}} {
		if graph, err := ComposeStores(c, ReferenceDependencies{}); err == nil || graph.state != nil {
			t.Fatal("selected API keys accepted missing native owners")
		}
	}
	var absent *APIKeyService
	var unavailable identity.UnavailableError
	if _, err := absent.Create(t.Context(), apikey.CreateRequest{}); !errors.As(err, &unavailable) {
		t.Fatal("nil handle reached native issuance")
	}
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	drained := make(chan struct{})
	close(drained)
	state := &storeState{durable: true, lifetime: lifetime, cancel: cancel, drained: drained, tenants: map[string]*tenantRecovery{"tenant": {}}, features: &featureState{composed: true, ready: true, timeout: time.Second, apiKey: &apiKeyState{}}}
	handle, err := (FeatureSet{state: state}).APIKeys()
	if err != nil {
		t.Fatal(err)
	}
	if err := (StoreSet{state: state}).Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	caller := apikey.Authentication{TenantID: "tenant"}
	if _, err := handle.Create(t.Context(), apikey.CreateRequest{Authentication: caller}); !errors.As(err, &unavailable) {
		t.Fatal("retained closed handle reached native issuance")
	}
	if _, err := handle.Rotate(t.Context(), apikey.Rotation{Authentication: caller}); !errors.As(err, &unavailable) {
		t.Fatal("retained closed handle reached native rotation")
	}
	if _, err := handle.Revoke(t.Context(), apikey.Revocation{Authentication: caller}); !errors.As(err, &unavailable) {
		t.Fatal("retained closed handle reached native revocation")
	}
	if _, err := handle.Recover(t.Context(), apikey.RecoveryRequest{Authentication: caller}); !errors.As(err, &unavailable) {
		t.Fatal("retained closed handle reached native recovery")
	}
	if _, err := handle.VerifyAndConsume(t.Context(), apikey.AtomicVerificationRequest{TenantID: "tenant"}); !errors.As(err, &unavailable) {
		t.Fatal("retained closed handle reached native verification")
	}
	if _, err := handle.ReconcileVerifyAndConsume(t.Context(), apikey.VerificationReconcileQuery{TenantID: "tenant"}); !errors.As(err, &unavailable) {
		t.Fatal("retained closed handle reached verification recovery")
	}
}
