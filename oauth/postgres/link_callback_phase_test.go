package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestRPCallbackPreparationKeepsRootAccountDistinctFromOriginalState(t *testing.T) {
	p, retained, request, now := rpCallbackInputFixture(t)
	flow, err := p.service.authenticateRPCallback(context.Background(), request, retained.Binding, retained.StateProofCiphertext, *now)
	if err != nil {
		t.Fatal(err)
	}
	defer flow.destroy()
	spec, err := callbackSpecification(flow)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(retained.Binding)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	b := spec.Binding
	if b.CommandID != retained.Binding.CallbackCommandID || b.RecordID != retained.Binding.AccountRecordID || b.RecordID == spec.FlowID || b.OperationID != "identity.account.link-token" || b.SchemaID != "identity-account" || b.SchemaVersion != 1 || b.LinkMode != identity.AccountLinkExplicit || b.UserID != p.input.binding().UserID || b.ActorID != p.input.binding().ActorID || spec.FlowID != p.input.binding().RecordID || spec.FlowFingerprint != sha256.Sum256(encoded) || spec.ProviderID != retained.Binding.Provider.ID || spec.ProviderConfigVersion != retained.Binding.Provider.Version || spec.SessionID != "session" || spec.SessionVersion != 1 {
		t.Fatal("callback preparation retargeted state or changed original account/session/provider intent")
	}
	// Terminal metadata may reconstruct the original command for journal replay;
	// it cannot authenticate state again or start another generation.
	flow.erased = true
	replayed, err := callbackSpecification(flow)
	if err != nil || replayed.Binding != spec.Binding || replayed.FlowFingerprint != spec.FlowFingerprint {
		t.Fatal("erasure changed the original journal identity", err)
	}
	for _, wrong := range []rpCallbackFlow{{}, {binding: flow.binding}} {
		if _, err := callbackSpecification(wrong); err == nil {
			t.Fatal("missing original session accepted")
		}
	}
}
