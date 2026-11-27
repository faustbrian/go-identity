package postgres

import (
	"bytes"
	"reflect"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestProxyStartOutputRemainsBoundToItsOriginalRequestAndGeneration(t *testing.T) {
	crypto, locator, fixture := proxyBindingFixture(t)
	command := identity.CommandBinding{CommandID: locator.OriginCommand, TenantID: locator.Tenant,
		RecordID: string(locator.Transaction), AnonymousFlowID: string(locator.Transaction)}
	request := [32]byte{81}
	output := proxyStartOutput{Version: 1, Locator: locator, State: fixture.CallbackNonce, Challenge: fixture.CallbackNonce,
		BindingCiphertext: []byte{1}, StateProofCiphertext: []byte{2}, PKCECiphertext: []byte{3}, Checkpoint: []byte{4},
		Grant: rpStoredGrant{CapabilityID: "original-proxy-grant", Purpose: "identity.oauth.proxy-forward", ReplayKeyVersion: 1,
			ReplayDigest: [32]byte{1}, ProofFingerprint: [32]byte{2}, MaxUses: 1, ExpiresAt: locator.ExpiresAt},
	}
	sealed, err := sealProxyStartOutput(t.Context(), crypto, "binding-v1", command, request, 7, output)
	if err != nil || bytes.Contains(sealed, []byte(output.State)) {
		t.Fatal("did not seal original OAuth state", err)
	}
	opened, err := openProxyStartOutput(t.Context(), crypto, command, request, 7, sealed)
	if err != nil || !reflect.DeepEqual(opened, output) {
		t.Fatal("did not recover exact original issuance and PKCE custody", err)
	}
	other := command
	other.TenantID = "unrelated-tenant"
	if _, err := openProxyStartOutput(t.Context(), crypto, other, request, 7, sealed); err == nil {
		t.Fatal("foreign tenant could open retained preparation")
	}
	if _, err := openProxyStartOutput(t.Context(), crypto, command, [32]byte{82}, 7, sealed); err == nil {
		t.Fatal("changed original preview request could open retained preparation")
	}
	if _, err := openProxyStartOutput(t.Context(), crypto, command, request, 8, sealed); err == nil {
		t.Fatal("a different preparation generation could open the original")
	}
	output.Grant.ExpiresAt = locator.ExpiresAt.AddDate(0, 0, 1)
	if _, err := sealProxyStartOutput(t.Context(), crypto, "binding-v1", command, request, 7, output); err == nil {
		t.Fatal("a checkpoint with a renewed grant expiry could be sealed")
	}
}
