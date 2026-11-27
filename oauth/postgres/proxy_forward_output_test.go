package postgres

import (
	"bytes"
	"testing"
	"time"

	oauthproxy "github.com/faustbrian/go-identity/oauth/proxy"
)

func TestProxyForwardOutputAuthenticatesOriginalAndGeneration(t *testing.T) {
	service, locator, _ := proxyBindingFixture(t)
	key := "binding-v1"
	value := proxyForwardOutput{Disposition: oauthproxy.CallbackForwarded, Artifact: []byte{31, 45, 61}, Until: locator.ExpiresAt.Add(-time.Second)}
	wire, err := sealProxyForwardOutput(t.Context(), service, key, locator, 8, value)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wire)
	got, err := openProxyForwardOutput(t.Context(), service, locator, 8, wire)
	if err != nil || got.Disposition != value.Disposition || !got.Until.Equal(value.Until) || !bytes.Equal(got.Artifact, value.Artifact) {
		t.Fatal("native generation changed prepared provider outcome", err)
	}
	if outcome, err := openProxyForwardOutput(t.Context(), service, locator, 9, wire); err == nil || len(outcome.Artifact) != 0 {
		t.Fatal("another generation could recover original provider output")
	}
	locator.LookupDigest[0] ^= 1
	if outcome, err := openProxyForwardOutput(t.Context(), service, locator, 8, wire); err == nil || len(outcome.Artifact) != 0 {
		t.Fatal("another durable row could recover original provider output")
	}
	locator.LookupDigest[0] ^= 1
	value.Until = locator.ExpiresAt.Add(time.Second)
	if bad, err := sealProxyForwardOutput(t.Context(), service, key, locator, 8, value); err == nil || len(bad) != 0 {
		t.Fatal("generation renewed original validity")
	}
	value = proxyForwardOutput{Disposition: oauthproxy.CallbackNeedsReconciliation}
	if bad, err := sealProxyForwardOutput(t.Context(), service, key, locator, 8, value); err == nil || len(bad) != 0 {
		t.Fatal("unknown provider work became a terminal outcome")
	}
}
