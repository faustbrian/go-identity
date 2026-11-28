package postgres

import (
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
)

func TestProxyProviderDisableCoversOnlyOriginalAuthority(t *testing.T) {
	disable := ProviderAuthorityChange{
		Key:             ProviderAuthorityKey{TenantID: "tenant-a", ProviderID: "provider-a"},
		ExpectedVersion: 7,
		Next:            ProviderAuthorityState{Version: 8, ProfileVersion: 3},
	}
	for _, tc := range []struct {
		name     string
		tenant   identity.TenantID
		provider string
		epoch    uint64
		profile  uint64
		want     bool
	}{
		{"last enabled epoch", "tenant-a", "provider-a", 7, 3, true},
		{"still pending before a profile change", "tenant-a", "provider-a", 5, 2, true},
		{"legacy binding proves no epoch", "tenant-a", "provider-a", 0, 3, false},
		{"no original profile", "tenant-a", "provider-a", 7, 0, false},
		{"disable itself is not an issuance epoch", "tenant-a", "provider-a", 8, 3, false},
		{"re-enabled with same profile", "tenant-a", "provider-a", 9, 3, false},
		{"profile after disable", "tenant-a", "provider-a", 7, 4, false},
		{"another provider", "tenant-a", "provider-b", 7, 3, false},
		{"another tenant", "tenant-b", "provider-a", 7, 3, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			binding := oauth.ProxyOIDCEvidenceBinding{TenantID: tc.tenant, ProviderID: tc.provider, ProviderAuthorityEpoch: tc.epoch, ProviderVersion: tc.profile}
			if got := proxyProviderDisableCoversOriginal(disable, binding); got != tc.want {
				t.Fatalf("disable covers original authority: got %t, want %t", got, tc.want)
			}
		})
	}
}
