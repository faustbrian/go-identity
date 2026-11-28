package reference

import (
	"testing"

	oauthpg "github.com/faustbrian/go-identity/oauth/postgres"
)

func TestOAuthProxyMaintenanceRequiresExplicitOwners(t *testing.T) {
	if owner, err := (FeatureSet{}).NewOAuthProxyMaintenance(nil, OAuthProxyMaintenanceConfiguration{}); owner != nil || err == nil {
		t.Fatal("an absent deployment pair enabled maintenance")
	}
	var owner OAuthProxyMaintenance
	if ack, err := owner.Acknowledge(t.Context(), oauthpg.ProxyCustodyFenceSealRequest{}); ack != (oauthpg.ProxyDisablePairAcknowledgement{}) || err == nil {
		t.Fatal("a zero maintenance owner acknowledged cleanup")
	}
}
