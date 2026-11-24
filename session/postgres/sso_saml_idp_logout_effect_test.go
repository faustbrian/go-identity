package postgres

import (
	"context"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestSSOSAMLIDPLogoutRetainedIntentBindsExactOriginal(t *testing.T) {
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	intent := kernel.SSOSAMLIDPLogoutIntent{
		OrganizationID: "org", ProviderID: "provider", RequestDigest: [32]byte{1},
		ValidUntil: time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC),
		Targets:    []kernel.SSOSAMLIDPLogoutTarget{{SessionID: "session", FamilyID: "family", IssuanceCommandID: id, Version: 1}},
	}
	original, err := samlIDPLogoutIntentDigest(intent)
	if err != nil || original == ([32]byte{}) {
		t.Fatal("valid intent produced no evidence", err)
	}
	for _, change := range []func(*kernel.SSOSAMLIDPLogoutIntent){
		func(i *kernel.SSOSAMLIDPLogoutIntent) { i.OrganizationID += "2" },
		func(i *kernel.SSOSAMLIDPLogoutIntent) { i.ProviderID += "2" },
		func(i *kernel.SSOSAMLIDPLogoutIntent) { i.RequestDigest[31]++ },
		func(i *kernel.SSOSAMLIDPLogoutIntent) { i.ValidUntil = i.ValidUntil.Add(time.Microsecond) },
		func(i *kernel.SSOSAMLIDPLogoutIntent) { i.Targets[0].Version++ },
	} {
		candidate := intent
		candidate.Targets = append([]kernel.SSOSAMLIDPLogoutTarget(nil), intent.Targets...)
		change(&candidate)
		if digest, err := samlIDPLogoutIntentDigest(candidate); err != nil || digest == original {
			t.Fatal("substituted intent did not change evidence", err)
		}
	}
	intent.Targets = append(intent.Targets, intent.Targets[0])
	if _, err := samlIDPLogoutIntentDigest(intent); err == nil {
		t.Fatal("duplicate target produced evidence")
	}
}

func TestSSOSAMLIDPLogoutEffectRequiresInstalledScope(t *testing.T) {
	for _, cfg := range []Config{{}, {Schema: "public", MaximumDuration: time.Second}, {Schema: "session_store", MaximumDuration: time.Minute + 1}} {
		if _, err := NewSSOSAMLIDPLogoutEffect(cfg); err == nil {
			t.Fatal("invalid configuration was admitted")
		}
	}
	effect, err := NewSSOSAMLIDPLogoutEffect(Config{Schema: "session_store", MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if got, err := effect.Apply(ctx, kernel.Work{}, nil, identity.Command{}, kernel.SSOSAMLIDPLogoutIntent{}); err == nil || got != (identity.FeatureReceipt{}) {
		t.Fatal("zero Work returned a mutation receipt", got, err)
	}
	if got, err := effect.Recover(ctx, kernel.RecoveryWork{}, nil, kernel.SSOSAMLIDPLogoutIntent{}); err == nil || got != kernel.RecoveryUnknown {
		t.Fatal("zero Work returned a conclusive recovery vote", got, err)
	}
}
