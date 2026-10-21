package passwordpostgres

import (
	"context"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// This supplies synthetic signed-original custody to test framing only. Real
// target authentication, guest possession and atomic proof consumption must be
// proven together by the native upgrade consumer before that flow is delivered.
func TestAnonymousUpgradePrimaryKeepsPermanentProofSeparateFromGuest(t *testing.T) {
	const action = "identity.anonymous.upgrade"
	source, request, fields, binding := phonePrimaryFixture(t, action)
	guest, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	request.RecordID, binding.RecordID = string(guest), string(guest)
	admission, err := source.Restore(context.Background(), request, fields)
	if err != nil {
		t.Fatal("target-owned original action proof rejected", err)
	}
	guestFields := []identity.FeatureField{{Name: "anonymous.upgrade.source", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(guest)}}}
	command, err := admission.Command(binding, guestFields)
	if err != nil {
		t.Fatal("target proof could not bind a distinct guest resource", err)
	}
	spec, ok := command.Feature()
	token, hasToken := command.SessionToken()
	if !ok || !hasToken || token.Token() != request.Session.Token() || spec.Operation.Owner != "identity/anonymous" || spec.Operation.SchemaID != action+".native-v1" || spec.Binding.UserID != "user" || spec.Binding.ActorID != "user" || spec.Binding.RecordID != string(guest) {
		t.Fatal("upgrade confused guest resource with permanent proof authority")
	}
	restored, err := source.RestoreCommand(context.Background(), command, request.Caller, request.CSRFToken)
	if err != nil {
		t.Fatal("restart lost original permanent proof custody", err)
	}
	original, err := restored.Original()
	if err != nil {
		t.Fatal(err)
	}
	originalScope, err := original.Bindings()
	if err != nil || originalScope.UserID != binding.UserID || originalScope.Authentication.Kind != session.AuthenticationVerified {
		t.Fatal("guest was substituted for the original verified target", err)
	}
	for _, mutate := range []func(*identity.CommandBinding){
		func(b *identity.CommandBinding) { b.UserID = identity.UserID(guest) },
		func(b *identity.CommandBinding) { b.ActorID = identity.ActorID(guest) },
		func(b *identity.CommandBinding) { b.TenantID = "foreign" },
		func(b *identity.CommandBinding) { b.SchemaID = "foreign-upgrade" },
		func(b *identity.CommandBinding) { b.SchemaVersion++ },
	} {
		changed := binding
		mutate(&changed)
		if _, err := admission.Command(changed, guestFields); err == nil {
			t.Fatal("target primary custody acquired substituted authority")
		}
	}
	request.TargetSubjectID = identity.UserID(guest)
	if _, err := source.Restore(context.Background(), request, fields); err == nil {
		t.Fatal("guest was accepted as an administrative proof target")
	}
	if !reauthenticationConsumptionAction(action) {
		t.Fatal("owning proof consumer does not admit its exact upgrade action")
	}
}

func TestAnonymousUpgradeConsumptionMigrationPreservesPredecessors(t *testing.T) {
	base := ActionReauthenticationMigrationSource{Base: EmailReauthenticationMigrationSource{}, Version: 100}
	before, err := base.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	suffix := AnonymousUpgradeReauthenticationMigrationSource{Base: base, Version: 101}
	after, err := suffix.Load(context.Background())
	if err != nil || len(after) != len(before)+1 {
		t.Fatal("missing upgrade proof-consumption suffix", err)
	}
	for n := range before {
		if before[n] != after[n] {
			t.Fatal("upgrade rewrote installed proof history")
		}
	}
	if after[len(before)].DownSQL() != "" {
		t.Fatal("proof-consumption suffix permits destructive downgrade")
	}
	if _, err := (AnonymousUpgradeReauthenticationMigrationSource{Base: EmailReauthenticationMigrationSource{}, Version: 101}).Load(context.Background()); err == nil {
		t.Fatal("missing action proof history admitted")
	}
	if _, err := (AnonymousUpgradeReauthenticationMigrationSource{Base: base, Version: 100}).Load(context.Background()); err == nil {
		t.Fatal("upgrade suffix reordered installed history")
	}
	ctx, stop := context.WithCancel(context.Background())
	stop()
	if _, err := suffix.Load(ctx); err != context.Canceled {
		t.Fatal("upgrade migration ignored cancellation", err)
	}
}
