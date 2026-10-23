package postgres

import (
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func deviceGrantBinding(t *testing.T, tenant identity.TenantID) identity.CommandBinding {
	t.Helper()
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	return identity.CommandBinding{CommandID: id, TenantID: tenant, AnonymousFlowID: "approved-device", RecordID: "approved-device", ActorKind: authorization.SubjectServiceAccount, ActorID: "screen-client", OperationID: "identity.oauth-server.device-token", SchemaID: "identity.oauth-server.device-token.native-device-v1", SchemaVersion: 1, PolicyID: "oauth", PolicyVersion: 1, CorrelationID: "device-source"}
}

func TestOriginalDeviceGrantAdmissionPreservesSourceWithoutChangingClient(t *testing.T) {
	original, human, profile := identifierSessionFixture(t)
	b := deviceGrantBinding(t, human.Binding.TenantID)
	d, c, a, err := OriginalDeviceGrantAdmission(profile, original, b)
	wantD, wantC, wantA, wantErr := OriginalSessionAdmission(profile, original, human.Binding)
	if err != nil || wantErr != nil || d != wantD || c != wantC || a != wantA {
		t.Fatal("device poll lost original human owner expectations", err)
	}
	if b.UserID != "" || b.ActorKind != authorization.SubjectServiceAccount || b.ActorID != "screen-client" || b.AnonymousFlowID != "approved-device" {
		t.Fatal("source derivation relabeled actual client command")
	}
	for _, change := range []func(*identity.CommandBinding){
		func(b *identity.CommandBinding) { b.TenantID = "foreign" },
		func(b *identity.CommandBinding) { b.UserID = human.Binding.UserID },
		func(b *identity.CommandBinding) { b.ActorKind = authorization.SubjectUser },
		func(b *identity.CommandBinding) { b.ActorID = "" },
		func(b *identity.CommandBinding) { b.AnonymousFlowID = "other" },
		func(b *identity.CommandBinding) { b.RecordID = "other" },
		func(b *identity.CommandBinding) { b.OperationID = "identity.oauth-server.token" },
		func(b *identity.CommandBinding) { b.SchemaID += ".other" },
		func(b *identity.CommandBinding) { b.SchemaVersion++ },
	} {
		foreign := b
		change(&foreign)
		if d, c, a, err := OriginalDeviceGrantAdmission(profile, original, foreign); err == nil || d != (kernel.DirectoryAuthorityAdmission{}) || c.Credential.ID != "" || a.Version != 0 {
			t.Fatal("foreign device source acquired owner expectations")
		}
	}
	if _, _, _, err := OriginalDeviceGrantAdmission(profile, session.Session{}, b); err == nil {
		t.Fatal("empty source manufactured admission")
	}
	profile.Audience = "other"
	if _, _, _, err := OriginalDeviceGrantAdmission(profile, original, b); err == nil {
		t.Fatal("foreign profile reinterpreted original source")
	}
}

func TestOriginalDeviceGrantAdmissionRetainsCredentialContinuation(t *testing.T) {
	original, human, profile := identifierSessionFixture(t)
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	continued, err := session.ContinuePasswordSession(original, session.CredentialContinuationSpec{CommandID: id, BeforeAuthorityVersion: 7, BeforeCredentialVersion: 9})
	if err != nil {
		t.Fatal(err)
	}
	b := deviceGrantBinding(t, human.Binding.TenantID)
	_, c, _, err := OriginalDeviceGrantAdmission(profile, continued, b)
	if err != nil || c.Credential.Version != 10 || c.CredentialAuthorityVersion != 8 || c.UserAuthorityVersion != 5 || c.IdentifierAuthorityVersion != 6 {
		t.Fatal("device source erased original credential continuation", err)
	}
	before, _ := original.Bindings()
	after, _ := continued.Bindings()
	if !before.Authentication.Proof.IssuedAt.Equal(after.Authentication.Proof.IssuedAt) || !before.Authentication.Proof.ExpiresAt.Equal(after.Authentication.Proof.ExpiresAt) {
		t.Fatal("continuation renewed original authentication")
	}
}
