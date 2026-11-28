package postgres

import (
	"context"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func TestAdminStatusPreparationRejectsUnavailableOwner(t *testing.T) {
	key, err := identity.NewIdempotencyKey([]byte("unit-status-preparation"))
	if err != nil {
		t.Fatal(err)
	}
	for _, owner := range []*StatusUnitOfWork{nil, {}} {
		got, err := owner.ResolveAdminStatusKey(context.Background(), key, AdminStatusKeyRequest{}, authorization.DecisionContext{})
		if err == nil || got != (AdminStatusKeyAdmission{}) {
			t.Fatal("unconfigured status owner allowed key preparation")
		}
	}
}

func TestAdminStatusVersionsRequireOriginalPreparationBinding(t *testing.T) {
	key := [32]byte{1}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	const ban = "identity.admin.user-ban"
	binding := RequestKeyPreparationBinding{
		Namespace: "status", PolicyVersion: 9, IntentDigest: [32]byte{2},
		Scope:     RequestKeyScope{TenantID: "tenant-a", ActorID: "actor", ActorKind: authorization.SubjectUser, Method: "POST", RouteID: ban},
		Admission: RequestKeyAdmission{CommandID: id, FingerprintKeyVersion: 1},
		Feature:   FeatureRegistration{Operation: identity.FeatureOperation{Owner: "identity", OperationID: ban, SchemaID: "status-key", SchemaVersion: 1}},
	}
	sealed, err := sealAdminStatusVersions(key, binding, 41, 7)
	if err != nil {
		t.Fatal(err)
	}
	version, authority, err := openAdminStatusVersions(key, binding, sealed)
	if err != nil || version != 41 || authority != 7 {
		t.Fatal("prepared command lost its distinct original versions", err)
	}
	for name, alter := range map[string]func(*RequestKeyPreparationBinding){
		"other command":      func(b *RequestKeyPreparationBinding) { b.Admission.CommandID = replacement },
		"other key revision": func(b *RequestKeyPreparationBinding) { b.Admission.FingerprintKeyVersion++ },
		"other tenant":       func(b *RequestKeyPreparationBinding) { b.Scope.TenantID = "tenant-b" },
		"other actor":        func(b *RequestKeyPreparationBinding) { b.Scope.ActorID = "other" },
		"other operation":    func(b *RequestKeyPreparationBinding) { b.Scope.RouteID = "identity.admin.user-unban" },
		"other input":        func(b *RequestKeyPreparationBinding) { b.IntentDigest[0]++ },
		"other policy":       func(b *RequestKeyPreparationBinding) { b.PolicyVersion++ },
		"other namespace":    func(b *RequestKeyPreparationBinding) { b.Namespace = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			other := binding
			alter(&other)
			if version, authority, err := openAdminStatusVersions(key, other, sealed); err == nil || version != 0 || authority != 0 {
				t.Fatal("mismatched preparation returned a usable version")
			}
		})
	}
	if v, a, err := openAdminStatusVersions([32]byte{3}, binding, sealed); err == nil || v != 0 || a != 0 {
		t.Fatal("unretained key opened original preparation")
	}
	if v, a, err := openAdminStatusVersions(key, binding, sealed[:len(sealed)-1]); err == nil || v != 0 || a != 0 {
		t.Fatal("incomplete preparation returned a usable version")
	}
}
