package passwordpostgres

import (
	"bytes"
	"context"
	"testing"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	envelope "github.com/faustbrian/go-secret-envelope"
	"github.com/faustbrian/go-secret-envelope/adapters/keyring"
)

type signupInputOwner interface {
	signupInputAAD(kernel.RequestKeyPreparationBinding, [32]byte) (envelope.Context, error)
}

// SU05/SU09: the original immutable request-key input envelope must reject a
// substitution of any coordinator provenance or deployment profile. This uses
// actual local AEAD/key custody, not digest equality or a source-text assertion.
func TestSignupOriginalInputRejectsProvenanceSubstitution(t *testing.T) {
	owner, present := any(&Repository{}).(signupInputOwner)
	if !present {
		t.Fatal("native signup has no original input envelope binding")
	}
	id, _ := identity.NewCommandID()
	k := kernel.RequestKeyPreparationBinding{Namespace: "signup", Scope: kernel.RequestKeyScope{TenantID: "tenant", ActorID: "ingress", ActorKind: authorization.SubjectServiceAccount, Method: "POST", RouteID: "identity.password.signup"}, Admission: kernel.RequestKeyAdmission{CommandID: id, FingerprintKeyVersion: 1}, Feature: kernel.FeatureRegistration{Contributor: kernel.ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}, Operation: identity.FeatureOperation{Owner: "identity/password", OperationID: "identity.password.signup", SchemaID: "password-signup", SchemaVersion: 1, SubjectRequirement: identity.FeatureSubjectAnonymousFlow, RecordRequirement: identity.FeatureRecordOmitted}}, PolicyVersion: 3, IntentDigest: [32]byte{1}}
	profile := [32]byte{2}
	ctx := context.Background()
	keys, err := keyring.New(map[string][]byte{"signup-input": bytes.Repeat([]byte{75}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		t.Fatal(err)
	}
	aad, err := owner.signupInputAAD(k, profile)
	if err != nil {
		t.Fatal("original provenance denied")
	}
	sealed, err := crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: []byte("synthetic original signup input"), KeyReference: "signup-input", Context: aad})
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*kernel.RequestKeyPreparationBinding, *[32]byte){
		func(k *kernel.RequestKeyPreparationBinding, _ *[32]byte) { k.Namespace = "other-signup" },
		func(k *kernel.RequestKeyPreparationBinding, _ *[32]byte) { k.Scope.TenantID = "other" },
		func(k *kernel.RequestKeyPreparationBinding, _ *[32]byte) { k.Scope.ActorID = "other" },
		func(k *kernel.RequestKeyPreparationBinding, _ *[32]byte) {
			k.Scope.ActorKind = authorization.SubjectAPIKey
		},
		func(k *kernel.RequestKeyPreparationBinding, _ *[32]byte) { k.Scope.Method = "GET" },
		func(k *kernel.RequestKeyPreparationBinding, _ *[32]byte) {
			k.Scope.RouteID = "identity.password.signin"
		},
		func(k *kernel.RequestKeyPreparationBinding, _ *[32]byte) {
			k.Admission.CommandID, _ = identity.NewCommandID()
		},
		func(k *kernel.RequestKeyPreparationBinding, _ *[32]byte) { k.Admission.FingerprintKeyVersion++ },
		func(k *kernel.RequestKeyPreparationBinding, _ *[32]byte) { k.Feature.Contributor.Owner = "other" },
		func(k *kernel.RequestKeyPreparationBinding, _ *[32]byte) { k.Feature.Contributor.ContractID = "other" },
		func(k *kernel.RequestKeyPreparationBinding, _ *[32]byte) { k.Feature.Contributor.Version++ },
		func(k *kernel.RequestKeyPreparationBinding, _ *[32]byte) {
			k.Feature.Operation.Owner = "identity/username"
		},
		func(k *kernel.RequestKeyPreparationBinding, _ *[32]byte) {
			k.Feature.Operation.OperationID = "identity.username.signup"
		},
		func(k *kernel.RequestKeyPreparationBinding, _ *[32]byte) { k.Feature.Operation.SchemaID = "other" },
		func(k *kernel.RequestKeyPreparationBinding, _ *[32]byte) { k.Feature.Operation.SchemaVersion++ },
		func(k *kernel.RequestKeyPreparationBinding, _ *[32]byte) {
			k.Feature.Operation.SubjectRequirement = identity.FeatureSubjectUser
		},
		func(k *kernel.RequestKeyPreparationBinding, _ *[32]byte) {
			k.Feature.Operation.RecordRequirement = identity.FeatureRecordRequired
		},
		func(k *kernel.RequestKeyPreparationBinding, _ *[32]byte) { k.PolicyVersion++ },
		func(k *kernel.RequestKeyPreparationBinding, _ *[32]byte) { k.IntentDigest[0]++ },
		func(_ *kernel.RequestKeyPreparationBinding, profile *[32]byte) { profile[0]++ },
	} {
		changed, selected := k, profile
		mutate(&changed, &selected)
		foreign, err := owner.signupInputAAD(changed, selected)
		if err == nil {
			plain, err := crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: foreign})
			clear(plain)
			if err == nil {
				t.Fatal("foreign provenance decrypted original signup input")
			}
		}
	}
	if _, err := owner.signupInputAAD(k, [32]byte{}); err == nil {
		t.Fatal("missing native configuration identity admitted")
	}
	if _, err := owner.signupInputAAD(kernel.RequestKeyPreparationBinding{}, profile); err == nil {
		t.Fatal("missing original mapping provenance admitted")
	}
	resumed, err := owner.signupInputAAD(k, profile)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: resumed})
	defer clear(plain)
	if err != nil || !bytes.Equal(plain, []byte("synthetic original signup input")) {
		t.Fatal("unchanged original provenance cannot resume")
	}
}
