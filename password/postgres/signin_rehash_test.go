package passwordpostgres

import (
	"context"
	"slices"
	"testing"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	primitive "github.com/faustbrian/go-password"
)

func TestSigninRehashCommitmentRequiresCompleteOriginalMaterial(t *testing.T) {
	policy := primitive.DefaultPolicy()
	service, err := primitive.New(policy)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := service.Hash(context.Background(), []byte("synthetic-upgrade-password"))
	if err != nil {
		t.Fatal("hash fixture failed")
	}
	intent := kernel.PasswordHashUpgradeIntent{Admission: kernel.CredentialAdmission{Credential: identity.CredentialRef{ID: "credential", TenantID: "tenant", UserID: "user", Kind: identity.CredentialPassword, Owner: "identity/password", Version: 7}, UserAuthorityVersion: 19, IdentifierAuthorityVersion: 17, CredentialAuthorityVersion: 13}, ExpectedUserVersion: 11}
	fields, err := kernel.PasswordHashUpgradeFields(intent)
	if err != nil {
		t.Fatal("intent fixture failed", err)
	}
	fields = append(fields, signinRehashCommitment(hash))
	p := &signinPhase{upgrade: &intent, replacement: hash, hashPolicy: policy}
	if p.validateRehashFields(fields) != nil {
		t.Fatal("complete original material denied")
	}
	for _, mode := range []string{"missing", "altered", "extra", "unbounded", "unowned", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			candidate := slices.Clone(fields)
			phase := *p
			switch mode {
			case "missing":
				candidate = candidate[:len(candidate)-1]
			case "altered":
				candidate[len(candidate)-1].Value.Bytes = make([]byte, 32)
			case "extra":
				candidate = append(candidate, identity.FeatureField{Name: "password.rehash.unowned", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 1}})
			case "unbounded":
				phase.hashPolicy = primitive.Policy{}
			case "unowned":
				phase.upgrade = nil
			case "duplicate":
				candidate = append(candidate, candidate[len(candidate)-1])
			}
			if phase.validateRehashFields(candidate) == nil {
				t.Fatal("foreign material admitted")
			}
		})
	}
	if (&signinPhase{}).validateRehashFields(nil) != nil {
		t.Fatal("ordinary signin requires upgrade")
	}
}
