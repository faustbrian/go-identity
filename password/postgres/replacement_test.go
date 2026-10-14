package passwordpostgres

import (
	"context"
	"errors"
	"testing"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	primitive "github.com/faustbrian/go-password"
)

func replacementFixture(t *testing.T) (identity.FeatureCommandSpec, kernel.CredentialReplacementIntent, string, primitive.Policy) {
	t.Helper()
	_, material, policy := storedFixture(t)
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	intent := kernel.CredentialReplacementIntent{Credential: identity.CredentialRef{ID: "password", TenantID: "tenant", UserID: "user", Kind: identity.CredentialPassword, Owner: "identity/password", Version: 7}, ExpectedUserVersion: 3, ExpectedAuthorityVersion: 5}
	fields, err := kernel.CredentialReplacementFields(intent)
	if err != nil {
		t.Fatal(err)
	}
	op := identity.FeatureOperation{Owner: "identity/password", OperationID: "identity.password.change", SchemaID: "password-change", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	b := identity.CommandBinding{CommandID: id, TenantID: "tenant", UserID: "user", ActorID: "actor", ActorKind: authorization.SubjectUser, RecordID: "password", OperationID: op.OperationID, PolicyID: "password-policy", PolicyVersion: 1, SchemaID: op.SchemaID, SchemaVersion: 1, CorrelationID: "correlation"}
	return identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields}, intent, material.hash, policy
}

func TestPasswordReplacementMappingRejectsNonIssuanceMaterial(t *testing.T) {
	spec, intent, encoded, policy := replacementFixture(t)
	command, err := identity.NewFeaturePasswordHashCommand(spec, encoded)
	if err != nil {
		t.Fatal(err)
	}
	got, hash, err := passwordReplacement(command, policy)
	if err != nil || got != intent || hash.String() != encoded {
		t.Fatal("exact issuance material denied")
	}
	for _, raw := range []string{"malformed", "$argon2id$v=19$m=16,t=1,p=1$c3ludGhldGlj$RkFLRUZBS0VGQUtFRkFLRQ"} {
		bad, err := identity.NewFeaturePasswordHashCommand(spec, raw)
		if err != nil {
			t.Fatal(err)
		}
		if i, h, e := passwordReplacement(bad, policy); !errors.Is(e, password.ErrPasswordWork) || i != (kernel.CredentialReplacementIntent{}) || h.String() != "" {
			t.Fatal("non-issuance material admitted")
		}
	}
	for _, mutate := range []func(*identity.FeatureCommandSpec){
		func(s *identity.FeatureCommandSpec) { s.Fields[0].Value.Text = "foreign" },
		func(s *identity.FeatureCommandSpec) { s.Fields[5].Value.Uint64++ },
		func(s *identity.FeatureCommandSpec) {
			s.Fields = append(s.Fields, identity.FeatureField{Name: "undeclared", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "value"}})
		},
	} {
		s := spec
		s.Fields = append([]identity.FeatureField(nil), spec.Fields...)
		mutate(&s)
		bad, e := identity.NewFeaturePasswordHashCommand(s, encoded)
		if e != nil {
			t.Fatal(e)
		}
		i, h, e := passwordReplacement(bad, policy)
		// Reference version is independent and valid when changed; it must be
		// preserved, not compared against a hard-coded fixture predecessor.
		if len(s.Fields) == 8 && s.Fields[5].Value.Uint64 == 8 {
			if e != nil || i.Credential.Version != 8 || h.String() != encoded {
				t.Fatal("reference predecessor was inferred")
			}
		} else if !errors.Is(e, password.ErrPasswordWork) || i != (kernel.CredentialReplacementIntent{}) || h.String() != "" {
			t.Fatal("foreign or undeclared native metadata admitted")
		}
	}
	plain, err := identity.NewFeatureCommand(spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := passwordReplacement(plain, policy); !errors.Is(err, password.ErrPasswordWork) {
		t.Fatal("hash-free material command admitted")
	}
}

func TestPasswordReplacementZeroRepositoryAndWorkDeny(t *testing.T) {
	s, _, raw, _ := replacementFixture(t)
	c, err := identity.NewFeaturePasswordHashCommand(s, raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []*Repository{nil, {}} {
		if err := r.ValidateFeatureCommand(c, kernel.CommandPlan{}); !errors.Is(err, password.ErrPasswordWork) {
			t.Fatal("zero validation admitted")
		}
		if i, err := r.CredentialReplacement(c); !errors.Is(err, password.ErrPasswordWork) || i != (kernel.CredentialReplacementIntent{}) {
			t.Fatal("zero replacement mapper admitted")
		}
		if receipt, err := r.ApplyFeature(context.Background(), kernel.Work{}, c); !errors.Is(err, password.ErrPasswordWork) || receipt != (identity.FeatureReceipt{}) {
			t.Fatal("zero native write admitted")
		}
		if status, err := r.RecoverParticipant(context.Background(), kernel.RecoveryWork{}); !errors.Is(err, password.ErrPasswordWork) || status != kernel.RecoveryUnknown {
			t.Fatal("zero recovery admitted")
		}
	}
}

func TestPasswordReplacementUsesSelectedAlgorithmParameters(t *testing.T) {
	s, _, _, baseline := replacementFixture(t)
	for _, config := range []primitive.PolicyConfig{
		{Algorithm: primitive.Bcrypt, BcryptCost: 4, Argon2id: baseline.Argon2idParameters(), Limits: baseline.Limits()},
		{Algorithm: primitive.Argon2id, BcryptCost: 4, Argon2id: baseline.Argon2idParameters(), Limits: baseline.Limits()},
	} {
		policy, err := primitive.NewPolicy(config)
		if err != nil {
			t.Fatal(err)
		}
		engine, err := primitive.New(policy)
		if err != nil {
			t.Fatal(err)
		}
		hash, err := engine.Hash(context.Background(), []byte("synthetic-selected-profile"))
		if err != nil {
			t.Fatal("profile fixture unavailable")
		}
		c, err := identity.NewFeaturePasswordHashCommand(s, hash.String())
		if err != nil {
			t.Fatal(err)
		}
		if _, got, err := passwordReplacement(c, policy); err != nil || got.String() != hash.String() {
			t.Fatal("irrelevant algorithm parameters rejected selected issuance profile")
		}
	}
}
