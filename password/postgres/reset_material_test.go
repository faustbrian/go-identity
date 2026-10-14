package passwordpostgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func resetMaterialProof(t *testing.T) capability.Proof {
	t.Helper()
	signer, err := capability.NewHMACSHA256Signer("synthetic", []byte(strings.Repeat("x", 32)))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	wire, err := capability.Issue(context.Background(), capability.Payload{Version: 1, Issuer: "https://identity.test", Audiences: []string{"reset"}, Subject: "user", Tenant: "tenant", Resource: "identity.password/password", Operation: "identity.password.reset-complete", ID: "synthetic-reset", IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(time.Minute), MaxUses: 1}, signer, capability.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := capability.ParseProof(wire, capability.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func TestPasswordResetMaterialEffectScopeIsClosed(t *testing.T) {
	spec, previous, _, _ := replacementFixture(t)
	reset := resetOperation()
	life := kernel.LifecyclePlan{EventType: "password.reset.v1", BeforeVersion: previous.Credential.Version, AfterVersion: previous.Credential.Version + 1}
	if !replacementEffectScope(reset, life) {
		t.Fatal("reset cannot use the original material writer and retained evidence")
	}
	for _, mutation := range []func(*identity.FeatureOperation, *kernel.LifecyclePlan){
		func(op *identity.FeatureOperation, _ *kernel.LifecyclePlan) { op.SchemaID = "password-change" },
		func(op *identity.FeatureOperation, _ *kernel.LifecyclePlan) { op.Owner = "foreign" },
		func(op *identity.FeatureOperation, _ *kernel.LifecyclePlan) { op.SchemaVersion++ },
		func(_ *identity.FeatureOperation, l *kernel.LifecyclePlan) { l.EventType = "password.changed.v1" },
		func(_ *identity.FeatureOperation, l *kernel.LifecyclePlan) { l.AfterVersion++ },
		func(_ *identity.FeatureOperation, l *kernel.LifecyclePlan) { l.BeforeVersion = 0 },
		func(_ *identity.FeatureOperation, l *kernel.LifecyclePlan) {
			l.BeforeVersion = ^uint64(0)
			l.AfterVersion = 0
		},
	} {
		op, l := reset, life
		mutation(&op, &l)
		if replacementEffectScope(op, l) {
			t.Fatal("foreign material effect scope admitted")
		}
	}
	life.EventType = "password.changed.v1"
	if !replacementEffectScope(spec.Operation, life) {
		t.Fatal("existing password-change scope no longer supported")
	}
	life.EventType = "password.reset.v1"
	if replacementEffectScope(spec.Operation, life) {
		t.Fatal("change metadata can claim reset effect")
	}
}

func TestPasswordResetMaterialPreservesIndependentPredecessors(t *testing.T) {
	spec, previous, encoded, policy := replacementFixture(t)
	spec.Operation.OperationID, spec.Operation.SchemaID = "identity.password.reset-complete", "password-reset-complete"
	spec.Binding.OperationID, spec.Binding.SchemaID = spec.Operation.OperationID, spec.Operation.SchemaID
	for _, enabled := range []bool{false, true} {
		intent := kernel.CredentialResetIntent{Replacement: previous, ExpectedEnabled: enabled}
		fields, err := kernel.CredentialResetFields(intent)
		if err != nil {
			t.Fatal(err)
		}
		spec.Fields = fields
		proof := resetMaterialProof(t)
		command, err := identity.NewFeaturePasswordResetCommand(spec, encoded, proof)
		if err != nil {
			t.Fatal(err)
		}
		got, hash, err := passwordResetMaterial(command, policy)
		if err != nil || got != intent || hash.String() != encoded {
			t.Fatal("reset material lost exact predecessors or issuance profile")
		}
		// Structural mapping must not consume the original opaque proof.
		if proof.ValidateBounds(32, 4096) != nil {
			t.Fatal("mapping consumed proof")
		}
		for _, mutate := range []func(*identity.FeatureCommandSpec){
			func(s *identity.FeatureCommandSpec) { s.Fields[0].Value.Text = "foreign" },
			func(s *identity.FeatureCommandSpec) {
				s.Fields[8].Value.Kind = identity.FeatureText
				s.Fields[8].Value.Text = "true"
				s.Fields[8].Value.Bool = false
			},
			func(s *identity.FeatureCommandSpec) { s.Fields = append(s.Fields, s.Fields[8]) },
			func(s *identity.FeatureCommandSpec) { s.Fields = s.Fields[:8] },
		} {
			bad := spec
			bad.Fields = append([]identity.FeatureField(nil), spec.Fields...)
			mutate(&bad)
			c, e := identity.NewFeaturePasswordResetCommand(bad, encoded, proof)
			if e != nil {
				// Duplicate fields are already denied by root structural custody.
				continue
			}
			if i, h, e := passwordResetMaterial(c, policy); !errors.Is(e, password.ErrPasswordWork) || i != (kernel.CredentialResetIntent{}) || h.String() != "" {
				t.Fatal("foreign or malformed reset metadata admitted")
			}
		}
		generic, err := identity.NewFeatureCommand(spec)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := passwordResetMaterial(generic, policy); !errors.Is(err, password.ErrPasswordWork) {
			t.Fatal("proof-free hash command substituted for original reset")
		}
		bad, err := identity.NewFeaturePasswordResetCommand(spec, "malformed", proof)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := passwordResetMaterial(bad, policy); !errors.Is(err, password.ErrPasswordWork) {
			t.Fatal("malformed verifier admitted")
		}
		if err := proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }); err != nil {
			t.Fatal(err)
		}
		if _, _, err := passwordResetMaterial(command, policy); !errors.Is(err, password.ErrPasswordWork) {
			t.Fatal("terminal proof alias admitted")
		}
	}
}
