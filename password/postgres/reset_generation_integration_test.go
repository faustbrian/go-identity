//go:build integration

package passwordpostgres

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	primitive "github.com/faustbrian/go-password"
	envelope "github.com/faustbrian/go-secret-envelope"
	"github.com/faustbrian/go-secret-envelope/adapters/keyring"
)

type resetGenerationOwner interface {
	generateResetCommand(context.Context, identity.Command, password.HashPreparationConfig, risk.AuthenticationAdmission, capability.Service, password.ResetProfile, password.ResetGrantSpec, capability.Grant, kernel.CapabilityPlan) (identity.Command, []risk.Signal, error)
}

type resetOutputOwner interface {
	sealResetOutput(context.Context, *envelope.Service, string, identity.Command, uint64, [32]byte, identity.Command, risk.AuthenticationAdmission, []risk.Signal) ([]byte, error)
	restoreResetOutput(context.Context, *envelope.Service, identity.Command, uint64, [32]byte, []byte) (identity.Command, risk.PreparedAuthenticationAdmission, []risk.Signal, error)
}

type resetOutputIntentReader interface {
	readResetOutputIntent(context.Context, *envelope.Service, identity.CommandBinding, uint64, [32]byte, []byte) (identity.FeatureCommandSpec, error)
}

// Real signed scope, raw secret, Authentication custody, HIBP policy and hash
// primitive. Provider/counter/audit IO are deliberate fixture boundaries; this
// is not proof of durable issuance, PostgreSQL effects or public orchestration.
func TestResetGenerationPreservesOriginalProofAndSignedScope(t *testing.T) {
	spec, previous, _, policy := replacementFixture(t)
	spec.Operation, spec.Binding.OperationID, spec.Binding.SchemaID = resetOperation(), "identity.password.reset-complete", "password-reset-complete"
	intent := kernel.CredentialResetIntent{Replacement: previous, ExpectedEnabled: false}
	spec.Binding.TenantID = signinTestTenant
	intent.Replacement.Credential.TenantID = signinTestTenant
	intent.Replacement.ExpectedUserVersion = 101
	spec.Fields, _ = kernel.CredentialResetFields(intent)
	origin, _ := identity.NewCommandID()
	now := time.Now().UTC()
	original := password.ResetGrantSpec{TenantID: "tenant", UserID: "user", CredentialID: "password", CredentialVersion: 7, CredentialAuthorityVersion: 5, UserAuthorityVersion: 3, IdentifierID: "email", IdentifierVersion: 11, FactorVersion: 2, OriginCommandID: origin, RecoveryPath: auth.RecoveryPathEmail, CallbackURL: "https://identity.test/reset", IssuedAt: now.Add(-time.Second).Truncate(time.Second), ExpiresAt: now.Add(time.Minute).Truncate(time.Second)}
	original.TenantID = signinTestTenant
	profile, err := password.NewResetProfile(password.ResetProfileConfig{Issuer: "https://identity.test", Audience: "reset", MaximumLifetime: 2 * time.Minute, Callbacks: []string{original.CallbackURL}, CurrentBindingKeyVersion: 1, RetainedBindingKeys: map[uint32][32]byte{1: {31}}})
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := capability.NewHMACSHA256Signer("synthetic-reset", []byte(strings.Repeat("x", 32)))
	verifier, _ := capability.NewHMACSHA256Verifier([]byte(strings.Repeat("x", 32)))
	resolver, _ := capability.NewKeySet([]capability.Key{{ID: "synthetic-reset", Verifier: verifier}})
	engine, _ := capability.NewService(capability.ServiceConfig{Signer: signer, Resolver: resolver, Clock: func() time.Time { return now }, Limits: capability.DefaultLimits()})
	payload, err := profile.Payload(original)
	if err != nil {
		t.Fatal(err)
	}
	payload.ID = "synthetic-original-reset"
	proof, _, err := engine.Issue(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	defer proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
	grant, err := engine.Verify(context.Background(), proof, "identity.password.reset-complete", "reset")
	if err != nil {
		t.Fatal(err)
	}
	plan := kernel.CapabilityPlan{CapabilityID: payload.ID, Purpose: "identity.password.reset-complete", ReplayDigest: [32]byte{19}, ReplayKeyVersion: 2, ProofFingerprint: grant.EnvelopeDigest(), ExpiresAt: original.ExpiresAt, MaxUses: 1}
	crypto, _ := primitive.New(policy)
	dummy, _ := crypto.Hash(context.Background(), []byte("synthetic-dummy"))
	screening := signupScreeningPolicy(t)
	for _, mode := range []string{"clean", "foreign-proof", "foreign-version", "missing-factor", "missing-admission", "breached", "expired-during-provider", "foreign-command", "provider-panic", "expired-risk", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			at := now
			candidate, _ := primitive.NewSecret([]byte(" synthetic-reset-password "))
			defer candidate.Destroy()
			borrowed := proof
			if mode == "foreign-proof" {
				p := payload
				p.ID = "synthetic-other-reset"
				borrowed, _, err = engine.Issue(context.Background(), p)
				if err != nil {
					t.Fatal(err)
				}
				defer borrowed.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
			}
			command, err := identity.NewFeaturePasswordResetInputCommand(spec, candidate, borrowed)
			if err != nil {
				t.Fatal(err)
			}
			riskConfig := signinTestRisk(t)
			admission := signinTestAdmissionWithConfig(t, context.Background(), spec.Binding, riskConfig)
			at = time.Now().UTC()
			selected := original
			ctx := context.Background()
			before := true
			switch mode {
			case "foreign-proof":
			case "foreign-version":
				selected.CredentialVersion++
			case "missing-factor":
				selected.FactorVersion = 0
			case "missing-admission":
				admission = risk.AuthenticationAdmission{}
			case "expired-risk":
				at = admission.Prepared().Signals[0].ExpiresAt
			case "foreign-command":
				s := spec
				s.Binding.CommandID, _ = identity.NewCommandID()
				command, err = identity.NewFeaturePasswordResetInputCommand(s, candidate, borrowed)
				if err != nil {
					t.Fatal(err)
				}
			case "cancelled":
				var stop context.CancelFunc
				ctx, stop = context.WithCancel(ctx)
				stop()
			default:
				before = false
			}
			calls := 0
			config := password.HashPreparationConfig{Primitive: crypto, MinimumBytes: 8, MaximumBytes: 128, Timeout: time.Second, DummyHash: dummy, Policy: screening, Now: func() time.Time { return at }, Collect: func(ctx context.Context, scope risk.Context, secret primitive.Secret) ([]risk.Signal, error) {
				calls++
				if mode == "provider-panic" {
					panic("synthetic private reset provider diagnostic")
				}
				observation := risk.PasswordObservation{ObservedAt: scope.Now, CheckedAt: scope.Now, ValidUntil: scope.Now.Add(time.Hour)}
				if mode == "breached" {
					observation.BreachCount = 1
				}
				if mode == "expired-during-provider" {
					at = original.ExpiresAt
				}
				fact, e := screening.PasswordSignal(ctx, scope, observation)
				return []risk.Signal{fact}, e
			}}
			owner, ok := any(&Repository{policy: policy}).(resetGenerationOwner)
			if !ok {
				t.Fatal("native reset cannot generate its original proof-bound verifier")
			}
			generated, facts, err := owner.generateResetCommand(ctx, command, config, admission, engine, profile, selected, grant, plan)
			if mode == "clean" {
				got, hash, e := passwordResetOriginalMaterial(generated, policy, profile, original, grant, plan, at)
				metadata, valid := generated.PasswordResetFeature()
				input, _ := command.PasswordResetInputFeature()
				if err != nil || e != nil || got != intent || !valid || !reflect.DeepEqual(metadata, input) || len(facts) != len(admission.Prepared().Signals)+1 {
					t.Fatal("generated reset changed original scope", err, e)
				}
				match, e := crypto.Verify(ctx, []byte(" synthetic-reset-password "), hash.String())
				if e != nil || !match.Match() {
					t.Fatal("reset changed original password bytes")
				}
				_, finalProof, valid := generated.PasswordResetCustody()
				verified, e := engine.Verify(ctx, finalProof, "identity.password.reset-complete", "reset")
				if !valid || e != nil || verified.EnvelopeDigest() != grant.EnvelopeDigest() {
					t.Fatal("original proof custody lost")
				}
				phase := &resetCompletionPhase{repository: &Repository{policy: policy}, original: command, generated: generated, intent: intent, profile: profile, origin: original, grant: grant, consumption: plan}
				declaration := kernel.CommandPlan{Feature: &kernel.FeatureRegistration{Contributor: phase.Descriptor(), Operation: resetOperation()}, SubjectType: "credential", Capability: &plan, Lifecycle: &kernel.LifecyclePlan{EventType: "password.reset.v1", BeforeVersion: 7, AfterVersion: 8}, Audits: []kernel.AuditPlan{{EventType: "identity.password.reset-complete", Required: true, RequiredRecordCount: 1, RetentionClass: "protected"}}}
				if got, e := phase.CredentialReset(generated); e != nil || got != intent || phase.ValidateFeatureCommand(generated, declaration) != nil || phase.ValidateFeaturePreparation(command, declaration) != nil {
					t.Fatal("native reset phase lost its closed original/generated intent", e)
				}
				foreignCommand, _ := identity.NewFeaturePasswordResetCommand(metadata, hash.String(), finalProof)
				if _, e := phase.CredentialReset(foreignCommand); e == nil || phase.ValidateFeatureCommand(foreignCommand, declaration) == nil {
					t.Fatal("reconstructed command borrowed native reset authority")
				}
				foreignPlan := declaration
				changedConsumption := plan
				changedConsumption.ReplayKeyVersion++
				foreignPlan.Capability = &changedConsumption
				if phase.ValidateFeatureCommand(generated, foreignPlan) == nil {
					t.Fatal("native reset adopted a replacement consumption identity")
				}
				output, exists := any(&Repository{policy: policy}).(resetOutputOwner)
				if !exists {
					t.Fatal("reset output cannot survive native journal recovery")
				}
				keys, _ := keyring.New(map[string][]byte{"reset-output": bytes.Repeat([]byte{75}, 32)})
				crypto, _ := envelope.NewService(keys)
				configuration := [32]byte{17}
				wire, e := output.sealResetOutput(ctx, crypto, "reset-output", command, 1, configuration, generated, admission, facts)
				if e != nil || bytes.Contains(wire, []byte(hash.String())) || bytes.Contains(wire, []byte("synthetic-reset-password")) {
					t.Fatal("reset checkpoint lost encryption", e)
				}
				defer clear(wire)
				reader, ok := any(&Repository{policy: policy}).(resetOutputIntentReader)
				if !ok {
					t.Fatal("reset retry cannot recover original aggregate CAS without today's account version")
				}
				originalSpec, e := reader.readResetOutputIntent(ctx, crypto, spec.Binding, 1, configuration, wire)
				if e != nil || !reflect.DeepEqual(originalSpec, input) {
					t.Fatal("retained reset intent changed independent original predecessors", e)
				}
				originalSpec.Fields[0].Value.Text = "foreign"
				originalSpec, e = reader.readResetOutputIntent(ctx, crypto, spec.Binding, 1, configuration, wire)
				if e != nil || !reflect.DeepEqual(originalSpec, input) {
					t.Fatal("caller mutation changed retained original intent", e)
				}
				foreignBinding := spec.Binding
				foreignBinding.CommandID, _ = identity.NewCommandID()
				for _, changed := range []struct {
					binding       identity.CommandBinding
					generation    uint64
					configuration [32]byte
				}{{foreignBinding, 1, configuration}, {spec.Binding, 2, configuration}, {spec.Binding, 1, [32]byte{18}}} {
					got, e := reader.readResetOutputIntent(ctx, crypto, changed.binding, changed.generation, changed.configuration, wire)
					if e == nil || got.Binding != (identity.CommandBinding{}) || len(got.Fields) != 0 {
						t.Fatal("foreign reset output disclosed original intent")
					}
				}
				restored, retained, restoredFacts, e := output.restoreResetOutput(ctx, crypto, command, 1, configuration, wire)
				_, restoredHash, materialError := passwordResetOriginalMaterial(restored, policy, profile, original, grant, plan, at)
				beforeAdmission, _ := json.Marshal(resetStoredAdmission(admission.Prepared()))
				afterAdmission, _ := json.Marshal(resetStoredAdmission(retained))
				beforeFacts, _ := json.Marshal(facts)
				afterFacts, _ := json.Marshal(restoredFacts)
				if e != nil || materialError != nil || restoredHash.String() != hash.String() || !bytes.Equal(beforeAdmission, afterAdmission) || !bytes.Equal(beforeFacts, afterFacts) || calls != 1 {
					t.Fatal("reset restoration renewed or regenerated original material", e, materialError)
				}
				custody, e := risk.NewAuthenticationAdmissionCustody(riskConfig)
				if e != nil {
					t.Fatal(e)
				}
				if _, e := custody.Restore(ctx, retained, retained.Scope, risk.Subject{Network: "192.0.2.1", Device: "synthetic-device", IdentifierDigest: strings.Repeat("a", 64)}); e != nil {
					t.Fatal("checkpoint did not preserve real risk signature", e)
				}
				for _, changed := range []struct {
					generation uint64
					profile    [32]byte
				}{{2, configuration}, {1, [32]byte{18}}, {0, configuration}} {
					_, _, _, e := output.restoreResetOutput(ctx, crypto, command, changed.generation, changed.profile, wire)
					if e == nil {
						t.Fatal("foreign preparation decrypted original reset output")
					}
				}
				foreign := spec
				foreign.Binding.CommandID, _ = identity.NewCommandID()
				foreignInput, _ := identity.NewFeaturePasswordResetInputCommand(foreign, candidate, borrowed)
				if _, _, _, e := output.restoreResetOutput(ctx, crypto, foreignInput, 1, configuration, wire); e == nil {
					t.Fatal("foreign attempt restored reset output")
				}
				changedPredecessor := input
				changedPredecessor.Fields = append([]identity.FeatureField(nil), input.Fields...)
				for i := range changedPredecessor.Fields {
					if changedPredecessor.Fields[i].Name == "credential.expected-user-version" {
						changedPredecessor.Fields[i].Value.Uint64++
					}
				}
				changedInput, e := identity.NewFeaturePasswordResetInputCommand(changedPredecessor, candidate, borrowed)
				if e != nil {
					t.Fatal(e)
				}
				if _, _, _, e := output.restoreResetOutput(ctx, crypto, changedInput, 1, configuration, wire); e == nil {
					t.Fatal("same binding restored a substituted aggregate predecessor")
				}
				aad, e := resetOutputAAD(command, 1, configuration)
				if e != nil {
					t.Fatal(e)
				}
				stored := resetStoredOutput{Schema: 2, Spec: input, Hash: hash.String(), Admission: resetStoredAdmission(admission.Prepared()), Facts: facts}
				canonical, e := json.Marshal(stored)
				if e != nil {
					t.Fatal(e)
				}
				defer clear(canonical)
				missing := stored
				missing.Facts = nil
				missingJSON, _ := json.Marshal(missing)
				defer clear(missingJSON)
				for _, malformed := range [][]byte{
					append(append([]byte(nil), canonical...), ' '),
					append([]byte(`{"Schema":1,`), canonical[1:]...),
					append([]byte(`{"Unexpected":true,`), canonical[1:]...),
					missingJSON,
				} {
					sealed, e := crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: malformed, KeyReference: "reset-output", Context: aad})
					clear(malformed)
					if e != nil {
						t.Fatal(e)
					}
					badWire, e := sealed.MarshalBinary()
					if e != nil {
						t.Fatal(e)
					}
					badCommand, badAdmission, badFacts, e := output.restoreResetOutput(ctx, crypto, command, 1, configuration, badWire)
					clear(badWire)
					_, hasMaterial := badCommand.PasswordResetFeature()
					if e == nil || hasMaterial || badAdmission.Signature != ([32]byte{}) || len(badFacts) != 0 {
						t.Fatal("malformed retained output disclosed material")
					}
				}
				terminalProof, _, e := engine.Issue(ctx, payload)
				if e != nil {
					t.Fatal(e)
				}
				terminalInput, e := identity.NewFeaturePasswordResetInputCommand(spec, candidate, terminalProof)
				if e != nil {
					t.Fatal(e)
				}
				if e := terminalProof.Transfer(ctx, func(context.Context, []byte) error { return nil }); e != nil {
					t.Fatal(e)
				}
				if _, _, _, e := output.restoreResetOutput(ctx, crypto, terminalInput, 1, configuration, wire); e == nil {
					t.Fatal("checkpoint resurrected terminal proof custody")
				}
			} else {
				_, metadata := generated.PasswordResetFeature()
				_, _, custody := generated.PasswordResetCustody()
				if err == nil || len(facts) != 0 || metadata || custody {
					t.Fatal("invalid original reset generated material")
				}
				if strings.Contains(err.Error(), "private") {
					t.Fatal("reset provider diagnostic escaped redaction")
				}
			}
			if before && calls != 0 || !before && calls != 1 {
				t.Fatal("provider ran before original scope admission or ran twice")
			}
			if candidate.Len() == 0 || borrowed.ValidateBounds(32, 4096) != nil {
				t.Fatal("generation consumed borrowed custody")
			}
		})
	}
}
