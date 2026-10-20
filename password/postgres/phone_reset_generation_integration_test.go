//go:build integration

package passwordpostgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	primitive "github.com/faustbrian/go-password/v2"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

type phoneResetGenerationOwner interface {
	generatePhoneResetCommand(context.Context, identity.Command, password.HashPreparationConfig, capability.Service, password.ResetProfile, password.ResetGrantSpec, capability.Grant, kernel.CapabilityPlan, ResetScreeningCollector) (identity.Command, []risk.Signal, error)
	sealPhoneResetOutput(context.Context, *envelope.Service, string, identity.Command, uint64, [32]byte, identity.Command, []risk.Signal, kernel.RiskEvidencePlan, kernel.OTPAttemptPlan) ([]byte, error)
	restorePhoneResetOutput(context.Context, *envelope.Service, identity.Command, uint64, [32]byte, []byte) (identity.Command, []risk.Signal, kernel.RiskEvidencePlan, kernel.OTPAttemptPlan, error)
	readPhoneResetOutputIntent(context.Context, *envelope.Service, identity.CommandBinding, uint64, [32]byte, []byte) (identity.FeatureCommandSpec, kernel.RiskEvidencePlan, kernel.OTPAttemptPlan, error)
}

type phoneResetGenerationFixture struct {
	repository *Repository
	policy     primitive.Policy
	primitive  *primitive.Service
	dummy      primitive.EncodedHash
	spec       identity.FeatureCommandSpec
	intent     kernel.CredentialResetIntent
	profile    password.ResetProfile
	original   password.ResetGrantSpec
	engine     capability.Service
	grant      capability.Grant
	proof      capability.Proof
	plan       kernel.CapabilityPlan
	now        time.Time
	crypto     *envelope.Service
	riskPlan   kernel.RiskEvidencePlan
	otpPlan    kernel.OTPAttemptPlan
}

// Component proof uses real signed phone-reset scope, original joint secret
// custody, selected HIBP/provider policy, primitive hashing and envelope crypto.
// Issued grants are synthetic; provider IO is a deliberate external seam. This
// does not prove PostgreSQL issuance, actual one-use risk or protected reset.
func TestPhoneResetGenerationPreservesOriginalJointCustody(t *testing.T) {
	f := newPhoneResetGenerationFixture(t)
	owner, ok := any(f.repository).(phoneResetGenerationOwner)
	if !ok {
		t.Fatal("native phone reset cannot generate and retain original joint input")
	}
	for _, attributed := range []bool{false, true} {
		t.Run(fmt.Sprint(attributed), func(t *testing.T) {
			input, candidate := f.input(t, f.spec, f.proof)
			at, calls := f.now, 0
			config := f.screening(t, &at, &calls, "clean")
			var collector ResetScreeningCollector
			if attributed {
				collect := config.Collect
				config.Collect = nil
				collector = func(ctx context.Context, binding identity.CommandBinding, challenge string, scope risk.Context, borrowed primitive.Secret) ([]risk.Signal, error) {
					if binding != f.spec.Binding || challenge != f.grant.Payload().ID || scope.Tenant != string(binding.TenantID) || scope.Attempt != string(binding.CommandID) || scope.Operation != risk.Action(binding.OperationID) || borrowed.Len() != candidate.Len() {
						t.Fatal("collector lost exact original attribution")
					}
					return collect(ctx, scope, borrowed)
				}
			}
			generated, facts, err := owner.generatePhoneResetCommand(context.Background(), input, config, f.engine, f.profile, f.original, f.grant, f.plan, collector)
			if err != nil || len(facts) != 1 || calls != 1 {
				t.Fatal("original phone reset cannot produce screened verifier", err)
			}
			got, hash, err := passwordResetOriginalMaterial(generated, f.policy, f.profile, f.original, f.grant, f.plan, at)
			metadata, ok := generated.PhonePasswordResetFeature()
			originalSpec, _ := input.PhonePasswordResetInputFeature()
			if err != nil || got != f.intent || !ok || !reflect.DeepEqual(metadata, originalSpec) {
				t.Fatal("generation changed original joint intent", err)
			}
			verified, err := f.primitive.Verify(context.Background(), []byte(" phone-generation-original-password "), hash.String())
			if err != nil || !verified.Match() {
				t.Fatal("phone generation changed original password bytes", err)
			}
			assertPhoneResetGenerationCustody(t, f.engine, f.grant, input, generated)
			wire, err := owner.sealPhoneResetOutput(context.Background(), f.crypto, "phone-output", input, 1, [32]byte{17}, generated, facts, f.riskPlan, f.otpPlan)
			if err != nil || bytes.Contains(wire, []byte(hash.String())) || bytes.Contains(wire, []byte("phone-generation-original-password")) {
				t.Fatal("phone output lacks bounded encryption", err)
			}
			defer clear(wire)
			retained, retainedRisk, retainedOTP, err := owner.readPhoneResetOutputIntent(context.Background(), f.crypto, f.spec.Binding, 1, [32]byte{17}, wire)
			if err != nil || !reflect.DeepEqual(retained, originalSpec) || retainedRisk != f.riskPlan || retainedOTP != f.otpPlan {
				t.Fatal("retained original phone intent/plans changed", err)
			}
			retained.Fields[0].Value.Text = "caller-changed"
			retained, _, _, err = owner.readPhoneResetOutputIntent(context.Background(), f.crypto, f.spec.Binding, 1, [32]byte{17}, wire)
			if err != nil || !reflect.DeepEqual(retained, originalSpec) {
				t.Fatal("caller mutated retained original phone intent", err)
			}
			// Restoration must not consult providers, clocks, hashers or grant
			// freshness. Native admission rechecks the unchanged original facts.
			at = f.original.ExpiresAt.Add(time.Hour)
			restored, restoredFacts, restoredRisk, restoredOTP, err := owner.restorePhoneResetOutput(context.Background(), f.crypto, input, 1, [32]byte{17}, wire)
			raw, _, _, _, custody := restored.PhonePasswordResetCustody()
			if err != nil || !custody || raw != hash.String() || !reflect.DeepEqual(facts, restoredFacts) || calls != 1 || restoredRisk != f.riskPlan || restoredOTP != f.otpPlan {
				t.Fatal("restoration renewed or regenerated original phone material/plans", err)
			}
			assertPhoneResetGenerationCustody(t, f.engine, f.grant, input, restored)
			for _, value := range []any{generated, restored, []any{restored}} {
				for _, format := range []string{"%v", "%+v", "%#v"} {
					text := fmt.Sprintf(format, value)
					if strings.Contains(text, hash.String()) || strings.Contains(text, "phone-generation-original-password") || !strings.Contains(text, "redacted") {
						t.Fatal("joint generation diagnostics leaked custody")
					}
				}
			}
			if _, err := json.Marshal(restored); err == nil {
				t.Fatal("generated command serialized secret custody")
			}
			if candidate.Len() == 0 || f.proof.ValidateBounds(32, 4096) != nil {
				t.Fatal("generation/output consumed borrowed custody")
			}
		})
	}
}

func TestPhoneResetGenerationDeniesBeforeProviderAndPreservesFailures(t *testing.T) {
	f := newPhoneResetGenerationFixture(t)
	owner, ok := any(f.repository).(phoneResetGenerationOwner)
	if !ok {
		t.Fatal("native phone reset generation boundary missing")
	}
	for _, mode := range []string{"foreign-proof", "foreign-original", "foreign-command", "missing-factor", "missing-cookie", "destroyed-password", "zero-input", "cancelled", "ambiguous-collector", "breached", "unavailable", "missing", "required-status", "foreign-provider", "velocity", "expired-provider", "expired-grant", "provider-panic"} {
		t.Run(mode, func(t *testing.T) {
			input, candidate := f.input(t, f.spec, f.proof)
			selected, at, calls := f.original, f.now, 0
			config := f.screening(t, &at, &calls, mode)
			ctx := context.Background()
			var collect ResetScreeningCollector
			before := true
			switch mode {
			case "foreign-proof":
				payload := f.grant.Payload()
				payload.ID = "foreign-issued-phone-reset"
				foreign, _, err := f.engine.Issue(ctx, payload)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = foreign.Transfer(context.Background(), func(context.Context, []byte) error { return nil }) })
				input, _ = f.input(t, f.spec, foreign)
			case "foreign-original":
				selected.CredentialVersion++
			case "foreign-command":
				spec := f.spec
				spec.Binding.TenantID = "foreign"
				input, _ = f.input(t, spec, f.proof)
			case "missing-factor":
				selected.FactorVersion = 0
			case "missing-cookie":
				password, proof, sms, totp, _ := input.PhonePasswordResetInputCustody()
				spec, _ := input.PhonePasswordResetInputFeature()
				var err error
				input, err = identity.NewFeaturePhonePasswordResetInputCommand(spec, password, proof, sms, totp)
				if err != nil {
					t.Fatal(err)
				}
			case "destroyed-password":
				candidate.Destroy()
			case "zero-input":
				input = identity.Command{}
			case "cancelled":
				var stop context.CancelFunc
				ctx, stop = context.WithCancel(ctx)
				stop()
			case "ambiguous-collector":
				collect = func(context.Context, identity.CommandBinding, string, risk.Context, primitive.Secret) ([]risk.Signal, error) {
					t.Fatal("ambiguous collector ran")
					return nil, nil
				}
			default:
				before = false
			}
			generated, facts, err := owner.generatePhoneResetCommand(ctx, input, config, f.engine, f.profile, selected, f.grant, f.plan, collect)
			if err == nil || generated != (identity.Command{}) || len(facts) != 0 || strings.Contains(err.Error(), "private-provider") {
				t.Fatal("invalid original phone reset disclosed material", err)
			}
			if before && calls != 0 || !before && calls != 1 {
				t.Fatal("provider ran before original admission or was recollected")
			}
			if mode == "cancelled" && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation identity lost", err)
			}
		})
	}
}

func TestPhoneResetOutputRejectsForeignAndChangedCustody(t *testing.T) {
	f := newPhoneResetGenerationFixture(t)
	owner, ok := any(f.repository).(phoneResetGenerationOwner)
	if !ok {
		t.Fatal("native phone output boundary missing")
	}
	input, _ := f.input(t, f.spec, f.proof)
	at, calls := f.now, 0
	generated, facts, err := owner.generatePhoneResetCommand(context.Background(), input, f.screening(t, &at, &calls, "clean"), f.engine, f.profile, f.original, f.grant, f.plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := owner.sealPhoneResetOutput(context.Background(), f.crypto, "phone-output", input, 1, [32]byte{17}, generated, facts, f.riskPlan, f.otpPlan)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wire)
	for _, mode := range []string{"generation", "configuration", "binding", "fields", "tamper", "empty", "zero-input", "terminal-proof", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			command, version, configuration, blob, ctx := input, uint64(1), [32]byte{17}, bytes.Clone(wire), context.Background()
			defer clear(blob)
			spec, _ := input.PhonePasswordResetInputFeature()
			switch mode {
			case "generation":
				version++
			case "configuration":
				configuration[0]++
			case "binding":
				spec.Binding.CommandID, _ = identity.NewCommandID()
				command, _ = f.input(t, spec, f.proof)
			case "fields":
				for i := range spec.Fields {
					if spec.Fields[i].Name == "credential.expected-user-version" {
						spec.Fields[i].Value.Uint64++
					}
				}
				command, _ = f.input(t, spec, f.proof)
			case "tamper":
				blob[len(blob)-1] ^= 1
			case "empty":
				blob = nil
			case "zero-input":
				command = identity.Command{}
			case "terminal-proof":
				proof, _, e := f.engine.Issue(ctx, f.grant.Payload())
				if e != nil {
					t.Fatal(e)
				}
				command, _ = f.input(t, f.spec, proof)
				if e := proof.Transfer(ctx, func(context.Context, []byte) error { return nil }); e != nil {
					t.Fatal(e)
				}
			case "cancelled":
				var stop context.CancelFunc
				ctx, stop = context.WithCancel(ctx)
				stop()
			}
			out, gotFacts, gotRisk, gotOTP, e := owner.restorePhoneResetOutput(ctx, f.crypto, command, version, configuration, blob)
			if e == nil || out != (identity.Command{}) || len(gotFacts) != 0 || gotRisk != (kernel.RiskEvidencePlan{}) || gotOTP != (kernel.OTPAttemptPlan{}) {
				t.Fatal("changed phone output disclosed retained material")
			}
			if mode == "generation" || mode == "configuration" || mode == "binding" || mode == "tamper" || mode == "empty" || mode == "cancelled" {
				got, gotRisk, gotOTP, e := owner.readPhoneResetOutputIntent(ctx, f.crypto, spec.Binding, version, configuration, blob)
				if e == nil || got.Binding != (identity.CommandBinding{}) || len(got.Fields) != 0 || gotRisk != (kernel.RiskEvidencePlan{}) || gotOTP != (kernel.OTPAttemptPlan{}) {
					t.Fatal("foreign phone output disclosed retained intent")
				}
			}
		})
	}
}

func TestPhoneResetOutputRetainsCompleteProvidersAndRejectsMalformedFraming(t *testing.T) {
	f := newPhoneResetGenerationFixture(t)
	owner, ok := any(f.repository).(phoneResetGenerationOwner)
	if !ok {
		t.Fatal("phone generation/output missing")
	}
	input, _ := f.input(t, f.spec, f.proof)
	at, calls := f.now, 0
	generated, facts, err := owner.generatePhoneResetCommand(context.Background(), input, f.screening(t, &at, &calls, "complete-providers"), f.engine, f.profile, f.original, f.grant, f.plan, nil)
	if err != nil || len(facts) != 2 {
		t.Fatal("configured provider requirements were lost", err)
	}
	wire, err := owner.sealPhoneResetOutput(context.Background(), f.crypto, "phone-output", input, 1, [32]byte{17}, generated, facts, f.riskPlan, f.otpPlan)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wire)
	_, retained, _, _, err := owner.restorePhoneResetOutput(context.Background(), f.crypto, input, 1, [32]byte{17}, wire)
	if err != nil || !reflect.DeepEqual(retained, facts) || calls != 1 {
		t.Fatal("complete providers changed during restore", err)
	}
	hash, _, _, _, _ := generated.PhonePasswordResetCustody()
	spec, _ := input.PhonePasswordResetInputFeature()
	stored := phoneResetStoredOutput{Schema: 1, Spec: spec, Hash: hash, Facts: facts, Risk: phoneResetStoredRiskPlan(f.riskPlan), OTP: phoneResetStoredOTPPlan(f.otpPlan)}
	if text := fmt.Sprintf("%+v", stored); strings.Contains(text, hash) || !strings.Contains(text, "redacted") {
		t.Fatal("private stored output diagnostics exposed verifier")
	}
	plain, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	// Only schema/spec/verifier/provider metadata and the two original plans
	// may enter this deliberate encrypted representation. No joint secret does.
	var members map[string]json.RawMessage
	if err := json.Unmarshal(plain, &members); err != nil || len(members) != 6 {
		t.Fatal("encrypted output schema contains extra custody", err)
	}
	for _, name := range []string{"Schema", "Spec", "Hash", "Facts", "Risk", "OTP"} {
		if _, ok := members[name]; !ok {
			t.Fatal("encrypted output lost declared field")
		}
	}
	aad, err := phoneResetOutputBindingAAD(spec.Binding, 1, [32]byte{17})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"whitespace", "duplicate", "unknown", "missing-facts", "hint", "duplicate-hibp", "velocity", "foreign-fact", "risk-binding", "risk-phase", "risk-time", "otp-key", "otp-version", "extra-fields", "wrong-hash"} {
		t.Run(name, func(t *testing.T) {
			bad := stored
			bad.Facts = append([]risk.Signal(nil), stored.Facts...)
			bad.Spec.Fields = append([]identity.FeatureField(nil), stored.Spec.Fields...)
			switch name {
			case "missing-facts":
				bad.Facts = nil
			case "hint":
				bad.Facts[0].Trust = risk.RequestHint
			case "duplicate-hibp":
				bad.Facts = append(bad.Facts, bad.Facts[0])
			case "velocity":
				bad.Facts[1].Name = "velocity"
			case "foreign-fact":
				bad.Facts[0].Attempt = "foreign"
			case "risk-binding":
				bad.Risk.ConsumerCommandID = "AgICAgICAgICAgICAgICAg"
			case "risk-phase":
				bad.Risk.Purpose = "phone-password-reset-initiate"
			case "risk-time":
				bad.Risk.CheckedAt = bad.Risk.ExpiresAt
			case "otp-key":
				bad.OTP.DigestKeyVersion++
			case "otp-version":
				bad.OTP.ExpectedVersion = 0
			case "extra-fields":
				for len(bad.Spec.Fields) <= 128 {
					bad.Spec.Fields = append(bad.Spec.Fields, identity.FeatureField{})
				}
			case "wrong-hash":
				bad.Hash = "$not-a-verifier$"
			}
			malformed, e := json.Marshal(bad)
			if e != nil {
				t.Fatal(e)
			}
			if name == "whitespace" {
				malformed = append(malformed, ' ')
			}
			if name == "duplicate" {
				malformed = append([]byte(`{"Schema":1,`), malformed[1:]...)
			}
			if name == "unknown" {
				malformed = append([]byte(`{"Unknown":true,`), malformed[1:]...)
			}
			sealed, e := f.crypto.Encrypt(context.Background(), envelope.EncryptRequest{Plaintext: malformed, KeyReference: "phone-output", Context: aad})
			clear(malformed)
			if e != nil {
				t.Fatal(e)
			}
			blob, e := sealed.MarshalBinary()
			if e != nil {
				t.Fatal(e)
			}
			defer clear(blob)
			command, facts, riskPlan, otpPlan, e := owner.restorePhoneResetOutput(context.Background(), f.crypto, input, 1, [32]byte{17}, blob)
			if e == nil || command != (identity.Command{}) || facts != nil || riskPlan != (kernel.RiskEvidencePlan{}) || otpPlan != (kernel.OTPAttemptPlan{}) {
				t.Fatal("malformed encrypted output disclosed material")
			}
			intent, riskPlan, otpPlan, e := owner.readPhoneResetOutputIntent(context.Background(), f.crypto, spec.Binding, 1, [32]byte{17}, blob)
			if e == nil || intent.Binding != (identity.CommandBinding{}) || len(intent.Fields) != 0 || riskPlan != (kernel.RiskEvidencePlan{}) || otpPlan != (kernel.OTPAttemptPlan{}) {
				t.Fatal("malformed encrypted output disclosed invalid intent")
			}
		})
	}
}

func FuzzPhoneResetGeneratedOutput(f *testing.F) {
	fixture := newPhoneResetGenerationFixture(f)
	// Fuzz workers must share deterministic authenticated seed inputs. Actual
	// hashing/proof generation is exercised above; this seed tests only framing.
	fixture.spec.Binding.CommandID = "AQEBAQEBAQEBAQEBAQEBAQ"
	fixture.now = time.Date(2026, 10, 20, 13, 0, 0, 0, time.UTC)
	fixture.riskPlan.ConsumerCommandID = string(fixture.spec.Binding.CommandID)
	fixture.riskPlan.IssuanceCommandID = "AgICAgICAgICAgICAgICAg"
	fixture.riskPlan.IssuedAt = fixture.now.Add(-time.Second)
	fixture.riskPlan.CheckedAt = fixture.now.Add(-time.Nanosecond)
	fixture.riskPlan.ExpiresAt = fixture.now.Add(time.Minute)
	fixture.otpPlan.AttemptID = "AwMDAwMDAwMDAwMDAwMDAw"
	var parseErr error
	fixture.dummy, parseErr = primitive.ParseEncodedHash("$argon2id$v=19$m=8,t=1,p=1$MTIzNDU2Nzg$MDEyMzQ1Njc4OWFiY2RlZg", fixture.policy.Limits())
	if parseErr != nil {
		f.Fatal(parseErr)
	}
	input, _ := fixture.input(f, fixture.spec, fixture.proof)
	_, proof, sms, totp, _ := input.PhonePasswordResetInputCustody()
	spec, _ := input.PhonePasswordResetInputFeature()
	cookie, _ := input.PhonePasswordResetPreAuthCookie()
	generated, err := identity.NewFeaturePhonePasswordResetCommand(spec, fixture.dummy.String(), proof, sms, totp)
	if err != nil {
		f.Fatal(err)
	}
	generated, err = identity.BindPhonePasswordResetPreAuth(generated, cookie)
	if err != nil {
		f.Fatal(err)
	}
	facts := []risk.Signal{{Tenant: string(spec.Binding.TenantID), Operation: risk.Action(spec.Binding.OperationID), Attempt: string(spec.Binding.CommandID), Name: "hibp", Trust: risk.ServerVerified, State: risk.SignalClean, ObservedAt: fixture.now, CheckedAt: fixture.now, ProviderValidUntil: fixture.now.Add(time.Hour), ExpiresAt: fixture.now.Add(time.Minute)}}
	owner, ok := any(fixture.repository).(phoneResetGenerationOwner)
	if !ok {
		f.Fatal("phone output owner missing")
	}
	wire, err := owner.sealPhoneResetOutput(context.Background(), fixture.crypto, "phone-output", input, 1, [32]byte{17}, generated, facts, fixture.riskPlan, fixture.otpPlan)
	if err != nil {
		f.Fatal(err)
	}
	defer clear(wire)
	f.Add(wire)
	f.Add([]byte{})
	f.Add([]byte("invalid-envelope"))
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > maximumResetOutput+1 {
			t.Skip()
		}
		command, retained, riskPlan, otpPlan, err := owner.restorePhoneResetOutput(context.Background(), fixture.crypto, input, 1, [32]byte{17}, wire)
		if err != nil {
			if command != (identity.Command{}) || retained != nil || riskPlan != (kernel.RiskEvidencePlan{}) || otpPlan != (kernel.OTPAttemptPlan{}) {
				t.Fatal("failed open disclosed partial custody")
			}
			return
		}
		hash, _, _, _, ok := command.PhonePasswordResetCustody()
		if !ok || hash != fixture.dummy.String() || !reflect.DeepEqual(retained, facts) || riskPlan != fixture.riskPlan || otpPlan != fixture.otpPlan {
			t.Fatal("unauthenticated wire changed retained output")
		}
	})
}

func newPhoneResetGenerationFixture(t testing.TB) phoneResetGenerationFixture {
	t.Helper()
	policy, err := primitive.NewPolicy(primitive.PolicyConfig{Algorithm: primitive.Argon2id, Argon2id: primitive.Argon2idParameters{Version: 19, Time: 1, MemoryKiB: 8, Parallelism: 1, SaltLength: 8, OutputLength: 16}, Limits: primitive.Limits{PasswordBytes: 128, EncodedHashBytes: 256, Argon2Time: 2, MemoryKiB: 16, Parallelism: 1, SaltBytes: 16, OutputBytes: 32, BcryptCost: 4, Concurrent: 2, Queue: 2}})
	if err != nil {
		t.Fatal(err)
	}
	commandID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	spec := identity.FeatureCommandSpec{Binding: identity.CommandBinding{CommandID: commandID, TenantID: "tenant", UserID: "user", ActorID: "actor", ActorKind: "user", RecordID: "password", PolicyID: "password-policy", PolicyVersion: 1, SchemaVersion: 1, CorrelationID: "correlation"}}
	previous := kernel.CredentialReplacementIntent{Credential: identity.CredentialRef{ID: "password", TenantID: "tenant", UserID: "user", Kind: identity.CredentialPassword, Owner: "identity/password", Version: 7}, ExpectedUserVersion: 101, ExpectedAuthorityVersion: 5}
	spec.Operation = phonePasswordResetOperation()
	spec.Binding.OperationID, spec.Binding.SchemaID = spec.Operation.OperationID, spec.Operation.SchemaID
	intent := kernel.CredentialResetIntent{Replacement: previous, ExpectedEnabled: true}
	intent.Replacement.ExpectedUserVersion = 101
	fields, err := kernel.CredentialResetFields(intent)
	if err != nil {
		t.Fatal(err)
	}
	spec.Fields = append(fields, identity.FeatureField{Name: "phone.original-profile", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "original-phone-commitment"}}, identity.FeatureField{Name: "otp.attempt-custody", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: []byte{1, 2, 3}}}, identity.FeatureField{Name: "otp.digest-key-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 3}})
	now := time.Now().UTC().Truncate(time.Second)
	origin, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	original := password.ResetGrantSpec{TenantID: "tenant", UserID: "user", CredentialID: "password", CredentialVersion: 7, CredentialAuthorityVersion: 5, UserAuthorityVersion: 3, IdentifierID: "original-phone", IdentifierVersion: 11, FactorVersion: 4, OriginCommandID: origin, RecoveryPath: auth.RecoveryPathPhone, CallbackURL: "https://identity.test/reset", IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute), Phone: password.PhoneResetBinding{PreAuthTransaction: "original-phone-browser", OTPChallengeID: "original-phone-challenge", AttemptID: origin, NumberDigest: [32]byte{91}, NumberKeyVersion: 1, VerificationVersion: 3, FactorID: "independent-confirmed-totp", FactorVersion: 5, RiskPolicyVersion: 3}}
	profile, err := password.NewPhoneResetProfile(password.ResetProfileConfig{Issuer: "https://identity.test", Audience: "reset", MaximumLifetime: 2 * time.Minute, Callbacks: []string{original.CallbackURL}, CurrentBindingKeyVersion: 1, RetainedBindingKeys: map[uint32][32]byte{1: {31}}})
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := capability.NewHMACSHA256Signer("synthetic-phone-reset", bytes.Repeat([]byte{71}, 32))
	verifier, _ := capability.NewHMACSHA256Verifier(bytes.Repeat([]byte{71}, 32))
	resolver, _ := capability.NewKeySet([]capability.Key{{Issuer: "https://identity.test", ID: "synthetic-phone-reset", Verifier: verifier}})
	engine, err := capability.NewService(capability.ServiceConfig{Issuer: "https://identity.test", Signer: signer, Resolver: resolver, Clock: func() time.Time { return now }, Limits: capability.DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := profile.Payload(original)
	if err != nil {
		t.Fatal(err)
	}
	payload.ID = "synthetic-original-phone-reset"
	proof, _, err := engine.Issue(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }) })
	grant, err := engine.Verify(context.Background(), proof, capability.Purpose(spec.Operation.OperationID), "reset")
	if err != nil {
		t.Fatal(err)
	}
	plan := kernel.CapabilityPlan{CapabilityID: payload.ID, Purpose: capability.Purpose(payload.Operation), ReplayDigest: [32]byte{19}, ReplayKeyVersion: 2, ProofFingerprint: grant.EnvelopeDigest(), ExpiresAt: original.ExpiresAt, MaxUses: 1}
	service, err := primitive.New(policy)
	if err != nil {
		t.Fatal(err)
	}
	dummy, err := service.Hash(context.Background(), []byte("synthetic-phone-dummy"))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := keyring.New(map[string][]byte{"phone-output": bytes.Repeat([]byte{75}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		t.Fatal(err)
	}
	riskID, _ := identity.NewCommandID()
	riskPlan := kernel.RiskEvidencePlan{IssuanceCommandID: string(riskID), Tenant: string(spec.Binding.TenantID), Subject: string(spec.Binding.UserID), IssuerActor: "phone-risk-owner", Purpose: "phone-password-reset-complete", Phase: "phone-reset-completion", RecoveryOperation: spec.Binding.OperationID, PolicyVersion: 3, KeyVersion: 1, IntentDigest: [32]byte{1}, ConsumerCommandID: string(spec.Binding.CommandID), ConsumerActor: string(spec.Binding.ActorID), EvidenceDigest: [32]byte{2}, ProofDigest: [32]byte{3}, Signature: [32]byte{4}, IssuedAt: now.Add(-time.Second), CheckedAt: now.Add(-time.Nanosecond), ExpiresAt: now.Add(time.Minute)}
	attemptID, _ := identity.NewCommandID()
	otpPlan := kernel.OTPAttemptPlan{AttemptID: string(attemptID), AttemptFingerprint: [32]byte{5}, FingerprintKeyVersion: 1, ChallengeID: original.Phone.OTPChallengeID, ScopeDigest: [32]byte{6}, DigestKeyVersion: 3, ExpectedVersion: 7, Mode: kernel.OTPConsume}
	return phoneResetGenerationFixture{repository: &Repository{policy: policy}, policy: policy, primitive: service, dummy: dummy, spec: spec, intent: intent, profile: profile, original: original, engine: engine, grant: grant, proof: proof, plan: plan, now: now, crypto: crypto, riskPlan: riskPlan, otpPlan: otpPlan}
}

func (f phoneResetGenerationFixture) input(t testing.TB, spec identity.FeatureCommandSpec, proof capability.Proof) (identity.Command, primitive.Secret) {
	t.Helper()
	candidate, err := primitive.NewSecret([]byte(" phone-generation-original-password "))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(candidate.Destroy)
	sms, _ := auth.NewOneTimeCode("123456")
	totp, _ := auth.NewOneTimeCode("654321")
	command, err := identity.NewFeaturePhonePasswordResetInputCommand(spec, candidate, proof, sms, totp)
	if err != nil {
		t.Fatal(err)
	}
	cookie := auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{81}, 32)))
	command, err = identity.BindPhonePasswordResetPreAuth(command, cookie)
	if err != nil {
		t.Fatal(err)
	}
	return command, candidate
}

func (f phoneResetGenerationFixture) screening(t *testing.T, at *time.Time, calls *int, mode string) password.HashPreparationConfig {
	t.Helper()
	base := signupScreeningPolicy(t)
	var profiles []risk.Profile
	for _, action := range []risk.Action{"identity.password.signin", "identity.password.change", "identity.admin.user-ban", "identity.session.get"} {
		admission, err := base.Admit(action)
		if err != nil {
			t.Fatal(err)
		}
		if admission.Profile.Class == risk.Authentication {
			admission.Profile.RequiredSignals = []string{"velocity"}
			if mode == "required-status" || mode == "complete-providers" {
				admission.Profile.RequiredSignals = append(admission.Profile.RequiredSignals, "status")
			}
		}
		profiles = append(profiles, admission.Profile)
	}
	policy, err := risk.NewPolicy(risk.PolicyConfig{Version: 3, Profiles: profiles, HIBP: risk.HIBPPolicy{CacheTTL: time.Hour, Operations: []risk.Action{"identity.phone.password-reset-complete"}}, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}})
	if err != nil {
		t.Fatal(err)
	}
	return password.HashPreparationConfig{Primitive: f.primitive, MinimumBytes: 8, MaximumBytes: 128, Timeout: time.Second, DummyHash: f.dummy, Policy: policy, Now: func() time.Time { return *at }, Collect: func(ctx context.Context, scope risk.Context, candidate primitive.Secret) ([]risk.Signal, error) {
		*calls++
		if _, bounded := ctx.Deadline(); !bounded || candidate.Len() == 0 {
			t.Fatal("provider lost bounded original borrow")
		}
		if mode == "provider-panic" {
			panic("private-provider-diagnostic")
		}
		observation := risk.PasswordObservation{ObservedAt: scope.Now, CheckedAt: scope.Now, ValidUntil: scope.Now.Add(time.Hour)}
		if mode == "breached" {
			observation.BreachCount = 1
		}
		if mode == "unavailable" {
			observation = risk.PasswordObservation{Failure: risk.ProviderUnavailable}
		}
		fact, err := policy.PasswordSignal(ctx, scope, observation)
		if err != nil {
			return nil, err
		}
		if mode == "missing" {
			return nil, nil
		}
		if mode == "foreign-provider" {
			fact.Attempt = "foreign"
		}
		if mode == "expired-provider" {
			*at = fact.ExpiresAt
		}
		if mode == "expired-grant" {
			*at = f.original.ExpiresAt
		}
		facts := []risk.Signal{fact}
		if mode == "velocity" {
			velocity := fact
			velocity.Name = "velocity"
			facts = append(facts, velocity)
		}
		if mode == "complete-providers" {
			facts = append(facts, risk.Signal{Tenant: scope.Tenant, Operation: scope.Operation, Attempt: scope.Attempt, Name: "status", State: risk.SignalClean, Trust: risk.ServerVerified, ObservedAt: scope.Now, ExpiresAt: scope.Now.Add(time.Minute)})
		}
		return facts, nil
	}}
}

func assertPhoneResetGenerationCustody(t *testing.T, engine capability.Service, grant capability.Grant, input, generated identity.Command) {
	t.Helper()
	_, proof, sms, totp, _ := input.PhonePasswordResetInputCustody()
	_, retainedProof, retainedSMS, retainedTOTP, ok := generated.PhonePasswordResetCustody()
	if !ok {
		t.Fatal("generated phone reset lost joint custody")
	}
	for _, borrowed := range []capability.Proof{proof, retainedProof} {
		verified, err := engine.Verify(context.Background(), borrowed, capability.Purpose("identity.phone.password-reset-complete"), "reset")
		if err != nil || verified.EnvelopeDigest() != grant.EnvelopeDigest() {
			t.Fatal("generation replaced original proof", err)
		}
	}
	for _, pair := range [][2]auth.OneTimeCode{{sms, retainedSMS}, {totp, retainedTOTP}} {
		a, _ := pair[0].CommandDigest([32]byte{1}, "test")
		b, err := pair[1].CommandDigest([32]byte{1}, "test")
		if err != nil || a != b {
			t.Fatal("generation changed original code custody")
		}
	}
	a, present := input.PhonePasswordResetPreAuthCookie()
	b, retained := generated.PhonePasswordResetPreAuthCookie()
	if !present || !retained || a.Token() != b.Token() {
		t.Fatal("generation replaced original browser cookie")
	}
	if _, ok := generated.PasswordResetFeature(); ok {
		t.Fatal("joint phone reset downgraded to email")
	}
	if _, ok := generated.OneTimeCode(); ok {
		t.Fatal("joint phone reset downgraded to one code")
	}
}
