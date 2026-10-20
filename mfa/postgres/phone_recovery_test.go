package mfapostgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	password "github.com/faustbrian/go-password/v2"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

func TestPhoneRecoveryTOTPRejectsMissingCustody(t *testing.T) {
	if _, err := NewPhoneRecoveryTOTPVerifier(nil, [32]byte{1}, 1); err == nil {
		t.Fatal("missing envelope owner accepted")
	}
	for _, ctx := range []context.Context{nil, context.Background()} {
		if _, err := (*TOTPFactorReader)(nil).ReadForPhoneRecovery(ctx, "tenant-a", "user-a", "AAAAAAAAAAAAAAAAAAAAAQ"); err == nil {
			t.Fatal("missing reader returned factor custody")
		}
		if _, err := (*PhoneRecoveryTOTPVerifier)(nil).Prepare(ctx, TOTPFactorSnapshot{}, identity.Command{}, time.Now().Add(time.Minute)); err == nil {
			t.Fatal("missing encrypted preparation accepted")
		}
		if _, err := VerifyPhoneRecoveryTOTPAttempt(ctx, kernel.OTPAttemptWork{}, nil, PreparedPhoneRecoveryTOTP{}); err == nil {
			t.Fatal("missing live attempt accepted")
		}
		if _, err := VerifyAndRecordPhoneRecoveryTOTP(ctx, kernel.Work{}, nil, identity.Command{}, PreparedPhoneRecoveryTOTP{}); err == nil {
			t.Fatal("missing live consuming command accepted")
		}
		if err := RequirePhoneRecoveryTOTPReservation(ctx, kernel.OTPReservationWork{}, nil, identity.Command{}, TOTPFactorSnapshot{}, time.Now().Add(time.Minute)); err == nil {
			t.Fatal("missing exact pre-reservation owner accepted")
		}
	}
	if err := (PhoneRecoveryTOTPCompletion{}).RequireRecorded(context.Background(), kernel.Work{}, nil, identity.Command{}); err == nil {
		t.Fatal("zero completion became successful factor proof")
	}
	if _, err := (PhoneRecoveryTOTPAttempt{}).Accepted(context.Background(), kernel.OTPAttemptWork{}, nil); err == nil {
		t.Fatal("zero attempt became successful factor proof")
	}
	(PreparedPhoneRecoveryTOTP{}).Destroy()
}

func TestPhoneRecoveryTOTPApplyRejectsMissingWork(t *testing.T) {
	_, snapshot := phoneRecoveryFixture(t)
	for _, ctx := range []context.Context{nil, context.Background()} {
		if err := RequirePhoneRecoveryTOTPApply(ctx, kernel.OTPApplyWork{}, nil, snapshot, time.Now().UTC().Truncate(time.Microsecond).Add(time.Minute)); err == nil {
			t.Fatal("encrypted metadata without actual protected OTP Work became authority")
		}
	}
}

func TestPhoneRecoveryTOTPCompletionRequiresActualOTPApplyOrigin(t *testing.T) {
	_, snapshot := phoneRecoveryFixture(t)
	state := phoneRecoveryTOTPCompletion{snapshot: snapshot, step: 1, until: time.Now().UTC().Truncate(time.Microsecond).Add(time.Minute)}
	populated := PhoneRecoveryTOTPCompletion{custody: func() phoneRecoveryTOTPCompletion { return state }}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, receipt := range []PhoneRecoveryTOTPCompletion{{}, populated} {
		for _, ctx := range []context.Context{nil, context.Background(), canceled} {
			if err := receipt.RequireOTPApplyRecorded(ctx, kernel.OTPApplyWork{}, nil); err == nil {
				t.Fatal("completion metadata without actual same-Work origin became factor proof")
			}
		}
	}
}

// This is only the closed code-free metadata guard. It is not live admission;
// the consuming component test must obtain the actual OTPApplyWork separately.
func TestPhoneRecoveryTOTPApplySpecRequiresOriginalFactor(t *testing.T) {
	_, snapshot := phoneRecoveryFixture(t)
	m, err := snapshot.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	command := phoneRecoveryTestCommand(t, m, false, "12345678", nil)
	spec, _ := command.PhonePasswordResetFeature()
	if err := phoneRecoveryFactorSpec(spec, m); err != nil {
		t.Fatal("original code-free scope rejected", err)
	}
	changeField := func(name string, change func(*identity.FeatureValue)) func(*identity.FeatureCommandSpec) {
		return func(f *identity.FeatureCommandSpec) {
			for i := range f.Fields {
				if f.Fields[i].Name == name {
					change(&f.Fields[i].Value)
					return
				}
			}
			t.Fatal("fixture has no selected factor field")
		}
	}
	for name, change := range map[string]func(*identity.FeatureCommandSpec){
		"foreign tenant":     func(f *identity.FeatureCommandSpec) { f.Binding.TenantID = "foreign" },
		"foreign user":       func(f *identity.FeatureCommandSpec) { f.Binding.UserID = "foreign" },
		"foreign owner":      func(f *identity.FeatureCommandSpec) { f.Operation.Owner = "identity/mfa" },
		"foreign schema":     func(f *identity.FeatureCommandSpec) { f.Operation.SchemaID = "alias" },
		"foreign version":    func(f *identity.FeatureCommandSpec) { f.Operation.SchemaVersion = 2 },
		"missing record":     func(f *identity.FeatureCommandSpec) { f.Operation.RecordRequirement = identity.FeatureRecordOmitted },
		"foreign factor":     changeField("phone.reset.factor-id", func(v *identity.FeatureValue) { v.Text = "AAAAAAAAAAAAAAAAAAAAAg" }),
		"foreign enrollment": changeField("phone.reset.factor-version", func(v *identity.FeatureValue) { v.Uint64++ }),
		"foreign aggregate":  changeField("phone.reset.factor-authority-version", func(v *identity.FeatureValue) { v.Uint64++ }),
		"missing field":      func(f *identity.FeatureCommandSpec) { f.Fields = f.Fields[:2] },
		"duplicate field":    func(f *identity.FeatureCommandSpec) { f.Fields = append(f.Fields, f.Fields[0]) },
		"unknown factor field": func(f *identity.FeatureCommandSpec) {
			f.Fields = append(f.Fields, identity.FeatureField{Name: "phone.reset.factor-unrecognized", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "unknown"}})
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := spec
			f.Fields = append([]identity.FeatureField(nil), spec.Fields...)
			change(&f)
			if err := phoneRecoveryFactorSpec(f, m); err == nil {
				t.Fatal("foreign code-free factor scope accepted")
			}
		})
	}
}

// These are structural/encryption fixtures, not capability authorization or a
// successful native phone-reset consumer. Native Work custody remains required.
func phoneRecoveryFixture(t testing.TB) (*PhoneRecoveryTOTPVerifier, TOTPFactorSnapshot) {
	t.Helper()
	keys, err := keyring.New(map[string][]byte{"test-wrap-v1": []byte(strings.Repeat("k", 32))})
	if err != nil {
		t.Fatal(err)
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewPhoneRecoveryTOTPVerifier(crypto, [32]byte{3}, 1)
	if err != nil {
		t.Fatal(err)
	}
	m := TOTPFactorMetadata{TenantID: "tenant-a", UserID: "mfa-user", FactorID: "AAAAAAAAAAAAAAAAAAAAAQ", EnrollmentVersion: 1, RowVersion: 1, FactorAuthorityVersion: 1, Profile: mfa.TOTPProfile{Algorithm: "SHA1", Digits: 8, Period: 30 * time.Second, AllowedSkewSteps: 1, Issuer: "Example"}}
	binding, err := totpEncryptionContext(m.TenantID, m.UserID, m.FactorID, m.EnrollmentVersion, m.Profile)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := crypto.Encrypt(t.Context(), envelope.EncryptRequest{Plaintext: []byte("12345678901234567890"), KeyReference: "test-wrap-v1", Context: binding})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := sealed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	f := totpFactorCustody{metadata: m, wire: wire, binding: binding}
	return v, TOTPFactorSnapshot{custody: func() totpFactorCustody { return f }}
}

func phoneRecoveryTestCommand(t testing.TB, m TOTPFactorMetadata, input bool, code string, change func(*identity.FeatureCommandSpec)) identity.Command {
	t.Helper()
	op := identity.FeatureOperation{Owner: "identity/phone", OperationID: "identity.phone.password-reset-complete", SchemaID: "identity.phone.password-reset-complete.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	b := identity.CommandBinding{CommandID: "AgICAgICAgICAgICAgICAg", TenantID: m.TenantID, UserID: m.UserID, ActorID: "actor-a", ActorKind: authorization.SubjectServiceAccount, OperationID: op.OperationID, PolicyID: "test-phone-recovery", PolicyVersion: 1, SchemaID: op.SchemaID, SchemaVersion: 1, RecordID: "credential-a", CorrelationID: "phone-recovery-fixture"}
	f := identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: []identity.FeatureField{
		{Name: "phone.reset.factor-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: m.FactorID}},
		{Name: "phone.reset.factor-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: m.EnrollmentVersion}},
		{Name: "phone.reset.factor-authority-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: m.FactorAuthorityVersion}},
	}}
	if change != nil {
		change(&f)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	signer, err := capability.NewHMACSHA256Signer("fixture", []byte(strings.Repeat("s", 32)))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := capability.Issue(t.Context(), capability.Payload{Version: 1, Issuer: "https://identity.test", Audiences: []string{"identity"}, Subject: string(m.UserID), Resource: "test-only", Operation: op.OperationID, IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(time.Minute), ID: "structural-fixture", Tenant: string(m.TenantID), MaxUses: 1}, signer, capability.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := capability.ParseProof(wire, capability.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	sms, _ := auth.NewOneTimeCode("123456")
	factor, err := auth.NewOneTimeCode(code)
	if err != nil {
		t.Fatal(err)
	}
	var c identity.Command
	if input {
		secret, secretErr := password.NewSecret([]byte("fixture replacement password"))
		if secretErr != nil {
			t.Fatal(secretErr)
		}
		t.Cleanup(secret.Destroy)
		c, err = identity.NewFeaturePhonePasswordResetInputCommand(f, secret, proof, sms, factor)
	} else {
		c, err = identity.NewFeaturePhonePasswordResetCommand(f, "$fixture$replacement", proof, sms, factor)
	}
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestPhoneRecoveryTOTPPreparationOwnsTerminalSecretAndExactOriginalFactor(t *testing.T) {
	v, snapshot := phoneRecoveryFixture(t)
	m, _ := snapshot.Metadata()
	until := time.Now().UTC().Truncate(time.Microsecond).Add(time.Minute)
	for _, input := range []bool{true, false} {
		c := phoneRecoveryTestCommand(t, m, input, "94287082", nil)
		prepared, err := v.Prepare(t.Context(), snapshot, c, until)
		if err != nil {
			t.Fatal("exact encrypted preparation denied", err)
		}
		alias := prepared
		use, err := prepared.borrow()
		if err != nil || use.secret.Len() != 20 || use.command != c || use.input != input {
			t.Fatal("owned preparation changed")
		}
		if _, err := alias.borrow(); err == nil {
			t.Fatal("concurrent alias borrowed the same secret")
		}
		retained := use.secret
		use.finish()
		alias.Destroy()
		if retained.Len() != 0 {
			t.Fatal("moved plaintext survived terminal cleanup")
		}
		if _, err := prepared.borrow(); err == nil {
			t.Fatal("retired preparation resurrected")
		}
	}
	for _, change := range []func(*identity.FeatureCommandSpec){
		func(f *identity.FeatureCommandSpec) { f.Binding.UserID = "foreign-user" },
		func(f *identity.FeatureCommandSpec) { f.Binding.TenantID = "foreign-tenant" },
		func(f *identity.FeatureCommandSpec) { f.Fields[0].Value.Text = "AAAAAAAAAAAAAAAAAAAAAg" },
		func(f *identity.FeatureCommandSpec) { f.Fields[1].Value.Uint64++ },
		func(f *identity.FeatureCommandSpec) { f.Fields[2].Value.Uint64++ },
		func(f *identity.FeatureCommandSpec) { f.Fields = f.Fields[:2] },
		func(f *identity.FeatureCommandSpec) {
			f.Fields = append(f.Fields, identity.FeatureField{Name: "phone.reset.factor-accepted", Value: identity.FeatureValue{Kind: identity.FeatureBool, Bool: true}})
		},
	} {
		c := phoneRecoveryTestCommand(t, m, true, "94287082", change)
		if p, err := v.Prepare(t.Context(), snapshot, c, until); err == nil {
			p.Destroy()
			t.Fatal("foreign/missing/scalar factor authority accepted")
		}
	}
	c := phoneRecoveryTestCommand(t, m, true, "94287082", nil)
	for _, change := range []func(*totpFactorCustody){
		func(f *totpFactorCustody) { f.metadata.ContinuationID = "ordinary-login" },
		func(f *totpFactorCustody) { f.metadata.EnrollmentVersion++ },
		func(f *totpFactorCustody) { f.metadata.Profile.Issuer = "Different" },
		func(f *totpFactorCustody) { f.wire = append([]byte(nil), f.wire...); f.wire[len(f.wire)-1] ^= 1 },
	} {
		f := snapshot.custody()
		change(&f)
		bad := TOTPFactorSnapshot{custody: func() totpFactorCustody { return f }}
		if p, err := v.Prepare(t.Context(), bad, c, until); err == nil {
			p.Destroy()
			t.Fatal("mixed encrypted factor accepted")
		}
	}
	if p, err := v.Prepare(t.Context(), snapshot, c, time.Now().UTC().Truncate(time.Microsecond).Add(-time.Second)); err == nil {
		p.Destroy()
		t.Fatal("expired preparation accepted")
	}
	for _, value := range []any{v, PreparedPhoneRecoveryTOTP{}, PhoneRecoveryTOTPAttempt{}, PhoneRecoveryTOTPCompletion{}} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
			if !strings.Contains(fmt.Sprintf(verb, value), "redacted") {
				t.Fatal("custody diagnostic not redacted")
			}
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("custody serialized")
		}
	}
}

func TestPhoneRecoveryTOTPFailureClearsPreparedSecret(t *testing.T) {
	v, snapshot := phoneRecoveryFixture(t)
	m, _ := snapshot.Metadata()
	for _, input := range []bool{true, false} {
		c := phoneRecoveryTestCommand(t, m, input, "94287082", nil)
		p, err := v.Prepare(t.Context(), snapshot, c, time.Now().UTC().Truncate(time.Microsecond).Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		secret := p.custody().secret
		if input {
			_, err = VerifyPhoneRecoveryTOTPAttempt(t.Context(), kernel.OTPAttemptWork{}, nil, p)
		} else {
			_, err = VerifyAndRecordPhoneRecoveryTOTP(t.Context(), kernel.Work{}, nil, c, p)
		}
		if err == nil || secret.Len() != 0 {
			t.Fatal("failed native ownership check retained secret")
		}
		p.Destroy()
	}
}

func TestPhoneRecoveryTOTPSecretMoveReleasesLockBeforeWork(t *testing.T) {
	v, snapshot := phoneRecoveryFixture(t)
	m, _ := snapshot.Metadata()
	p, err := v.Prepare(t.Context(), snapshot, phoneRecoveryTestCommand(t, m, true, "94287082", nil), time.Now().UTC().Truncate(time.Microsecond).Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	use, err := p.borrow()
	if err != nil {
		t.Fatal(err)
	}
	s := p.custody()
	if !s.mu.TryLock() {
		use.finish()
		t.Fatal("custody lock retained across native SQL lifetime")
	}
	s.mu.Unlock()
	retained := use.secret
	destroyed := make(chan struct{})
	go func() { p.Destroy(); close(destroyed) }()
	use.finish()
	select {
	case <-destroyed:
	case <-time.After(time.Second):
		t.Fatal("Destroy did not join bounded secret use")
	}
	if retained.Len() != 0 {
		t.Fatal("Destroy returned with plaintext still live")
	}
}

// This is the exact sealed-custody guard, not nonzero Work, code verification
// or a successful recovery. It must use the same guard as the native callback.
func TestPhoneRecoveryTOTPAttemptCommandRequiresExactSealedVariant(t *testing.T) {
	v, snapshot := phoneRecoveryFixture(t)
	m, _ := snapshot.Metadata()
	for _, input := range []bool{true, false} {
		name := "generated"
		if input {
			name = "input"
		}
		t.Run(name, func(t *testing.T) {
			command := phoneRecoveryTestCommand(t, m, input, "94287082", nil)
			prepared, err := v.Prepare(t.Context(), snapshot, command, time.Now().UTC().Truncate(time.Microsecond).Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			defer prepared.Destroy()
			use, err := prepared.borrow()
			if err != nil {
				t.Fatal(err)
			}
			defer use.finish()
			spec, _ := command.PhonePasswordResetFeature()
			if input {
				spec, _ = command.PhonePasswordResetInputFeature()
			}
			if err := requirePhoneRecoveryTOTPAttemptCommand(command, spec.Binding, use); err != nil {
				t.Errorf("exact %s sealed custody denied: %v", name, err)
			}
			if _, ok := command.Feature(); ok {
				t.Fatal("joint custody downgraded to ordinary feature")
			}
			if _, ok := command.OneTimeCode(); ok {
				t.Fatal("joint custody downgraded to one-code command")
			}

			var reconstructed identity.Command
			if input {
				secret, proof, sms, totp, _ := command.PhonePasswordResetInputCustody()
				reconstructed, err = identity.NewFeaturePhonePasswordResetInputCommand(spec, secret, proof, sms, totp)
			} else {
				hash, proof, sms, totp, _ := command.PhonePasswordResetCustody()
				reconstructed, err = identity.NewFeaturePhonePasswordResetCommand(spec, hash, proof, sms, totp)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := requirePhoneRecoveryTOTPAttemptCommand(reconstructed, spec.Binding, use); err == nil {
				t.Fatal("reconstructed command replaced original pointer custody")
			}
			foreign := spec.Binding
			foreign.CommandID = "BwcHBwcHBwcHBwcHBwcHBw"
			if err := requirePhoneRecoveryTOTPAttemptCommand(command, foreign, use); err == nil {
				t.Fatal("foreign live binding accepted")
			}
			mixed := *use
			mixed.input = !use.input
			if err := requirePhoneRecoveryTOTPAttemptCommand(command, spec.Binding, &mixed); err == nil {
				t.Fatal("mixed preparation variant accepted")
			}
			factor := snapshot.custody()
			factor.metadata.EnrollmentVersion++
			mixed = *use
			mixed.snapshot = TOTPFactorSnapshot{custody: func() totpFactorCustody { return factor }}
			if err := requirePhoneRecoveryTOTPAttemptCommand(command, spec.Binding, &mixed); err == nil {
				t.Fatal("foreign factor generation accepted")
			}
			generic, err := identity.NewFeatureCommand(spec)
			if err != nil {
				t.Fatal(err)
			}
			mixed = *use
			mixed.command = generic
			if err := requirePhoneRecoveryTOTPAttemptCommand(generic, spec.Binding, &mixed); err == nil {
				t.Fatal("generic metadata became sealed recovery custody")
			}
			if err := requirePhoneRecoveryTOTPAttemptCommand(identity.Command{}, spec.Binding, use); err == nil {
				t.Fatal("zero command accepted")
			}
			if err := requirePhoneRecoveryTOTPAttemptCommand(command, spec.Binding, nil); err == nil {
				t.Fatal("missing prepared custody accepted")
			}
		})
	}
}
