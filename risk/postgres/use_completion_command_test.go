package postgres

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	primitive "github.com/faustbrian/go-password/v2"
)

type completionUsePreparer interface {
	PreparePhoneResetCompletionEvidenceUse(identity.Command, risk.PhoneEvidenceRequest, risk.EvidenceUse) (identity.Command, identitypostgres.RiskEvidencePlan, error)
}

func rebuildCompletionUseForTest(t *testing.T, original identity.Command, spec identity.FeatureCommandSpec) identity.Command {
	t.Helper()
	var rebuilt identity.Command
	var err error
	if password, proof, sms, totp, input := original.PhonePasswordResetInputCustody(); input {
		rebuilt, err = identity.NewFeaturePhonePasswordResetInputCommand(spec, password, proof, sms, totp)
	} else if hash, proof, sms, totp, generated := original.PhonePasswordResetCustody(); generated {
		rebuilt, err = identity.NewFeaturePhonePasswordResetCommand(spec, hash, proof, sms, totp)
	} else {
		t.Fatal("test requires compound command")
	}
	if err != nil {
		t.Fatal("invalid tampering fixture", err)
	}
	cookie, ok := original.PhonePasswordResetPreAuthCookie()
	if !ok {
		t.Fatal("test requires original cookie")
	}
	rebuilt, err = identity.BindPhonePasswordResetPreAuth(rebuilt, cookie)
	if err != nil {
		t.Fatal(err)
	}
	return rebuilt
}

// These are structural custody fixtures, never an authenticated reset grant,
// current phone/factor authority or proof of PostgreSQL commitment.
func completionUseCommands(t *testing.T, binding identity.CommandBinding) (identity.Command, identity.Command, primitive.Secret, capability.Proof, string, auth.OneTimeCode, auth.OneTimeCode) {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	signer, err := capability.NewHMACSHA256Signer("test-key", key)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	wire, err := capability.Issue(t.Context(), capability.Payload{Version: 1, Issuer: "https://issuer.example", Audiences: []string{"identity"}, Subject: string(binding.UserID), Resource: "identity.password/credential", Operation: "identity.password.reset-complete", IssuedAt: at, NotBefore: at, ExpiresAt: at.Add(time.Minute), ID: "test-reset", Tenant: string(binding.TenantID), MaxUses: 1}, signer, capability.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := capability.ParseProof(wire, capability.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	passwordBytes := make([]byte, 32)
	if _, err := rand.Read(passwordBytes); err != nil {
		t.Fatal(err)
	}
	password, err := primitive.NewSecret(passwordBytes)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(password.Destroy)
	sms, _ := auth.NewOneTimeCode("123456")
	totp, _ := auth.NewOneTimeCode("654321")
	op := identity.FeatureOperation{Owner: "identity/phone", OperationID: "identity.phone.password-reset-complete", SchemaID: "identity.phone.password-reset-complete.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	spec := identity.FeatureCommandSpec{Binding: binding, Operation: op, Fields: []identity.FeatureField{textField("phone.mode", "reset")}}
	input, err := identity.NewFeaturePhonePasswordResetInputCommand(spec, password, proof, sms, totp)
	if err != nil {
		t.Fatal(err)
	}
	generated, err := identity.NewFeaturePhonePasswordResetCommand(spec, "synthetic-replacement-verifier", proof, sms, totp)
	if err != nil {
		t.Fatal(err)
	}
	cookieBytes := make([]byte, 32)
	if _, err := rand.Read(cookieBytes); err != nil {
		t.Fatal(err)
	}
	cookie := auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(cookieBytes))
	input, err = identity.BindPhonePasswordResetPreAuth(input, cookie)
	if err != nil {
		t.Fatal(err)
	}
	generated, err = identity.BindPhonePasswordResetPreAuth(generated, cookie)
	if err != nil {
		t.Fatal(err)
	}
	return input, generated, password, proof, wire, sms, totp
}

func completionUseFixture(t *testing.T) (*Repository, risk.PhoneEvidenceRequest, risk.EvidenceUse, identity.CommandBinding) {
	t.Helper()
	issue, key := evaluatedIssue(t, risk.PhoneResetCompletion)
	at := issue.Prepared().PreparedAt
	record, err := issue.Materialize(at)
	if err != nil {
		t.Fatal(err)
	}
	issuer, original, _ := issuanceFixture(t, risk.PhoneResetCompletion, at.Add(time.Nanosecond), issue.Prepared().Binding.CommandID, captureExecutor{}, true, nil)
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	use, err := issuer.PrecheckUse(t.Context(), original, risk.EvidenceUseRequest{CommandID: string(id), Actor: "phone-service", Recovery: original.Recovery, Reference: record.Reference}, record)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewRepository(Config{Schema: "risk_store", PolicyVersion: 3, EvidenceKeys: []risk.EvidenceKey{key}, EnvelopeKeys: map[string][]byte{"wrapping_v1": wrappingKey(1)}, CurrentEnvelopeKey: "wrapping_v1", UseIssuer: &issuer})
	if err != nil {
		t.Fatal(err)
	}
	binding := identity.CommandBinding{CommandID: id, TenantID: "tenant", UserID: "subject", ActorID: "phone-service", ActorKind: authorization.SubjectServiceAccount, OperationID: "identity.phone.password-reset-complete", SchemaID: "identity.phone.password-reset-complete.native-v1", SchemaVersion: 1, PolicyID: "phone-policy", PolicyVersion: 1, RecordID: "phone-record", CorrelationID: string(id)}
	return r, original, use, binding
}

func TestNativeCompletionUsePreparationPreservesConjunctiveCustody(t *testing.T) {
	r, original, use, binding := completionUseFixture(t)
	preparer, ok := any(r).(completionUsePreparer)
	if !ok {
		t.Fatal("native risk owner cannot prepare sealed completion custody")
	}
	input, generated, password, proof, wire, sms, totp := completionUseCommands(t, binding)
	var mappedCommands []identity.Command
	for _, before := range []identity.Command{input, generated} {
		mapped, plan, err := preparer.PreparePhoneResetCompletionEvidenceUse(before, original, use)
		if err != nil || plan != nativeUsePlan(use.Prepared()) || r.ValidateRiskEvidenceCommand(mapped, plan) != nil {
			t.Fatal("authentic completion scope rejected or renewed", err)
		}
		mappedCommands = append(mappedCommands, mapped)
		_, wasInput := before.PhonePasswordResetInputFeature()
		_, isInput := mapped.PhonePasswordResetInputFeature()
		if wasInput != isInput {
			t.Fatal("completion mapping changed input/generated variant")
		}
		var gotProof capability.Proof
		var gotSMS, gotTOTP auth.OneTimeCode
		if wasInput {
			var gotPassword primitive.Secret
			gotPassword, gotProof, gotSMS, gotTOTP, ok = mapped.PhonePasswordResetInputCustody()
			if !ok {
				t.Fatal("input custody missing")
			}
			var expected []byte
			if err := password.Use(func(raw []byte) error {
				expected = bytes.Clone(raw)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err := gotPassword.Use(func(actual []byte) error {
				if !bytes.Equal(expected, actual) {
					t.Fatal("original password changed")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			clear(expected)
		} else {
			var hash string
			hash, gotProof, gotSMS, gotTOTP, ok = mapped.PhonePasswordResetCustody()
			if !ok || hash != "synthetic-replacement-verifier" {
				t.Fatal("replacement verifier changed")
			}
		}
		for _, pair := range [][2]auth.OneTimeCode{{sms, gotSMS}, {totp, gotTOTP}} {
			want, _ := pair[0].CommandDigest([32]byte{1}, "test")
			got, err := pair[1].CommandDigest([32]byte{1}, "test")
			if err != nil || want != got {
				t.Fatal("independent code omitted or swapped")
			}
		}
		cookieBefore, _ := before.PhonePasswordResetPreAuthCookie()
		cookieAfter, present := mapped.PhonePasswordResetPreAuthCookie()
		if !present || cookieAfter.Token() != cookieBefore.Token() {
			t.Fatal("original browser custody omitted or replaced")
		}
		if _, generic := mapped.Feature(); generic {
			t.Fatal("completion downgraded to generic feature")
		}
		if _, single := mapped.OneTimeCode(); single {
			t.Fatal("completion downgraded to single factor")
		}
		if _, legacy := mapped.PreAuthCookie(); legacy {
			t.Fatal("completion downgraded browser custody")
		}
		for _, format := range []string{"%v", "%+v", "%#v"} {
			for _, sensitive := range []string{wire, cookieBefore.Token(), "synthetic-replacement-verifier", original.Recovery.Binding.CanonicalNumber} {
				if strings.Contains(fmt.Sprintf(format, mapped), sensitive) {
					t.Fatal("completion diagnostics expose custody")
				}
			}
		}
		if _, err := json.Marshal(mapped); err == nil {
			t.Fatal("completion custody serialized")
		}
		if _, _, err := preparer.PreparePhoneResetCompletionEvidenceUse(mapped, original, use); err == nil {
			t.Fatal("risk scope attached twice")
		}
		if err := gotProof.ValidateBounds(32, 4096); err != nil {
			t.Fatal("original proof lost")
		}
	}
	password.Destroy()
	mappedPassword, _, _, _, _ := mappedCommands[0].PhonePasswordResetInputCustody()
	if err := mappedPassword.Use(func([]byte) error { return nil }); err == nil {
		t.Fatal("mapping duplicated terminal password ownership")
	}
	// The mapping must share terminal proof ownership, never parse a new proof.
	if err := proof.Transfer(context.Background(), func(_ context.Context, actual []byte) error {
		if string(actual) != wire {
			t.Fatal("original canonical proof changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_, mappedProof, _, _, _ := mappedCommands[1].PhonePasswordResetCustody()
	if mappedProof.ValidateBounds(32, 4096) == nil {
		t.Fatal("mapping duplicated terminal proof ownership")
	}
}

func TestNativeCompletionUsePreparationRejectsSubstitutionAndMetadataOnlyInput(t *testing.T) {
	r, original, use, binding := completionUseFixture(t)
	preparer, ok := any(r).(completionUsePreparer)
	if !ok {
		t.Fatal("native risk owner cannot prepare sealed completion custody")
	}
	input, generated, password, proof, _, sms, totp := completionUseCommands(t, binding)
	spec, _ := input.PhonePasswordResetInputFeature()
	plain, err := identity.NewFeatureCommand(spec)
	if err != nil {
		t.Fatal(err)
	}
	unbound, err := identity.NewFeaturePhonePasswordResetInputCommand(spec, password, proof, sms, totp)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []identity.Command{{}, plain, unbound} {
		if c, p, err := preparer.PreparePhoneResetCompletionEvidenceUse(bad, original, use); err == nil || c != (identity.Command{}) || p != (identitypostgres.RiskEvidencePlan{}) {
			t.Fatal("metadata-only or missing browser custody admitted")
		}
	}
	for _, before := range []identity.Command{input, generated} {
		for _, change := range []func(*risk.PhoneEvidenceRequest){
			func(r *risk.PhoneEvidenceRequest) { r.Recovery.Phase = risk.PhoneResetInitiation },
			func(r *risk.PhoneEvidenceRequest) {
				r.Recovery.Binding.RecoveryOperation = "identity.phone.password-reset-request"
			},
			func(r *risk.PhoneEvidenceRequest) { r.Recovery.Binding.CanonicalNumber += "1" },
			func(r *risk.PhoneEvidenceRequest) { r.Recovery.Binding.PreAuthTransaction += "x" },
			func(r *risk.PhoneEvidenceRequest) { r.Recovery.Binding.Attempt += "x" },
			func(r *risk.PhoneEvidenceRequest) { r.Subject.Network = "2001:db8::2" },
			func(r *risk.PhoneEvidenceRequest) { r.Subject.Device += "x" },
			func(r *risk.PhoneEvidenceRequest) { r.Subject.IdentifierDigest = strings.Repeat("b", 64) },
		} {
			foreign := original
			change(&foreign)
			if c, p, err := preparer.PreparePhoneResetCompletionEvidenceUse(before, foreign, use); err == nil || c != (identity.Command{}) || p != (identitypostgres.RiskEvidencePlan{}) {
				t.Fatal("foreign signed completion scope admitted")
			}
		}
		if _, _, err := preparer.PreparePhoneResetCompletionEvidenceUse(before, original, risk.EvidenceUse{}); err == nil {
			t.Fatal("zero completion use admitted")
		}
		mapped, plan, err := preparer.PreparePhoneResetCompletionEvidenceUse(before, original, use)
		if err != nil {
			t.Fatal(err)
		}
		metadata, input := mapped.PhonePasswordResetInputFeature()
		if !input {
			metadata, _ = mapped.PhonePasswordResetFeature()
		}
		for i, field := range metadata.Fields {
			if field.Name == "phone.mode" {
				continue
			}
			changed := metadata
			changed.Fields = append([]identity.FeatureField(nil), metadata.Fields...)
			if field.Value.Kind == identity.FeatureText {
				changed.Fields[i].Value.Text += "x"
			} else {
				changed.Fields[i].Value.Bytes = bytes.Clone(field.Value.Bytes)
				changed.Fields[i].Value.Bytes[0] ^= 1
			}
			if r.ValidateRiskEvidenceCommand(rebuildCompletionUseForTest(t, mapped, changed), plan) == nil {
				t.Fatal("altered compound signed scope admitted", field.Name)
			}
			changed.Fields = append(append([]identity.FeatureField(nil), metadata.Fields[:i]...), metadata.Fields[i+1:]...)
			if r.ValidateRiskEvidenceCommand(rebuildCompletionUseForTest(t, mapped, changed), plan) == nil {
				t.Fatal("missing compound signed scope admitted", field.Name)
			}
		}
		unknown := metadata
		unknown.Fields = append(append([]identity.FeatureField(nil), metadata.Fields...), textField("risk.use.extra", "unexpected"))
		if r.ValidateRiskEvidenceCommand(rebuildCompletionUseForTest(t, mapped, unknown), plan) == nil {
			t.Fatal("unknown compound risk scope admitted")
		}
		plan.CheckedAt = plan.CheckedAt.Add(time.Nanosecond)
		if r.ValidateRiskEvidenceCommand(mapped, plan) == nil {
			t.Fatal("signed precheck freshness renewed")
		}
	}
}
