package postgres

import (
	"bytes"
	"context"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	primitive "github.com/faustbrian/go-password/v2"
)

func phoneResetCodecSpec() identity.FeatureCommandSpec {
	s := passwordResetCodecSpec()
	s.Operation = identity.FeatureOperation{Owner: "identity/phone", OperationID: "identity.phone.password-reset-complete", SchemaID: "identity.phone.password-reset-complete.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	s.Binding.OperationID, s.Binding.SchemaID = s.Operation.OperationID, s.Operation.SchemaID
	return s
}

func TestPhoneResetCanonicalIntentBindsEveryOriginalInput(t *testing.T) {
	proof, wire := passwordResetCodecProof(t, 1)
	secret, _ := primitive.NewSecret([]byte("original-phone-password"))
	defer secret.Destroy()
	other, _ := primitive.NewSecret([]byte("different-phone-password"))
	defer other.Destroy()
	code, _ := auth.NewOneTimeCode("123456")
	factor, _ := auth.NewOneTimeCode("654321")
	changed, _ := auth.NewOneTimeCode("234567")
	original, err := identity.NewFeaturePhonePasswordResetInputCommand(phoneResetCodecSpec(), secret, proof, code, factor)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := prepareClaim(original, [32]byte{1})
	if err != nil {
		t.Fatal("joint phone reset original input cannot be bound", err)
	}
	for _, sensitive := range []string{"original-phone-password", wire, "123456", "654321"} {
		if bytes.Contains(claim.canonical, []byte(sensitive)) || bytes.Contains(claim.safeFields, []byte(sensitive)) {
			t.Fatal("original secret entered journal scope")
		}
	}
	for _, variant := range []struct {
		password    primitive.Secret
		phone, totp auth.OneTimeCode
	}{
		{other, code, factor}, {secret, changed, factor}, {secret, code, changed}, {secret, factor, code},
	} {
		command, err := identity.NewFeaturePhonePasswordResetInputCommand(phoneResetCodecSpec(), variant.password, proof, variant.phone, variant.totp)
		if err != nil {
			t.Fatal(err)
		}
		got, err := prepareClaim(command, [32]byte{1})
		if err != nil || bytes.Equal(got.canonical, claim.canonical) || !bytes.Equal(got.safeFields, claim.safeFields) {
			t.Fatal("a changed password/factor reused original command intent", err)
		}
	}
	foreignProof, _ := passwordResetCodecProof(t, 2)
	command, _ := identity.NewFeaturePhonePasswordResetInputCommand(phoneResetCodecSpec(), secret, foreignProof, code, factor)
	got, err := prepareClaim(command, [32]byte{1})
	if err != nil || bytes.Equal(got.canonical, claim.canonical) {
		t.Fatal("changed original capability not bound", err)
	}
	rotated, err := prepareClaim(original, [32]byte{2})
	if err != nil || bytes.Equal(rotated.canonical, claim.canonical) {
		t.Fatal("joint custody digest was not keyed", err)
	}
	generated, err := identity.NewFeaturePhonePasswordResetCommand(phoneResetCodecSpec(), "synthetic-hash", proof, code, factor)
	if err != nil {
		t.Fatal(err)
	}
	final, err := prepareClaim(generated, [32]byte{1})
	if err != nil || bytes.Equal(final.canonical, claim.canonical) || bytes.Contains(final.canonical, []byte("synthetic-hash")) {
		t.Fatal("generated hash omitted or substituted original input domain", err)
	}
	changedFinal, _ := identity.NewFeaturePhonePasswordResetCommand(phoneResetCodecSpec(), "changed-synthetic-hash", proof, code, factor)
	different, err := prepareClaim(changedFinal, [32]byte{1})
	if err != nil || bytes.Equal(final.canonical, different.canonical) {
		t.Fatal("changed final verifier not bound", err)
	}
	for _, v := range []struct{ phone, totp auth.OneTimeCode }{{changed, factor}, {code, changed}, {factor, code}} {
		command, err := identity.NewFeaturePhonePasswordResetCommand(phoneResetCodecSpec(), "synthetic-hash", proof, v.phone, v.totp)
		if err != nil {
			t.Fatal(err)
		}
		got, err := prepareClaim(command, [32]byte{1})
		if err != nil || bytes.Equal(got.canonical, final.canonical) {
			t.Fatal("final command lost or swapped factor intent", err)
		}
	}
	command, _ = identity.NewFeaturePhonePasswordResetCommand(phoneResetCodecSpec(), "synthetic-hash", foreignProof, code, factor)
	got, err = prepareClaim(command, [32]byte{1})
	if err != nil || bytes.Equal(got.canonical, final.canonical) {
		t.Fatal("final command lost original capability intent", err)
	}
	if err := proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareClaim(original, [32]byte{1}); err == nil {
		t.Fatal("transferred proof was resurrected during original fingerprinting")
	}
	if _, err := prepareClaim(generated, [32]byte{1}); err == nil {
		t.Fatal("transferred proof was resurrected during final fingerprinting")
	}
}

func TestPhoneResetPlainMetadataAndGenericExecutionCannotOmitFactors(t *testing.T) {
	spec := phoneResetCodecSpec()
	plain, err := identity.NewFeatureCommand(spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepareClaim(plain, [32]byte{1}); err == nil {
		t.Fatal("plain metadata silently discarded required joint custody")
	}
	proof, _ := passwordResetCodecProof(t, 1)
	secret, _ := primitive.NewSecret([]byte("synthetic"))
	defer secret.Destroy()
	code, _ := auth.NewOneTimeCode("123456")
	input, _ := identity.NewFeaturePhonePasswordResetInputCommand(spec, secret, proof, code, code)
	generated, _ := identity.NewFeaturePhonePasswordResetCommand(spec, "synthetic", proof, code, code)
	coordinator, _, plan := coordinatorFixture(t)
	for _, c := range []identity.Command{input, generated} {
		prepared, err := coordinator.PrepareCommandPlan(spec.Binding, c, plan)
		if err == nil || prepared.Digest != ([32]byte{}) {
			t.Fatal("generic reservation admitted incomplete compound recovery")
		}
	}
}
