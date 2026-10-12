package identity_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
)

func TestRecoveryFeaturePreservesDistinctOpaqueCustody(t *testing.T) {
	const submitted = "synthetic-recovery-code"
	code, _ := auth.NewRecoveryCode(submitted)
	wire := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	spec := featureCommandSpec()
	command, err := identity.NewFeatureRecoveryCodePreAuthCommand(spec, code, auth.NewBearerCredential(wire))
	if err != nil {
		t.Fatal(err)
	}
	borrowed, ok := command.RecoveryCode()
	if !ok {
		t.Fatal("missing recovery custody")
	}
	want, _ := code.KeyedDigest([32]byte{1}, []byte("original-recovery-input"))
	got, err := borrowed.KeyedDigest([32]byte{1}, []byte("original-recovery-input"))
	if err != nil || got != want {
		t.Fatal("recovery input changed")
	}
	if _, ok := command.OneTimeCode(); ok {
		t.Fatal("recovery code coerced to OTP")
	}
	cookie, ok := command.PreAuthCookie()
	if !ok || cookie.Token() != wire {
		t.Fatal("original browser custody lost")
	}
	projected, ok := command.Feature()
	if !ok || projected.Binding != spec.Binding {
		t.Fatal("recovery scope lost")
	}
	spec.Binding.UserID = "changed"
	projected, _ = command.Feature()
	if projected.Binding.UserID == "changed" {
		t.Fatal("borrowed scope alias")
	}
	for _, rendered := range []string{fmt.Sprintf("%+v", command), fmt.Sprintf("%#v", command)} {
		if strings.Contains(rendered, submitted) || strings.Contains(rendered, wire) {
			t.Fatal("command leaked recovery material")
		}
	}
	if data, err := json.Marshal(command); err == nil && (strings.Contains(string(data), submitted) || strings.Contains(string(data), wire)) {
		t.Fatal("JSON leaked recovery material")
	}
}

func TestRecoveryFeatureRejectsMissingAndForeignCustody(t *testing.T) {
	code, _ := auth.NewRecoveryCode("synthetic-recovery-code")
	wire := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for _, input := range []struct {
		spec   identity.FeatureCommandSpec
		code   auth.RecoveryCode
		cookie auth.BearerCredential
	}{
		{identity.FeatureCommandSpec{}, code, auth.NewBearerCredential(wire)},
		{featureCommandSpec(), auth.RecoveryCode{}, auth.NewBearerCredential(wire)},
		{featureCommandSpec(), code, auth.BearerCredential{}},
		{featureCommandSpec(), code, auth.NewBearerCredential(wire + "=")},
	} {
		command, err := identity.NewFeatureRecoveryCodePreAuthCommand(input.spec, input.code, input.cookie)
		if err == nil {
			t.Fatal("invalid recovery custody admitted")
		}
		if _, ok := command.RecoveryCode(); ok {
			t.Fatal("failed construction retained recovery custody")
		}
	}
	plain, _ := identity.NewFeatureCommand(featureCommandSpec())
	if _, ok := plain.RecoveryCode(); ok {
		t.Fatal("structural command acquired recovery code")
	}
	otp, _ := auth.NewOneTimeCode("123456")
	legacy, _ := identity.NewFeatureOneTimeCodeCommand(featureCommandSpec(), otp)
	if _, ok := legacy.RecoveryCode(); ok {
		t.Fatal("OTP acquired recovery custody")
	}
}
