package postgres

import (
	"bytes"
	"encoding/base64"
	"testing"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
)

func TestRecoveryClaimBindsOriginalCodeAndBrowser(t *testing.T) {
	spec := featureCodecSpec()
	key := [32]byte{9}
	wire := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32))
	makeCommand := func(value, cookie string) identity.Command {
		code, _ := auth.NewRecoveryCode(value)
		command, err := identity.NewFeatureRecoveryCodePreAuthCommand(spec, code, auth.NewBearerCredential(cookie))
		if err != nil {
			t.Fatal(err)
		}
		return command
	}
	const original = "synthetic-original-recovery-code"
	first, err := prepareClaim(makeCommand(original, wire), key)
	if err != nil {
		t.Fatal(err)
	}
	for _, changed := range []identity.Command{
		makeCommand("synthetic-changed-recovery-code", wire),
		makeCommand(original, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32))),
	} {
		next, err := prepareClaim(changed, key)
		if err != nil || bytes.Equal(next.canonical, first.canonical) {
			t.Fatal("different recovery input shares original claim")
		}
	}
	code, _ := auth.NewOneTimeCode(original)
	otp, err := identity.NewFeatureOneTimeCodePreAuthCommand(spec, code, auth.NewBearerCredential(wire))
	if err != nil {
		t.Fatal(err)
	}
	other, err := prepareClaim(otp, key)
	if err != nil || bytes.Equal(other.canonical, first.canonical) {
		t.Fatal("recovery input relabelled as OTP")
	}
	for _, data := range [][]byte{first.canonical, first.safeFields} {
		if bytes.Contains(data, []byte(original)) || bytes.Contains(data, []byte(wire)) {
			t.Fatal("claim leaks original recovery or browser material")
		}
	}
}

func TestRecoveryCustodyCannotEnterOrdinaryReservation(t *testing.T) {
	c, plain, plan := featurePlanFixture(t)
	spec, _ := plain.Feature()
	if _, err := c.PrepareCommandPlan(spec.Binding, plain, plan); err != nil {
		t.Fatal("ordinary feature baseline unavailable", err)
	}
	code, _ := auth.NewRecoveryCode("synthetic-original-recovery-code")
	command, err := identity.NewFeatureRecoveryCodePreAuthCommand(spec, code, auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32))))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.PrepareCommandPlan(spec.Binding, command, plan); err == nil {
		t.Fatal("ordinary feature discards protected recovery custody")
	}
}
