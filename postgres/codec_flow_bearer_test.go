package postgres

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
)

func TestFlowBearerOnlyBindsOriginalCommandIntent(t *testing.T) {
	spec := featureCodecSpec()
	wire := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x71}, 32))
	key := [32]byte{1}
	plainCommand, _ := identity.NewFeatureCommand(spec)
	plain, err := prepareClaim(plainCommand, key)
	if err != nil {
		t.Fatal(err)
	}
	var cookieCanonical []byte
	for _, session := range []bool{false, true} {
		construct, domain := identity.NewFeaturePreAuthCommand, "pre-auth-cookie"
		if session {
			construct, domain = identity.NewFeatureSessionCommand, "session-token"
		}
		command, err := construct(spec, auth.NewBearerCredential(wire))
		if err != nil {
			t.Fatal(err)
		}
		bound, err := prepareClaim(command, key)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(bound.canonical, plain.canonical) || !bytes.Equal(bound.safeFields, plain.safeFields) || bytes.Contains(bound.canonical, []byte(wire)) || bytes.Contains(bound.canonical, []byte("one_time_code")) {
			t.Fatal("bearer omitted, disclosed or became OTP")
		}
		mac := hmac.New(sha256.New, key[:])
		mac.Write([]byte("identity-command-secret-v1"))
		mac.Write(binary.BigEndian.AppendUint32(nil, uint32(len(domain))))
		mac.Write([]byte(domain))
		mac.Write(binary.BigEndian.AppendUint64(nil, uint64(len(wire))))
		mac.Write([]byte(wire))
		if !bytes.Contains(bound.canonical, mac.Sum(nil)) {
			t.Fatal("original named bearer digest absent")
		}
		if session {
			if bytes.Equal(bound.canonical, cookieCanonical) {
				t.Fatal("contexts aliased")
			}
		} else {
			cookieCanonical = bytes.Clone(bound.canonical)
		}
		otherWire := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x72}, 32))
		other, _ := construct(spec, auth.NewBearerCredential(otherWire))
		changed, err := prepareClaim(other, key)
		if err != nil || bytes.Equal(bound.canonical, changed.canonical) {
			t.Fatal("bearer substitution shared intent")
		}
		rotated, err := prepareClaim(command, [32]byte{2})
		if err != nil || rotated.source == nil {
			t.Fatal("original custody lost")
		}
		retained, err := prepareClaim(*rotated.source, key)
		if err != nil || !bytes.Equal(retained.canonical, bound.canonical) {
			t.Fatal("retained-key replay renewed intent")
		}
	}
}

func TestFlowBearerOnlyCannotEnterOTPAttemptOrReservation(t *testing.T) {
	owner := &otpReservationProbe{}
	coordinator, original, plan := otpAttemptFixture(t, owner)
	spec, _ := original.Feature()
	wire := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x73}, 32))
	for _, construct := range []func(identity.FeatureCommandSpec, auth.BearerCredential) (identity.Command, error){identity.NewFeaturePreAuthCommand, identity.NewFeatureSessionCommand} {
		command, err := construct(spec, auth.NewBearerCredential(wire))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := coordinator.PrepareOTPAttemptPlan(spec.Binding, command, plan); err == nil {
			t.Fatal("no-code custody admitted a comparison")
		}
		if _, err := coordinator.PrepareOTPReservationPlan(spec.Binding, command, plan); err == nil {
			t.Fatal("no-code custody admitted consumption")
		}
	}
}
