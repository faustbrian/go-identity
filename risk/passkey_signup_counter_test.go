package risk

import (
	"bytes"
	"reflect"
	"testing"
	"time"
)

func TestPasskeySignupCountersPreserveProtectedPolicyAndActualDimensions(t *testing.T) {
	key, _ := NewCounterDigestKey(1, bytes.Repeat([]byte{73}, 32))
	policy, err := NewCommandCounterPolicy(CommandCounterPolicyConfig{Policy: testPolicy(t), Keys: []CounterDigestKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	now := testContext().Now.UTC().Truncate(time.Microsecond)
	subject := Subject{Network: "127.0.0.1", Device: "signup-browser"}
	for _, action := range []Action{"identity.passkey.register-options", "identity.passkey.register-verify"} {
		scope := Context{Tenant: "tenant", Operation: action, Attempt: "signup-one"}
		command, err := policy.PreparePasskeySignup(scope, subject, "original-browser", now)
		if err != nil {
			t.Fatal("original anonymous signup counters missing", err)
		}
		b := command.Bindings()
		if b.Limit != 5 || b.Window != 15*time.Minute || b.Phase != ReserveWithCommand || command.state.profile.ThresholdAction != Deny || command.state.profile.Unknown != DenyUnknown || !reflect.DeepEqual(command.state.profile.RequiredSignals, []string{"status", "captcha"}) {
			t.Fatal("signup changed protected registration policy")
		}
		if len(b.Targets) != 4 || b.Targets[0].Dimension != TenantDimension || b.Targets[1].Dimension != BrowserFlowDimension || b.Targets[2].Dimension != NetworkDimension || b.Targets[3].Dimension != DeviceDimension {
			t.Fatal("signup invented account/session dimensions")
		}
		if err := policy.ValidatePasskeySignup(command, scope, subject, "original-browser", now); err != nil {
			t.Fatal(err)
		}
		scope.Attempt = "signup-two"
		second, err := policy.PreparePasskeySignup(scope, subject, "original-browser", now)
		if err != nil || !reflect.DeepEqual(b.Targets, second.Bindings().Targets) || b.Fingerprint == second.Bindings().Fingerprint {
			t.Fatal("new command resets original browser budget", err)
		}
		if policy.ValidatePasskeySignup(command, scope, subject, "original-browser", now) == nil {
			t.Fatal("original attempt retargeted")
		}
		scope.Attempt = "signup-one"
		if policy.Validate(command, scope, subject, now) == nil || policy.ValidateMFALoginSend(command, scope, subject, "original-browser", now) == nil {
			t.Fatal("signup crossed protected profile")
		}
		if policy.ValidatePasskeySignup(command, scope, subject, "other-browser", now) == nil {
			t.Fatal("browser flow substituted")
		}
		changed := subject
		changed.Device = "other-device"
		if policy.ValidatePasskeySignup(command, scope, changed, "original-browser", now) == nil {
			t.Fatal("device substituted")
		}
		a, _ := testPolicy(t).Admit(action)
		if policy.ValidatePasskeySignup(command, scope, subject, "original-browser", now.Add(a.Profile.EvidenceTTL)) == nil {
			t.Fatal("original evidence renewed")
		}
		foreign, _ := NewCommandCounterPolicy(CommandCounterPolicyConfig{Policy: testPolicy(t), Keys: []CounterDigestKey{key}})
		if foreign.ValidatePasskeySignup(command, scope, subject, "original-browser", now) == nil {
			t.Fatal("foreign policy adopted custody")
		}
	}
}

func TestPasskeySignupCounterProjectionIsClosed(t *testing.T) {
	key, _ := NewCounterDigestKey(1, bytes.Repeat([]byte{74}, 32))
	p, _ := NewCommandCounterPolicy(CommandCounterPolicyConfig{Policy: testPolicy(t), Keys: []CounterDigestKey{key}})
	now := testContext().Now.UTC().Truncate(time.Microsecond)
	scope := Context{Tenant: "tenant", Operation: "identity.passkey.register-options", Attempt: "attempt"}
	for _, subject := range []Subject{{Network: "127.0.0.1"}, {Device: "device"}, {Network: "127.0.0.1", Device: "device", User: "invented"}, {Network: "127.0.0.1", Device: "device", Session: "invented"}, {Network: "127.0.0.1", Device: "device", IdentifierDigest: "invented"}, {Network: "127.0.0.0/8", Device: "device"}} {
		if _, err := p.PreparePasskeySignup(scope, subject, "original-browser", now); err == nil {
			t.Fatal("invalid or fabricated signup dimension admitted")
		}
	}
	for _, action := range []Action{"identity.passkey.register", "identity.passkey.signin-options", "identity.passkey.update", "identity.mfa.otp-send"} {
		scope.Operation = action
		if _, err := p.PreparePasskeySignup(scope, Subject{Network: "127.0.0.1", Device: "device"}, "original-browser", now); err == nil {
			t.Fatal("foreign operation admitted signup counters")
		}
	}
	scope.Operation = "identity.passkey.register-options"
	var zero CommandCounterPolicy
	if _, err := zero.PreparePasskeySignup(scope, Subject{Network: "127.0.0.1", Device: "device"}, "original-browser", now); err == nil {
		t.Fatal("zero policy admitted")
	}
}
