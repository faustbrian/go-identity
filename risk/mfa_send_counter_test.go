package risk

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestMFALoginSendCountersProtectOriginalBrowserWithoutSession(t *testing.T) {
	key, _ := NewCounterDigestKey(1, bytes.Repeat([]byte{73}, 32))
	config := CommandCounterPolicyConfig{Policy: testPolicy(t), Keys: []CounterDigestKey{key}}
	policy, err := NewCommandCounterPolicy(config)
	if err != nil {
		t.Fatal(err)
	}
	now := testContext().Now.UTC().Truncate(time.Microsecond)
	scope := Context{Tenant: "tenant", Operation: "identity.mfa.otp-send", Attempt: "send-one"}
	subject := Subject{User: "verified-subject", Network: "127.0.0.1"}
	command, err := policy.PrepareMFALoginSend(scope, subject, "original-browser", now)
	if err != nil {
		t.Fatal("original anonymous MFA send rejected", err)
	}
	b := command.Bindings()
	if b.Limit != 5 || b.Window != 15*time.Minute || b.Phase != ReserveWithCommand || len(b.Targets) != 4 || b.Targets[2].Dimension != BrowserFlowDimension {
		t.Fatal("MFA send changed canonical limits or browser dimension")
	}
	if err := policy.ValidateMFALoginSend(command, scope, subject, "original-browser", now); err != nil {
		t.Fatal(err)
	}
	secondScope := scope
	secondScope.Attempt = "send-two"
	second, err := policy.PrepareMFALoginSend(secondScope, subject, "original-browser", now)
	if err != nil || !reflect.DeepEqual(b.Targets, second.Bindings().Targets) || b.Fingerprint == second.Bindings().Fingerprint {
		t.Fatal("new command bypassed original browser budget or shared replay identity")
	}
	other, err := policy.PrepareMFALoginSend(secondScope, subject, "other-browser", now)
	if err != nil || reflect.DeepEqual(b.Targets[2], other.Bindings().Targets[2]) || !reflect.DeepEqual(b.Targets[1], other.Bindings().Targets[1]) {
		t.Fatal("browser budget did not separate flows or account protection")
	}
	for _, target := range b.Targets {
		for _, k := range target.Keys {
			if strings.Contains(k.Encoded, subject.User) || strings.Contains(k.Encoded, subject.Network) || strings.Contains(k.Encoded, "original-browser") {
				t.Fatal("raw counter dimension escaped")
			}
		}
	}
	if policy.Validate(command, scope, subject, now) == nil || policy.ValidateVerification(command, scope, subject, "original-browser", now) == nil || policy.ValidateMFACompletion(command, scope, subject, "original-browser", now) == nil {
		t.Fatal("anonymous send crossed another counter profile")
	}
	foreign, _ := NewCommandCounterPolicy(config)
	if foreign.ValidateMFALoginSend(command, scope, subject, "original-browser", now) == nil || policy.ValidateMFALoginSend(command, secondScope, subject, "original-browser", now) == nil || policy.ValidateMFALoginSend(command, scope, subject, "other-browser", now) == nil {
		t.Fatal("foreign custody or changed attempt/browser adopted original allowance")
	}
	for _, changed := range []Subject{
		{User: "other-subject", Network: subject.Network},
		{User: subject.User, Network: "127.0.0.2"},
	} {
		if policy.ValidateMFALoginSend(command, scope, changed, "original-browser", now) == nil {
			t.Fatal("changed subject/network adopted original allowance")
		}
	}
	foreignTenant := scope
	foreignTenant.Tenant = "other-tenant"
	if policy.ValidateMFALoginSend(command, foreignTenant, subject, "original-browser", now) == nil {
		t.Fatal("foreign tenant adopted original allowance")
	}
	mapped := subject
	mapped.Network = "::ffff:127.0.0.1"
	if policy.ValidateMFALoginSend(command, scope, mapped, "original-browser", now) != nil {
		t.Fatal("equivalent canonical network reset its budget")
	}
	admission, _ := config.Policy.Admit(scope.Operation)
	if policy.ValidateMFALoginSend(command, scope, subject, "original-browser", now.Add(admission.Profile.EvidenceTTL-time.Microsecond)) != nil {
		t.Fatal("unexpired original evidence rejected")
	}
	for _, at := range []time.Time{now.Add(-time.Microsecond), now.Add(admission.Profile.EvidenceTTL)} {
		if policy.ValidateMFALoginSend(command, scope, subject, "original-browser", at) == nil {
			t.Fatal("counter evidence accepted outside original interval")
		}
	}
	invalid := []Subject{
		{Network: subject.Network},
		{User: subject.User},
		{User: subject.User, Network: "127.0.0.0/8"},
		{User: subject.User, Network: subject.Network, Session: "invented-session"},
		{User: subject.User, Network: subject.Network, Device: "unverified-device"},
		{User: subject.User, Network: subject.Network, Actor: "actor"},
		{User: subject.User, Network: subject.Network, Resource: "resource"},
	}
	for _, changed := range invalid {
		if value, err := policy.PrepareMFALoginSend(scope, changed, "original-browser", now); err == nil || value.state != nil {
			t.Fatal("incomplete or fabricated subject accepted")
		}
	}
	for _, browser := range []string{"", "invalid browser", strings.Repeat("b", 257)} {
		if _, err := policy.PrepareMFALoginSend(scope, subject, browser, now); err == nil {
			t.Fatal("invalid browser accepted")
		}
	}
	for _, action := range []Action{"identity.mfa.otp-verify", "identity.mfa.enable", "identity.email.verification-confirm"} {
		changed := scope
		changed.Operation = action
		if _, err := policy.PrepareMFALoginSend(changed, subject, "original-browser", now); err == nil {
			t.Fatal("another operation borrowed anonymous send profile")
		}
	}
	var zero CommandCounterPolicy
	if _, err := zero.PrepareMFALoginSend(scope, subject, "original-browser", now); err == nil || zero.ValidateMFALoginSend(command, scope, subject, "original-browser", now) == nil || policy.ValidateMFALoginSend(CounterCommand{}, scope, subject, "original-browser", now) == nil {
		t.Fatal("zero policy/command admitted anonymous send")
	}
}
