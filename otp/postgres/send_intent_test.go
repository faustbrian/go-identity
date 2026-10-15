package postgres

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
)

func TestNativeSendInitiationConfigurationAuthenticatesCiphertext(t *testing.T) {
	p, command, binding := initiationFixture(t)
	c := sendInitiationConfig{policyID: "otp-policy", policyVersion: 7, preAuthAction: "identity.otp.signin", intentKey: [32]byte{1}, identifierKey: [32]byte{2}, maximumDuration: time.Second}
	var err error
	p.initiation, err = newSendInitiationProfile(p.send.configuration, c)
	if err != nil {
		t.Fatal(err)
	}
	risk := sendInitiationRisk{network: "192.0.2.8", device: "device", identifierDigest: strings.Repeat("a", 64)}
	wire, err := p.sealSendInitiation(context.Background(), binding, command, risk, false)
	if err != nil {
		t.Fatal(err)
	}
	bearer, _ := command.SessionToken()
	if _, err := p.restoreSendInitiation(context.Background(), binding, wire, bearer); err != nil {
		t.Fatal("matching native configuration lost custody", err)
	}
	fresh := *p
	c.policyVersion++
	fresh.initiation, err = newSendInitiationProfile(p.send.configuration, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.restoreSendInitiation(context.Background(), binding, wire, bearer); err == nil {
		t.Fatal("changed native configuration decrypted original ciphertext")
	}
	fresh.initiation = nil
	if _, err := fresh.restoreSendInitiation(context.Background(), binding, wire, bearer); err == nil {
		t.Fatal("legacy profile decrypted native initiating ciphertext")
	}
}

func TestSendIntentFreezesEveryInitiatingSelection(t *testing.T) {
	p, command, _ := initiationFixture(t)
	config := sendInitiationConfig{policyID: "otp-policy", policyVersion: 7, preAuthAction: "identity.otp.signin", intentKey: [32]byte{1}, identifierKey: [32]byte{2}, maximumDuration: time.Second}
	profile, err := newSendInitiationProfile(p.send.configuration, config)
	if err != nil {
		t.Fatal(err)
	}
	p.initiation = profile
	bearer, _ := command.SessionToken()
	destination, _ := otp.NewDestinationInput("user@example.test")
	input := sendInitiatingRequest{userID: "user", flowKind: otp.FlowAuthorizationAuthenticatedSession, flowID: "session", purpose: otp.PurposeSignin, channel: otp.ChannelEmail, destination: destination, target: "target", network: "192.0.2.8", device: "device"}
	intent, err := p.sendRequestIntent(input, bearer)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := intent.Fields()
	got, err := p.readSendRequestIntent(intent)
	if err != nil || !reflect.DeepEqual(got, input) {
		t.Fatal("closed intent round trip", err)
	}
	for _, f := range want {
		if f.Value.Text == bearer.Token() || bytes.Contains(f.Value.Bytes, []byte(bearer.Token())) {
			t.Fatal("raw bearer escaped custody")
		}
	}
	changes := []func(*sendInitiatingRequest){
		func(r *sendInitiatingRequest) { r.userID = "other" },
		func(r *sendInitiatingRequest) { r.flowID = "other-session" },
		func(r *sendInitiatingRequest) { r.purpose = otp.PurposeStepUp },
		func(r *sendInitiatingRequest) { r.channel = otp.ChannelSMS },
		func(r *sendInitiatingRequest) { r.destination, _ = otp.NewDestinationInput("other@example.test") },
		func(r *sendInitiatingRequest) { r.target = "other-target" },
		func(r *sendInitiatingRequest) { r.network = "192.0.2.9" },
		func(r *sendInitiatingRequest) { r.device = "other-device" },
	}
	for i, change := range changes {
		changed := input
		change(&changed)
		next, err := p.sendRequestIntent(changed, bearer)
		fields, _ := next.Fields()
		if err != nil || reflect.DeepEqual(fields, want) {
			t.Fatalf("selection %d omitted: %v", i, err)
		}
	}
	other := auth.NewBearerCredential(strings.Repeat("A", 43))
	next, err := p.sendRequestIntent(input, other)
	fields, _ := next.Fields()
	if err != nil || reflect.DeepEqual(fields, want) {
		t.Fatal("bearer commitment omitted", err)
	}
	for i := range want {
		fields := append([]identity.FeatureField(nil), want...)
		fields = append(fields[:i], fields[i+1:]...)
		partial, err := identity.NewRequestIntent(fields)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.readSendRequestIntent(partial); err == nil {
			t.Fatal("partial intent accepted")
		}
	}
	fields = append(want, identity.FeatureField{Name: "unexpected", Value: identity.FeatureValue{Kind: identity.FeatureBool}})
	extra, _ := identity.NewRequestIntent(fields)
	if _, err := p.readSendRequestIntent(extra); err == nil {
		t.Fatal("unknown field accepted")
	}
	if _, err := p.sendRequestIntent(input, auth.BearerCredential{}); err == nil {
		t.Fatal("absent bearer accepted")
	}
	for _, change := range []func(*sendInitiationConfig){
		func(c *sendInitiationConfig) { c.policyID = "other-policy" },
		func(c *sendInitiationConfig) { c.policyVersion++ },
		func(c *sendInitiationConfig) { c.preAuthAction = "other-action" },
		func(c *sendInitiationConfig) { c.intentKey[1] = 3 },
		func(c *sendInitiationConfig) { c.identifierKey[1] = 3 },
		func(c *sendInitiationConfig) { c.maximumDuration += time.Millisecond },
	} {
		changed := config
		change(&changed)
		fresh := *p
		fresh.initiation, err = newSendInitiationProfile(p.send.configuration, changed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fresh.readSendRequestIntent(intent); err == nil {
			t.Fatal("changed configuration adopted original intent")
		}
	}
	for i, field := range want {
		changed := append([]identity.FeatureField(nil), want...)
		if field.Value.Kind == identity.FeatureBytes {
			changed[i].Value.Bytes = make([]byte, 32)
		} else {
			changed[i].Value = identity.FeatureValue{Kind: identity.FeatureBool}
		}
		wrong, err := identity.NewRequestIntent(changed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.readSendRequestIntent(wrong); err == nil {
			t.Fatal("wrong typed field accepted")
		}
	}
}
