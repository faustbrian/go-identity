package postgres

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	envelope "github.com/faustbrian/go-secret-envelope"
	"github.com/faustbrian/go-secret-envelope/adapters/keyring"
)

func issuanceDeliveryOwner(t *testing.T) *deliverypg.Contributor {
	t.Helper()
	keys, err := keyring.New(map[string][]byte{"issue-envelope": bytes.Repeat([]byte{0x71}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		t.Fatal(err)
	}
	c, err := deliverypg.NewContributor(deliverypg.ContributorConfig{Deployment: "deployment", CurrentDigestKeyVersion: 1, RetainedDigestKeys: map[uint32][32]byte{1: {0x72}}, ActiveEnvelopeKeyID: "issue-envelope", PreparationTimeout: time.Second, ProviderProfiles: map[uint64]deliverypg.ProviderProfile{1: {Provider: "test-sender", PolicyVersion: 1}}}, crypto)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func issuanceDeliveryFixture(t *testing.T, codec *AttemptCodec, challenge otp.Challenge, spec identity.FeatureCommandSpec) (*deliverypg.Contributor, deliverypg.PreparedDelivery) {
	t.Helper()
	c := issuanceDeliveryOwner(t)
	s, _ := challenge.Bindings()
	b, _ := s.Continuation.Bindings()
	scope, _ := s.Continuation.DigestScope()
	digest, err := codec.verifier.ScopeDigest(scope, s.Digest.KeyVersion)
	if err != nil {
		t.Fatal(err)
	}
	target := b.Scope.SubjectID
	if target == "" {
		target = spec.Binding.AnonymousFlowID
	}
	input := deliverypg.IntentInput{Purpose: "otp-" + string(b.Scope.Purpose), SubjectID: target, TemplateID: "otp-code", TemplateVersion: 1, ProviderConfigVersion: 1, ExpiresAt: s.ExpiresAt, Recipient: delivery.Recipient{Channel: delivery.ChannelEmail, Address: "recipient@example.invalid", ScopeDigest: hex.EncodeToString(digest.Value[:])}, Rendered: delivery.RenderedMessage{Channel: delivery.ChannelEmail, Locale: "en", Subject: "verification", Body: "123456", ContentType: "text/plain"}}
	prepared, err := c.Prepare(context.Background(), spec.Binding, []deliverypg.IntentInput{input})
	if err != nil {
		t.Fatal(err)
	}
	return c, prepared
}

func issuancePhaseFixture(t *testing.T) (*issuanceContributor, identity.Command, kernel.CommandPlan) {
	t.Helper()
	codec, challenge, spec, cookie, authority := issuanceCustodyFixture(t, true)
	config, _, _, _ := nativeSessionFixture(t)
	config.Codec = codec
	p, err := NewContributorWithSession(config.ContributorConfig, *config.Session)
	if err != nil {
		t.Fatal(err)
	}
	command, err := codec.MapIssuanceSession(context.Background(), challenge, spec, cookie, authority)
	if err != nil {
		t.Fatal(err)
	}
	d, prepared := issuanceDeliveryFixture(t, codec, challenge, spec)
	phase, err := newIssuanceContributor(p, d, prepared)
	if err != nil {
		t.Fatal(err)
	}
	dp, _ := prepared.Plan()
	plan := kernel.CommandPlan{SubjectType: "otp_challenge", Feature: &kernel.FeatureRegistration{Contributor: phase.Descriptor(), Operation: spec.Operation}, Lifecycle: &kernel.LifecyclePlan{EventType: "otp.sent.v1", AfterVersion: 1}, Audits: []kernel.AuditPlan{{EventType: "otp.send"}}, Delivery: &dp}
	return phase, command, plan
}

func TestIssuancePhaseRequiresExactOriginalAndFrozenDelivery(t *testing.T) {
	p, command, plan := issuancePhaseFixture(t)
	if err := p.ValidateFeatureCommand(command, plan); err != nil {
		t.Fatal("original issuance declaration rejected", err)
	}
	for _, change := range []func(*kernel.CommandPlan){
		func(p *kernel.CommandPlan) { p.Delivery = nil },
		func(p *kernel.CommandPlan) { p.Delivery.Intents[0].IntentDigest[0] ^= 1 },
		func(p *kernel.CommandPlan) {
			p.Delivery.Intents[0].ExpiresAt = p.Delivery.Intents[0].ExpiresAt.Add(time.Second)
		},
		func(p *kernel.CommandPlan) { p.OTP = &kernel.OTPAttemptPlan{} },
		func(p *kernel.CommandPlan) { p.Lifecycle.AfterVersion = 2 },
		func(p *kernel.CommandPlan) { p.Audits[0].EventType = "otp.check" },
	} {
		_, _, altered := issuancePhaseFixture(t)
		// Keep the same original ciphertext declaration before changing one field.
		dp, _ := p.prepared.Plan()
		altered.Delivery = &dp
		change(&altered)
		if err := p.ValidateFeatureCommand(command, altered); err == nil {
			t.Fatal("changed issuance declaration admitted")
		}
	}
	if _, err := p.ApplyFeature(context.Background(), kernel.Work{}, command); err == nil {
		t.Fatal("unowned issuance Work admitted")
	}
	if _, err := newIssuanceContributor(nil, p.delivery, p.prepared); err == nil {
		t.Fatal("zero store admitted")
	}
	if _, err := newIssuanceContributor(p.store, nil, p.prepared); err == nil {
		t.Fatal("zero delivery owner admitted")
	}
}
