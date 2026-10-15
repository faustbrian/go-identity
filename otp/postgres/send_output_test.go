package postgres

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope"
)

func TestSendOutputRestoresOriginalNativeIssuance(t *testing.T) {
	p, command, plan := issuancePhaseFixture(t)
	spec, _ := command.Feature()
	bearer, _ := command.SessionToken()
	wire, err := p.sealSendOutput(context.Background(), command, 1)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wire, []byte(bearer.Token())) || bytes.Contains(wire, []byte("123456")) {
		t.Fatal("preparation persisted credential plaintext")
	}
	// Fresh owned delivery instance, not a preserved opaque preparation handle.
	freshDelivery := issuanceDeliveryOwner(t)
	freshConfig, _, _, _ := nativeSessionFixture(t)
	freshConfig.Codec, err = NewAttemptCodec(codecConfig())
	if err != nil {
		t.Fatal(err)
	}
	freshStore, err := NewContributorWithSession(freshConfig.ContributorConfig, *freshConfig.Session)
	if err != nil {
		t.Fatal(err)
	}
	restored, actual, err := restoreSendOutput(context.Background(), freshStore, freshDelivery, spec.Binding, 1, bearer, wire)
	if err != nil {
		t.Fatal(err)
	}
	actualSpec, _ := actual.Feature()
	if !reflect.DeepEqual(spec, actualSpec) {
		t.Fatal("generated command was remapped")
	}
	originalPlan, _ := p.prepared.Plan()
	restoredPlan, _ := restored.prepared.Plan()
	if !reflect.DeepEqual(originalPlan, restoredPlan) {
		t.Fatal("original delivery declaration changed")
	}
	if err := restored.ValidateFeatureCommand(actual, plan); err != nil {
		t.Fatal("restored output cannot enter native execution", err)
	}
	for _, generation := range []uint64{0, 2} {
		if got, cmd, err := restoreSendOutput(context.Background(), p.store, freshDelivery, spec.Binding, generation, bearer, wire); err == nil || got != nil {
			t.Fatal("wrong provenance restored", cmd, err)
		}
	}
	if got, _, err := restoreSendOutput(context.Background(), p.store, freshDelivery, spec.Binding, 1, auth.NewBearerCredential("different"), wire); err == nil || got != nil {
		t.Fatal("restoration manufactured original bearer possession")
	}
	bad := bytes.Clone(wire)
	bad[len(bad)/2] ^= 1
	if got, _, err := restoreSendOutput(context.Background(), p.store, freshDelivery, spec.Binding, 1, bearer, bad); err == nil || got != nil {
		t.Fatal("corrupt combined custody restored")
	}
}

func TestSendOutputRejectsMalformedAuthenticatedFrames(t *testing.T) {
	p, command, _ := issuancePhaseFixture(t)
	spec, _ := command.Feature()
	bearer, _ := command.SessionToken()
	wire, err := p.sealSendOutput(context.Background(), command, 1)
	if err != nil {
		t.Fatal(err)
	}
	aad, err := sendOutputAAD(spec, 1)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		t.Fatal(err)
	}
	body, err := p.store.codec.crypto.Decrypt(context.Background(), envelope.DecryptRequest{Envelope: sealed, Context: aad})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(body)
	for name, change := range map[string]func([]byte) []byte{
		"header":              func(b []byte) []byte { b[0] ^= 1; return b },
		"key version":         func(b []byte) []byte { clear(b[5:9]); return b },
		"variant":             func(b []byte) []byte { b[9] = 3; return b },
		"wrong authorization": func(b []byte) []byte { b[9] = 1; return b },
		"empty issue":         func(b []byte) []byte { clear(b[10:14]); return b },
		"oversized issue":     func(b []byte) []byte { binary.BigEndian.PutUint32(b[10:14], 8193); return b },
		"truncated delivery":  func(b []byte) []byte { return b[:len(b)-1] },
		"trailing bytes":      func(b []byte) []byte { return append(b, 0) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := change(bytes.Clone(body))
			defer clear(bad)
			sealed, err := p.store.codec.crypto.Encrypt(context.Background(), envelope.EncryptRequest{Plaintext: bad, KeyReference: p.store.codec.current, Context: aad})
			if err != nil {
				t.Fatal(err)
			}
			wire, err := sealed.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			phase, cmd, err := restoreSendOutput(context.Background(), p.store, p.delivery, spec.Binding, 1, bearer, wire)
			if err == nil || phase != nil || !reflect.DeepEqual(cmd, identity.Command{}) {
				t.Fatal("malformed output returned usable custody")
			}
		})
	}
}

func FuzzSendOutputField(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1, 42})
	f.Add([]byte{255, 255, 255, 255})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, wire []byte) {
		field, rest, ok := sendOutputField(wire, 8192)
		if !ok {
			return
		}
		if len(field) < 1 || len(field) > 8192 || len(wire) != 4+len(field)+len(rest) || !bytes.Equal(wire[4:4+len(field)], field) || !bytes.Equal(wire[4+len(field):], rest) {
			t.Fatal("invalid field framing accepted")
		}
	})
}

func TestSendOutputPreservesDisjointPreAuthVariant(t *testing.T) {
	codec, challenge, spec, bearer, authority := issuanceCustodyFixture(t, false)
	config := ContributorConfig{Schema: "otp_store", Codec: codec, GlobalAuthorityID: "deployment", UserPolicyNamespace: "users", LockoutKey: [32]byte{0x61}, PreAuth: sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}, PreAuthCookieKeys: map[uint32][]byte{3: bytes.Repeat([]byte{0x56}, 32)}}
	store, err := NewContributor(config)
	if err != nil {
		t.Fatal(err)
	}
	command, err := codec.MapIssuancePreAuth(context.Background(), challenge, spec, bearer, authority)
	if err != nil {
		t.Fatal(err)
	}
	delivery, prepared := issuanceDeliveryFixture(t, codec, challenge, spec)
	p, err := newIssuanceContributor(store, delivery, prepared)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := p.sealSendOutput(context.Background(), command, 3)
	if err != nil {
		t.Fatal(err)
	}
	config.Codec, err = NewAttemptCodec(codecConfig())
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := NewContributor(config)
	if err != nil {
		t.Fatal(err)
	}
	restored, actual, err := restoreSendOutput(context.Background(), fresh, issuanceDeliveryOwner(t), spec.Binding, 3, bearer, wire)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := actual.PreAuthCookie(); !ok {
		t.Fatal("pre-auth possession lost")
	}
	if _, ok := actual.SessionToken(); ok {
		t.Fatal("restoration upgraded to session authorization")
	}
	if _, ok := actual.OneTimeCode(); ok {
		t.Fatal("restoration manufactured a submitted code")
	}
	if err := restored.validateSendOutput(actual); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*identity.CommandBinding){
		func(b *identity.CommandBinding) { b.TenantID = "other" },
		func(b *identity.CommandBinding) { b.ActorID = "other" },
		func(b *identity.CommandBinding) { b.RecordID = "other" },
		func(b *identity.CommandBinding) { b.PolicyVersion++ },
	} {
		b := spec.Binding
		change(&b)
		if p, _, err := restoreSendOutput(context.Background(), fresh, delivery, b, 3, bearer, wire); err == nil || p != nil {
			t.Fatal("cross-scope output adopted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.sealSendOutput(ctx, command, 3); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled seal accepted", err)
	}
	if p, _, err := restoreSendOutput(ctx, fresh, delivery, spec.Binding, 3, bearer, wire); !errors.Is(err, context.Canceled) || p != nil {
		t.Fatal("cancelled restore accepted", err)
	}
	// The same original intent cannot gain custody for an unrelated plan.
	dp, _ := restored.prepared.Plan()
	plan := kernel.CommandPlan{SubjectType: "otp_challenge", Feature: &kernel.FeatureRegistration{Contributor: restored.Descriptor(), Operation: spec.Operation}, Lifecycle: &kernel.LifecyclePlan{EventType: "otp.sent.v1", AfterVersion: 1}, Audits: []kernel.AuditPlan{{EventType: "otp.send"}}, Delivery: &dp}
	plan.Delivery.Intents[0].ExpiresAt = plan.Delivery.Intents[0].ExpiresAt.Add(time.Second)
	if restored.ValidateFeatureCommand(actual, plan) == nil {
		t.Fatal("restored native output accepted changed expiry")
	}
}
