package postgres

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	secretenvelope "github.com/faustbrian/go-secret-envelope"
	"github.com/faustbrian/go-secret-envelope/adapters/keyring"
)

func custodyFixture(t testing.TB) (*payloadCodec, payloadBinding, payload) {
	t.Helper()
	provider, err := keyring.New(map[string][]byte{"envelope-a": bytes.Repeat([]byte{1}, 32), "envelope-b": bytes.Repeat([]byte{2}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	service, err := secretenvelope.NewService(provider)
	if err != nil {
		t.Fatal(err)
	}
	codec, err := newPayloadCodec(service, map[uint32][32]byte{1: {3}, 2: {4}}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	b := payloadBinding{Deployment: "test", Command: identity.CommandBinding{CommandID: id, TenantID: "tenant-a", UserID: "user-a", ActorID: "actor-a", ActorKind: authorization.SubjectUser, OperationID: "identity.user.create", PolicyID: "policy-a", PolicyVersion: 1, SchemaID: "schema-a", SchemaVersion: 1, CorrelationID: "correlation-a"}, Intent: identitypostgres.DeliveryIntentPlan{EffectID: "effect-a", Purpose: "verification", SubjectID: "user-a", TemplateID: "verify", TemplateVersion: 1, ProviderConfigVersion: 1, ExpiresAt: time.Now().UTC().Truncate(time.Microsecond).Add(time.Hour)}, Provider: "test-provider", PolicyVersion: 1, DigestKeyVersion: 1}
	p := payload{Recipient: delivery.Recipient{Channel: delivery.ChannelEmail, Address: "recipient@example.invalid", ScopeDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, Rendered: delivery.RenderedMessage{Channel: delivery.ChannelEmail, Locale: "en", Subject: "verify", Body: "synthetic-code", ContentType: "text/plain"}}
	return codec, b, p
}

func TestCustodyBindsOriginalCommandAndKeepsLogicalIdentity(t *testing.T) {
	c, b, p := custodyFixture(t)
	frozen, first, err := c.seal(context.Background(), b, p, "envelope-a")
	if err != nil {
		t.Fatal(err)
	}
	again, second, err := c.seal(context.Background(), b, p, "envelope-a")
	if err != nil || frozen.Intent.IntentDigest != again.Intent.IntentDigest || bytes.Equal(first.Ciphertext, second.Ciphertext) {
		t.Fatal("logical identity follows randomized encryption", err)
	}
	if bytes.Contains(first.Ciphertext, []byte(p.Rendered.Body)) || bytes.Contains(first.Ciphertext, []byte(p.Recipient.Address)) {
		t.Fatal("persisted custody contains plaintext")
	}
	got, err := c.open(context.Background(), frozen, first)
	if err != nil || !reflect.DeepEqual(got, p) {
		t.Fatal("bound payload round trip", err)
	}
	for _, change := range []func(*payloadBinding){
		func(v *payloadBinding) { v.Deployment = "other" },
		func(v *payloadBinding) { v.Command.CommandID = "AQEBAQEBAQEBAQEBAQEBAQ" },
		func(v *payloadBinding) { v.Command.TenantID = "other" },
		func(v *payloadBinding) { v.Command.UserID = "other" },
		func(v *payloadBinding) { v.Command.ActorID = "other" },
		func(v *payloadBinding) { v.Command.ActorKind = authorization.SubjectAPIKey },
		func(v *payloadBinding) { v.Command.OperationID = "identity.user.update" },
		func(v *payloadBinding) { v.Command.PolicyID = "other" },
		func(v *payloadBinding) { v.Command.PolicyVersion++ },
		func(v *payloadBinding) { v.Command.SchemaID = "other" },
		func(v *payloadBinding) { v.Command.SchemaVersion++ },
		func(v *payloadBinding) { v.Command.CorrelationID = "other" },
		func(v *payloadBinding) { v.Command.RecordID = "other" },
		func(v *payloadBinding) { v.Command.LinkMode = identity.AccountLinkExplicit },
		func(v *payloadBinding) { v.Intent.EffectID = "other" },
		func(v *payloadBinding) { v.Intent.EffectIndex++ },
		func(v *payloadBinding) { v.Intent.Purpose = "password-reset" },
		func(v *payloadBinding) { v.Intent.SubjectID = "other" },
		func(v *payloadBinding) { v.Intent.TemplateID = "other" },
		func(v *payloadBinding) { v.Intent.TemplateVersion++ },
		func(v *payloadBinding) { v.Intent.ProviderConfigVersion++ },
		func(v *payloadBinding) { v.Intent.ExpiresAt = v.Intent.ExpiresAt.Add(time.Microsecond) },
		func(v *payloadBinding) { v.Intent.IntentDigest[0]++ },
		func(v *payloadBinding) { v.Provider = "other" },
		func(v *payloadBinding) { v.PolicyVersion++ },
		func(v *payloadBinding) { v.DigestKeyVersion++ },
		func(v *payloadBinding) { v.NoOpEquivalent = true },
	} {
		changed := frozen
		change(&changed)
		if c.verify(changed, first) == nil {
			t.Fatal("changed original binding authenticated")
		}
	}
	changed := first
	changed.Ciphertext = bytes.Clone(first.Ciphertext)
	changed.Ciphertext[len(changed.Ciphertext)-1] ^= 1
	if c.verify(frozen, changed) == nil {
		t.Fatal("tampered custody authenticated")
	}
	changed = first
	changed.KeyID = "envelope-b"
	if c.verify(frozen, changed) == nil {
		t.Fatal("changed key authenticated")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.open(cancelled, frozen, first); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled decrypt returned payload", err)
	}
}

func TestCustodyExpiredPreparationCannotRenewLifetime(t *testing.T) {
	c, b, p := custodyFixture(t)
	b.Intent.ExpiresAt = time.Now().UTC().Add(-time.Second).Truncate(time.Microsecond)
	if _, _, err := c.seal(context.Background(), b, p, "envelope-a"); !errors.Is(err, delivery.ErrExpired) {
		t.Fatal("expired payload prepared", err)
	}
}

func TestCustodyDiagnosticsRedactPrivateHolders(t *testing.T) {
	c, _, p := custodyFixture(t)
	wire := payloadWire{Channel: p.Rendered.Channel, Address: p.Recipient.Address, RecipientScope: p.Recipient.ScopeDigest, Locale: p.Rendered.Locale, Subject: p.Rendered.Subject, Body: p.Rendered.Body, ContentType: p.Rendered.ContentType}
	for i, value := range []any{c, *c, p, wire} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			for _, verb := range []string{"%v", "%+v", "%#v", "%x"} {
				if fmt.Sprintf(verb, value) != "delivery.postgres(redacted)" {
					t.Fatal("diagnostic formatting exposed private holder")
				}
			}
			var logged bytes.Buffer
			slog.New(slog.NewJSONHandler(&logged, nil)).Info("synthetic", slog.Any("custody", value))
			if !strings.Contains(logged.String(), "delivery.postgres(redacted)") || strings.Contains(logged.String(), p.Recipient.Address) || strings.Contains(logged.String(), p.Rendered.Body) {
				t.Fatal("structured log exposed private holder")
			}
		})
	}
}

func TestCustodyRotationBoundsAndPureVerification(t *testing.T) {
	c, b, p := custodyFixture(t)
	frozen, envelope, err := c.seal(context.Background(), b, p, "envelope-a")
	if err != nil {
		t.Fatal(err)
	}
	service := c.service
	c.service = nil
	if err := c.verify(frozen, envelope); err != nil {
		t.Fatal("pure verification depended on key provider", err)
	}
	c.service = service
	keys := map[uint32][32]byte{1: {3}, 2: {4}}
	rotated, err := newPayloadCodec(service, keys, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	keys[1] = [32]byte{9}
	if _, err := rotated.open(context.Background(), frozen, envelope); err != nil {
		t.Fatal("retained key rotation or ownership", err)
	}
	b.DigestKeyVersion = 2
	newBinding, newEnvelope, err := rotated.seal(context.Background(), b, p, "envelope-b")
	if err != nil || newEnvelope.KeyID != "envelope-b" {
		t.Fatal("modern rotated issuance", err)
	}
	if _, err := rotated.open(context.Background(), newBinding, newEnvelope); err != nil {
		t.Fatal(err)
	}
	delete(rotated.keys, 1)
	if err := rotated.verify(frozen, envelope); !errors.Is(err, delivery.ErrUnavailable) {
		t.Fatal("missing retained key did not fail closed", err)
	}
	for _, wire := range [][]byte{nil, {}, envelope.Ciphertext[:8], envelope.Ciphertext[:40], bytes.Repeat([]byte{1}, maximumCustody+1)} {
		bad := envelope
		bad.Ciphertext = wire
		if c.verify(frozen, bad) == nil {
			t.Fatal("malformed custody accepted")
		}
	}
	for _, change := range []func(*payload){
		func(v *payload) { v.Recipient.Address = "" },
		func(v *payload) { v.Recipient.Address = strings.Repeat("x", 321) },
		func(v *payload) { v.Rendered.Locale = "" },
		func(v *payload) { v.Rendered.Locale = "en--US" },
		func(v *payload) { v.Rendered.Subject = "bad\r\nheader" },
		func(v *payload) { v.Rendered.Body = "" },
		func(v *payload) { v.Rendered.Body = strings.Repeat("x", maximumPlaintext+1) },
		func(v *payload) { v.Rendered.Body = string([]byte{0xff}) },
		func(v *payload) { v.Rendered.Channel = delivery.ChannelSMS },
		func(v *payload) { v.Rendered.ContentType = "unsafe" },
	} {
		bad := p
		change(&bad)
		if _, _, err := c.seal(context.Background(), b, bad, "envelope-a"); !errors.Is(err, delivery.ErrInvalidInput) {
			t.Fatal("unbounded or malformed payload prepared", err)
		}
	}
	for _, change := range []func(*payload){
		func(v *payload) { v.Recipient.Address = "other@example.invalid" },
		func(v *payload) { v.Recipient.ScopeDigest = strings.Repeat("b", 64) },
		func(v *payload) { v.Rendered.Locale = "fr" },
		func(v *payload) { v.Rendered.Subject = "other" },
		func(v *payload) { v.Rendered.Body = "other-synthetic-code" },
		func(v *payload) { v.Rendered.ContentType = "text/html" },
	} {
		changed := p
		change(&changed)
		bound, _, err := c.seal(context.Background(), b, changed, "envelope-a")
		original, _, originalErr := c.seal(context.Background(), b, p, "envelope-a")
		if err != nil || originalErr != nil || bound.Intent.IntentDigest == original.Intent.IntentDigest {
			t.Fatal("logical payload field omitted", err, originalErr)
		}
	}
}

func TestCustodyConcurrentRoundTrips(t *testing.T) {
	c, b, p := custodyFixture(t)
	var wg sync.WaitGroup
	failures := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			bound, envelope, err := c.seal(context.Background(), b, p, "envelope-a")
			if err == nil {
				var got payload
				got, err = c.open(context.Background(), bound, envelope)
				if err == nil && !reflect.DeepEqual(got, p) {
					err = delivery.ErrConflict
				}
			}
			failures <- err
		})
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal("concurrent custody", err)
		}
	}
}

func FuzzCustodyVerify(f *testing.F) {
	c, b, p := custodyFixture(f)
	frozen, envelope, err := c.seal(context.Background(), b, p, "envelope-a")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(envelope.Ciphertext)
	f.Add([]byte(custodyHeader))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, wire []byte) {
		v := envelope
		v.Ciphertext = wire
		err := c.verify(frozen, v)
		if err == nil && !bytes.Equal(wire, envelope.Ciphertext) {
			t.Fatal("unauthenticated modified envelope accepted")
		}
	})
}
