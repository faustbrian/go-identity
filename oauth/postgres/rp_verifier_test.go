package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	oauth "github.com/faustbrian/go-identity/oauth"
	secretenvelope "github.com/faustbrian/go-secret-envelope/v2"
)

var verifierIssued = time.Date(2026, 11, 1, 18, 0, 0, 123456000, time.UTC)

func verifierProfile() oauth.ProviderProfile {
	return oauth.ProviderProfile{ID: "generic", Version: 7, Issuer: "https://issuer.example", ClientID: "client", RedirectURI: "https://app.example/callback", ResponseMode: "query", PKCEMethod: "S256", NonceRequired: true, StateBytes: 32, NonceBytes: 32}
}

func verifierBinding(t *testing.T) rpVerifierBinding {
	t.Helper()
	b, err := newRPVerifierBinding("tenant-a", verifierProfile(), base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16)), sha256.Sum256([]byte("synthetic-state-commitment")), "identity.account.link-start")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func verifierKeys() rpVerifierKeyConfig {
	return rpVerifierKeyConfig{CurrentEnvelopeKey: "envelope-v1", EnvelopeKeys: map[string][]byte{"envelope-v1": bytes.Repeat([]byte{1}, 32)}, CurrentCommitmentVersion: 1, CommitmentKeys: map[uint32][]byte{1: bytes.Repeat([]byte{2}, 32)}}
}

func TestRPVerifierExactRecoverableCustody(t *testing.T) {
	owner, err := newRPVerifierCustody(verifierKeys())
	if err != nil {
		t.Fatal(err)
	}
	binding := verifierBinding(t)
	verifier := []byte(strings.Repeat("x", 43) + "-._~012AZaz")
	want := sha256.Sum256(verifier)
	sealed, err := owner.seal(context.Background(), binding, verifier, verifierIssued, verifierIssued.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := secretenvelope.ParseEnvelope(sealed.ciphertext); err != nil {
		t.Fatal("not actual upstream envelope format")
	}
	if bytes.Contains(sealed.ciphertext, verifier) {
		t.Fatal("plaintext persisted")
	}
	clear(verifier)
	recovered, err := owner.open(context.Background(), binding, sealed, verifierIssued, verifierIssued.Add(10*time.Minute), verifierIssued.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Destroy()
	if recovered.Challenge() != base64.RawURLEncoding.EncodeToString(want[:]) {
		t.Fatal("original verifier bytes changed")
	}
}

func TestRPVerifierRejectsTamperingEveryBindingAndOriginalTime(t *testing.T) {
	owner, err := newRPVerifierCustody(verifierKeys())
	if err != nil {
		t.Fatal(err)
	}
	binding := verifierBinding(t)
	expiry := verifierIssued.Add(5 * time.Minute)
	sealed, err := owner.seal(context.Background(), binding, bytes.Repeat([]byte{'v'}, 64), verifierIssued, expiry)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*rpVerifierBinding){
		func(b *rpVerifierBinding) { b.tenant = "tenant-b" },
		func(b *rpVerifierBinding) { b.provider.ID = "other" },
		func(b *rpVerifierBinding) { b.provider.Issuer = "https://other.example" },
		func(b *rpVerifierBinding) { b.provider.ClientID = "other" },
		func(b *rpVerifierBinding) {
			b.transactionID = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 16))
		},
		func(b *rpVerifierBinding) { b.stateDigest[0] ^= 1 },
		func(b *rpVerifierBinding) { b.provider.RedirectURI = "https://app.example/other" },
		func(b *rpVerifierBinding) { b.provider.ResponseMode = "form_post" },
		func(b *rpVerifierBinding) { b.operation = "identity.oauth.signin-start" },
		func(b *rpVerifierBinding) { b.provider.Version++ },
	} {
		wrong := binding
		change(&wrong)
		out, err := owner.open(context.Background(), wrong, sealed, verifierIssued, expiry, verifierIssued.Add(time.Minute))
		out.Destroy()
		if err == nil {
			t.Fatal("wrong AAD dimension admitted")
		}
	}
	for _, change := range []func(*rpSealedVerifier){
		func(s *rpSealedVerifier) {
			s.ciphertext = bytes.Clone(s.ciphertext)
			s.ciphertext[len(s.ciphertext)-1] ^= 1
		},
		func(s *rpSealedVerifier) { s.commitment[0] ^= 1 },
		func(s *rpSealedVerifier) { s.keyVersion++ },
		func(s *rpSealedVerifier) { s.ciphertext = bytes.Repeat([]byte{1}, 4097) },
	} {
		wrong := sealed
		change(&wrong)
		out, err := owner.open(context.Background(), binding, wrong, verifierIssued, expiry, verifierIssued.Add(time.Minute))
		out.Destroy()
		if err == nil {
			t.Fatal("tampered sealed verifier admitted")
		}
	}
	for _, times := range [][3]time.Time{
		{verifierIssued.Add(-time.Nanosecond), expiry, verifierIssued.Add(time.Minute)},
		{verifierIssued, expiry.Add(time.Second), verifierIssued.Add(time.Minute)},
		{verifierIssued, expiry, expiry}, {verifierIssued, expiry, verifierIssued.Add(-time.Nanosecond)},
	} {
		out, err := owner.open(context.Background(), binding, sealed, times[0], times[1], times[2])
		out.Destroy()
		if err == nil {
			t.Fatal("changed original time or invalid lifetime admitted")
		}
	}
}

func TestRPVerifierRetainedRotationAndIndependentKeySnapshots(t *testing.T) {
	keys := verifierKeys()
	owner, err := newRPVerifierCustody(keys)
	if err != nil {
		t.Fatal(err)
	}
	clear(keys.EnvelopeKeys["envelope-v1"])
	clear(keys.CommitmentKeys[1])
	delete(keys.EnvelopeKeys, "envelope-v1")
	delete(keys.CommitmentKeys, 1)
	binding := verifierBinding(t)
	sealed, err := owner.seal(context.Background(), binding, bytes.Repeat([]byte{'v'}, 64), verifierIssued, verifierIssued.Add(time.Minute))
	if err != nil {
		t.Fatal("source keys were retained by reference")
	}
	rotated := verifierKeys()
	rotated.CurrentEnvelopeKey = "envelope-v2"
	rotated.EnvelopeKeys["envelope-v2"] = bytes.Repeat([]byte{3}, 32)
	rotated.CurrentCommitmentVersion = 2
	rotated.CommitmentKeys[2] = bytes.Repeat([]byte{4}, 64)
	newOwner, err := newRPVerifierCustody(rotated)
	if err != nil {
		t.Fatal(err)
	}
	out, err := newOwner.open(context.Background(), binding, sealed, verifierIssued, verifierIssued.Add(time.Minute), verifierIssued)
	if err != nil {
		t.Fatal("retained keys failed")
	}
	out.Destroy()
	latest, err := newOwner.seal(context.Background(), binding, bytes.Repeat([]byte{'v'}, 64), verifierIssued, verifierIssued.Add(time.Minute))
	if err != nil || latest.keyVersion != 2 {
		t.Fatal("active commitment key not selected")
	}
	envelope, err := secretenvelope.ParseEnvelope(latest.ciphertext)
	if err != nil || envelope.KeyReference() != "envelope-v2" {
		t.Fatal("active envelope key not selected")
	}
	delete(rotated.EnvelopeKeys, "envelope-v1")
	delete(rotated.CommitmentKeys, 1)
	withoutOld, err := newRPVerifierCustody(rotated)
	if err != nil {
		t.Fatal(err)
	}
	out, err = withoutOld.open(context.Background(), binding, sealed, verifierIssued, verifierIssued.Add(time.Minute), verifierIssued)
	out.Destroy()
	if err == nil {
		t.Fatal("unavailable retained keys admitted")
	}
	bad := verifierKeys()
	bad.CommitmentKeys[1] = bytes.Clone(bad.EnvelopeKeys["envelope-v1"])
	if _, err := newRPVerifierCustody(bad); err == nil {
		t.Fatal("shared envelope/commitment key admitted")
	}
}

func TestRPVerifierBoundsZeroCancellationAndRedaction(t *testing.T) {
	owner, err := newRPVerifierCustody(verifierKeys())
	if err != nil {
		t.Fatal(err)
	}
	binding := verifierBinding(t)
	for _, raw := range [][]byte{nil, bytes.Repeat([]byte{'v'}, 42), bytes.Repeat([]byte{'v'}, 129), append(bytes.Repeat([]byte{'v'}, 43), ' '), append(bytes.Repeat([]byte{'v'}, 43), 0xff)} {
		if _, err := owner.seal(context.Background(), binding, raw, verifierIssued, verifierIssued.Add(time.Minute)); err == nil {
			t.Fatal("invalid verifier admitted")
		}
	}
	for _, times := range [][2]time.Time{{{}, verifierIssued}, {verifierIssued, verifierIssued}, {verifierIssued, verifierIssued.Add(10*time.Minute + time.Nanosecond)}, {verifierIssued.In(time.FixedZone("other", 3600)), verifierIssued.Add(time.Minute)}} {
		if _, err := owner.seal(context.Background(), binding, bytes.Repeat([]byte{'v'}, 64), times[0], times[1]); err == nil {
			t.Fatal("invalid original lifetime admitted")
		}
	}
	var zero rpVerifierCustody
	if _, err := zero.seal(context.Background(), binding, bytes.Repeat([]byte{'v'}, 64), verifierIssued, verifierIssued.Add(time.Minute)); err == nil {
		t.Fatal("zero custody admitted")
	}
	if _, err := newRPVerifierCustody(rpVerifierKeyConfig{}); err == nil {
		t.Fatal("zero keys admitted")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, canceled} {
		_, err := owner.seal(ctx, binding, bytes.Repeat([]byte{'v'}, 64), verifierIssued, verifierIssued.Add(time.Minute))
		if err == nil || ctx != nil && !errors.Is(err, context.Canceled) {
			t.Fatal("context denial or cancellation classification missing")
		}
	}
	sealed, err := owner.seal(context.Background(), binding, bytes.Repeat([]byte{'v'}, 64), verifierIssued, verifierIssued.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	deadline, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	for _, ctx := range []context.Context{nil, canceled, deadline} {
		out, err := owner.open(ctx, binding, sealed, verifierIssued, verifierIssued.Add(time.Minute), verifierIssued)
		out.Destroy()
		if err == nil || ctx != nil && !errors.Is(err, ctx.Err()) {
			t.Fatal("open context denial lost")
		}
	}
	for _, invalidOwner := range []*rpVerifierCustody{nil, &zero} {
		out, err := invalidOwner.open(context.Background(), binding, sealed, verifierIssued, verifierIssued.Add(time.Minute), verifierIssued)
		out.Destroy()
		if err == nil {
			t.Fatal("absent owner admitted open")
		}
	}
	if _, err := owner.seal(deadline, binding, bytes.Repeat([]byte{'v'}, 64), verifierIssued, verifierIssued.Add(time.Minute)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("earlier context deadline lost")
	}
	if _, err := owner.seal(context.Background(), rpVerifierBinding{}, bytes.Repeat([]byte{'v'}, 64), verifierIssued, verifierIssued.Add(time.Minute)); err == nil {
		t.Fatal("zero binding admitted")
	}
	invalid, err := owner.open(context.Background(), binding, rpSealedVerifier{}, verifierIssued, verifierIssued.Add(time.Minute), verifierIssued)
	invalid.Destroy()
	if err == nil {
		t.Fatal("zero sealed verifier admitted")
	}
	for _, value := range []any{binding, sealed, owner, verifierKeys()} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
			if rendered := fmt.Sprintf(verb, value); !strings.Contains(rendered, "redacted") {
				t.Fatal("custody diagnostic not redacted")
			}
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("secret-bearing custody serialized")
		}
		if value, ok := value.(interface{ MarshalText() ([]byte, error) }); !ok {
			t.Fatal("text guard missing")
		} else if _, err := value.MarshalText(); err == nil {
			t.Fatal("secret-bearing custody text serialized")
		}
	}
}

func TestRPVerifierBindingBoundsProfileSnapshotAndAAD(t *testing.T) {
	base := verifierBinding(t)
	p := verifierProfile()
	p.Scopes = []string{"openid"}
	p.Algorithms = []string{"ES256"}
	bound, err := newRPVerifierBinding("tenant-a", p, base.transactionID, base.stateDigest, "identity.oauth.signin-start")
	if err != nil {
		t.Fatal(err)
	}
	p.Scopes[0], p.Algorithms[0] = "changed", "none"
	got := bound.profile()
	got.Scopes[0], got.Algorithms[0] = "changed", "none"
	if bound.profile().Scopes[0] != "openid" || bound.profile().Algorithms[0] != "ES256" {
		t.Fatal("binding retained mutable profile slices")
	}
	p = verifierProfile()
	prefix := "https://issuer.example/"
	p.Issuer = prefix + strings.Repeat("x", 1024-len(prefix))
	if _, err := newRPVerifierBinding("tenant-a", p, base.transactionID, base.stateDigest, base.operation); err != nil {
		t.Fatal("upstream context value boundary rejected")
	}
	p.Issuer += "x"
	if _, err := newRPVerifierBinding("tenant-a", p, base.transactionID, base.stateDigest, base.operation); err == nil {
		t.Fatal("upstream context value overflow admitted")
	}
	for _, change := range []func(*rpVerifierBinding){func(b *rpVerifierBinding) { b.tenant = "" }, func(b *rpVerifierBinding) { b.transactionID = "bad" }, func(b *rpVerifierBinding) { b.stateDigest = [32]byte{} }, func(b *rpVerifierBinding) { b.operation = "identity.account.link-token" }, func(b *rpVerifierBinding) { b.provider.PKCEMethod = "plain" }, func(b *rpVerifierBinding) { b.provider.Version = 0 }, func(b *rpVerifierBinding) { b.provider.NonceRequired = false }} {
		wrong := base
		change(&wrong)
		if _, err := wrong.aad(); err == nil {
			t.Fatal("malformed binding admitted")
		}
	}
}
