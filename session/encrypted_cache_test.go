package session_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	identity "github.com/faustbrian/go-identity"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/session"
	envelope "github.com/faustbrian/go-secret-envelope"
	"github.com/faustbrian/go-secret-envelope/adapters/keyring"
)

func TestEncryptedCacheRestartPreservesOriginalDeadline(t *testing.T) {
	_, request, clock, observed, config, _ := validationFixture(t)
	outage := false
	reads := 0
	reader := observedSession(func(context.Context, session.SessionLookup) (session.SessionObservation, error) {
		reads++
		if outage {
			return session.SessionObservation{}, session.ErrUnavailable
		}
		return *observed, nil
	})
	service, _ := session.NewSessionService(reader, config)
	keys, _ := keyring.New(map[string][]byte{"cache-v1": make([]byte, 32)})
	crypto, _ := envelope.NewService(keys)
	profile := session.EncryptedCacheConfig{Issuer: "issuer", Environment: "test", DeploymentEpoch: 1, KeyReference: "cache-v1", MaximumAge: 5 * time.Minute, MaximumBytes: 32768}
	codec, err := session.NewEncryptedCacheCodec(service, crypto, profile)
	if err != nil {
		t.Fatal(err)
	}
	original, err := service.Get(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := codec.Seal(context.Background(), original)
	if err != nil {
		t.Fatal(err)
	}
	restarted, _ := session.NewSessionService(reader, config)
	restored, err := session.NewEncryptedCacheCodec(restarted, crypto, profile)
	if err != nil {
		t.Fatal(err)
	}
	outage = true
	clock.now = original.ValidUntil().Add(-time.Nanosecond)
	warm, err := restored.Get(context.Background(), request, blob)
	if err != nil || !warm.Authenticated || reads != 1 || !warm.ValidUntil().Equal(original.ValidUntil()) {
		t.Fatal("restart renewed or lost original evidence", err)
	}
	beforeSpec, _ := original.Session.Bindings()
	afterSpec, _ := warm.Session.Bindings()
	if afterSpec.Authority.CompareCurrent(beforeSpec.Authority) != nil || afterSpec.Remember != beforeSpec.Remember {
		t.Fatal("complete authority or remember policy changed")
	}
	afterSpec.Authority = beforeSpec.Authority
	if afterSpec != beforeSpec {
		t.Fatal("session projection lost original identity, digest, authentication or lifetime")
	}
	promoted, err := restored.Seal(context.Background(), warm)
	if err != nil {
		t.Fatal(err)
	}
	clock.now = original.ValidUntil()
	denied, err := restored.Get(context.Background(), request, promoted)
	if err != session.ErrUnavailable || denied.Authenticated || reads != 2 {
		t.Fatal("expired encrypted evidence survived outage", err)
	}
}

func encryptedFixture(t *testing.T) (*session.EncryptedCacheCodec, session.GetRequest, *mutableIssueClock, *session.SessionObservation, session.ServiceConfig, *envelope.Service, session.EncryptedCacheConfig, session.GetResult, []byte) {
	t.Helper()
	service, request, clock, observed, config, _ := validationFixture(t)
	keys, err := keyring.New(map[string][]byte{"cache-v1": make([]byte, 32), "cache-v2": bytes.Repeat([]byte{1}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	crypto, _ := envelope.NewService(keys)
	profile := session.EncryptedCacheConfig{Issuer: "issuer", Environment: "test", DeploymentEpoch: 1, KeyReference: "cache-v1", MaximumAge: 5 * time.Minute, MaximumBytes: 32768}
	codec, err := session.NewEncryptedCacheCodec(service, crypto, profile)
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Get(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := codec.Seal(context.Background(), result)
	if err != nil {
		t.Fatal(err)
	}
	return codec, request, clock, observed, config, crypto, profile, result, blob
}

func TestEncryptedCacheScopeTamperingAndUnavailablePrimary(t *testing.T) {
	codec, request, _, _, config, crypto, profile, _, blob := encryptedFixture(t)
	outageReader := observedSession(func(context.Context, session.SessionLookup) (session.SessionObservation, error) {
		return session.SessionObservation{}, session.ErrUnavailable
	})
	source, _ := session.NewSessionService(outageReader, config)
	outage, _ := session.NewEncryptedCacheCodec(source, crypto, profile)
	if got, e := outage.Get(context.Background(), request, blob); e != nil || !got.Authenticated {
		t.Fatal("warm outage", e)
	}
	for _, change := range []func(*session.EncryptedCacheConfig){func(p *session.EncryptedCacheConfig) { p.Issuer = "other" }, func(p *session.EncryptedCacheConfig) { p.Environment = "other" }, func(p *session.EncryptedCacheConfig) { p.DeploymentEpoch++ }} {
		modified := profile
		change(&modified)
		foreign, _ := session.NewEncryptedCacheCodec(source, crypto, modified)
		if got, e := foreign.Get(context.Background(), request, blob); e != session.ErrUnavailable || got.Authenticated {
			t.Fatal("foreign deployment", e)
		}
	}
	for _, bad := range [][]byte{nil, {}, []byte("SEV1"), bytes.Repeat([]byte{1}, 32769), append(append([]byte(nil), blob...), 0), func() []byte { b := append([]byte(nil), blob...); b[len(b)-1] ^= 1; return b }()} {
		if got, e := outage.Get(context.Background(), request, bad); e != session.ErrUnavailable || got.Authenticated {
			t.Fatal("invalid cache bypassed primary", e)
		}
	}
	badTenant := request
	badTenant.TenantID = "other"
	if got, e := outage.Get(context.Background(), badTenant, blob); e != session.ErrUnavailable || got.Authenticated {
		t.Fatal("foreign tenant", e)
	}
	token, _ := session.NewToken(32)
	alternate := request
	alternate.Credential, _ = session.NewCredential(session.CredentialCookie, token)
	if got, e := outage.Get(context.Background(), alternate, blob); e != session.ErrUnavailable || got.Authenticated {
		t.Fatal("foreign bearer", e)
	}
	// A healthy primary may ignore a corrupt cache, but cannot reuse its custody.
	if got, e := codec.Get(context.Background(), request, []byte("broken")); e != nil || !got.Authenticated {
		t.Fatal("healthy primary fallback", e)
	}
}

func TestEncryptedCacheKeyRotationRemovalAndAge(t *testing.T) {
	_, request, clock, _, config, crypto, profile, result, blob := encryptedFixture(t)
	source, _ := session.NewSessionService(observedSession(func(context.Context, session.SessionLookup) (session.SessionObservation, error) {
		return session.SessionObservation{}, session.ErrUnavailable
	}), config)
	profile.KeyReference = "cache-v2"
	rotated, _ := session.NewEncryptedCacheCodec(source, crypto, profile)
	warm, e := rotated.Get(context.Background(), request, blob)
	if e != nil || !warm.Authenticated {
		t.Fatal("retained old key", e)
	}
	next, e := rotated.Seal(context.Background(), warm)
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := envelope.ParseEnvelope(next)
	if e != nil || parsed.KeyReference() != "cache-v2" {
		t.Fatal("new issuance key", e)
	}
	onlyNew, _ := keyring.New(map[string][]byte{"cache-v2": bytes.Repeat([]byte{1}, 32)})
	cryptoNew, _ := envelope.NewService(onlyNew)
	removed, _ := session.NewEncryptedCacheCodec(source, cryptoNew, profile)
	if got, e := removed.Get(context.Background(), request, blob); e != session.ErrUnavailable || got.Authenticated {
		t.Fatal("removed old key", e)
	}
	if got, e := removed.Get(context.Background(), request, next); e != nil || !got.Authenticated || !got.ValidUntil().Equal(result.ValidUntil()) {
		t.Fatal("rotated payload", e)
	}
	profile.MaximumAge = time.Second
	short, _ := session.NewEncryptedCacheCodec(source, crypto, profile)
	clock.now = clock.now.Add(time.Second)
	if got, e := short.Get(context.Background(), request, blob); e != session.ErrUnavailable || got.Authenticated {
		t.Fatal("tightened cache age", e)
	}
}

func TestEncryptedCacheBoundsCancellationCustodyAndConcurrency(t *testing.T) {
	codec, request, clock, _, config, crypto, profile, result, blob := encryptedFixture(t)
	for _, change := range []func(*session.EncryptedCacheConfig){func(p *session.EncryptedCacheConfig) { p.Issuer = "" }, func(p *session.EncryptedCacheConfig) { p.Environment = "" }, func(p *session.EncryptedCacheConfig) { p.DeploymentEpoch = 0 }, func(p *session.EncryptedCacheConfig) { p.KeyReference = "" }, func(p *session.EncryptedCacheConfig) { p.MaximumAge = 0 }, func(p *session.EncryptedCacheConfig) { p.MaximumAge = 5*time.Minute + 1 }, func(p *session.EncryptedCacheConfig) { p.MaximumBytes = 255 }, func(p *session.EncryptedCacheConfig) { p.MaximumBytes = 32769 }} {
		p := profile
		change(&p)
		service, _, _, _, _, _ := validationFixture(t)
		if _, e := session.NewEncryptedCacheCodec(service, crypto, p); e != session.ErrInvalidInput {
			t.Fatal("invalid configuration", e)
		}
	}
	service, _, _, _, _, _ := validationFixture(t)
	if _, e := session.NewEncryptedCacheCodec(nil, crypto, profile); e != session.ErrInvalidInput {
		t.Fatal("nil service")
	}
	if _, e := session.NewEncryptedCacheCodec(service, nil, profile); e != session.ErrInvalidInput {
		t.Fatal("nil crypto")
	}
	if _, e := codec.Seal(context.Background(), session.GetResult{Authenticated: true, Session: result.Session}); e != session.ErrUnauthenticated {
		t.Fatal("fabricated custody", e)
	}
	if _, e := codec.Seal(context.Background(), func() session.GetResult { r := result; r.NeedsRefresh = !r.NeedsRefresh; return r }()); e != session.ErrUnauthenticated {
		t.Fatal("mutated custody", e)
	}
	if _, e := codec.Seal(nil, result); e != session.ErrInvalidInput {
		t.Fatal("nil ctx")
	}
	if _, e := (*session.EncryptedCacheCodec)(nil).Get(context.Background(), request, blob); e != session.ErrInvalidInput {
		t.Fatal("nil codec")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var cancelled identity.CancelledError
	if got, e := codec.Get(ctx, request, blob); !errors.As(e, &cancelled) || got.Authenticated {
		t.Fatal("cancelled read", e)
	}
	if out, e := codec.Seal(ctx, result); !errors.As(e, &cancelled) || out != nil {
		t.Fatal("cancelled seal", e)
	}
	if fmt.Sprintf("%#v", codec) != "session.EncryptedCacheCodec(redacted)" {
		t.Fatal("diagnostic leak")
	}
	if b, e := json.Marshal(codec); e == nil || len(b) != 0 {
		t.Fatal("JSON export")
	}
	if bytes.Contains(blob, []byte("SessionID")) || bytes.Contains(blob, []byte("CredentialID")) {
		t.Fatal("unencrypted projection")
	}
	// Read immutable snapshots concurrently; caller-owned byte slices are borrowed
	// only during each operation and never retained by the codec.
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			got, e := codec.Get(context.Background(), request, blob)
			if e != nil || !got.Authenticated {
				t.Error("concurrent get", e)
			}
			if _, e := codec.Seal(context.Background(), result); e != nil {
				t.Error("concurrent seal", e)
			}
		})
	}
	wg.Wait()
	original := clock.now
	clock.now = original.Add(-time.Millisecond)
	if got, e := codec.Get(context.Background(), request, blob); e != session.ErrUnavailable || got.Authenticated {
		t.Fatal("backward admission clock", e)
	}
	clock.now = original
	config.Audience = "foreign"
	foreign, _ := session.NewSessionService(observedSession(func(context.Context, session.SessionLookup) (session.SessionObservation, error) {
		return session.SessionObservation{}, session.ErrUnavailable
	}), config)
	other, _ := session.NewEncryptedCacheCodec(foreign, crypto, profile)
	if got, e := other.Get(context.Background(), request, blob); e != session.ErrUnavailable || got.Authenticated {
		t.Fatal("foreign audience", e)
	}
}

func TestEncryptedCacheRejectsAuthenticatedMalformedProjections(t *testing.T) {
	_, request, _, _, config, crypto, profile, _, blob := encryptedFixture(t)
	reads := 0
	source, _ := session.NewSessionService(observedSession(func(context.Context, session.SessionLookup) (session.SessionObservation, error) {
		reads++
		return session.SessionObservation{}, session.ErrUnavailable
	}), config)
	codec, _ := session.NewEncryptedCacheCodec(source, crypto, profile)
	aad, e := envelope.NewContext(map[string]string{"purpose": "golib.session.encrypted-cache.v1", "issuer": profile.Issuer, "environment": profile.Environment, "epoch": strconv.FormatUint(profile.DeploymentEpoch, 10), "audience": config.Audience, "tenant": string(request.TenantID), "clock-uncertainty": strconv.FormatInt(int64(config.ClockUncertainty), 10)})
	if e != nil {
		t.Fatal(e)
	}
	parsed, _ := envelope.ParseEnvelope(blob)
	plain, e := crypto.Decrypt(context.Background(), envelope.DecryptRequest{Envelope: parsed, Context: aad})
	if e != nil {
		t.Fatal(e)
	}
	defer clear(plain)
	changed := func(edit func(map[string]any)) []byte {
		var value map[string]any
		if e := json.Unmarshal(plain, &value); e != nil {
			t.Fatal(e)
		}
		edit(value)
		b, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	// Wrong shapes are authenticated with a real key, so these cases exercise
	// projection validation rather than merely the outer AEAD failure branch.
	cases := [][]byte{
		append(append([]byte(nil), plain...), []byte("{}")...),
		bytes.Replace(plain, []byte(`"Schema":1`), []byte(`"Schema":1,"Schema":1`), 1),
		changed(func(v map[string]any) { v["Unknown"] = true }),
		changed(func(v map[string]any) { v["Session"].(map[string]any)["Authority"] = nil }),
		changed(func(v map[string]any) { delete(v["Session"].(map[string]any)["Authority"].(map[string]any), "Factor") }),
		changed(func(v map[string]any) { v["Session"].(map[string]any)["Lookup"].(map[string]any)["Sum"] = []any{1} }),
		changed(func(v map[string]any) { v["Session"].(map[string]any)["Version"] = 0 }),
		changed(func(v map[string]any) { v["Until"] = "2030-01-01T00:00:00Z" }),
		changed(func(v map[string]any) { v["Eligible"] = "2030-01-01T00:00:00Z" }),
	}
	for _, bad := range cases {
		encrypted, e := crypto.Encrypt(context.Background(), envelope.EncryptRequest{Plaintext: bad, KeyReference: profile.KeyReference, Context: aad})
		if e != nil {
			t.Fatal(e)
		}
		wire, e := encrypted.MarshalBinary()
		if e != nil {
			t.Fatal(e)
		}
		before := reads
		if got, e := codec.Get(context.Background(), request, wire); e != session.ErrUnavailable || got.Authenticated || reads != before+1 {
			t.Fatal("malformed authenticated projection accepted", e)
		}
	}
	// Valid plaintext with changed transport must also reach primary rather than
	// reinterpret a cookie's retained custody as a bearer.
	alternate := bytes.Replace(plain, []byte(`"Transport":1`), []byte(`"Transport":2`), 1)
	if bytes.Equal(alternate, plain) {
		t.Fatal("transport fixture did not change")
	}
	enc, e := crypto.Encrypt(context.Background(), envelope.EncryptRequest{Plaintext: alternate, KeyReference: profile.KeyReference, Context: aad})
	if e != nil {
		t.Fatal(e)
	}
	wire, _ := enc.MarshalBinary()
	if got, e := codec.Get(context.Background(), request, wire); e != session.ErrUnavailable || got.Authenticated {
		t.Fatal("transport mismatch accepted", e)
	}
}
