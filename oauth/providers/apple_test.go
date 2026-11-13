package providers_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/oauth/providers"
	secretenvelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

func TestAppleEncryptedHandleToTokenEncoder(t *testing.T) {
	signer, request, public := appleFixture(t, elliptic.P256())
	result, err := signer.Sign(context.Background(), request)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	defer result.Secret.Destroy()
	if !result.IssuedAt.Equal(time.Unix(1800000000, 0)) || !result.ExpiresAt.Equal(result.IssuedAt.Add(request.Lifetime)) {
		t.Fatal("original issued/expiry metadata changed")
	}
	var borrowed []byte
	err = result.Secret.Use(func(jwt []byte) error {
		borrowed = jwt // Deliberately retained only to assert post-callback zeroization.
		parts := bytes.Split(jwt, []byte("."))
		if len(parts) != 3 {
			return errors.New("wrong compact shape")
		}
		header, e := base64.RawURLEncoding.Strict().DecodeString(string(parts[0]))
		if e != nil {
			return e
		}
		defer clear(header)
		claims, e := base64.RawURLEncoding.Strict().DecodeString(string(parts[1]))
		if e != nil {
			return e
		}
		defer clear(claims)
		if string(header) != `{"alg":"ES256","kid":"KEYID12345"}` {
			return errors.New("wrong protected header")
		}
		want := fmt.Sprintf(`{"iss":"TEAMID1234","iat":1800000000,"exp":%d,"aud":"https://appleid.apple.com","sub":"com.example.apple"}`, result.ExpiresAt.Unix())
		if string(claims) != want {
			return errors.New("wrong ordered claims")
		}
		sig, e := base64.RawURLEncoding.Strict().DecodeString(string(parts[2]))
		if e != nil {
			return e
		}
		defer clear(sig)
		if len(sig) != 64 {
			return errors.New("signature is not JOSE P-256")
		}
		input := jwt[:len(parts[0])+1+len(parts[1])]
		digest := sha256.Sum256(input)
		if !ecdsa.Verify(public, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			return errors.New("independent ECDSA verification denied")
		}
		// A synchronous form encoder can write the JWT bytes to its intended sink.
		var sink bytes.Buffer
		sink.WriteString("client_id=com.example.apple&client_secret=")
		sink.Write(jwt) // compact base64url and periods need no form escaping.
		defer clear(sink.Bytes())
		if sink.Len() <= len(jwt) {
			return errors.New("missing encoded request")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("consumer encoder/verification: %v", err)
	}
	if len(borrowed) == 0 || !allZero(borrowed) {
		t.Fatal("callback JWT copy was not erased")
	}
}

func TestAppleSigningBounds(t *testing.T) {
	signer, original, _ := appleFixture(t, elliptic.P256())
	for name, mutate := range map[string]func(*providers.AppleClientSecretRequest){
		"short team":          func(r *providers.AppleClientSecretRequest) { r.TeamID = "short" },
		"lowercase team":      func(r *providers.AppleClientSecretRequest) { r.TeamID = "teamid1234" },
		"bad key":             func(r *providers.AppleClientSecretRequest) { r.KeyID = "KEYID1234!" },
		"empty client":        func(r *providers.AppleClientSecretRequest) { r.ClientID = "" },
		"client whitespace":   func(r *providers.AppleClientSecretRequest) { r.ClientID = " com.example.apple" },
		"zero handle":         func(r *providers.AppleClientSecretRequest) { r.SigningKey = providers.AppleSigningKeyHandle{} },
		"zero lifetime":       func(r *providers.AppleClientSecretRequest) { r.Lifetime = 0 },
		"subsecond lifetime":  func(r *providers.AppleClientSecretRequest) { r.Lifetime = time.Second - time.Nanosecond },
		"fractional lifetime": func(r *providers.AppleClientSecretRequest) { r.Lifetime = time.Second + time.Nanosecond },
		"above maximum":       func(r *providers.AppleClientSecretRequest) { r.Lifetime = 15777000*time.Second + time.Second },
	} {
		t.Run(name, func(t *testing.T) {
			r := original
			mutate(&r)
			result, err := signer.Sign(context.Background(), r)
			assertAppleError(t, err, "invalid_bounds")
			assertZeroResult(t, result)
		})
	}
	for _, lifetime := range []time.Duration{time.Second, 15777000 * time.Second} {
		r := original
		r.Lifetime = lifetime
		result, err := signer.Sign(context.Background(), r)
		if err != nil {
			t.Fatal(err)
		}
		if result.ExpiresAt.Sub(result.IssuedAt) != lifetime {
			t.Fatal("wrong accepted boundary")
		}
		result.Secret.Destroy()
	}
}

func TestAppleHandleRejectsNormalizationAndRedacts(t *testing.T) {
	for _, raw := range []string{"", strings.Repeat("a", 257), " x", "x ", "x\n", "é", "x%2Fy", "x?y", "x\\y"} {
		h, err := providers.NewAppleSigningKeyHandle(raw)
		assertAppleError(t, err, "invalid_bounds")
		if h != (providers.AppleSigningKeyHandle{}) {
			t.Fatal("invalid handle returned")
		}
	}
	for _, raw := range []string{"A", "vault:apple/team.KEY_1-2/key", strings.Repeat("a", 256)} {
		h, err := providers.NewAppleSigningKeyHandle(raw)
		if err != nil {
			t.Fatal(err)
		}
		if fmt.Sprintf("%v %#v %+v", h, h, h) != "[REDACTED] [REDACTED] [REDACTED]" {
			t.Fatal("handle formatting did not preserve fixed redaction")
		}
		if _, err := h.MarshalJSON(); err == nil {
			t.Fatal("handle JSON permitted")
		}
		if _, err := h.MarshalText(); err == nil {
			t.Fatal("handle text permitted")
		}
	}
	handle, _ := providers.NewAppleSigningKeyHandle("private:configured/key-handle")
	binding, err := providers.AppleSigningKeyContext(handle)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fmt.Sprint(binding.Values()), "private:configured/key-handle") || bytes.Contains(binding.AdditionalData(), []byte("private:configured/key-handle")) {
		t.Fatal("provisioning AAD exposed the opaque handle")
	}
	other, _ := providers.NewAppleSigningKeyHandle("private:configured/Key-handle")
	otherBinding, _ := providers.AppleSigningKeyContext(other)
	if bytes.Equal(binding.AdditionalData(), otherBinding.AdditionalData()) {
		t.Fatal("AAD normalized distinct handles")
	}
}

func TestAppleUseContainsErrorsPanicsAndDestroy(t *testing.T) {
	signer, request, _ := appleFixture(t, elliptic.P256())
	for _, panicCallback := range []bool{false, true} {
		result, err := signer.Sign(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		var borrowed []byte
		err = result.Secret.Use(func(jwt []byte) error {
			borrowed = jwt
			if panicCallback {
				panic(string(jwt))
			}
			return errors.New(string(jwt))
		})
		var useError providers.AppleClientSecretUseError
		if !errors.As(err, &useError) || strings.Contains(err.Error(), "eyJ") {
			t.Fatal("callback error/panic was not contained")
		}
		if !allZero(borrowed) {
			t.Fatal("failed callback copy retained")
		}
		if result.Secret.Use(nil) == nil {
			t.Fatal("nil callback accepted")
		}
		alias := result.Secret
		result.Secret.Destroy()
		if alias.Use(func([]byte) error { t.Fatal("destroyed secret borrowed"); return nil }) == nil {
			t.Fatal("alias survived destroy")
		}
	}
}

func TestAppleClockAndKeyFailuresReturnZero(t *testing.T) {
	for name, now := range map[string]time.Time{
		"zero":            {},
		"fraction":        time.Unix(1800000000, 1),
		"expiry overflow": time.Unix(1<<63-2, 0),
	} {
		t.Run(name, func(t *testing.T) {
			config, request, _ := appleConfiguration(t, elliptic.P256())
			config.Clock = fixedClock{now}
			signer, err := providers.NewAppleClientSecretSigner(config)
			if err != nil {
				t.Fatal(err)
			}
			result, err := signer.Sign(context.Background(), request)
			assertAppleError(t, err, "invalid_bounds")
			assertZeroResult(t, result)
		})
	}
	for _, curve := range []elliptic.Curve{elliptic.P384(), elliptic.P521()} {
		signer, request, _ := appleFixture(t, curve)
		result, err := signer.Sign(context.Background(), request)
		assertAppleError(t, err, "signer_failure")
		assertZeroResult(t, result)
	}
	signer, request, _ := appleFixture(t, elliptic.P256())
	request.SigningKey, _ = providers.NewAppleSigningKeyHandle("missing-key")
	result, err := signer.Sign(context.Background(), request)
	assertAppleError(t, err, "signer_failure")
	assertZeroResult(t, result)
}

func TestAppleExpiryTimeRepresentationBoundary(t *testing.T) {
	// Go's time.Time stores seconds from year 1, not the Unix epoch. This is
	// the final Unix second representable without overflowing that internal sum.
	lastUnixSecond := int64(math.MaxInt64 - 62135596800)
	for _, test := range []struct {
		name     string
		lifetime time.Duration
		valid    bool
	}{
		{name: "expiry crosses internal bound", lifetime: 2 * time.Second},
		{name: "last representable successful expiry", lifetime: time.Second, valid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			config, request, _ := appleConfiguration(t, elliptic.P256())
			now := time.Unix(lastUnixSecond-1, 0)
			config.Clock = fixedClock{now}
			request.Lifetime = test.lifetime
			signer, err := providers.NewAppleClientSecretSigner(config)
			if err != nil {
				t.Fatal(err)
			}
			result, err := signer.Sign(context.Background(), request)
			defer result.Secret.Destroy()
			if !test.valid {
				if err == nil {
					t.Logf("unexpected success: ExpiresAt.Before(IssuedAt)=%t", result.ExpiresAt.Before(result.IssuedAt))
				}
				assertAppleError(t, err, "invalid_bounds")
				assertZeroResult(t, result)
				return
			}
			if err != nil {
				t.Fatalf("last representable expiry rejected: %v", err)
			}
			if !result.IssuedAt.Equal(now) || !result.ExpiresAt.Equal(time.Unix(lastUnixSecond, 0)) || !result.ExpiresAt.After(result.IssuedAt) || result.ExpiresAt.Sub(result.IssuedAt) != time.Second {
				t.Fatal("last representable expiry did not retain exact original time metadata")
			}
			if err := result.Secret.Use(func(jwt []byte) error {
				parts := bytes.Split(jwt, []byte("."))
				if len(parts) != 3 {
					return errors.New("wrong compact shape")
				}
				payload, err := base64.RawURLEncoding.Strict().DecodeString(string(parts[1]))
				if err != nil {
					return err
				}
				defer clear(payload)
				var claims struct {
					IssuedAt int64 `json:"iat"`
					Expiry   int64 `json:"exp"`
				}
				if json.Unmarshal(payload, &claims) != nil || claims.IssuedAt != now.Unix() || claims.Expiry != lastUnixSecond {
					return errors.New("JWT did not retain exact representable boundary claims")
				}
				return nil
			}); err != nil {
				t.Fatalf("boundary secret: %v", err)
			}
		})
	}
}

type countClock struct {
	now   time.Time
	calls atomic.Int64
}

func (c *countClock) Now() time.Time { c.calls.Add(1); return c.now }

func TestAppleClockIsReadOnceAndConcurrentBorrowHasNoLock(t *testing.T) {
	config, request, _ := appleConfiguration(t, elliptic.P256())
	clock := &countClock{now: time.Unix(1800000000, 0)}
	config.Clock = clock
	signer, err := providers.NewAppleClientSecretSigner(config)
	if err != nil {
		t.Fatal(err)
	}
	result, err := signer.Sign(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if clock.calls.Load() != 1 {
		t.Fatal("signing did not preserve one original clock read")
	}
	if err := result.Secret.Use(func([]byte) error {
		if result.Secret.Use(func([]byte) error { t.Fatal("reentrant borrow admitted"); return nil }) == nil {
			t.Fatal("reentrant use accepted")
		}
		result.Secret.Destroy() // Would deadlock if a callback held the custody lock.
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for range 12 {
		group.Go(func() {
			result, err := signer.Sign(context.Background(), request)
			if err != nil {
				t.Error("concurrent sign failed")
				return
			}
			defer result.Secret.Destroy()
			if err := result.Secret.Use(func(jwt []byte) error {
				if len(jwt) == 0 {
					return errors.New("empty token")
				}
				return nil
			}); err != nil {
				t.Error("concurrent secret use failed")
			}
		})
	}
	group.Wait()
}

func TestAppleCancellationAndEnvelopeFailuresAreRedacted(t *testing.T) {
	config, request, _ := appleConfiguration(t, elliptic.P256())
	signer, err := providers.NewAppleClientSecretSigner(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := signer.Sign(ctx, request)
	assertAppleError(t, err, "canceled")
	assertZeroResult(t, result)
	for _, mode := range []string{"error", "panic", "wait", "late cancel"} {
		t.Run(mode, func(t *testing.T) {
			config, request, _ := appleConfiguration(t, elliptic.P256())
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			config.Envelope, _ = secretenvelope.NewService(failingUnwrapper{mode: mode, cancel: cancel})
			config.Timeout = 10 * time.Millisecond
			signer, err := providers.NewAppleClientSecretSigner(config)
			if err != nil {
				t.Fatal(err)
			}
			result, err := signer.Sign(ctx, request)
			code := "signer_failure"
			if mode == "wait" || mode == "late cancel" {
				code = "canceled"
			}
			assertAppleError(t, err, code)
			assertZeroResult(t, result)
			if strings.Contains(fmt.Sprintf("%v %#v", err, err), "private diagnostic") {
				t.Fatal("signer diagnostic leaked")
			}
		})
	}
}

func TestAppleRejectsMalformedKeysAndWrongEnvelopeBinding(t *testing.T) {
	for _, mode := range []string{"malformed DER", "non EC", "wrong binding", "tampered envelope"} {
		t.Run(mode, func(t *testing.T) {
			config, request, _ := appleConfiguration(t, elliptic.P256())
			binding, err := providers.AppleSigningKeyContext(request.SigningKey)
			if err != nil {
				t.Fatal(err)
			}
			var plaintext []byte
			switch mode {
			case "non EC":
				_, private, e := ed25519.GenerateKey(rand.Reader)
				if e != nil {
					t.Fatal(e)
				}
				defer clear(private)
				plaintext, err = x509.MarshalPKCS8PrivateKey(private)
			case "wrong binding":
				private, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if e != nil {
					t.Fatal(e)
				}
				plaintext, err = x509.MarshalPKCS8PrivateKey(private)
				binding, _ = secretenvelope.NewContext(map[string]string{"wrong": "purpose"})
			default:
				plaintext = []byte("not a private key")
			}
			if err != nil {
				t.Fatal(err)
			}
			defer clear(plaintext)
			encrypted, err := config.Envelope.Encrypt(context.Background(), secretenvelope.EncryptRequest{Plaintext: plaintext, KeyReference: "wrap-v1", Context: binding})
			if err != nil {
				t.Fatal(err)
			}
			if mode == "tampered envelope" {
				encoded, err := encrypted.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				defer clear(encoded)
				encoded[len(encoded)-1] ^= 1
				encrypted, err = secretenvelope.ParseEnvelope(encoded)
				if err != nil {
					t.Fatal(err)
				}
			}
			config.Keys[0].Envelope = encrypted
			signer, err := providers.NewAppleClientSecretSigner(config)
			if err != nil {
				t.Fatal(err)
			}
			result, err := signer.Sign(context.Background(), request)
			assertAppleError(t, err, "signer_failure")
			assertZeroResult(t, result)
		})
	}
}

func TestAppleConstructionOwnershipAndSecretDiagnostics(t *testing.T) {
	config, request, _ := appleConfiguration(t, elliptic.P256())
	for name, mutate := range map[string]func(*providers.AppleClientSecretSignerConfig){
		"nil envelope": func(c *providers.AppleClientSecretSignerConfig) { c.Envelope = nil },
		"nil clock":    func(c *providers.AppleClientSecretSignerConfig) { c.Clock = nil },
		"no keys":      func(c *providers.AppleClientSecretSignerConfig) { c.Keys = nil },
		"too many keys": func(c *providers.AppleClientSecretSignerConfig) {
			c.Keys = make([]providers.AppleSigningKeyEnvelope, 65)
		},
		"duplicate keys": func(c *providers.AppleClientSecretSignerConfig) {
			c.Keys = []providers.AppleSigningKeyEnvelope{c.Keys[0], c.Keys[0]}
		},
		"zero envelope": func(c *providers.AppleClientSecretSignerConfig) {
			c.Keys = []providers.AppleSigningKeyEnvelope{{Handle: c.Keys[0].Handle}}
		},
		"short timeout": func(c *providers.AppleClientSecretSignerConfig) { c.Timeout = time.Nanosecond },
		"long timeout":  func(c *providers.AppleClientSecretSignerConfig) { c.Timeout = 31 * time.Second },
	} {
		t.Run(name, func(t *testing.T) {
			copy := config
			mutate(&copy)
			signer, err := providers.NewAppleClientSecretSigner(copy)
			assertAppleError(t, err, "invalid_bounds")
			if signer != nil {
				t.Fatal("invalid construction returned signer")
			}
		})
	}
	signer, err := providers.NewAppleClientSecretSigner(config)
	if err != nil {
		t.Fatal(err)
	}
	config.Keys[0] = providers.AppleSigningKeyEnvelope{}
	result, err := signer.Sign(context.Background(), request)
	if err != nil {
		t.Fatal("source mutation changed configured key set")
	}
	defer result.Secret.Destroy()
	for _, value := range []any{request, result, result.Secret, request.SigningKey, signer, config} {
		if strings.Contains(fmt.Sprintf("%v %#v %+v", value, value, value), "eyJ") || strings.Contains(fmt.Sprintf("%v %#v %+v", value, value, value), "vault:apple") {
			t.Fatal("secret-bearing diagnostic leaked")
		}
	}
	for _, value := range []any{request, result, result.Secret, request.SigningKey} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("secret-bearing JSON was accepted")
		}
	}
	var nilSigner *providers.AppleClientSecretSigner
	zero, err := nilSigner.Sign(context.Background(), request)
	assertAppleError(t, err, "signer_failure")
	assertZeroResult(t, zero)
	zero, err = signer.Sign(nil, request)
	assertAppleError(t, err, "invalid_bounds")
	assertZeroResult(t, zero)
}

func FuzzAppleSigningKeyHandle(f *testing.F) {
	for _, seed := range []string{"", "vault:apple/key-v1", " A", "é", "x\n", strings.Repeat("a", 257)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		handle, err := providers.NewAppleSigningKeyHandle(raw)
		valid := len(raw) >= 1 && len(raw) <= 256
		for i := 0; i < len(raw) && valid; i++ {
			b := raw[i]
			valid = b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || strings.ContainsRune("._:/-", rune(b))
		}
		if !valid {
			assertAppleError(t, err, "invalid_bounds")
			return
		}
		if err != nil {
			t.Fatal("valid exact ASCII handle rejected")
		}
		if fmt.Sprintf("%v", handle) != "[REDACTED]" {
			t.Fatal("handle formatting changed")
		}
		binding, err := providers.AppleSigningKeyContext(handle)
		if err != nil || len(binding.Values()["key"]) != 64 {
			t.Fatal("valid handle has no bounded AAD digest")
		}
	})
}

type failingUnwrapper struct {
	mode   string
	cancel context.CancelFunc
}

func (f failingUnwrapper) GenerateDataKey(context.Context, string, secretenvelope.Context) (secretenvelope.DataKey, error) {
	return secretenvelope.DataKey{}, errors.New("unused")
}
func (f failingUnwrapper) DecryptDataKey(ctx context.Context, _ string, _ []byte, _ secretenvelope.Context) ([]byte, error) {
	switch f.mode {
	case "panic":
		panic("private diagnostic")
	case "wait":
		<-ctx.Done()
		return nil, ctx.Err()
	case "late cancel":
		f.cancel()
		return nil, errors.New("private diagnostic")
	default:
		return nil, errors.New("private diagnostic")
	}
}

func appleFixture(t *testing.T, curve elliptic.Curve) (*providers.AppleClientSecretSigner, providers.AppleClientSecretRequest, *ecdsa.PublicKey) {
	t.Helper()
	config, request, public := appleConfiguration(t, curve)
	signer, err := providers.NewAppleClientSecretSigner(config)
	if err != nil {
		t.Fatal(err)
	}
	return signer, request, public
}

func appleConfiguration(t *testing.T, curve elliptic.Curve) (providers.AppleClientSecretSignerConfig, providers.AppleClientSecretRequest, *ecdsa.PublicKey) {
	t.Helper()
	private, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(der)
	wrapping := make([]byte, 32)
	if _, err := rand.Read(wrapping); err != nil {
		t.Fatal(err)
	}
	defer clear(wrapping)
	keyringProvider, err := keyring.New(map[string][]byte{"wrap-v1": wrapping})
	if err != nil {
		t.Fatal(err)
	}
	envelopeService, err := secretenvelope.NewService(keyringProvider)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := providers.NewAppleSigningKeyHandle("vault:apple/team/key-v1")
	if err != nil {
		t.Fatal(err)
	}
	binding, err := providers.AppleSigningKeyContext(handle)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := envelopeService.Encrypt(context.Background(), secretenvelope.EncryptRequest{Plaintext: der, KeyReference: "wrap-v1", Context: binding})
	if err != nil {
		t.Fatal(err)
	}
	config := providers.AppleClientSecretSignerConfig{Envelope: envelopeService, Keys: []providers.AppleSigningKeyEnvelope{{Handle: handle, Envelope: envelope}}, Clock: fixedClock{time.Unix(1800000000, 0)}, Timeout: time.Second}
	request := providers.AppleClientSecretRequest{TeamID: "TEAMID1234", ClientID: "com.example.apple", KeyID: "KEYID12345", SigningKey: handle, Lifetime: 5 * time.Minute}
	return config, request, &private.PublicKey
}

func assertAppleError(t *testing.T, err error, code string) {
	t.Helper()
	var classified providers.AppleClientSecretError
	if !errors.As(err, &classified) || classified.Code() != code {
		t.Fatalf("expected %s, got %v", code, err)
	}
}
func assertZeroResult(t *testing.T, r providers.AppleClientSecretResult) {
	t.Helper()
	if !r.IssuedAt.IsZero() || !r.ExpiresAt.IsZero() || r.Secret.Use(func([]byte) error { t.Fatal("failure returned secret"); return nil }) == nil {
		t.Fatal("failure did not return zero result")
	}
}
func allZero(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}
