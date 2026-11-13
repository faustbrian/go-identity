package sessionvalkey_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/session"
	cache "github.com/faustbrian/go-identity/session/valkey"
)

func structuralConfig(t testing.TB) cache.Config {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("certificate setup")
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "configuration-validation"}, NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, public, private)
	if err != nil {
		t.Fatal("certificate setup")
	}
	password, err := cache.NewSecret(bytes.Repeat([]byte{31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	namespaceKey, err := cache.NewSecret(bytes.Repeat([]byte{32}, 32))
	if err != nil {
		t.Fatal(err)
	}
	lookup, err := session.NewDigestKey(1, bytes.Repeat([]byte{33}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return cache.Config{Profile: "positive-cache", Topology: "standalone", Endpoint: "rediss://unreachable.invalid:6380", Username: "default", Namespace: "validation", Password: password, NamespaceKey: namespaceKey, TrustPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), DeploymentEpoch: 1, LookupKeys: []session.DigestKey{lookup}, MaximumDuration: 2 * time.Second, CacheTimeout: 300 * time.Millisecond, MaximumConcurrent: 4, MaximumScopes: 8, MaximumPayloadBytes: 32768}
}

func TestConfigValidateWithoutNetwork(t *testing.T) {
	config := structuralConfig(t)
	// .invalid cannot resolve to a server. Structural validation succeeds with
	// no codec, clock, context, entropy source or externally reachable dependency.
	if err := config.Validate(); err != nil {
		t.Fatal("structurally valid unreachable profile denied", err)
	}
}

type observingClock struct{ calls atomic.Int32 }

func (c *observingClock) Now() time.Time { c.calls.Add(1); return time.Now() }

func TestConfigValidateAndNewRejectTheSameMalformedSelection(t *testing.T) {
	base := structuralConfig(t)
	wrongKey, _ := cache.NewSecret(make([]byte, 64))
	cases := map[string]func(*cache.Config){
		"zero":                  func(c *cache.Config) { *c = cache.Config{} },
		"profile":               func(c *cache.Config) { c.Profile = "authoritative" },
		"cluster":               func(c *cache.Config) { c.Topology = "cluster" },
		"replica":               func(c *cache.Config) { c.Topology = "replica" },
		"sentinel":              func(c *cache.Config) { c.Topology = "sentinel" },
		"username":              func(c *cache.Config) { c.Username = "" },
		"namespace":             func(c *cache.Config) { c.Namespace = "has space" },
		"namespace-limit":       func(c *cache.Config) { c.Namespace = strings.Repeat("a", 129) },
		"epoch":                 func(c *cache.Config) { c.DeploymentEpoch = 0 },
		"password-custody":      func(c *cache.Config) { c.Password = cache.Secret{} },
		"namespace-key-custody": func(c *cache.Config) { c.NamespaceKey = cache.Secret{} },
		"namespace-key-size":    func(c *cache.Config) { c.NamespaceKey = wrongKey },
		"trust-absent":          func(c *cache.Config) { c.TrustPEM = nil },
		"trust-malformed":       func(c *cache.Config) { c.TrustPEM = []byte("not a certificate") },
		"trust-limit":           func(c *cache.Config) { c.TrustPEM = make([]byte, 65537) },
		"payload-small":         func(c *cache.Config) { c.MaximumPayloadBytes = 255 },
		"payload-large":         func(c *cache.Config) { c.MaximumPayloadBytes = 32769 },
		"duration-small":        func(c *cache.Config) { c.MaximumDuration = 0 },
		"duration-large":        func(c *cache.Config) { c.MaximumDuration = 5*time.Second + 1 },
		"cache-small":           func(c *cache.Config) { c.CacheTimeout = 0 },
		"cache-large":           func(c *cache.Config) { c.CacheTimeout = time.Second + 1 },
		"cache-whole-budget":    func(c *cache.Config) { c.MaximumDuration = 300 * time.Millisecond; c.CacheTimeout = c.MaximumDuration },
		"concurrency-small":     func(c *cache.Config) { c.MaximumConcurrent = 0 },
		"concurrency-large":     func(c *cache.Config) { c.MaximumConcurrent = 129 },
		"scopes-small":          func(c *cache.Config) { c.MaximumScopes = 0 },
		"scopes-large":          func(c *cache.Config) { c.MaximumScopes = 4097 },
		"lookup-absent":         func(c *cache.Config) { c.LookupKeys = nil },
		"lookup-zero":           func(c *cache.Config) { c.LookupKeys = []session.DigestKey{{}} },
		"lookup-duplicate":      func(c *cache.Config) { c.LookupKeys = []session.DigestKey{base.LookupKeys[0], base.LookupKeys[0]} },
		"lookup-limit":          func(c *cache.Config) { c.LookupKeys = make([]session.DigestKey, 5) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			config := base
			change(&config)
			if err := config.Validate(); !errors.Is(err, cache.ErrInvalidInput) {
				t.Fatal("malformed configuration accepted", err)
			}
			clock := &observingClock{}
			if got, err := cache.New(context.Background(), config, new(session.EncryptedCacheCodec), clock); got != nil || !errors.Is(err, cache.ErrInvalidInput) {
				t.Fatal("constructor disagrees with pure validation", err)
			}
			if clock.calls.Load() != 0 {
				t.Fatal("invalid configuration reached runtime dependency")
			}
		})
	}
	for _, profile := range []string{"", "secondary-source", "offline-fallback", "cache-only"} {
		config := base
		config.Profile = profile
		if err := config.Validate(); !errors.Is(err, cache.ErrInvalidInput) {
			t.Fatal("unsupported profile accepted")
		}
	}
	for _, endpoint := range []string{"", "redis://localhost:6379", "rediss://localhost", "rediss://localhost:0", "rediss://localhost:65536", "rediss://user:password@localhost:6379", "rediss://localhost:6379/", "rediss://localhost:6379?", "rediss://localhost:6379#", strings.Repeat("x", 2049)} {
		config := base
		config.Endpoint = endpoint
		if err := config.Validate(); !errors.Is(err, cache.ErrInvalidInput) {
			t.Fatal("malformed endpoint accepted")
		}
		clock := &observingClock{}
		if got, err := cache.New(context.Background(), config, new(session.EncryptedCacheCodec), clock); got != nil || !errors.Is(err, cache.ErrInvalidInput) || clock.calls.Load() != 0 {
			t.Fatal("constructor did not reject malformed endpoint before runtime", err)
		}
	}
}

func TestConfigValidateConcurrentReuseDoesNotMutateInput(t *testing.T) {
	config := structuralConfig(t)
	before := config
	before.TrustPEM = bytes.Clone(config.TrustPEM)
	before.LookupKeys = append([]session.DigestKey(nil), config.LookupKeys...)
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				if err := config.Validate(); err != nil {
					t.Error("concurrent structural validation failed")
				}
			}
		}()
	}
	wg.Wait()
	if !reflect.DeepEqual(before, config) {
		t.Fatal("validation mutated caller configuration")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	clock := &observingClock{}
	if got, err := cache.New(ctx, config, new(session.EncryptedCacheCodec), clock); got != nil || !errors.Is(err, cache.ErrUnavailable) {
		t.Fatal("constructor stopped honoring canceled startup", err)
	}
	if clock.calls.Load() != 0 {
		t.Fatal("canceled startup reached runtime dependency")
	}
}

func FuzzConfigValidate(f *testing.F) {
	base := structuralConfig(f)
	f.Add(base.Endpoint, base.TrustPEM)
	f.Add("redis://localhost:6379", []byte("malformed"))
	f.Add("rediss://localhost:0", []byte{})
	f.Fuzz(func(t *testing.T, endpoint string, trust []byte) {
		config := base
		config.Endpoint = endpoint
		config.TrustPEM = trust
		err := config.Validate()
		if err != nil && !errors.Is(err, cache.ErrInvalidInput) {
			t.Fatal("validation leaked a non-structural failure")
		}
	})
}
