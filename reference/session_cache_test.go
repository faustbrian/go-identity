package reference

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/faustbrian/go-clock"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	sessionvalkey "github.com/faustbrian/go-identity/session/valkey"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

type cacheInactivePrimary struct{ calls int }

func (p *cacheInactivePrimary) ObserveSession(context.Context, session.SessionLookup) (session.SessionObservation, error) {
	p.calls++
	return session.SessionObservation{}, nil
}

func sessionCacheTestConfiguration(t *testing.T) (SessionCacheConfiguration, sessionpg.SignOutServiceConfig, *session.SessionService, envelope.KeyProvider, *cacheInactivePrimary) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost"}, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	lookup, err := session.NewDigestKey(1, bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	validation := session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: "service-a", Clock: clock.System{}, MaximumDuration: 100 * time.Millisecond, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{lookup}}
	reader := &cacheInactivePrimary{}
	primary, err := session.NewSessionService(reader, validation)
	if err != nil {
		t.Fatal(err)
	}
	validation.Clock = nil
	native := sessionpg.SignOutServiceConfig{Validation: validation, Execution: sessionpg.IssueExecutorConfig{Clock: clock.System{}}, MaximumDuration: time.Second}
	keys, err := keyring.New(map[string][]byte{"cache-v1": bytes.Repeat([]byte{2}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	password, _ := sessionvalkey.NewSecret(bytes.Repeat([]byte{3}, 32))
	namespace, _ := sessionvalkey.NewSecret(bytes.Repeat([]byte{4}, 32))
	config := SessionCacheConfiguration{
		Codec:  session.EncryptedCacheConfig{Issuer: "deployment", Environment: "test", DeploymentEpoch: 1, KeyReference: "cache-v1", MaximumAge: 20 * time.Second, MaximumBytes: 32768},
		Valkey: sessionvalkey.Config{Profile: "positive-cache", Topology: "standalone", Endpoint: "rediss://localhost:1", Username: "default", Password: password, NamespaceKey: namespace, Namespace: "session-test", TrustPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), DeploymentEpoch: 1, MaximumDuration: time.Second, CacheTimeout: 10 * time.Millisecond, MaximumConcurrent: 2, MaximumScopes: 16, MaximumPayloadBytes: 32768},
	}
	return config, native, primary, keys, reader
}

func TestSessionCacheCompositionHasNoIOAndFreezesConfiguration(t *testing.T) {
	config, native, primary, keys, reader := sessionCacheTestConfiguration(t)
	owner, err := composeSessionCache(&config, native, primary, keys)
	if err != nil || owner == nil || reader.calls != 0 {
		t.Fatal("valid unreachable cache could not compose without IO", err)
	}
	trust := append([]byte(nil), config.Valkey.TrustPEM...)
	config.Valkey.TrustPEM[0] ^= 1
	config.Valkey.Endpoint = "rediss://other.example:1"
	native.Validation.LookupKeys[0] = session.DigestKey{}
	if !bytes.Equal(owner.config.TrustPEM, trust) || owner.config.Endpoint != "rediss://localhost:1" || len(owner.config.LookupKeys) != 1 {
		t.Fatal("composed cache retained caller-mutable configuration")
	}
	if err := owner.config.Validate(); err != nil {
		t.Fatal("derived lookup custody changed after caller mutation", err)
	}
	if _, err := json.Marshal(config); err == nil {
		t.Fatal("cache deployment configuration was implicitly exported")
	}
}

func TestSessionCacheCompositionRejectsConflictingCustody(t *testing.T) {
	for _, scenario := range []string{"epoch", "lookup", "payload", "budget", "fallback-budget", "trust", "primary", "keys"} {
		t.Run(scenario, func(t *testing.T) {
			config, native, primary, keys, reader := sessionCacheTestConfiguration(t)
			switch scenario {
			case "epoch":
				config.Valkey.DeploymentEpoch++
			case "lookup":
				config.Valkey.LookupKeys = append(config.Valkey.LookupKeys, native.Validation.LookupKeys...)
			case "payload":
				config.Valkey.MaximumPayloadBytes = 1024
			case "budget":
				config.Valkey.MaximumDuration = 2 * time.Second
			case "fallback-budget":
				config.Valkey.MaximumDuration = 110 * time.Millisecond
			case "trust":
				config.Valkey.TrustPEM = []byte("invalid")
			case "primary":
				primary = nil
			case "keys":
				keys = nil
			}
			if owner, err := composeSessionCache(&config, native, primary, keys); err == nil || owner != nil || reader.calls != 0 {
				t.Fatal("conflicting cache custody accepted or performed IO")
			}
		})
	}
	if owner, err := composeSessionCache(nil, sessionpg.SignOutServiceConfig{}, nil, nil); err != nil || owner != nil {
		t.Fatal("unselected cache acquired dependencies", err)
	}
}
