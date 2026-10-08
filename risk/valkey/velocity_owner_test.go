package valkey

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/risk/internal/velocity"
)

func TestPublicVelocityOwnerConstructionAndShutdown(t *testing.T) {
	f := newConfirmationFixture(t, 0)
	secret := []byte("fixture-password")
	credential, err := NewCredential("default", secret)
	if err != nil {
		t.Fatal(err)
	}
	secret[0] = 'X'
	c := f.owner.transport.config
	client := c.tls.Clone()
	client.RootCAs = nil
	config := VelocityRecoveryConfig{Namespace: f.owner.layout.namespace, ReplaySecret: f.owner.layout.secret, Policy: f.owner.layout.policy, Keys: f.owner.layout.keys, Endpoint: c.endpoint, TLS: client, TrustPEM: f.wire.trustPEM, Credential: credential, Timeout: c.timeout, PoolSize: c.poolSize, Topology: "standalone"}
	owner, err := NewVelocityRecovery(config)
	if err != nil {
		t.Fatal("public native owner missing", err)
	}
	defer owner.Close(context.Background())
	if owner.state.transport.config.credential.password != "fixture-password" {
		t.Fatal("caller mutated retained credential")
	}
	primaryIssuer, primaryVerifier, err := owner.PrimaryAuthorities()
	if err != nil || primaryIssuer.ValidateNative(primaryVerifier) != nil {
		t.Fatal("public primary authorities are not paired", err)
	}
	if err := owner.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := owner.PrimaryAuthorities(); err == nil {
		t.Fatal("closed owner exported primary capabilities")
	}
	// Deliberate unit boundary: already-recovered native owner and simulated
	// primary. Joint public-constructor/real-primary proving is separate.
	owner = VelocityRecovery{state: &f.owner}
	ack, err := owner.Confirm(context.Background(), f.lease, f.closure, f.publication, f.confirmation)
	if err != nil {
		t.Fatal("public native confirmation missing", err)
	}
	eligible, err := f.journal.AcknowledgeEligibility(context.Background(), f.lease, f.closure, f.publication, f.confirmation, ack, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	journal, err := velocity.BindJournal(f.owner.layout.replay.Namespace(), func(risk.CounterCommand) error { return nil }, func(context.Context, risk.CounterCommand) error { return nil }, func(context.Context, risk.CounterCommand) (velocity.Attempt, error) {
		t.Fatal("constructor dispatched intent")
		return velocity.Attempt{}, nil
	}, func(context.Context, risk.CounterCommand) (risk.CounterResult, error) {
		t.Fatal("constructor read replay")
		return risk.CounterResult{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := f.native.Verifier()
	if err != nil {
		t.Fatal(err)
	}
	journal, err = velocity.BindCurrentJournal(context.Background(), journal, f.owner.reader, verifier, velocity.CurrentChain{Lease: f.lease, Closure: f.closure, Publication: f.publication, Confirmation: f.confirmation, Native: ack, Eligibility: eligible})
	if err != nil {
		t.Fatal(err)
	}
	store, err := owner.OwnedCounterStore(context.Background(), journal)
	if err != nil || store == nil {
		t.Fatal("public journal-fenced native factory missing", err)
	}
	if _, err := owner.OwnedCounterStore(nil, journal); err == nil {
		t.Fatal("nil factory context accepted")
	}
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if _, err := owner.OwnedCounterStore(canceled, journal); !errors.Is(err, context.Canceled) {
		t.Fatal("factory cancellation lost", err)
	}
	foreignOwner, err := NewVelocityRecovery(config)
	if err != nil {
		t.Fatal(err)
	}
	defer foreignOwner.Close(context.Background())
	if _, err := foreignOwner.OwnedCounterStore(context.Background(), journal); err == nil {
		t.Fatal("foreign native graph accepted")
	}
	if _, err := owner.OwnedCounterStore(context.Background(), velocity.Journal{}); err == nil {
		t.Fatal("zero primary connection accepted")
	}
	for _, value := range []any{credential, config, owner, store} {
		if strings.Contains(fmt.Sprintf("%+v", value), "fixture-password") {
			t.Fatal("public custody leaked")
		}
		if _, err := json.Marshal(value); !errors.Is(err, risk.ErrSensitiveSerialization) {
			t.Fatal("public custody serialized", err)
		}
	}
	if err := owner.Close(context.Background()); err != nil {
		t.Fatal("public shutdown failed", err)
	}
	if _, err := owner.OwnedCounterStore(context.Background(), journal); err == nil {
		t.Fatal("closed native owner constructed store")
	}
	if err := owner.Close(context.Background()); err != nil {
		t.Fatal("repeat shutdown failed", err)
	}
	if err := (VelocityRecovery{}).Close(context.Background()); err == nil {
		t.Fatal("zero shutdown accepted")
	}
}

func TestPublicVelocityOwnerRejectsInvalidConfigurationAndZero(t *testing.T) {
	f := newConfirmationFixture(t, 0)
	credential, _ := NewCredential("default", []byte("fixture-password"))
	c := f.owner.transport.config
	client := c.tls.Clone()
	client.RootCAs = nil
	config := VelocityRecoveryConfig{Namespace: f.owner.layout.namespace, ReplaySecret: f.owner.layout.secret, Policy: f.owner.layout.policy, Keys: f.owner.layout.keys, Endpoint: c.endpoint, TLS: client, TrustPEM: f.wire.trustPEM, Credential: credential, Timeout: c.timeout, PoolSize: c.poolSize, Topology: "standalone"}
	for _, change := range []func(*VelocityRecoveryConfig){
		func(c *VelocityRecoveryConfig) { c.Namespace = "" }, func(c *VelocityRecoveryConfig) { c.ReplaySecret = nil }, func(c *VelocityRecoveryConfig) { c.Policy = risk.Policy{} }, func(c *VelocityRecoveryConfig) { c.Keys = nil }, func(c *VelocityRecoveryConfig) { c.Endpoint = "redis://localhost:6379" }, func(c *VelocityRecoveryConfig) { c.TLS = nil }, func(c *VelocityRecoveryConfig) { c.Credential = Credential{} }, func(c *VelocityRecoveryConfig) { c.Timeout = 0 }, func(c *VelocityRecoveryConfig) { c.PoolSize = 0 }, func(c *VelocityRecoveryConfig) { c.Topology = "cluster" }, func(c *VelocityRecoveryConfig) { c.TLS = c.TLS.Clone(); c.TLS.InsecureSkipVerify = true }, func(c *VelocityRecoveryConfig) { c.TLS = c.TLS.Clone(); c.TLS.MinVersion = tls.VersionTLS10 },
		func(c *VelocityRecoveryConfig) { c.TLS = c.TLS.Clone(); c.TLS.Time = time.Now },
		func(c *VelocityRecoveryConfig) { c.TLS = c.TLS.Clone(); c.TLS.Rand = bytes.NewReader(nil) },
		func(c *VelocityRecoveryConfig) { c.TLS = c.TLS.Clone(); c.TLS.Certificates = []tls.Certificate{{}} },
		func(c *VelocityRecoveryConfig) { c.TLS = c.TLS.Clone(); c.TLS.NextProtos = []string{"h2"} },
	} {
		bad := config
		change(&bad)
		if owner, err := NewVelocityRecovery(bad); err == nil || owner.state != nil {
			if owner.state != nil {
				_ = owner.Close(context.Background())
			}
			t.Fatal("invalid public configuration accepted")
		}
	}
	for _, input := range []struct {
		user string
		pass []byte
	}{{"", []byte("x")}, {"default", nil}, {"default", make([]byte, 4097)}} {
		if _, err := NewCredential(input.user, input.pass); err == nil {
			t.Fatal("invalid credential accepted")
		}
	}
	zero := VelocityRecovery{}
	if _, _, err := zero.PrimaryAuthorities(); err == nil {
		t.Fatal("zero exported primary authority")
	}
	if err := zero.Fence(context.Background(), risk.VelocityLease{}, risk.VelocityLease{}); err == nil {
		t.Fatal("zero fenced")
	}
	if _, err := zero.Restore(context.Background(), risk.VelocityLease{}, risk.VelocityHistory{}); err == nil {
		t.Fatal("zero restored")
	}
	if _, err := zero.Publish(context.Background(), risk.VelocityLease{}, risk.VelocityClosure{}); err == nil {
		t.Fatal("zero published")
	}
	if _, err := zero.Confirm(context.Background(), risk.VelocityLease{}, risk.VelocityClosure{}, risk.VelocityPublication{}, risk.VelocityConfirmation{}); err == nil {
		t.Fatal("zero confirmed")
	}
	if _, err := zero.OwnedCounterStore(context.Background(), velocity.Journal{}); err == nil {
		t.Fatal("zero constructed store")
	}
	for _, value := range []interface{ MarshalText() ([]byte, error) }{credential, config, zero} {
		if _, err := value.MarshalText(); !errors.Is(err, risk.ErrSensitiveSerialization) {
			t.Fatal("public text serialization exposed custody", err)
		}
	}
}

func TestPublicVelocityOwnerOwnsTLSHandshakeSlices(t *testing.T) {
	for _, mode := range []string{"cipher", "curve", "trust"} {
		t.Run(mode, func(t *testing.T) {
			f := newConfirmationFixture(t, 0)
			credential, _ := NewCredential("default", []byte("fixture-password"))
			client := f.owner.transport.config.tls.Clone()
			client.RootCAs = nil
			trust := bytes.Clone(f.wire.trustPEM)
			client.MaxVersion = tls.VersionTLS12
			client.CipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
			client.CurvePreferences = []tls.CurveID{tls.X25519}
			owner, err := NewVelocityRecovery(VelocityRecoveryConfig{Namespace: "public-tls-owned", ReplaySecret: f.owner.layout.secret, Policy: f.owner.layout.policy, Keys: f.owner.layout.keys, Endpoint: f.owner.transport.config.endpoint, TLS: client, TrustPEM: trust, Credential: credential, Timeout: time.Second, PoolSize: 1, Topology: "standalone"})
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close(context.Background())
			owner.state.transport.dial = f.owner.transport.dial // Deliberate test-only TLS server boundary.
			if mode == "cipher" {
				client.CipherSuites[0] = tls.TLS_RSA_WITH_AES_128_CBC_SHA256
			} else if mode == "curve" {
				client.CurvePreferences[0] = 0
			} else {
				clear(trust)
				client.ServerName = "untrusted.invalid"
			}
			primary, _, err := owner.PrimaryAuthorities()
			if err != nil {
				t.Fatal(err)
			}
			lease, err := primary.Lease(risk.VelocityLeaseBinding{Tenant: "tenant", Namespace: owner.state.layout.replay.Namespace(), Epoch: [16]byte{44}, Generation: 1, Owner: [16]byte{22}, ExpiresAt: time.UnixMicro(f.db.now).Add(time.Minute)}, func(context.Context) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			if err := owner.Fence(context.Background(), lease, risk.VelocityLease{}); err != nil {
				t.Fatal("caller mutation changed retained native TLS handshake", err)
			}
		})
	}
}

func TestPublicVelocityOwnerRejectsCallerTrustPool(t *testing.T) {
	f := newConfirmationFixture(t, 0)
	block, _ := pem.Decode(f.wire.trustPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCertWithConstraint(cert, func([]*x509.Certificate) error { t.Error("caller constraint executed"); return nil })
	client := f.owner.transport.config.tls.Clone()
	client.RootCAs = pool
	credential, _ := NewCredential("default", []byte("fixture-password"))
	owner, err := NewVelocityRecovery(VelocityRecoveryConfig{Namespace: f.owner.layout.namespace, ReplaySecret: f.owner.layout.secret, Policy: f.owner.layout.policy, Keys: f.owner.layout.keys, Endpoint: f.owner.transport.config.endpoint, TLS: client, TrustPEM: f.wire.trustPEM, Credential: credential, Timeout: time.Second, PoolSize: 1, Topology: "standalone"})
	if owner.state != nil {
		defer owner.Close(context.Background())
	}
	if !errors.Is(err, risk.ErrInvalidPolicy) || owner.state != nil {
		t.Fatal("public constructor retained opaque caller trust callbacks")
	}
}

func TestOwnedVelocityTrustStrictBounds(t *testing.T) {
	f := newConfirmationFixture(t, 0)
	client := f.owner.transport.config.tls.Clone()
	client.RootCAs = nil
	valid := f.wire.trustPEM
	for name, input := range map[string][]byte{
		"empty":                       nil,
		"whitespace":                  []byte(" \n\t"),
		"oversize":                    bytes.Repeat([]byte(" "), 65537),
		"garbage":                     append(bytes.Clone(valid), 'x'),
		"preamble":                    append([]byte("ignored prefix\n"), valid...),
		"bad DER":                     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid")}),
		"wrong type":                  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("invalid")}),
		"header":                      pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Origin": "caller"}, Bytes: []byte("invalid")}),
		"malformed followed by valid": append([]byte("-----BEGIN CERTIFICATE-----\n!\n-----END CERTIFICATE-----\n"), valid...),
		"unclosed followed by valid":  append([]byte("-----BEGIN CERTIFICATE-----\n!\n"), valid...),
		"truncated":                   valid[:len(valid)/2],
		"too many":                    bytes.Repeat(valid, 33),
	} {
		t.Run(name, func(t *testing.T) {
			if config, err := ownedVelocityTLS(client, input); !errors.Is(err, risk.ErrInvalidPolicy) || config != nil {
				t.Fatal("invalid trust accepted")
			}
		})
	}
	for _, n := range []int{65535, 65536} {
		input := append(bytes.Clone(valid), bytes.Repeat([]byte(" "), n-len(valid))...)
		if config, err := ownedVelocityTLS(client, input); err != nil || config.RootCAs == nil {
			t.Fatal("bounded valid trust rejected", err)
		}
	}
	for _, n := range []int{31, 32} {
		if _, err := ownedVelocityTLS(client, bytes.Repeat(valid, n)); err != nil {
			t.Fatal("bounded duplicate roots rejected", err)
		}
	}
}

func FuzzOwnedVelocityTrust(f *testing.F) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Unix(0, 0), NotAfter: time.Unix(4102444800, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
	if err != nil {
		f.Fatal(err)
	}
	valid := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	for _, seed := range [][]byte{nil, valid, valid[:len(valid)/2], append(bytes.Clone(valid), 'x'), bytes.Repeat([]byte(" "), 65537), bytes.Repeat(valid, 33), append([]byte("-----BEGIN CERTIFICATE-----\n!\n-----END CERTIFICATE-----\n"), valid...), append([]byte("-----BEGIN CERTIFICATE-----\n!\n"), valid...)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		config, err := ownedVelocityTLS(&tls.Config{ServerName: "localhost", MinVersion: tls.VersionTLS12}, input)
		if err != nil {
			if !errors.Is(err, risk.ErrInvalidPolicy) || config != nil {
				t.Fatal("trust failure exposed partial configuration")
			}
			return
		}
		if len(input) == 0 || len(input) > 65536 || config.RootCAs == nil || !supportedNativeTLS(config) {
			t.Fatal("trust acceptance escaped bounded TLS policy")
		}
	})
}

// Primary callbacks are deliberate doubles. The native transport, embedded
// scripts and public factory are real; this does not prove durable composition.
func TestPublicVelocityStoreConservesJournaledEffects(t *testing.T) {
	for _, mode := range []string{"healthy", "primary_before", "missing_marker", "lost_reply", "primary_after", "result_failed", "closed", "foreign_tenant", "wrong_policy", "protected"} {
		t.Run(mode, func(t *testing.T) {
			f := newConfirmationFixture(t, 0)
			owner := VelocityRecovery{state: &f.owner}
			ack, err := owner.Confirm(context.Background(), f.lease, f.closure, f.publication, f.confirmation)
			if err != nil {
				t.Fatal(err)
			}
			var unavailable atomic.Bool
			eligibility, err := f.journal.AcknowledgeEligibility(context.Background(), f.lease, f.closure, f.publication, f.confirmation, ack, func(context.Context) error {
				if unavailable.Load() {
					return errors.New("simulated primary unavailable")
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			var intent bool
			var recorded risk.CounterResult
			journal, err := velocity.BindJournal(f.owner.layout.replay.Namespace(), func(c risk.CounterCommand) error {
				return c.ValidateConfiguration(f.owner.layout.policy, f.owner.layout.keys)
			}, func(context.Context, risk.CounterCommand) error { return nil }, func(ctx context.Context, c risk.CounterCommand) (velocity.Attempt, error) {
				if intent {
					return velocity.Attempt{}, errors.New("simulated existing original intent")
				}
				intent = true
				return velocity.BindAttempt(c, func(_ context.Context, result risk.CounterResult) error {
					recorded = result
					if mode == "result_failed" {
						return errors.New("simulated result commit failure")
					}
					return nil
				})
			}, func(_ context.Context, c risk.CounterCommand) (risk.CounterResult, error) {
				if _, _, err := recorded.Declaration(c); err == nil {
					return recorded, nil
				}
				return risk.CounterResult{}, errors.New("simulated unresolved original intent")
			})
			if err != nil {
				t.Fatal(err)
			}
			verifier, _ := f.native.Verifier()
			journal, err = velocity.BindCurrentJournal(context.Background(), journal, f.owner.reader, verifier, velocity.CurrentChain{Lease: f.lease, Closure: f.closure, Publication: f.publication, Confirmation: f.confirmation, Native: ack, Eligibility: eligibility})
			if err != nil {
				t.Fatal(err)
			}
			store, err := owner.OwnedCounterStore(context.Background(), journal)
			if err != nil {
				t.Fatal(err)
			}
			policy, keys := f.owner.layout.policy, f.owner.layout.keys
			if mode == "wrong_policy" {
				policy, keys, _ = commandFixture(t, 9, 8)
			}
			coordinator, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: policy, Keys: keys, Store: store, Clock: func() time.Time { return time.UnixMicro(f.db.now) }, Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			tenant := "tenant"
			if mode == "foreign_tenant" {
				tenant = "foreign"
			}
			command := prepareFixture(t, coordinator, tenant, "public-effect", "192.0.2.1")
			if mode == "protected" {
				command, err = coordinator.Prepare(risk.Context{Tenant: tenant, Operation: "identity.password.change", Attempt: "public-protected"}, risk.Subject{User: "user", Session: "session", Network: "192.0.2.1"}, risk.ReserveWithCommand)
				if !errors.Is(err, risk.ErrUnsupportedCounterPhase) || intent {
					t.Fatal("protected preparation granted independent counter authority", err)
				}
				return
			}
			switch mode {
			case "primary_before":
				unavailable.Store(true)
			case "missing_marker":
				delete(f.db.strings, f.plan.keys[0])
			case "closed":
				if err := owner.Close(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			originalReply := f.wire.reply
			var debits atomic.Int32
			f.wire.reply = func(request []string) string {
				if request[1] == mutationScript {
					if !intent {
						t.Error("native effect preceded acknowledged intent")
					}
					debits.Add(1)
					response := originalReply(request)
					if mode == "primary_after" {
						unavailable.Store(true)
					}
					if mode == "lost_reply" {
						return ""
					}
					return response
				}
				return originalReply(request)
			}
			result, err := store.Mutate(context.Background(), command)
			outcome, _, declarationErr := result.Declaration(command)
			retained, _, retainedErr := recorded.Declaration(command)
			committed := mode == "healthy" || mode == "primary_after" || mode == "result_failed"
			if committed {
				if declarationErr != nil || outcome != risk.CounterCommitted || retainedErr != nil || retained != risk.CounterCommitted {
					t.Fatal("factory lost committed native outcome", err, outcome)
				}
				if (mode == "healthy") != (err == nil) {
					t.Fatal("post-effect failure granted admission or healthy denied", err)
				}
			} else if err == nil {
				t.Fatal("invalid factory path admitted", mode)
			}
			if mode == "lost_reply" && (declarationErr != nil || outcome != risk.CounterUnknown) {
				t.Fatal("lost native response fabricated outcome", outcome)
			}
			if committed || mode == "lost_reply" {
				if debits.Load() != 1 {
					t.Fatal("native effect count", debits.Load())
				}
				before, expiry := cloneScriptStrings(f.db.strings), cloneScriptExpiry(f.db.expiry)
				replay, replayErr := store.Mutate(context.Background(), command)
				replayed, _, replayDeclarationErr := replay.Declaration(command)
				if mode == "healthy" {
					if replayErr != nil || replayDeclarationErr != nil || replayed != risk.CounterCommitted {
						t.Fatal("terminal readback failed", replayErr)
					}
				}
				if debits.Load() != 1 {
					t.Fatal("original intent authorized redispatch")
				}
				for k, v := range before {
					if f.db.strings[k] != v || f.db.expiry[k] != expiry[k] {
						t.Fatal("terminal replay changed original state or expiry")
					}
				}
			} else if debits.Load() != 0 || intent {
				t.Fatal("invalid command/current state reached intent or effect")
			}
		})
	}
}
