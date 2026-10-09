package valkey

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/risk/internal/velocity"
)

// Credential owns a copied username/password for native authentication. Zero
// is invalid; copies are immutable and concurrent-safe. Rotation requires a
// new owner, not an update to an existing transport. Formatting is redacted and
// serialization is denied; the caller must protect and discard its input bytes.
type Credential struct{ value nativeCredential }

// NewCredential copies a bounded username (1–128 scope characters) and password
// (1–4096 bytes). Invalid values return ErrInvalidPolicy without disclosing them.
func NewCredential(username string, password []byte) (Credential, error) {
	c, err := newNativeCredential(username, password)
	return Credential{value: c}, err
}

// VelocityRecoveryConfig selects immutable native resources and policy custody,
// never an application executor, health checker, marker or issuance capability.
// Namespace and ReplaySecret must match the primary journal; secret and Keys
// are copied. Endpoint must be canonical rediss://DNS:port without userinfo.
// TLS requires matching ServerName, explicit trust and TLS 1.2 or later; custom
// verification, clock, entropy, certificate or session callbacks are forbidden.
// Client certificates, ALPN and ECH are unsupported. Trust and cipher/curve
// preference slices (at most 16/8 entries) are copied. TLS.RootCAs must be nil:
// TrustPEM supplies 1–65536 bytes containing at most 32 header-free CERTIFICATE
// blocks and whitespace only. Certificates are parsed into owned trust roots;
// no caller trust-pool objects or constraint callbacks are retained. Root
// admission requires valid certificate syntax; TLS enforces chain/name validity.
// Timeout must
// be 100ms–10s, PoolSize 1–200, and Topology exactly "standalone". Other profiles
// fail rather than silently degrade. Zero is invalid. Treat all inputs as
// sensitive; formatting is redacted and serialization is denied.
type VelocityRecoveryConfig struct {
	Namespace    string
	ReplaySecret []byte
	Policy       risk.Policy
	Keys         []risk.CounterDigestKey
	Endpoint     string
	TLS          *tls.Config
	TrustPEM     []byte
	Credential   Credential
	Timeout      time.Duration
	PoolSize     int
	Topology     string
}

// VelocityRecovery owns one native transport lifetime and its existing core
// custody graph. Copies share the same lifetime and immutable configuration;
// Close cancels all of them. No native issuance capability is exposed. A new
// owner creates a fresh graph, so it cannot silently adopt a predecessor's
// activation or continuity. Construction grants no recovery or traffic health.
// Operations are concurrent-safe, bounded and fail closed; zero is invalid.
type VelocityRecovery struct{ state *ownedRecovery }

// NewVelocityRecovery validates/copies configuration without network IO or
// goroutines. It creates one isolated existing core graph for this transport;
// PrimaryAuthorities supplies only the paired primary capabilities. The caller
// owns Close, including if later composition fails. Invalid input returns
// ErrInvalidPolicy; no resource or partial owner is exposed on failure.
func NewVelocityRecovery(c VelocityRecoveryConfig) (VelocityRecovery, error) {
	layout, err := newCommandLayout(c.Namespace, c.ReplaySecret, c.Policy, c.Keys)
	if err != nil {
		return VelocityRecovery{}, err
	}
	client, err := ownedVelocityTLS(c.TLS, c.TrustPEM)
	if err != nil {
		return VelocityRecovery{}, err
	}
	transport, err := newNativeTransport(nativeTransportConfig{endpoint: c.Endpoint, tls: client, credential: c.Credential.value, timeout: c.Timeout, poolSize: c.PoolSize, topology: c.Topology})
	if err != nil {
		return VelocityRecovery{}, err
	}
	primary, reader, issuer, _ := risk.NewVelocityRecoveryAuthorities()
	return VelocityRecovery{state: &ownedRecovery{layout: layout, transport: transport, issuer: issuer, reader: reader, primary: primary}}, nil
}

// A serialized trust boundary excludes opaque CertPool constraint callbacks,
// which cannot be inspected or bounded by the transport's context.
func ownedVelocityTLS(config *tls.Config, input []byte) (*tls.Config, error) {
	if config == nil || config.RootCAs != nil || len(input) == 0 || len(input) > 65536 {
		return nil, risk.ErrInvalidPolicy
	}
	remaining := bytes.Clone(input)
	roots := x509.NewCertPool()
	count := 0
	for len(bytes.TrimSpace(remaining)) != 0 {
		remaining = bytes.TrimSpace(remaining)
		if count == 32 || !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, risk.ErrInvalidPolicy
		}
		// pem.Decode skips malformed leading blocks. Isolate exactly the first
		// block so a later valid certificate cannot hide invalid trust input.
		end := bytes.Index(remaining, []byte("-----END CERTIFICATE-----"))
		if end < 0 {
			return nil, risk.ErrInvalidPolicy
		}
		end += len("-----END CERTIFICATE-----")
		if bytes.Count(remaining[:end], []byte("-----BEGIN ")) != 1 {
			return nil, risk.ErrInvalidPolicy
		}
		block, rest := pem.Decode(remaining[:end])
		if block == nil || len(rest) != 0 || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, risk.ErrInvalidPolicy
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, risk.ErrInvalidPolicy
		}
		roots.AddCert(cert)
		count++
		remaining = remaining[end:]
	}
	if count == 0 {
		return nil, risk.ErrInvalidPolicy
	}
	checked := config.Clone()
	checked.RootCAs = roots
	if !supportedNativeTLS(checked) {
		return nil, risk.ErrInvalidPolicy
	}
	return &tls.Config{RootCAs: roots, ServerName: config.ServerName, MinVersion: config.MinVersion, MaxVersion: config.MaxVersion, CipherSuites: slices.Clone(config.CipherSuites), CurvePreferences: slices.Clone(config.CurvePreferences)}, nil
}

// PrimaryAuthorities returns the original paired journal issuer and read-only
// native verifier for concrete primary-adapter configuration. It creates no new
// graph, performs no IO and grants no activation. Neither value can issue native
// acknowledgement. Zero/closed owners return ErrInvalidVelocityRecovery.
func (r VelocityRecovery) PrimaryAuthorities() (risk.VelocityJournalIssuer, risk.VelocityNativeVerifier, error) {
	if r.state == nil || r.state.primary == (risk.VelocityJournalIssuer{}) {
		return risk.VelocityJournalIssuer{}, risk.VelocityNativeVerifier{}, risk.ErrInvalidVelocityRecovery
	}
	r.state.transport.mu.Lock()
	closed := r.state.transport.closed
	r.state.transport.mu.Unlock()
	if closed {
		return risk.VelocityJournalIssuer{}, risk.VelocityNativeVerifier{}, risk.ErrInvalidVelocityRecovery
	}
	v, err := r.state.issuer.Verifier()
	if err != nil {
		return risk.VelocityJournalIssuer{}, risk.VelocityNativeVerifier{}, err
	}
	return r.state.primary, v, nil
}

// Fence explicitly installs the current primary lease's native recovery fence,
// or replaces the named predecessor. It does not restore history or mark health.
// Loss requires primary-owned restart from zero; no implicit retry/repair occurs.
// Primary checks finish before native IO. Nil/canceled contexts deny, failures
// are redacted, and ambiguous effects grant no acknowledgement.
func (r VelocityRecovery) Fence(ctx context.Context, lease, previous risk.VelocityLease) error {
	if r.state == nil {
		return risk.ErrInvalidVelocityRecovery
	}
	return r.state.fence(ctx, lease, previous)
}

// Restore applies only authenticated original history under an existing exact
// recovery fence. Missing/reset custody is not repaired. Current primary checks
// bracket native IO; ambiguous/lost replies expose no acknowledgement or resend
// permission. Counter observations and absolute expiries remain original.
func (r VelocityRecovery) Restore(ctx context.Context, lease risk.VelocityLease, history risk.VelocityHistory) (risk.VelocityAcknowledgement, error) {
	if r.state == nil {
		return risk.VelocityAcknowledgement{}, risk.ErrInvalidVelocityRecovery
	}
	return r.state.restore(ctx, lease, history)
}

// Publish transitions only the existing exact covered recovery marker. It
// neither restores counters nor activates primary health. Unknown/lost replies
// return no publication; retries must be explicitly reconciled by the primary.
func (r VelocityRecovery) Publish(ctx context.Context, lease risk.VelocityLease, closure risk.VelocityClosure) (risk.VelocityPublication, error) {
	if r.state == nil {
		return risk.VelocityPublication{}, risk.ErrInvalidVelocityRecovery
	}
	return r.state.publish(ctx, lease, closure)
}

// Confirm acknowledges this owner's exact published-to-confirmed marker after
// the primary has recorded its original confirmation. It grants no traffic by
// itself; the primary must activate and export its own opaque journal. The same
// owner performs later counter admission. No caller checker or executor exists.
func (r VelocityRecovery) Confirm(ctx context.Context, lease risk.VelocityLease, closure risk.VelocityClosure, publication risk.VelocityPublication, confirmation risk.VelocityConfirmation) (risk.VelocityNativeConfirmation, error) {
	if r.state == nil {
		return risk.VelocityNativeConfirmation{}, risk.ErrInvalidVelocityRecovery
	}
	return r.state.confirmed(ctx, lease, closure, publication, confirmation)
}

// OwnedCounterStore connects this native owner to the concrete primary owner's
// opaque activated journal. It accepts no separately selected chain, marker,
// health callback or effect executor. One outer Timeout bounds construction;
// construction does not debit or certify surviving native state. Every use
// authenticates command policy/keys/tenant, current primary eligibility, exact
// native marker and transport continuity before acknowledged intent and effect.
// Replay reads terminal history without redispatch; committed outcomes survive
// later errors, which deny admission. No SQL lock spans native IO. The returned
// store owns no resources; this recovery owner retains Close responsibility.
// Zero/foreign/closed/expired custody fails closed, preserving cancellation.
func (r VelocityRecovery) OwnedCounterStore(ctx context.Context, journal velocity.Journal) (risk.CounterStore, error) {
	if r.state == nil || r.state.transport == nil || ctx == nil {
		return nil, risk.ErrInvalidVelocityRecovery
	}
	s := r.state
	bounded, cancel := context.WithTimeout(ctx, s.transport.config.timeout)
	defer cancel()
	if err := bounded.Err(); err != nil {
		return nil, err
	}
	s.transport.mu.Lock()
	closed := s.transport.closed
	s.transport.mu.Unlock()
	if closed {
		return nil, risk.ErrInvalidVelocityRecovery
	}
	chain, err := velocity.Current(bounded, journal, s.issuer)
	if err != nil {
		return nil, err
	}
	lease, err := s.reader.Lease(chain.Lease)
	if err != nil || lease.Namespace != s.layout.replay.Namespace() {
		return nil, risk.ErrInvalidVelocityRecovery
	}
	native, err := velocity.BindCurrentNative(bounded, journal, s.issuer,
		func(c risk.CounterCommand) error { _, err := s.layout.prepare(c, lease.Epoch); return err },
		func(checkCtx context.Context, c risk.CounterCommand) error {
			return s.checkCurrent(checkCtx, c, chain.Lease, chain.Closure, chain.Publication, chain.Confirmation, chain.Native, chain.Eligibility)
		},
		func(effectCtx context.Context, c risk.CounterCommand) (risk.CounterResult, error) {
			return s.mutateCurrent(effectCtx, c, chain.Lease, chain.Closure, chain.Publication, chain.Confirmation, chain.Native, chain.Eligibility)
		})
	if err != nil {
		return nil, err
	}
	store, err := velocity.NewStore(journal, native, s.transport.config.timeout)
	if err != nil {
		return nil, err
	}
	return store, nil
}

// CheckCurrent checks this owner's original activated primary journal and exact
// confirmed native marker/server-time under one outer Timeout. Pass the opaque
// connection returned by the concrete primary owner's OwnedJournal; no caller
// callback, replacement chain or counter command is accepted. Current primary
// eligibility brackets native IO and transport continuity remains mandatory.
// No intent, replay, counter, marker, TTL or evidence is created or renewed.
// Success is a momentary readiness observation, never cached traffic authority;
// later mutations independently recheck their effect boundary. Zero, foreign,
// closed, lost or expired custody fails closed with redacted errors. Nil context
// is invalid; cancellation/deadlines are preserved. Concurrent calls are safe.
func (r VelocityRecovery) CheckCurrent(ctx context.Context, journal velocity.Journal) error {
	if r.state == nil || r.state.transport == nil || ctx == nil {
		return risk.ErrInvalidVelocityRecovery
	}
	s := r.state
	bounded, cancel := context.WithTimeout(ctx, s.transport.config.timeout)
	defer cancel()
	if err := bounded.Err(); err != nil {
		return err
	}
	s.transport.mu.Lock()
	closed := s.transport.closed
	s.transport.mu.Unlock()
	if closed {
		return risk.ErrInvalidVelocityRecovery
	}
	chain, err := velocity.Current(bounded, journal, s.issuer)
	if err != nil {
		return err
	}
	verifier, err := s.issuer.Verifier()
	if err != nil {
		return err
	}
	lb, err := s.reader.Lease(chain.Lease)
	if err != nil || lb.Namespace != s.layout.replay.Namespace() {
		return risk.ErrInvalidVelocityRecovery
	}
	return s.checkCurrentMarker(bounded, verifier, lb, chain)
}

// Close permanently rejects new native work, cancels active IO, closes idle
// connections and joins cleanup within the caller/adapter timeout. Repetition
// is safe. A deadline error leaves closing permanent; another call may wait for
// cleanup. The primary pool remains caller-owned and is never closed here.
// An already-canceled/expired nonnil context still permanently stops admission
// and initiates cancellation/idle cleanup; it bounds joining, not ownership.
func (r VelocityRecovery) Close(ctx context.Context) error {
	if r.state == nil {
		return risk.ErrInvalidVelocityRecovery
	}
	return r.state.transport.close(ctx)
}

func publicVelocityRedacted(s fmt.State)                  { _, _ = io.WriteString(s, "valkey.velocity(redacted)") }
func (Credential) Format(s fmt.State, _ rune)             { publicVelocityRedacted(s) }
func (VelocityRecoveryConfig) Format(s fmt.State, _ rune) { publicVelocityRedacted(s) }
func (VelocityRecovery) Format(s fmt.State, _ rune)       { publicVelocityRedacted(s) }
func (Credential) MarshalJSON() ([]byte, error)           { return nil, risk.ErrSensitiveSerialization }
func (Credential) MarshalText() ([]byte, error)           { return nil, risk.ErrSensitiveSerialization }
func (VelocityRecoveryConfig) MarshalJSON() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}
func (VelocityRecoveryConfig) MarshalText() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}
func (VelocityRecovery) MarshalJSON() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }
func (VelocityRecovery) MarshalText() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }
