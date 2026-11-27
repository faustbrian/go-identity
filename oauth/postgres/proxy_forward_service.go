package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	oauthproxy "github.com/faustbrian/go-identity/oauth/proxy"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

const proxyAuthorityLifetime = 20 * time.Second
const proxyStateProofLimit = 32 * 1024

// ProxyForwardConfig is the trusted configuration for one production proxy
// deployment. The service actor does not act as a production user. Retain old
// lookup and wrapping keys while the corresponding originals remain usable.
// The primary database must select the proxy and existing coordinator,
// capability, audit, lifecycle and directory histories.
type ProxyForwardConfig struct {
	Schema, ProductionDeployment  string
	Actor                         identity.ActorID
	PolicyID, GlobalAuthorityID   string
	PolicyVersion, AuditRetention uint64
	MaximumDuration               time.Duration
	Coordinator                   kernel.CoordinatorConfig
	Capability                    capabilitypg.IssuerConfig
	StateKeys                     map[uint32][32]byte
	CurrentEnvelopeKey            string
	EnvelopeKeys                  map[string][]byte
}

// ProxyForwardService settles a production callback in its original command.
// The service borrows a primary pool and opens no routes or background work.
// Each call independently binds proof, original ciphertext and generator.
type ProxyForwardService struct {
	pool                                 *database.Pool
	directory                            *kernel.Repository
	providerAuthority                    *ProviderAuthority
	envelopes                            *envelope.Service
	issuer                               *capabilitypg.Issuer
	limits                               capability.Limits
	capabilityIssuer, capabilityAudience string
	config                               ProxyForwardConfig
}

var _ oauthproxy.ProductionCallbackCommandStore = (*ProxyForwardService)(nil)

// NewProxyForwardService selects static production OAuth preview forwarding.
// It validates configuration without I/O. Callers keep the pool open and
// select the exact same deployment in NewProductionCommandCallback. Use
// NewProxyForwardServiceWithProviderAuthority for live provider invalidation.
func NewProxyForwardService(pool *database.Pool, c ProxyForwardConfig) (*ProxyForwardService, error) {
	invalid := identity.InvalidInputError{Field: "oauth_proxy_forward_configuration"}
	if pool == nil || pool.Raw() == nil || !rpSchemaName(c.Schema) || !rpProviderID(c.ProductionDeployment) ||
		!rpASCII(string(c.Actor), 1, 128) || !rpASCII(c.PolicyID, 1, 128) || !rpASCII(c.GlobalAuthorityID, 1, 128) ||
		c.PolicyVersion == 0 || c.AuditRetention == 0 || c.MaximumDuration < time.Millisecond || c.MaximumDuration > proxyAuthorityLifetime ||
		c.Coordinator.MaximumDuration <= 0 || c.Coordinator.MaximumDuration > c.MaximumDuration ||
		len(c.StateKeys) == 0 || len(c.StateKeys) > 32 || len(c.EnvelopeKeys) == 0 || len(c.EnvelopeKeys) > 33 ||
		!rpASCII(c.CurrentEnvelopeKey, 1, 256) || len(c.EnvelopeKeys[c.CurrentEnvelopeKey]) != 32 {
		return nil, invalid
	}
	for version, key := range c.StateKeys {
		if version == 0 || key == ([32]byte{}) {
			return nil, invalid
		}
		for _, encryptedWith := range c.EnvelopeKeys {
			if bytes.Equal(key[:], encryptedWith) {
				return nil, invalid
			}
		}
	}
	keys, err := keyring.New(c.EnvelopeKeys)
	if err != nil {
		return nil, invalid
	}
	envelopes, err := envelope.NewService(keys)
	if err != nil {
		return nil, invalid
	}
	directory, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: c.MaximumDuration})
	if err != nil {
		return nil, invalid
	}
	c.StateKeys = cloneRPStateKeys(c.StateKeys)
	c.EnvelopeKeys = nil // Retain wrapping keys only through the owning service.
	c.Coordinator.RetainedFingerprintKeys = cloneRPStateKeys(c.Coordinator.RetainedFingerprintKeys)
	// This coordinator does not perform command reads, ordinary admission or
	// final local authentication. Those optional profiles are not enabled here.
	if c.Coordinator.QueryPolicy != nil || c.Coordinator.AdmissionPolicy != nil || c.Coordinator.FinalAuthentication != nil {
		return nil, invalid
	}
	issuer, err := capabilitypg.NewIssuer(c.Capability)
	if err != nil {
		return nil, invalid
	}
	limits := c.Capability.Crypto.Limits
	capabilityIssuer, capabilityAudience := c.Capability.Crypto.Issuer, c.Capability.Audience
	c.Capability = capabilitypg.IssuerConfig{}
	s := &ProxyForwardService{pool: pool, directory: directory, envelopes: envelopes, issuer: issuer, limits: limits,
		capabilityIssuer: capabilityIssuer, capabilityAudience: capabilityAudience, config: c}
	if _, _, err := s.coordinator(&proxyForwardPhase{}); err != nil {
		return nil, invalid
	}
	return s, nil
}

// NewProxyForwardServiceWithProviderAuthority selects production OAuth preview
// forwarding with a shared current-primary reader. Paired Start and callback
// calls require the original profile and provider epoch to remain enabled.
// The reader must use a pool distinct from the production transaction pool,
// even when both pools connect to the same database. The caller owns both.
func NewProxyForwardServiceWithProviderAuthority(pool *database.Pool, c ProxyForwardConfig, a *ProviderAuthority) (*ProxyForwardService, error) {
	if pool == nil || a == nil || a.pool == nil || a.pool.Raw() == nil || pool.Raw() == a.pool.Raw() {
		return nil, identity.InvalidInputError{Field: "oauth_proxy_provider_authority"}
	}
	s, err := NewProxyForwardService(pool, c)
	if err != nil {
		return nil, err
	}
	s.providerAuthority = a
	return s, nil
}

func (s *ProxyForwardService) coordinator(phase *proxyForwardPhase) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	auditing, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, err
	}
	lifecycle, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, nil, err
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{s.directory, auditing, lifecycle, phase, capabilitypg.NewParticipant()})
	if err != nil {
		return nil, nil, err
	}
	coordinator, err := kernel.NewCoordinator(s.pool, registry, s.config.Coordinator)
	return coordinator, registry, err
}

// ExecuteOAuthProxyForward accepts only a current, exact original. Callback
// generation is single-use and runs only after acknowledged reservation. The
// service never reloads a prior artifact for delivery or retries an exchange.
func (s *ProxyForwardService) ExecuteOAuthProxyForward(ctx context.Context, lookup oauthproxy.CallbackLookup, generate oauthproxy.CallbackGeneration) (err error) {
	if s == nil || s.pool == nil || ctx == nil || ctx.Err() != nil || generate == nil {
		return oauthproxy.CallbackReconcile
	}
	defer func() {
		if recover() != nil {
			err = oauthproxy.CallbackReconcile
		}
	}()
	if lookup.ProductionDeployment != s.config.ProductionDeployment || proxyBindingHTTPS(lookup.ProductionCallback) == nil ||
		proxyBindingHTTPS(lookup.Issuer) == nil || !rpASCII(lookup.ClientID, 1, 1024) || !rpProviderID(lookup.ProviderID) ||
		lookup.ProviderVersion == 0 || lookup.StateDigest == ([32]byte{}) {
		return oauthproxy.ErrOriginalUnavailable
	}
	started := time.Now()
	ctx, stop := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer stop()
	row, err := readProxyLookup(ctx, s.pool.Raw(), s.config.Schema, s.config.StateKeys, proxyLookupSelection{
		production: lookup.ProductionDeployment, provider: lookup.ProviderID, callback: lookup.ProductionCallback,
		providerVersion: lookup.ProviderVersion, state: lookup.StateDigest,
	})
	defer row.clear()
	if err != nil {
		var denied identity.ForbiddenError
		if ctx.Err() == nil && errors.As(err, &denied) {
			return oauthproxy.ErrOriginalUnavailable
		}
		return oauthproxy.CallbackReconcile
	}
	if row.version != "1" {
		return oauthproxy.ErrOriginalUnavailable
	}
	locator, err := row.forwardLocator(lookup)
	if err != nil {
		return oauthproxy.CallbackReconcile
	}
	original, err := openProxyOriginalBinding(ctx, s.envelopes, locator, row.binding)
	if err != nil {
		return oauthproxy.CallbackReconcile
	}
	if original.Evidence.Issuer != lookup.Issuer || original.Evidence.ClientID != lookup.ClientID ||
		subtle.ConstantTimeCompare(original.Evidence.StateDigest[:], lookup.StateDigest[:]) != 1 {
		return oauthproxy.ErrOriginalUnavailable
	}
	if err := requireProxyProviderAuthority(ctx, s.providerAuthority, original.Evidence); err != nil {
		return proxyForwardAuthorityError(err)
	}
	command, err := makeProxyForwardCommand(locator, s.config.Actor, s.config.PolicyID, s.config.PolicyVersion, row.binding, lookup.ProviderDenied)
	if err != nil {
		return oauthproxy.CallbackReconcile
	}
	proof, replayKey, err := s.openStateProof(ctx, locator, row.proof)
	if err != nil {
		return oauthproxy.CallbackReconcile
	}
	defer func() {
		_ = proof.Transfer(context.WithoutCancel(ctx), func(context.Context, []byte) error { return nil })
	}()
	spec, _ := command.Feature()
	plan, err := s.issuer.PrepareOAuthProxyForwardConsumption(ctx, spec.Binding, locator.OriginCommand, sha256.Sum256(row.binding), proof, replayKey)
	if err != nil {
		return oauthproxy.CallbackReconcile
	}
	phase := &proxyForwardPhase{schema: s.config.Schema, authority: s.config.GlobalAuthorityID, envelopeKey: s.config.CurrentEnvelopeKey,
		envelopes: s.envelopes, directory: s.directory, providerAuthority: s.providerAuthority,
		locator: locator, original: original, row: row, command: command, proof: plan,
		generate: generate, providerDenied: lookup.ProviderDenied, startedAt: started}
	defer func() { clear(phase.output.Artifact) }()
	coordinator, registry, err := s.coordinator(phase)
	if err != nil || phase.declare(registry, s.config.AuditRetention) != nil {
		return oauthproxy.CallbackReconcile
	}
	result, err := coordinator.ExecutePreparedFeature(ctx, command, phase.plan)
	if err != nil || ctx.Err() != nil || result.Outcome != identity.CommitOutcomeCommitted {
		return oauthproxy.CallbackReconcile
	}
	if !phase.generatedHere {
		// The callback contract never delivers an encrypted bearer from retained
		// command output, even when the original transaction is known committed.
		return oauthproxy.ErrOriginalUnavailable
	}
	if err := requireProxyProviderAuthority(ctx, s.providerAuthority, original.Evidence); err != nil {
		return proxyForwardAuthorityError(err)
	}
	if ctx.Err() != nil || !time.Now().Before(original.Evidence.ExpiresAt) {
		return oauthproxy.CallbackReconcile
	}
	return nil
}

func proxyForwardAuthorityError(err error) error {
	var denied identity.ForbiddenError
	if errors.As(err, &denied) {
		return oauthproxy.ErrOriginalUnavailable
	}
	return oauthproxy.CallbackReconcile
}

func (row proxyLookupRow) forwardLocator(lookup oauthproxy.CallbackLookup) (proxyBindingLocator, error) {
	transaction, transactionErr := identity.ParsePreAuthTransactionID(row.transaction)
	origin, originErr := identity.ParseCommandID(base64.RawURLEncoding.EncodeToString(row.originCommand))
	callback, callbackErr := identity.ParseCommandID(base64.RawURLEncoding.EncodeToString(row.callbackCommand))
	if transactionErr != nil || originErr != nil || callbackErr != nil || origin == callback ||
		!rpDirectoryID(row.tenant) || row.stateKey == 0 || len(row.lookupDigest) != 32 ||
		len(row.proof) == 0 || len(row.verifier) == 0 {
		return proxyBindingLocator{}, errProxyBinding
	}
	return proxyBindingLocator{Tenant: identity.TenantID(row.tenant), Transaction: transaction, OriginCommand: origin,
		CallbackCommand: callback, Production: lookup.ProductionDeployment, Provider: lookup.ProviderID, CallbackURI: lookup.ProductionCallback,
		ProviderVersion: lookup.ProviderVersion, StateKeyVersion: row.stateKey, LookupDigest: [32]byte(row.lookupDigest),
		IssuedAt: row.issued, ExpiresAt: row.expires}, nil
}

func (s *ProxyForwardService) openStateProof(ctx context.Context, locator proxyBindingLocator, wire []byte) (capability.Proof, uint32, error) {
	plain, err := openProxyPart(ctx, s.envelopes, locator, proxyStateProof, 0, wire, proxyStateProofLimit)
	if err != nil {
		return capability.Proof{}, 0, err
	}
	defer clear(plain)
	// Version 1: one byte of format version, a nonzero big-endian replay key
	// version, then the capability library's canonical proof wire bytes.
	if len(plain) < 6 || plain[0] != 1 || binary.BigEndian.Uint32(plain[1:5]) == 0 {
		return capability.Proof{}, 0, errProxyBinding
	}
	proof, err := capability.ParseProof(string(plain[5:]), s.limits)
	if err != nil {
		return capability.Proof{}, 0, errProxyBinding
	}
	return proof, binary.BigEndian.Uint32(plain[1:5]), nil
}

func (ProxyForwardConfig) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("oauthpostgres.ProxyForwardConfig(redacted)"))
}

func (*ProxyForwardService) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("oauthpostgres.ProxyForwardService(redacted)"))
}

func (ProxyForwardConfig) MarshalJSON() ([]byte, error)   { return nil, errProxyBinding }
func (ProxyForwardConfig) MarshalText() ([]byte, error)   { return nil, errProxyBinding }
func (*ProxyForwardService) MarshalJSON() ([]byte, error) { return nil, errProxyBinding }
func (*ProxyForwardService) MarshalText() ([]byte, error) { return nil, errProxyBinding }
