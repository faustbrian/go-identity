package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// SigninServiceConfig selects existing-account OAuth initiation from a genuine
// original preauth browser, not a password session or an application-owned store.
// Install RP and prepared-request-key/preparation/admission histories first.
// Schema is the dedicated RP namespace; Session is the existing preauth store.
// IntentKey and ConfigurationID are stable for original-key retention. Retain
// old state/PKCE/envelope keys while their original transactions remain usable.
// Risk must be the counted, audited Authentication evaluator. Dependencies are
// borrowed, bounded and concurrency-safe; construction starts no resources.
type SigninServiceConfig struct {
	Schema, ConfigurationID, PolicyID, Origin string
	GlobalAuthorityID                         string
	Providers                                 []oauth.Provider
	CallbackAllowlist                         []string
	Session                                   sessionpg.Config
	FlowKeys                                  []session.DigestKey
	Risk                                      risk.AuthenticationAdmissionCustodyConfig
	Coordinator                               kernel.CoordinatorConfig
	Capability                                capabilitypg.IssuerConfig
	CapabilityPreparation                     capabilitypg.IssuancePreparationConfig
	MaximumDuration, StateLifetime            time.Duration
	AuditRetentionPolicyVersion               uint64
	IntentKey                                 [32]byte
	CurrentStateKeyVersion                    uint32
	StateKeys                                 map[uint32][32]byte
	CurrentPKCEKeyVersion                     uint32
	PKCECommitmentKeys                        map[uint32][32]byte
	CurrentEnvelopeKey                        string
	EnvelopeKeys                              map[string][]byte
}

// SigninService owns native original-browser OAuth initiation. State issuance,
// RP persistence, audit and lifecycle effects use the existing coordinator;
// this service owns no transaction, replay engine, goroutine or application
// store. Configuration is copied; providers and the primary pool are borrowed.
// Calls are concurrent-safe with independent invocation-local preparation.
type SigninService struct {
	pool       *database.Pool
	directory  *kernel.Repository
	issuer     *capabilitypg.Issuer
	checkpoint *capabilitypg.IssuancePreparationCodec
	providers  oauth.ProviderRegistry
	profiles   map[string]oauth.ProviderProfile
	envelopes  *envelope.Service
	verifiers  *rpVerifierCustody
	custody    risk.AuthenticationAdmissionCustody
	requestKey kernel.RequestKeyConfig
	profile    [32]byte
	config     SigninServiceConfig
}

var _ oauth.SigninStarter = (*SigninService)(nil)

// NewSigninService snapshots the explicit query/S256/OIDC initiation profile
// without database IO, provider callbacks, entropy or migration. It enables no
// HTTP route and creates neither a user nor a session. Startup and operation
// failures are typed/redacted; caller deadlines bound all later work.
func NewSigninService(pool *database.Pool, c SigninServiceConfig) (*SigninService, error) {
	invalid := identity.InvalidInputError{Field: "oauth_signin_configuration"}
	if pool == nil || pool.Raw() == nil || !rpSchemaName(c.Schema) || !rpASCII(c.ConfigurationID, 1, 96) || !rpASCII(c.PolicyID, 1, 128) || !rpASCII(c.GlobalAuthorityID, 1, 128) || c.IntentKey == ([32]byte{}) || c.AuditRetentionPolicyVersion == 0 {
		return nil, invalid
	}
	if c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || c.StateLifetime < time.Minute || c.StateLifetime > 10*time.Minute || c.Coordinator.MaximumDuration > c.MaximumDuration || c.Session.MaximumDuration <= 0 || c.Session.MaximumDuration > c.MaximumDuration || len(c.FlowKeys) < 1 || len(c.FlowKeys) > 32 {
		return nil, invalid
	}
	if c.Coordinator.QueryPolicy == nil || c.Coordinator.AdmissionPolicy == nil || c.Coordinator.QueryPolicy.PolicyVersion != c.Coordinator.AdmissionPolicy.PolicyVersion || len(c.Coordinator.RetainedFingerprintKeys) < 1 || len(c.Coordinator.RetainedFingerprintKeys) > 32 {
		return nil, invalid
	}
	if _, err := oauth.NewValidatedCallbackURL(c.Origin, []string{c.Origin}); err != nil || strings.Contains(c.Origin[len("https://"):], "/") || strings.ContainsAny(c.Origin, "?#") {
		return nil, invalid
	}
	if len(c.CallbackAllowlist) < 1 || len(c.CallbackAllowlist) > 64 {
		return nil, invalid
	}
	for _, callback := range c.CallbackAllowlist {
		if _, err := oauth.NewValidatedCallbackURL(callback, c.CallbackAllowlist); err != nil {
			return nil, invalid
		}
	}
	providers, err := oauth.NewProviderRegistry(c.Providers...)
	if err != nil {
		return nil, invalid
	}
	profiles := make(map[string]oauth.ProviderProfile, len(c.Providers))
	for _, provider := range c.Providers {
		p := provider.Profile()
		if p.ID != provider.ID() {
			return nil, invalid
		}
		binding, err := newRPVerifierBinding("configuration", p, "AAAAAAAAAAAAAAAAAAAAAQ", [32]byte{1}, "identity.oauth.signin-start")
		if err != nil {
			return nil, invalid
		}
		profiles[p.ID] = binding.profile()
	}
	if c.CurrentStateKeyVersion == 0 || len(c.StateKeys) < 1 || len(c.StateKeys) > 32 || c.StateKeys[c.CurrentStateKeyVersion] == ([32]byte{}) || len(c.Capability.RetainedReplayKeys) < 1 || len(c.Capability.RetainedReplayKeys) > 32 {
		return nil, invalid
	}
	for version, key := range c.StateKeys {
		if version == 0 || key == ([32]byte{}) || key == c.IntentKey {
			return nil, invalid
		}
		for _, pkce := range c.PKCECommitmentKeys {
			if key == pkce || pkce == c.IntentKey {
				return nil, invalid
			}
		}
		for _, aes := range c.EnvelopeKeys {
			if bytes.Equal(key[:], aes) || bytes.Equal(c.IntentKey[:], aes) {
				return nil, invalid
			}
		}
	}
	c.StateKeys = cloneRPStateKeys(c.StateKeys)
	c.PKCECommitmentKeys = cloneRPStateKeys(c.PKCECommitmentKeys)
	c.EnvelopeKeys = cloneRPEnvelopeKeys(c.EnvelopeKeys)
	commitmentKeys := make(map[uint32][]byte, len(c.PKCECommitmentKeys))
	for version, key := range c.PKCECommitmentKeys {
		commitmentKeys[version] = bytes.Clone(key[:])
	}
	verifiers, err := newRPVerifierCustody(rpVerifierKeyConfig{CurrentEnvelopeKey: c.CurrentEnvelopeKey, EnvelopeKeys: c.EnvelopeKeys, CurrentCommitmentVersion: c.CurrentPKCEKeyVersion, CommitmentKeys: commitmentKeys})
	if err != nil {
		return nil, invalid
	}
	keys, err := keyring.New(c.EnvelopeKeys)
	if err != nil {
		return nil, invalid
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		return nil, invalid
	}
	custody, err := risk.NewAuthenticationAdmissionCustody(c.Risk)
	if err != nil {
		return nil, invalid
	}
	issuer, err := capabilitypg.NewIssuer(c.Capability)
	if err != nil {
		return nil, invalid
	}
	checkpoint, err := capabilitypg.NewIssuancePreparationCodec(issuer, c.CapabilityPreparation)
	if err != nil {
		return nil, invalid
	}
	directory, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: c.MaximumDuration})
	if err != nil {
		return nil, invalid
	}
	if _, err := sessionpg.NewRepository(pool, c.Session); err != nil {
		return nil, invalid
	}
	query, admission := *c.Coordinator.QueryPolicy, *c.Coordinator.AdmissionPolicy
	c.Coordinator.QueryPolicy, c.Coordinator.AdmissionPolicy = &query, &admission
	c.Coordinator.RetainedFingerprintKeys = cloneRPStateKeys(c.Coordinator.RetainedFingerprintKeys)
	if c.Coordinator.FinalAuthentication != nil {
		final := *c.Coordinator.FinalAuthentication
		c.Coordinator.FinalAuthentication = &final
	}
	c.Capability.RetainedReplayKeys = cloneRPStateKeys(c.Capability.RetainedReplayKeys)
	c.Providers, c.CallbackAllowlist = slices.Clone(c.Providers), slices.Clone(c.CallbackAllowlist)
	c.FlowKeys, c.Risk.Keys = slices.Clone(c.FlowKeys), slices.Clone(c.Risk.Keys)
	requestKey, err := kernel.NewRequestKeyConfig(c.ConfigurationID+".signin", c.IntentKey, admission)
	if err != nil {
		return nil, invalid
	}
	frame, err := json.Marshal(struct {
		Schema, ID, Policy, Origin, SessionSchema, RiskID, Global string
		Callbacks                                                 []string
		Providers                                                 map[string]oauth.ProviderProfile
		TTL                                                       time.Duration
		PolicyVersion                                             uint64
	}{c.Schema, c.ConfigurationID, c.PolicyID, c.Origin, c.Session.Schema, c.Risk.ConfigurationID, c.GlobalAuthorityID, c.CallbackAllowlist, profiles, c.StateLifetime, admission.PolicyVersion})
	if err != nil {
		return nil, invalid
	}
	s := &SigninService{pool: pool, directory: directory, issuer: issuer, checkpoint: checkpoint, providers: providers, profiles: profiles, envelopes: crypto, verifiers: verifiers, custody: custody, requestKey: requestKey, profile: sha256.Sum256(frame), config: c}
	clear(frame)
	if _, _, err := s.startCoordinator(&signinStartPhase{service: s}); err != nil {
		return nil, invalid
	}
	return s, nil
}

func (s *SigninService) startCoordinator(p *signinStartPhase) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	auditing, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, err
	}
	lifecycle, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, nil, err
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{s.directory, auditing, lifecycle, p, s.issuer})
	if err != nil {
		return nil, nil, err
	}
	coordinator, err := kernel.NewCoordinatorWithRequestKeys(s.pool, registry, s.config.Coordinator, s.requestKey)
	return coordinator, registry, err
}

// SigninStart authenticates the original preauth cookie and intent before
// resolving its idempotency key. State/nonce/PKCE and their one-use grant are
// generated only after acknowledged preparation, then persisted atomically.
// Committed retries return the same unexpired authorization transaction; they
// do not renew its browser, state, risk or grant. No user is selected here.
func (s *SigninService) SigninStart(ctx context.Context, r oauth.SigninStartRequest) (out oauth.SigninStartResult, err error) {
	if ctx == nil || s == nil || r.Validate() != nil || r.Origin != s.config.Origin {
		return out, identity.InvalidInputError{Field: "oauth_signin_start"}
	}
	ctx, stop := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			out, err = oauth.SigninStartResult{}, identity.UnavailableError{}
		}
	}()
	profile, ok := s.profiles[string(r.Provider)]
	if !ok || !slices.Equal(profile.Scopes, r.Scopes.Values()) {
		return out, identity.InvalidInputError{Field: "oauth_signin_profile"}
	}
	for _, callback := range []oauth.ValidatedCallbackURL{r.Callback, r.ErrorCallback} {
		value := callback.URL()
		if _, err := oauth.NewValidatedCallbackURL(value.String(), s.config.CallbackAllowlist); err != nil {
			return out, err
		}
	}
	p, err := s.newStartPhase(ctx, r)
	if err != nil {
		return out, err
	}
	coordinator, _, err := s.startCoordinator(p)
	if err != nil {
		return out, err
	}
	intent, err := p.requestIntent()
	if err != nil {
		return out, err
	}
	scope := kernel.RequestKeyScope{TenantID: r.TenantID, ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: authorization.SubjectServiceAccount, Method: "POST", RouteID: "identity.oauth.signin-start"}
	caller := r.Caller.Clone()
	caller.Request.Resource = authorization.Resource{Type: "identity.request-admission", ID: authorization.ResourceID(scope.RouteID)}
	key, wire, err := coordinator.ResolvePreparedRequestKey(ctx, scope, r.IdempotencyKey, intent, caller, p.registration(), p)
	if err != nil {
		return out, err
	}
	defer clear(wire)
	if err := p.restoreInput(ctx, key, wire); err != nil {
		return out, err
	}
	coordinator, registry, err := s.startCoordinator(p)
	if err != nil {
		return out, err
	}
	command, err := p.command()
	if err != nil {
		return out, err
	}
	plan, err := p.plan(ctx, registry, nil)
	if err != nil {
		return out, err
	}
	result, err := coordinator.ExecutePreparedFeature(ctx, command, plan)
	if err != nil {
		return out, err
	}
	if result.Outcome != identity.CommitOutcomeCommitted {
		return out, identity.UnknownCommitError{CommandID: p.input.Binding.CommandID}
	}
	return p.committedRedirect(ctx)
}

func (SigninServiceConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthpostgres.SigninServiceConfig(redacted)"))
}
func (SigninServiceConfig) MarshalJSON() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "sensitive_configuration"}
}
func (SigninServiceConfig) MarshalText() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "sensitive_configuration"}
}
func (*SigninService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthpostgres.SigninService(redacted)"))
}
func (*SigninService) MarshalJSON() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "sensitive_configuration"}
}
func (*SigninService) MarshalText() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "sensitive_configuration"}
}
