package postgres

import (
	"bytes"
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	kernel "github.com/faustbrian/go-identity/postgres"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// LinkServiceConfig selects the native explicit-self password-session linking
// profile. Provider protocol work remains owned by oauth.Provider. All stores
// use the caller's migrated PRIMARY pool. No application domain store, raw
// transaction, permission callback or replay engine is supplied. Install RP,
// prepared request-key, protected-counter and terminal-erasure histories first.
// IntentKey is stable for original-key retention, separate from every other
// named key; rotating active state/PKCE/envelope keys cannot rewrite old intent.
// This initial profile denies enrolled MFA rather than silently downgrading it.
type LinkServiceConfig struct {
	Schema, ConfigurationID, PolicyID, Origin string
	Providers                                 []oauth.Provider
	CallbackAllowlist                         []string
	Session                                   sessionpg.SessionServiceConfig
	CSRFKeys                                  []session.CSRFKey
	Coordinator                               kernel.CoordinatorConfig
	Counters                                  riskpg.Config
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

// LinkService composes existing native owners without a private session,
// transaction or state-consumption engine. Configuration is immutable; each
// call owns independent request/preparation phases. Pools, providers and clocks
// are borrowed and must remain usable until all calls return. No goroutines or
// runtime resources are started or closed by this owner.
type LinkService struct {
	pool           *database.Pool
	directory      *kernel.Repository
	sessions       *session.SessionService
	counters       *riskpg.Repository
	issuer         *capabilitypg.Issuer
	checkpoint     *capabilitypg.IssuancePreparationCodec
	providers      oauth.ProviderRegistry
	profiles       map[string]oauth.ProviderProfile
	oauth2Profiles map[string]oauth.OAuth2UserInfoDetails
	envelopes      *envelope.Service
	verifiers      *rpVerifierCustody
	intentKey      session.DigestKey
	intentCSRF     session.CSRFKey
	requestKey     kernel.RequestKeyConfig
	profile        [32]byte
	config         func() LinkServiceConfig
}

var _ oauth.LinkStarter = (*LinkService)(nil)

// NewLinkService validates and snapshots startup policy without IO, entropy,
// provider exchange or migration. It enables no HTTP route. Only configured
// query/S256 OIDC or explicit distinct-route OAuth2/UserInfo providers and exact
// application callbacks are selected. Existing OIDC state bytes are unchanged.
func NewLinkService(pool *database.Pool, c LinkServiceConfig) (*LinkService, error) {
	invalid := identity.InvalidInputError{Field: "oauth_link_configuration"}
	if len(c.Coordinator.RetainedFingerprintKeys) == 0 || len(c.Coordinator.RetainedFingerprintKeys) > 32 || len(c.Capability.RetainedReplayKeys) == 0 || len(c.Capability.RetainedReplayKeys) > 32 {
		return nil, invalid
	}
	if pool == nil || pool.Raw() == nil || !rpSchemaName(c.Schema) || !rpASCII(c.ConfigurationID, 1, 96) || !rpASCII(c.PolicyID, 1, 128) || c.IntentKey == ([32]byte{}) || c.AuditRetentionPolicyVersion == 0 || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || c.StateLifetime < time.Minute || c.StateLifetime > 10*time.Minute || c.Coordinator.MaximumDuration > c.MaximumDuration || c.Coordinator.QueryPolicy == nil || c.Coordinator.AdmissionPolicy == nil || c.Coordinator.QueryPolicy.PolicyVersion != c.Coordinator.AdmissionPolicy.PolicyVersion || c.CurrentStateKeyVersion == 0 || c.StateKeys[c.CurrentStateKeyVersion] == ([32]byte{}) || len(c.StateKeys) == 0 || len(c.StateKeys) > 32 || len(c.CSRFKeys) == 0 || len(c.CSRFKeys) > 4 || c.Session.Profile.AuthenticationMethod != "password" || c.Session.Profile.CredentialKind != identity.CredentialPassword || c.Session.Profile.CredentialOwner != "identity/password" || c.Session.Profile.Audience == "" {
		return nil, invalid
	}
	// Per-call coordinators must use the same startup snapshot as the request
	// key and issuer owners. Their own constructors copy inputs, but retaining
	// caller containers here would select a new policy on the next request.
	c.Coordinator.RetainedFingerprintKeys = cloneRPStateKeys(c.Coordinator.RetainedFingerprintKeys)
	query, admission := *c.Coordinator.QueryPolicy, *c.Coordinator.AdmissionPolicy
	c.Coordinator.QueryPolicy, c.Coordinator.AdmissionPolicy = &query, &admission
	if c.Coordinator.FinalAuthentication != nil {
		selected := *c.Coordinator.FinalAuthentication
		c.Coordinator.FinalAuthentication = &selected
	}
	c.Capability.RetainedReplayKeys = cloneRPStateKeys(c.Capability.RetainedReplayKeys)
	if _, err := oauth.NewValidatedCallbackURL(c.Origin, []string{c.Origin}); err != nil || strings.Contains(c.Origin[len("https://"):], "/") || strings.ContainsAny(c.Origin, "?#") {
		return nil, invalid
	}
	if len(c.CallbackAllowlist) == 0 || len(c.CallbackAllowlist) > 64 {
		return nil, invalid
	}
	for _, callback := range c.CallbackAllowlist {
		if _, err := oauth.NewValidatedCallbackURL(callback, c.CallbackAllowlist); err != nil {
			return nil, invalid
		}
	}
	registry, err := oauth.NewProviderRegistry(c.Providers...)
	if err != nil {
		return nil, invalid
	}
	profiles := make(map[string]oauth.ProviderProfile, len(c.Providers))
	oauth2Profiles, err := oauth2ProviderProfiles(c.Providers)
	if err != nil {
		return nil, invalid
	}
	for _, provider := range c.Providers {
		profile := provider.Profile()
		if profile.ID != provider.ID() || profile.Version == 0 {
			return nil, invalid
		}
		// Validate the actual selected native AAD limit without minting state.
		probe, err := newRPVerifierBinding("configuration", profile, "AAAAAAAAAAAAAAAAAAAAAQ", [32]byte{1}, "identity.account.link-start")
		if err != nil {
			return nil, invalid
		}
		profiles[profile.ID] = probe.profile()
	}
	c.StateKeys = cloneRPStateKeys(c.StateKeys)
	c.PKCECommitmentKeys = cloneRPStateKeys(c.PKCECommitmentKeys)
	c.EnvelopeKeys = cloneRPEnvelopeKeys(c.EnvelopeKeys)
	commitmentKeys := make(map[uint32][]byte, len(c.PKCECommitmentKeys))
	for version, key := range c.PKCECommitmentKeys {
		commitmentKeys[version] = bytes.Clone(key[:])
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
	verifiers, err := newRPVerifierCustody(rpVerifierKeyConfig{CurrentEnvelopeKey: c.CurrentEnvelopeKey, EnvelopeKeys: c.EnvelopeKeys, CurrentCommitmentVersion: c.CurrentPKCEKeyVersion, CommitmentKeys: commitmentKeys})
	if err != nil {
		return nil, invalid
	}
	keys, err := keyring.New(c.EnvelopeKeys)
	if err != nil {
		return nil, invalid
	}
	envelopes, err := envelope.NewService(keys)
	if err != nil {
		return nil, invalid
	}
	reader, err := sessionpg.NewSessionService(pool, c.Session)
	if err != nil {
		return nil, invalid
	}
	directory, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: c.Session.Repository.MaximumDuration})
	if err != nil {
		return nil, invalid
	}
	// This selected workflow requires actual original-alias custody for retry;
	// legacy risk users do not inherit its optional SQL prerequisite.
	c.Counters.RetainCounterKeyVersions = true
	counters, err := riskpg.NewRepository(c.Counters)
	if err != nil || c.Counters.CommandCounters == nil {
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
	derive := func(purpose string) ([]byte, error) {
		return hkdf.Key(sha256.New, c.IntentKey[:], nil, "identity/oauth/"+purpose+"/v1", 32)
	}
	raw, err := derive("request-session")
	if err != nil {
		return nil, invalid
	}
	intentKey, err := session.NewDigestKey(1, raw)
	clear(raw)
	if err != nil {
		return nil, invalid
	}
	raw, err = derive("request-csrf")
	if err != nil {
		return nil, invalid
	}
	intentCSRF, err := session.NewCSRFKey(1, raw)
	clear(raw)
	if err != nil {
		return nil, invalid
	}
	requestKeys, err := kernel.NewRequestKeyConfig(c.ConfigurationID+".rp", c.IntentKey, *c.Coordinator.AdmissionPolicy)
	if err != nil {
		return nil, invalid
	}
	c.Providers = slices.Clone(c.Providers)
	c.CallbackAllowlist = slices.Clone(c.CallbackAllowlist)
	c.CSRFKeys = slices.Clone(c.CSRFKeys)
	c.Session.Validation.LookupKeys = slices.Clone(c.Session.Validation.LookupKeys)
	// Key rotations retain the same semantic profile. Key versions and original
	// commitments live in the authenticated records rather than changing intent.
	frame, err := json.Marshal(struct {
		Schema, ID, Policy, Origin string
		Callbacks                  []string
		Providers                  map[string]oauth.ProviderProfile
		Session                    rpStoredSessionProfile
		StateTTL                   time.Duration
		PolicyVersion              uint64
		OAuth2                     map[string]oauth.OAuth2UserInfoDetails `json:",omitempty"`
	}{c.Schema, c.ConfigurationID, c.PolicyID, c.Origin, c.CallbackAllowlist, profiles, rpStoredSessionProfile(c.Session.Profile), c.StateLifetime, c.Coordinator.AdmissionPolicy.PolicyVersion, oauth2Profiles})
	if err != nil {
		return nil, invalid
	}
	profile := sha256.Sum256(frame)
	clear(frame)
	s := &LinkService{pool: pool, directory: directory, sessions: reader, counters: counters, issuer: issuer, checkpoint: checkpoint, providers: registry, profiles: profiles, oauth2Profiles: oauth2Profiles, envelopes: envelopes, verifiers: verifiers, intentKey: intentKey, intentCSRF: intentCSRF, requestKey: requestKeys, profile: profile, config: func() LinkServiceConfig { return c }}
	if _, _, err := s.startCoordinator(&rpStartPhase{service: s}); err != nil {
		return nil, invalid
	}
	return s, nil
}

type rpStoredSessionProfile sessionpg.IdentifierAdmissionConfig

func cloneRPStateKeys(input map[uint32][32]byte) map[uint32][32]byte {
	output := make(map[uint32][32]byte, len(input))
	for version, key := range input {
		output[version] = key
	}
	return output
}
func cloneRPEnvelopeKeys(input map[string][]byte) map[string][]byte {
	output := make(map[string][]byte, len(input))
	for version, key := range input {
		output[version] = bytes.Clone(key)
	}
	return output
}

func (s *LinkService) startCoordinator(owner *rpStartPhase) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	auditing, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, err
	}
	lifecycle, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, nil, err
	}
	r, err := kernel.NewContributorRegistry([]kernel.Contributor{s.directory, auditing, lifecycle, s.counters, owner, s.issuer})
	if err != nil {
		return nil, nil, err
	}
	c, err := kernel.NewCoordinatorWithRequestKeys(s.pool, r, s.config().Coordinator, s.requestKey)
	return c, r, err
}

// LinkStart authenticates the original browser before generating anything,
// resolves one immutable request key and uses acknowledged native preparation.
// Only a committed start can return its original authorization redirect.
// Replays restore original RP data, not new state, nonce, PKCE or grant expiry.
func (s *LinkService) LinkStart(ctx context.Context, r oauth.LinkStartRequest) (out oauth.LinkStartResult, err error) {
	if ctx == nil || s == nil || s.config == nil || r.Validate() != nil {
		return out, identity.InvalidInputError{Field: "oauth_link_start"}
	}
	ctx, stop := context.WithTimeout(ctx, s.config().MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			out, err = oauth.LinkStartResult{}, identity.UnavailableError{}
		}
	}()
	profile, ok := s.profiles[string(r.Provider)]
	if !ok || !s.validStartRequest(r, profile) {
		return out, identity.InvalidInputError{Field: "oauth_link_profile"}
	}
	intent, err := s.startIntent(r)
	if err != nil {
		return out, err
	}
	owner := &rpStartPhase{service: s, request: r}
	c, _, err := s.startCoordinator(owner)
	if err != nil {
		return out, err
	}
	scope := kernel.RequestKeyScope{TenantID: r.TenantID, ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: authorization.SubjectUser, Method: "POST", RouteID: "identity.account.link-start"}
	// Request-key absence disclosure has its own exact resource contract. The
	// original self-user policy remains unchanged in intent and is separately
	// evaluated by PrepareRequestKey before any native input is retained.
	admission := r.Caller.Clone()
	admission.Request.Resource = authorization.Resource{Type: "identity.request-admission", ID: authorization.ResourceID(scope.RouteID)}
	key, wire, err := c.ResolvePreparedRequestKey(ctx, scope, r.IdempotencyKey, intent, admission, owner.registration(), owner)
	if err != nil {
		return out, err
	}
	defer clear(wire)
	input, err := owner.openInput(ctx, key, wire)
	if err != nil {
		return out, err
	}
	versions, _, err := s.counters.OriginalOAuthLinkCounterKeys(ctx, s.pool, input.binding(), input.Started, s.config().Session.Repository.MaximumDuration)
	if err != nil {
		return out, err
	}
	owner = &rpStartPhase{service: s, request: r, input: &input, counterVersions: versions}
	c, registry, err := s.startCoordinator(owner)
	if err != nil {
		return out, err
	}
	command, counter, err := owner.command()
	if err != nil {
		return out, err
	}
	declaration, err := owner.declaration(ctx, command, counter, registry)
	if err != nil {
		return out, err
	}
	declaration, err = c.PrepareFeaturePreparationPlan(command, declaration)
	if err != nil {
		return out, err
	}
	result, err := c.ExecutePreparedFeature(ctx, command, declaration)
	if err != nil {
		return out, err
	}
	if result.Outcome != identity.CommitOutcomeCommitted {
		return out, identity.UnknownCommitError{CommandID: input.binding().CommandID}
	}
	return owner.committedRedirect(ctx)
}

func (s *LinkService) validStartRequest(r oauth.LinkStartRequest, p oauth.ProviderProfile) bool {
	if r.Origin != s.config().Origin || !slices.Equal(r.Scopes.Values(), p.Scopes) {
		return false
	}
	for _, callback := range []oauth.ValidatedCallbackURL{r.Callback, r.ErrorCallback} {
		value := callback.URL()
		if _, err := oauth.NewValidatedCallbackURL(value.String(), s.config().CallbackAllowlist); err != nil {
			return false
		}
	}
	return true
}

func (s *LinkService) possesses(tenant identity.TenantID, bearer auth.BearerCredential, csrf session.CSRFToken, original session.Session) bool {
	spec, err := original.Bindings()
	if err != nil || !s.ownsSessionBearer(tenant, bearer, original) {
		return false
	}
	for _, key := range s.config().CSRFKeys {
		if original.CSRFState().Check(session.CSRFBinding{TenantID: tenant, SessionID: spec.SessionID, SessionVersion: spec.Version}, csrf, key) == nil {
			return true
		}
	}
	return false
}

func (LinkServiceConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthpostgres.LinkServiceConfig(redacted)"))
}
func (LinkServiceConfig) MarshalJSON() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "sensitive_configuration"}
}
func (LinkServiceConfig) MarshalText() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "sensitive_configuration"}
}
func (*LinkService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthpostgres.LinkService(redacted)"))
}
func (*LinkService) MarshalJSON() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "sensitive_configuration"}
}
func (*LinkService) MarshalText() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "sensitive_configuration"}
}
