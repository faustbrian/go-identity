package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	authorization "github.com/faustbrian/go-authorization/v3"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/oauth/onetap"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

const oneTapStartOperationID = "identity.oauth.onetap-start"

type oneTapSecondClock struct{ session.IssuerClock }

func (c oneTapSecondClock) Now() time.Time { return c.IssuerClock.Now().UTC().Truncate(time.Second) }

// OneTapStartConfig selects one trusted tenant, Google provider and
// deployment policy. Install the kernel, session, capability and OAuth One Tap
// migrations before use. Dependencies are borrowed for bounded requests; the
// service starts no goroutines and owns no provider HTTP endpoint or session.
type OneTapStartConfig struct {
	Schema, ConfigurationID, GlobalAuthorityID string
	TenantID                                   identity.TenantID
	Provider                                   *oauth.OIDCProvider
	Issuance                                   session.PreAuthIssuerConfig
	Session                                    sessionpg.Config
	Risk                                       risk.AuthenticationAdmissionCustodyConfig
	Coordinator                                kernel.CoordinatorConfig
	Capability                                 capabilitypg.IssuerConfig
	CapabilityPreparation                      capabilitypg.IssuancePreparationConfig
	MaximumDuration                            time.Duration
	AuditRetentionPolicyVersion                uint64
	IntentKey                                  [32]byte
	CurrentEnvelopeKey                         string
	EnvelopeKeys                               map[string][]byte
}

// OneTapStartService owns native initiation, not callback authentication.
// Independent calls share their existing durable coordinator only; volatile
// browser credential custody belongs to one invocation.
type OneTapStartService struct {
	pool              *database.Pool
	directory         *kernel.Repository
	config            func() OneTapStartConfig
	selected          session.PreAuthProviderBinding
	profile           [32]byte
	issuer            *capabilitypg.Issuer
	checkpoint        *capabilitypg.IssuancePreparationCodec
	custody           risk.AuthenticationAdmissionCustody
	envelopes         *envelope.Service
	requestKey        kernel.RequestKeyConfig
	redirectValidator *onetap.ProviderBoundValidator
}

// NewOneTapStartService validates trusted startup inputs without I/O or flow
// generation. The exact Google provider, actor, tenant and HTTPS origin cannot
// be selected or replaced by the browser.
func NewOneTapStartService(pool *database.Pool, c OneTapStartConfig) (*OneTapStartService, error) {
	return newOneTapStartService(pool, c, session.PreAuthProviderCallback)
}

// NewOneTapRedirectStartService explicitly selects Google button redirect start.
// Issuance.CallbackURL must be the exact registered canonical same-origin HTTPS
// endpoint with a non-root path, and Issuance.Cookie must be zero. The session
// owner supplies its path-bound frontchannel cookie. Only StartRedirect accepts
// requests on this service; callback completion remains unselected.
func NewOneTapRedirectStartService(pool *database.Pool, c OneTapStartConfig) (*OneTapStartService, error) {
	return newOneTapStartService(pool, c, session.PreAuthProviderRedirect)
}

func newOneTapStartService(pool *database.Pool, c OneTapStartConfig, mode session.PreAuthProviderMode) (*OneTapStartService, error) {
	invalid := identity.InvalidInputError{Field: "oauth_onetap_start_configuration"}
	if pool == nil || pool.Raw() == nil || !rpSchemaName(c.Schema) || !rpASCII(c.ConfigurationID, 1, 96) || c.Provider == nil ||
		c.AuditRetentionPolicyVersion == 0 || c.IntentKey == ([32]byte{}) || c.Issuance.Action != oneTapStartOperationID {
		return nil, invalid
	}
	if (kernel.DirectoryAuthorityQuery{GlobalAuthorityID: c.GlobalAuthorityID, TenantID: c.TenantID}).Validate() != nil {
		return nil, invalid
	}
	if c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || c.Issuance.MaximumDuration > c.MaximumDuration ||
		c.Session.MaximumDuration <= 0 || c.Session.MaximumDuration > c.MaximumDuration || c.Coordinator.MaximumDuration > c.MaximumDuration ||
		c.Coordinator.AdmissionPolicy == nil || c.Coordinator.QueryPolicy == nil ||
		c.Coordinator.AdmissionPolicy.PolicyVersion != c.Issuance.PolicyVersion || c.Coordinator.QueryPolicy.PolicyVersion != c.Issuance.PolicyVersion {
		return nil, invalid
	}
	validation := onetap.ProviderBoundConfig{
		Provider: c.Provider, TenantID: c.TenantID, Origin: c.Issuance.Origin,
		PolicyID: c.Issuance.PolicyID, PolicyVersion: c.Issuance.PolicyVersion, Clock: c.Issuance.Clock,
	}
	var redirectValidator *onetap.ProviderBoundValidator
	var err error
	if mode == session.PreAuthProviderRedirect {
		redirectValidator, err = onetap.NewProviderBoundRedirectValidator(validation, c.Issuance.CallbackURL)
	} else {
		_, err = onetap.NewProviderBoundValidator(validation)
	}
	if err != nil {
		return nil, invalid
	}
	profile := c.Provider.Profile()
	selected := session.PreAuthProviderBinding{
		ProviderID: profile.ID, ProviderVersion: profile.Version, ClientID: profile.ClientID, Mode: mode,
	}
	if _, err := sessionpg.NewRepository(pool, c.Session); err != nil {
		return nil, invalid
	}
	directory, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: c.MaximumDuration})
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
	custody, err := risk.NewAuthenticationAdmissionCustody(c.Risk)
	if err != nil {
		return nil, invalid
	}
	if len(c.EnvelopeKeys[c.CurrentEnvelopeKey]) == 0 {
		return nil, invalid
	}
	for _, key := range c.EnvelopeKeys {
		if bytes.Equal(key, c.IntentKey[:]) {
			return nil, invalid
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
	query, admission := *c.Coordinator.QueryPolicy, *c.Coordinator.AdmissionPolicy
	c.Coordinator.QueryPolicy, c.Coordinator.AdmissionPolicy = &query, &admission
	c.Coordinator.RetainedFingerprintKeys = cloneRPStateKeys(c.Coordinator.RetainedFingerprintKeys)
	if c.Coordinator.FinalAuthentication != nil {
		final := *c.Coordinator.FinalAuthentication
		c.Coordinator.FinalAuthentication = &final
	}
	requestKey, err := kernel.NewRequestKeyConfig(c.ConfigurationID+".onetap-start", c.IntentKey, admission)
	if err != nil {
		return nil, invalid
	}
	frame, err := json.Marshal(struct {
		Schema, Configuration, Directory, SessionSchema, RiskConfiguration string
		Tenant, Origin, Actor, Policy                                      string
		PolicyVersion                                                      uint64
		Provider                                                           oauth.ProviderProfile
	}{c.Schema, c.ConfigurationID, c.GlobalAuthorityID, c.Session.Schema, c.Risk.ConfigurationID,
		string(c.TenantID), c.Issuance.Origin, string(c.Issuance.ActorID), c.Issuance.PolicyID, c.Issuance.PolicyVersion, profile})
	if err != nil {
		return nil, invalid
	}
	defer clear(frame)
	profileDigest := sha256.Sum256(frame)
	if mode == session.PreAuthProviderRedirect {
		// The deployed popup frame above is unchanged. Redirect intent and sealed
		// custody use a separate domain and retain the exact mode and login URI.
		redirectFrame, err := json.Marshal(struct {
			Profile     [32]byte
			Mode        session.PreAuthProviderMode
			CallbackURL string
		}{profileDigest, mode, c.Issuance.CallbackURL})
		if err != nil {
			return nil, invalid
		}
		digest := sha256.New()
		_, _ = digest.Write([]byte("identity-oauth-onetap-redirect-start-profile-v1\x00"))
		_, _ = digest.Write(redirectFrame)
		clear(redirectFrame)
		profileDigest = [32]byte(digest.Sum(nil))
	}
	// The owned cryptographic services already copied their keys. The request
	// owner does not need those maps to enforce its selected execution profile.
	c.EnvelopeKeys, c.Capability.RetainedReplayKeys = nil, nil
	c.CapabilityPreparation = capabilitypg.IssuancePreparationConfig{}
	s := &OneTapStartService{pool: pool, directory: directory, config: func() OneTapStartConfig { return c }, selected: selected,
		profile: profileDigest, issuer: issuer, checkpoint: checkpoint, custody: custody, envelopes: envelopes, requestKey: requestKey, redirectValidator: redirectValidator}
	p := &oneTapStartPhase{service: s}
	if _, err := s.newSessionIssuer(p); err != nil {
		return nil, invalid
	}
	if _, _, err := s.coordinator(p); err != nil {
		return nil, invalid
	}
	return s, nil
}

func (s *OneTapStartService) newSessionIssuer(p *oneTapStartPhase) (*session.PreAuthIssuer, error) {
	if s.selected.Mode == session.PreAuthProviderRedirect {
		return session.NewOneTapRedirectStartPreAuthIssuer(p, s.sessionIssuance(), s.selected)
	}
	return session.NewOneTapStartPreAuthIssuer(p, s.sessionIssuance(), s.selected)
}

func (s *OneTapStartService) sessionIssuance() session.PreAuthIssuerConfig {
	c := s.config().Issuance
	// Round only the shared session/grant timeline. Risk and directory
	// evidence keep their exact original authority timestamps.
	c.Clock = oneTapSecondClock{c.Clock}
	return c
}

func (s *OneTapStartService) coordinator(p *oneTapStartPhase) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
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
	coordinator, err := kernel.NewCoordinatorWithRequestKeys(s.pool, registry, s.config().Coordinator, s.requestKey)
	return coordinator, registry, err
}

func (s *OneTapStartService) caller(action, kind, id string) authorization.DecisionContext {
	c := s.config()
	return authorization.DecisionContext{PolicyRevision: authorization.Revision(c.Issuance.PolicyVersion), Request: authorization.Request{
		Tenant: authorization.TenantID(c.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: authorization.SubjectID(c.Issuance.ActorID)},
		Action: authorization.Action(action), Resource: authorization.Resource{Type: authorization.ResourceType(kind), ID: authorization.ResourceID(id)},
		Environment: authorization.Environment{Time: c.Issuance.Clock.Now().UTC()},
	}}
}

// OneTapBrowserStart is explicit transport output, not an authenticated user or
// session. Set only this result's blank Cookie.Value using Token.Reveal once.
// Never log the original nonce, flow or cookie. The deadline is the original
// browser flow's and must not be refreshed by response handling.
type OneTapBrowserStart struct {
	FlowID                  identity.PreAuthTransactionID
	ClientID, Nonce, Origin string
	ExpiresAt               time.Time
	Options                 onetap.BrowserStartOptions
	Cookie                  http.Cookie
	Token                   session.Token
}

// OneTapRedirectBrowserStart is fresh committed redirect transport custody.
// Projection is the validator-owned typed GIS launch derived from the original
// flow. Set only Cookie.Value by revealing Token once; never log this value.
// This is not a session or a renderer. Original expiry cannot be renewed.
type OneTapRedirectBrowserStart struct {
	Projection onetap.BrowserRedirectStartProjection
	Cookie     http.Cookie
	Token      session.Token
}

// OneTapStartResult retains original command outcome independent of delivery.
// Browser is present only if this invocation committed its own generated flow
// and obtained custody from the exact session issuer receipt. Terminal replay
// and explicit recovery do not release any browser material.
type OneTapStartResult struct {
	CommandID       identity.CommandID
	Outcome         identity.CommitOutcome
	Replayed        bool
	browser         func() OneTapBrowserStart
	redirectBrowser func() OneTapRedirectBrowserStart
}

// Browser returns the fresh committed browser context if this invocation owns
// delivery. Token copies share the session issuer's one reveal permission.
func (r OneTapStartResult) Browser() (OneTapBrowserStart, bool) {
	if r.browser == nil {
		return OneTapBrowserStart{}, false
	}
	return r.browser(), true
}

// RedirectBrowser returns only this invocation's fresh committed redirect
// custody. Browser remains absent for redirect mode. Replay, recovery, unknown
// commitment or expired delivery never releases a token or launch projection.
func (r OneTapStartResult) RedirectBrowser() (OneTapRedirectBrowserStart, bool) {
	if r.redirectBrowser == nil {
		return OneTapRedirectBrowserStart{}, false
	}
	return r.redirectBrowser(), true
}

// Start resolves one original keyed request, performs admitted native
// preparation, and commits flow, capability, sealed callback proof, audit and
// lifecycle under the same coordinator. It calls no Google endpoint. If
// commitment is unknown, use only the same original key or authorized recovery.
func (s *OneTapStartService) Start(ctx context.Context, request onetap.BrowserStartRequest) (out OneTapStartResult, err error) {
	if s == nil || s.config == nil || s.selected.Mode != session.PreAuthProviderCallback {
		return out, identity.InvalidInputError{Field: "oauth_onetap_start"}
	}
	spec, err := request.Bindings()
	if err != nil {
		return out, identity.InvalidInputError{Field: "oauth_onetap_start"}
	}
	return s.start(ctx, spec)
}

// StartRedirect admits only an immutable redirect-button request on a service
// explicitly selected by NewOneTapRedirectStartService. It uses the existing
// keyed admission, risk, coordinator and atomic staging owners; no provider
// endpoint is called. Unknown commitment requires the original key or recovery.
func (s *OneTapStartService) StartRedirect(ctx context.Context, request onetap.BrowserRedirectStartRequest) (out OneTapStartResult, err error) {
	if s == nil || s.config == nil || s.selected.Mode != session.PreAuthProviderRedirect {
		return out, identity.InvalidInputError{Field: "oauth_onetap_start"}
	}
	spec, err := request.Bindings()
	if err != nil {
		return out, identity.InvalidInputError{Field: "oauth_onetap_start"}
	}
	return s.start(ctx, spec)
}

func (s *OneTapStartService) start(ctx context.Context, spec onetap.BrowserStartRequestSpec) (out OneTapStartResult, err error) {
	c := s.config()
	options, optionErr := spec.Options.Projection()
	redirect := options.Experience == onetap.BrowserStartRedirectButton && options.Button != nil && options.Button.UXMode == onetap.ButtonRedirect
	callback := options.Experience == onetap.BrowserStartPrompt || options.Experience == onetap.BrowserStartPopupButton
	if ctx == nil || optionErr != nil || spec.TenantID != c.TenantID || spec.Origin != c.Issuance.Origin ||
		(s.selected.Mode == session.PreAuthProviderRedirect && !redirect) || (s.selected.Mode == session.PreAuthProviderCallback && !callback) {
		return out, identity.InvalidInputError{Field: "oauth_onetap_start"}
	}
	ctx, cancel := context.WithTimeout(ctx, c.MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil {
			out.browser = nil
			out.redirectBrowser = nil
			err = identity.UnavailableError{}
		}
	}()
	p := &oneTapStartPhase{service: s, request: spec}
	p.sessionIssuer, err = s.newSessionIssuer(p)
	if err != nil {
		return out, err
	}
	coordinator, registry, err := s.coordinator(p)
	if err != nil {
		return out, err
	}
	p.registry = registry
	intent, err := p.intent()
	if err != nil {
		return out, err
	}
	scope := kernel.RequestKeyScope{TenantID: c.TenantID, ActorID: c.Issuance.ActorID, ActorKind: authorization.SubjectServiceAccount, Method: http.MethodPost, RouteID: oneTapStartOperationID}
	caller := s.caller(oneTapStartOperationID, "identity.request-admission", oneTapStartOperationID)
	key, wire, err := coordinator.ResolvePreparedRequestKey(ctx, scope, spec.Key, intent, caller, p.registration(), p)
	if err != nil {
		return out, err
	}
	defer clear(wire)
	if err := p.restoreInput(ctx, key, wire); err != nil {
		return out, err
	}
	command, err := p.command(nil)
	if err != nil {
		return out, err
	}
	plan, err := p.plan(ctx, nil)
	if err != nil {
		return out, err
	}
	receipt, err := coordinator.ExecutePreparedFeature(ctx, command, plan)
	out.CommandID, out.Outcome = key.Admission.CommandID, receipt.Outcome
	if err != nil || receipt.Outcome != identity.CommitOutcomeCommitted {
		return out, err
	}
	return p.deliver(ctx, out, receipt)
}

// Format hides trust and key custody.
func (OneTapStartConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.OneTapStartConfig(redacted)"))
}

// MarshalJSON refuses automatic serialization of the trusted configuration.
func (OneTapStartConfig) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// Format hides transient browser and cookie custody.
func (OneTapBrowserStart) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.OneTapBrowserStart(redacted)"))
}

// MarshalJSON requires explicit transport projection; it cannot send a cookie.
func (OneTapBrowserStart) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// Format hides transient redirect launch and cookie custody.
func (OneTapRedirectBrowserStart) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.OneTapRedirectBrowserStart(redacted)"))
}

// MarshalJSON requires explicit transport projection; it cannot send a cookie.
func (OneTapRedirectBrowserStart) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText refuses accidental browser-secret export.
func (OneTapRedirectBrowserStart) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
