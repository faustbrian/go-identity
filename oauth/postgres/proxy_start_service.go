package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	oauthproxy "github.com/faustbrian/go-identity/oauth/proxy"
	kernel "github.com/faustbrian/go-identity/postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// ProxyStartConfig opts one exact authenticated preview into the production
// proxy start. Provider and key material are selected by the trusted program,
// never by the request. Retain the original lookup and preparation keys while
// pending starts can recover. StateLifetime is one to five whole minutes or
// the whole seconds between those bounds.
type ProxyStartConfig struct {
	Preview                oauthproxy.PreviewInitiationConfig
	Provider               *oauth.OIDCProvider
	ClaimsProfile          string
	ClaimsVersion          uint64
	CurrentStateKeyVersion uint32
	StateLifetime          time.Duration
	CapabilityPreparation  capabilitypg.IssuancePreparationConfig
}

// ProxyStartService issues one original production proxy transaction. It
// borrows the exact forward store and provider but starts no HTTP listener,
// contacts no provider during initiation, and creates no identity or session.
type ProxyStartService struct {
	forward    *ProxyForwardService
	admission  *oauthproxy.PreviewInitiationAdmission
	provider   *oauth.OIDCProvider
	profile    oauth.ProviderProfile
	checkpoint *capabilitypg.IssuancePreparationCodec
	claims     string
	version    uint64
	stateKey   uint32
	lifetime   time.Duration
}

// NewProxyStartService validates and snapshots one trusted preview profile
// without I/O. Install the native proxy table and both coordinator erasure
// guards before selecting this writer.
func NewProxyStartService(forward *ProxyForwardService, c ProxyStartConfig) (*ProxyStartService, error) {
	if forward == nil || forward.issuer == nil || c.Provider == nil || !rpProviderID(c.ClaimsProfile) || c.ClaimsVersion == 0 ||
		c.CurrentStateKeyVersion == 0 || forward.config.StateKeys[c.CurrentStateKeyVersion] == ([32]byte{}) ||
		c.StateLifetime < time.Minute || c.StateLifetime > 5*time.Minute || c.StateLifetime%time.Second != 0 ||
		c.Preview.Target.Deployment == forward.config.ProductionDeployment || c.Preview.MaximumDuration > forward.config.MaximumDuration ||
		c.CapabilityPreparation.Deployment != forward.config.ProductionDeployment {
		return nil, oauthproxy.InitiationInvalid
	}
	profile := c.Provider.Profile()
	if profile.ValidateQueryCallback() != nil || proxyBindingHTTPS(profile.RedirectURI) == nil || proxyBindingHTTPS(profile.Issuer) == nil {
		return nil, oauthproxy.InitiationInvalid
	}
	admission, err := oauthproxy.NewPreviewInitiationAdmission(c.Preview)
	if err != nil {
		return nil, oauthproxy.InitiationInvalid
	}
	checkpoint, err := capabilitypg.NewIssuancePreparationCodec(forward.issuer, c.CapabilityPreparation)
	if err != nil {
		return nil, oauthproxy.InitiationInvalid
	}
	return &ProxyStartService{forward: forward, admission: admission, provider: c.Provider, profile: profile, checkpoint: checkpoint,
		claims: c.ClaimsProfile, version: c.ClaimsVersion, stateKey: c.CurrentStateKeyVersion, lifetime: c.StateLifetime}, nil
}

// ProxyStartResult holds the newly committed authorization request and the
// preview's original evidence binding. It contains no verifier or grant proof.
// Retain the binding in the intended preview before redirecting its browser.
type ProxyStartResult struct {
	authorization oauth.AuthorizationRequest
	binding       oauth.ProxyOIDCEvidenceBinding
}

func (r ProxyStartResult) Authorization() (oauth.AuthorizationRequest, bool) {
	return r.authorization, r.authorization.URL() != ""
}

func (r ProxyStartResult) Binding() (oauth.ProxyOIDCEvidenceBinding, bool) {
	return r.binding, r.authorization.URL() != ""
}

// Start verifies the configured preview credential and commits its original
// state and one-use capability atomically. A known replay cannot disclose its
// authorization URL again. An unavailable result conveys no commit decision.
func (s *ProxyStartService) Start(ctx context.Context, request oauthproxy.InitiationRequest) (out ProxyStartResult, err error) {
	if s == nil || s.admission == nil || s.forward == nil || ctx == nil || ctx.Err() != nil {
		return out, oauthproxy.InitiationInvalid
	}
	defer func() {
		if recover() != nil {
			out, err = ProxyStartResult{}, oauthproxy.InitiationUnavailable
		}
	}()
	started := time.Now()
	ctx, cancel := context.WithTimeout(ctx, s.forward.config.MaximumDuration)
	defer cancel()
	preview, err := s.admission.Admit(ctx, request)
	if err != nil {
		return out, err
	}
	query := kernel.DirectoryAuthorityQuery{TenantID: preview.TenantID, GlobalAuthorityID: s.forward.config.GlobalAuthorityID}
	authority, err := s.forward.directory.GetDirectoryAuthority(ctx, query)
	if err != nil || !authority.Enabled {
		var denied identity.ForbiddenError
		if err == nil || errors.As(err, &denied) {
			return out, oauthproxy.InitiationDenied
		}
		return out, oauthproxy.InitiationUnavailable
	}
	providerKey := ProviderAuthorityKey{TenantID: preview.TenantID, ProviderID: s.profile.ID}
	providerEpoch, err := readProxyProviderEpoch(ctx, s.forward.providerAuthority, providerKey, s.profile.Version)
	if err != nil {
		return out, proxyStartAuthorityError(err)
	}
	phase, err := s.phase(preview, authority, providerEpoch, started)
	if err != nil {
		return out, oauthproxy.InitiationUnavailable
	}
	defer phase.prepared.clear()
	coordinator, err := s.coordinator(phase)
	if err != nil {
		return out, oauthproxy.InitiationUnavailable
	}
	result, err := coordinator.ExecutePreparedFeature(ctx, phase.command, phase.basePlan)
	if err != nil || ctx.Err() != nil || result.Outcome != identity.CommitOutcomeCommitted {
		return out, oauthproxy.InitiationUnavailable
	}
	if !phase.generated || phase.response.URL() == "" {
		return out, oauthproxy.InitiationDenied
	}
	if err := requireProxyProviderAuthority(ctx, s.forward.providerAuthority, phase.evidence); err != nil {
		return out, proxyStartAuthorityError(err)
	}
	if ctx.Err() != nil || !time.Now().Before(phase.evidence.ExpiresAt) {
		return out, oauthproxy.InitiationDenied
	}
	return ProxyStartResult{authorization: phase.response, binding: phase.evidence}, nil
}

func proxyStartAuthorityError(err error) error {
	var denied identity.ForbiddenError
	if errors.As(err, &denied) {
		return oauthproxy.InitiationDenied
	}
	return oauthproxy.InitiationUnavailable
}

func (s *ProxyStartService) phase(preview oauthproxy.InitiationBinding, authority kernel.DirectoryAuthorityRecord, providerEpoch uint64, started time.Time) (*proxyStartPhase, error) {
	c, profile, t := s.forward.config, s.profile, preview.Target
	op := kernel.OAuthProxyStartOperation()
	binding := identity.CommandBinding{
		CommandID: preview.CommandID, TenantID: preview.TenantID, ActorID: preview.ActorID, ActorKind: authorization.SubjectServiceAccount,
		AnonymousFlowID: string(preview.TransactionID), RecordID: string(preview.TransactionID), CorrelationID: string(preview.CommandID),
		OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, PolicyID: c.PolicyID, PolicyVersion: c.PolicyVersion,
	}
	remember, err := preview.Remember.Bindings()
	if err != nil {
		return nil, err
	}
	// Keep the immutable preview fingerprint, resolved policy and exact provider
	// selection in the request commitment, but never include invocation time.
	fields := []any{"identity.oauth.proxy-start.v1", preview.RequestFingerprint, remember,
		c.ProductionDeployment, t, profile, s.claims, s.version, s.lifetime, authority.Query.GlobalAuthorityID, authority.GlobalVersion, authority.TenantVersion}
	if providerEpoch != 0 {
		fields[0] = "identity.oauth.proxy-start.v2"
		fields = append(fields, providerEpoch)
	}
	frame, err := json.Marshal(fields)
	defer clear(frame)
	if err != nil {
		return nil, err
	}
	p := &proxyStartPhase{forward: s.forward, checkpoint: s.checkpoint, binding: binding, request: sha256.Sum256(frame), startedAt: started,
		profile: s.provider, lifetime: s.lifetime, issuer: s.forward.capabilityIssuer, audience: s.forward.capabilityAudience,
		locator: proxyBindingLocator{Tenant: preview.TenantID, Transaction: preview.TransactionID, OriginCommand: preview.CommandID,
			Production: c.ProductionDeployment, Provider: profile.ID, CallbackURI: profile.RedirectURI, ProviderVersion: profile.Version, StateKeyVersion: s.stateKey},
		original: proxyOriginalBinding{GlobalVersion: authority.GlobalVersion, TenantVersion: authority.TenantVersion,
			Evidence: oauth.ProxyOIDCEvidenceBinding{TenantID: preview.TenantID, CommandID: preview.CommandID, TransactionID: preview.TransactionID,
				RequestFingerprint: preview.RequestFingerprint, ProductionDeployment: c.ProductionDeployment, PreviewDeployment: t.Deployment,
				ProviderID: profile.ID, Issuer: profile.Issuer, ClientID: profile.ClientID, PreviewOrigin: t.Origin, PreviewRedirect: t.Redirect,
				Recipient: t.Recipient, ProviderVersion: profile.Version, ProviderAuthorityEpoch: providerEpoch,
				ClaimsProfile: s.claims, ClaimsVersion: s.version, Remember: preview.Remember}},
	}
	p.command, err = p.executionCommand([32]byte{})
	return p, err
}

func (s *ProxyStartService) coordinator(p *proxyStartPhase) (*kernel.Coordinator, error) {
	auditing, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, err
	}
	lifecycle, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, err
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{s.forward.directory, auditing, lifecycle, p, s.forward.issuer})
	if err != nil {
		return nil, err
	}
	const event = "identity.oauth.start_authorization"
	b, operation := p.binding, kernel.OAuthProxyStartOperation()
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return nil, err
	}
	record, err := builder.Build(audit.RecordInput{OccurredAt: p.startedAt.UTC(), Action: event, Outcome: audit.OutcomeSucceeded,
		Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: proxySubjectType, ID: b.RecordID},
		Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID},
		Policy:  audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true},
		Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": proxySubjectType, "aggregate.id": b.RecordID,
			"aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "protected"},
	})
	if err != nil {
		return nil, err
	}
	scope, err := kernel.FeatureAuditBindingDigest(b, operation, proxySubjectType, record)
	if err != nil {
		return nil, err
	}
	descriptors := registry.Descriptors()
	effect := kernel.OAuthProxyStartLifecycle()
	p.basePlan = kernel.CommandPlan{Contributors: descriptors[:len(descriptors)-1], Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: operation},
		SubjectType: proxySubjectType, Lifecycle: &effect, Audits: []kernel.AuditPlan{{EventType: event, SchemaVersion: 1, RequiredRecordCount: 1, Required: true,
			MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: s.forward.config.AuditRetention, RetentionClass: "protected", BindingDigest: scope}}}
	return kernel.NewCoordinator(s.forward.pool, registry, s.forward.config.Coordinator)
}

func (ProxyStartConfig) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("oauthpostgres.ProxyStartConfig(redacted)"))
}
func (*ProxyStartService) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("oauthpostgres.ProxyStartService(redacted)"))
}
func (ProxyStartResult) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("oauthpostgres.ProxyStartResult(redacted)"))
}
func (ProxyStartConfig) MarshalJSON() ([]byte, error)   { return nil, oauthproxy.InitiationInvalid }
func (ProxyStartConfig) MarshalText() ([]byte, error)   { return nil, oauthproxy.InitiationInvalid }
func (*ProxyStartService) MarshalJSON() ([]byte, error) { return nil, oauthproxy.InitiationInvalid }
func (*ProxyStartService) MarshalText() ([]byte, error) { return nil, oauthproxy.InitiationInvalid }
func (ProxyStartResult) MarshalJSON() ([]byte, error)   { return nil, oauthproxy.InitiationInvalid }
func (ProxyStartResult) MarshalText() ([]byte, error)   { return nil, oauthproxy.InitiationInvalid }
