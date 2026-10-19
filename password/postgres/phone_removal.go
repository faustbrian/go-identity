package passwordpostgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/phone"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// PhoneRemovalNoticeConfig selects one required encrypted notice to the exact
// removed SMS number. The native delivery owner persists it in the removal Work;
// external sending remains an independent worker outcome. Templates are copied
// and versioned, use no per-request variables, and select SMS/text/plain.
// TTL is positive <=24h from original proof issuance, never from a retry.
type PhoneRemovalNoticeConfig struct {
	Delivery        deliverypg.ContributorConfig
	Templates       []delivery.Template
	TemplateID      string
	TemplateVersion uint32
	ProviderVersion uint64
	LocaleChain     []string
	TTL             time.Duration
}

// PhoneRemovalConfig selects self-service password/known-empty-MFA removal with
// an actual remaining verified-email/password signin and reset path. Removal
// advances identifier authority, denying all older identifier-bound sessions;
// it does not claim physical session-row cleanup or consumer acknowledgement.
// Domain fixes retained phone normalization, recycling and cascade policy.
// Risk/counters and one required old-number notice share the owning command.
// ConfigurationID versions borrowed semantics. Request namespace, intent/envelope
// keys and original configuration must outlive retained commands. IntentKey is
// independent of lookup, envelope, command fingerprint and number reuse keys.
// MaximumDuration is positive <=1m; construction performs no IO or callbacks.
type PhoneRemovalConfig struct {
	PolicyID, ConfigurationID string
	MaximumDuration           time.Duration
	Domain                    kernel.PhoneRemovalDomainConfig
	RequestKeys               kernel.RequestKeyConfig
	IntentKey                 [32]byte
	Risk                      risk.ProtectedProviderAdmissionCustodyConfig
	Counters                  riskpg.Config
	ActiveEnvelopeKeyID       string
	Notice                    PhoneRemovalNoticeConfig
}

// PhoneRemovalService composes actual proof, directory, factor, risk, recovery
// and delivery owners through the sole native coordinator. It borrows their
// lifetimes, owns no transaction, retry loop, journal or goroutine and supports
// concurrent independent calls. Opaque closure custody prevents nested diagnostic
// traversal of retained keys and owners. Zero denies every operation.
type PhoneRemovalService struct{ read func() *phoneRemovalService }

type phoneRemovalService struct {
	primary   *ActionPrimarySource
	signin    *SigninService
	reset     *ResetService
	policy    *phone.NumberPolicy
	directory *kernel.Repository
	domain    *kernel.PhoneRemovalDomain
	crypto    *envelope.Service
	custody   risk.ProtectedProviderAdmissionCustody
	counters  *riskpg.Repository
	notices   *deliverypg.Contributor
	renderer  *delivery.TemplateRenderer
	csrf      session.CSRFKey
	profile   [32]byte
	config    func() PhoneRemovalConfig
}

var _ phone.RemovalService = (*PhoneRemovalService)(nil)
var _ phone.RemovalRateSource = (*PhoneRemovalService)(nil)

func (s *PhoneRemovalService) state() *phoneRemovalService {
	if s == nil || s.read == nil {
		return nil
	}
	return s.read()
}

// NewPhoneRemovalService freezes explicit composition without IO. Primary must
// select identity.phone.remove and its signed audience. Signin and reset must be
// actual compatible email/password owners on that same pool; reset must include
// request and completion. Verified-looking counts or caller booleans cannot
// replace those recovery owners. Install forward removal/proof histories first.
func NewPhoneRemovalService(primary *ActionPrimarySource, signin *SigninService, reset *ResetService, p *phone.NumberPolicy, c PhoneRemovalConfig, keys *keyring.Provider) (*PhoneRemovalService, error) {
	if primary == nil || primary.primary == nil || primary.primary.source == nil || !primary.Matches("identity.phone.remove", primary.primary.config.Audience) ||
		signin == nil || signin.pool != primary.primary.source.pool || reset == nil || reset.pool != primary.primary.source.pool || reset.request == nil || reset.config == nil || reset.configuration == ([32]byte{}) || reset.request.profile == ([32]byte{}) ||
		p == nil || p.Profile() != phone.CurrentNumberProfile() || keys == nil || !compatibleRemovalOwners(primary.primary, signin, reset) ||
		!c.Counters.EnforceLockouts || c.Counters.CommandCounters == nil || c.IntentKey == ([32]byte{}) || c.MaximumDuration <= 0 || c.MaximumDuration > time.Minute ||
		!reauthenticationText(c.PolicyID, 128) || !reauthenticationText(c.ConfigurationID, 128) || !reauthenticationText(c.ActiveEnvelopeKeyID, 128) ||
		c.Domain.Directory.NormalizationProfile != p.Profile().ID || c.Domain.Directory.NormalizationVersion != p.Profile().Version ||
		c.Notice.TTL <= 0 || c.Notice.TTL > 24*time.Hour || c.Notice.TTL%time.Microsecond != 0 || c.Notice.TemplateVersion == 0 || c.Notice.ProviderVersion == 0 ||
		!reauthenticationText(c.Notice.TemplateID, 128) || len(c.Notice.LocaleChain) == 0 || len(c.Notice.LocaleChain) > 16 {
		return nil, password.ErrPasswordWork
	}
	source := primary.primary.source
	if source.c.Coordinator.AdmissionPolicy == nil || source.c.Coordinator.QueryPolicy == nil || c.RequestKeys.Policy.PolicyVersion != source.c.Coordinator.AdmissionPolicy.PolicyVersion {
		return nil, password.ErrPasswordWork
	}
	if _, err := NewKeyedEmailManagementConfig(c.RequestKeys, c.IntentKey); err != nil {
		return nil, err
	}
	directory, err := kernel.NewRepository(source.pool, kernel.Config{MaximumDuration: min(c.MaximumDuration, 5*time.Second)})
	if err != nil {
		return nil, err
	}
	domain, err := kernel.NewPhoneRemovalDomain(directory, c.Domain)
	if err != nil {
		return nil, err
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	custody, err := risk.NewProtectedProviderAdmissionCustody(c.Risk)
	if err != nil {
		return nil, fmt.Errorf("phone removal risk custody: %w", password.ErrPasswordWork)
	}
	if custody.ValidateCounterPolicy(c.Counters.CommandCounters.Policy) != nil {
		return nil, fmt.Errorf("phone removal counter policy: %w", password.ErrPasswordWork)
	}
	counters, err := riskpg.NewRepository(c.Counters)
	if err != nil {
		return nil, err
	}
	notices, err := deliverypg.NewContributor(c.Notice.Delivery, crypto)
	if err != nil {
		return nil, err
	}
	renderer, err := delivery.NewTemplateRenderer(c.Notice.Templates)
	if err != nil {
		return nil, err
	}
	for _, locale := range c.Notice.LocaleChain {
		if !reauthenticationText(locale, 64) {
			return nil, password.ErrPasswordWork
		}
	}
	// Hash only the selected notice catalog, explicitly in invocation memory.
	// Template.MarshalJSON correctly forbids implicit exports; this private
	// projection is cleared after hashing and is never persisted or logged.
	type templateProfileInput delivery.Template
	var selected []templateProfileInput
	for _, template := range c.Notice.Templates {
		if template.ID == c.Notice.TemplateID && uint64(c.Notice.TemplateVersion) == template.Version &&
			(template.Channel != delivery.ChannelSMS || template.ContentType != "text/plain" || len(template.VariableSchema) != 0 || len(template.RequiredVariables) != 0) {
			return nil, password.ErrPasswordWork
		}
		if template.ID == c.Notice.TemplateID && uint64(c.Notice.TemplateVersion) == template.Version && slices.Contains(c.Notice.LocaleChain, template.Locale) {
			selected = append(selected, templateProfileInput(template))
		}
	}
	if len(selected) == 0 {
		return nil, password.ErrPasswordWork
	}
	if _, ok := c.Notice.Delivery.ProviderProfiles[c.Notice.ProviderVersion]; !ok {
		return nil, password.ErrPasswordWork
	}
	templates, err := json.Marshal(selected)
	if err != nil {
		return nil, fmt.Errorf("phone removal template profile: %w", password.ErrPasswordWork)
	}
	templateProfile := sha256.Sum256(templates)
	clear(templates)
	frame, err := json.Marshal(struct {
		Profile, Configuration, Policy, Audience, Namespace, Comparison, Issuer, Environment, CounterSchema, SigninPolicy, Template string
		ComparisonVersion, TemplateVersion                                                                                          uint32
		PolicyVersion, CounterPolicyVersion, Provider                                                                               uint64
		MaximumAge, MaximumDuration, Cooldown, NoticeTTL                                                                            time.Duration
		Transport                                                                                                                   session.CredentialKind
		Cascade                                                                                                                     kernel.IdentifierRemovalCascadeConfig
		Reset, ResetRequest, Templates                                                                                              [32]byte
		Locales                                                                                                                     []string
	}{"identity-phone-removal-v1", c.ConfigurationID, c.PolicyID, primary.primary.config.Audience, c.RequestKeys.Namespace, p.Profile().ID, source.c.Issuer, source.c.Environment, c.Counters.Schema, signin.c.PolicyID, c.Notice.TemplateID,
		p.Profile().Version, c.Notice.TemplateVersion, c.RequestKeys.Policy.PolicyVersion, c.Counters.PolicyVersion, c.Notice.ProviderVersion,
		primary.primary.config.MaximumAge, c.MaximumDuration, c.Domain.Directory.ReuseCooldown, c.Notice.TTL, primary.primary.config.Transport,
		c.Domain.Cascade, reset.configuration, reset.request.profile, templateProfile, c.Notice.LocaleChain})
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	profile := sha256.Sum256(frame)
	clear(frame)
	c.Domain.Directory.RetainedIdentifierKeys = maps.Clone(c.Domain.Directory.RetainedIdentifierKeys)
	c.Domain.Cascade.Reasons = slices.Clone(c.Domain.Cascade.Reasons)
	c.Domain.Cascade.ConsumerContracts = maps.Clone(c.Domain.Cascade.ConsumerContracts)
	c.Risk.Keys = slices.Clone(c.Risk.Keys)
	c.Notice.LocaleChain = slices.Clone(c.Notice.LocaleChain)
	// Actual owners above have copied these catalogs/keys; do not retain another
	// mutable configuration graph in the workflow's immutable closure.
	c.Counters, c.Notice.Delivery, c.Notice.Templates = riskpg.Config{}, deliverypg.ContributorConfig{}, nil
	snapshot := *p
	s := &phoneRemovalService{primary: primary, signin: signin, reset: reset, policy: &snapshot, directory: directory, domain: domain, crypto: crypto, custody: custody, counters: counters, notices: notices, renderer: renderer, profile: profile, config: func() PhoneRemovalConfig { return c }}
	mac := hmac.New(sha256.New, c.IntentKey[:])
	_, _ = mac.Write([]byte("identity-phone-removal-csrf-intent-v1"))
	material := mac.Sum(nil)
	s.csrf, err = session.NewCSRFKey(1, material)
	clear(material)
	if err != nil {
		return nil, err
	}
	if _, _, err := s.coordinator(&phoneRemovalPhase{service: s}); err != nil {
		return nil, fmt.Errorf("phone removal coordinator: %w", err)
	}
	return &PhoneRemovalService{read: func() *phoneRemovalService { return s }}, nil
}

func (s *phoneRemovalService) coordinator(p *phoneRemovalPhase) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	audit, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, err
	}
	lifecycle, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, nil, err
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{s.directory, audit, lifecycle, p, s.counters, s.notices})
	if err != nil {
		return nil, nil, err
	}
	c, err := kernel.NewCoordinatorWithRequestKeys(s.primary.primary.source.pool, registry, s.primary.primary.source.c.Coordinator, s.config().RequestKeys)
	return c, registry, err
}

// Remove resolves retained original input before current-source reads, then
// executes the one protected removal. Matching terminal retries preserve original
// metadata and cannot remove a newer phone, consume another proof or renew time.
func (s *PhoneRemovalService) Remove(ctx context.Context, request phone.RemoveRequest) (out identity.CommandResult, err error) {
	state := s.state()
	if ctx == nil || state == nil {
		return out, password.ErrPasswordWork
	}
	r, err := request.Bindings()
	if err != nil {
		return out, err
	}
	ctx, stop := context.WithTimeout(ctx, state.config().MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			if out.Validate() != nil {
				out = identity.CommandResult{}
			}
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
	}()
	p, err := state.resolveRemoval(ctx, r)
	if err != nil {
		return out, err
	}
	plan, err := p.plan(false)
	if err != nil {
		return out, err
	}
	return p.coordinator.ExecutePreparedFeature(ctx, p.command, plan)
}

// RemovalRateSource authenticates exact original custody before HTTP admission.
// It neither consumes proof nor removes a phone or delivers a notification.
func (s *PhoneRemovalService) RemovalRateSource(ctx context.Context, request phone.RemoveRequest) (user identity.UserID, err error) {
	state := s.state()
	if ctx == nil || state == nil {
		return "", password.ErrPasswordWork
	}
	r, err := request.Bindings()
	if err != nil {
		return "", err
	}
	ctx, stop := context.WithTimeout(ctx, state.config().MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			user, err = "", identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			user, err = "", ctx.Err()
		}
	}()
	p, err := state.resolveRemoval(ctx, r)
	if err != nil {
		return "", err
	}
	spec, ok := p.command.Feature()
	if !ok {
		return "", password.ErrPasswordWork
	}
	return spec.Binding.UserID, nil
}

func (s *phoneRemovalService) resolveRemoval(ctx context.Context, r phone.RemoveRequestSpec) (*phoneRemovalPhase, error) {
	intent, err := s.requestIntent(r)
	if err != nil {
		return nil, err
	}
	p := &phoneRemovalPhase{service: s, request: r}
	p.coordinator, p.registry, err = s.coordinator(p)
	if err != nil {
		return nil, err
	}
	scope, caller, feature := s.requestScope(r, p.Descriptor())
	binding, wire, err := p.coordinator.ResolvePreparedRequestKey(ctx, scope, r.IdempotencyKey, intent, caller, feature, p)
	defer clear(wire)
	if err != nil {
		return nil, err
	}
	if err := p.restoreRequestKey(ctx, binding, wire); err != nil {
		return nil, err
	}
	return p, nil
}

// RecoverRemoval reconciles original code-free command history under current
// query policy even after removal invalidated its old session. It neither uses
// that old session as current permission nor repeats the mutation or notice.
// Caller retains the original identity.phone.remove action and self resource;
// the coordinator marks historical recovery in trusted resource attributes.
func (s *PhoneRemovalService) RecoverRemoval(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (identity.CommandResult, error) {
	state := s.state()
	if ctx == nil || state == nil || q.OperationID != "identity.phone.remove" || q.ActorKind != authorization.SubjectUser || q.UserID == "" || string(q.ActorID) != string(q.UserID) || q.RecordID == "" || q.AnonymousFlowID != "" || q.LinkMode != 0 {
		return identity.CommandResult{}, password.ErrPasswordWork
	}
	ctx, stop := context.WithTimeout(ctx, state.config().MaximumDuration)
	defer stop()
	p := &phoneRemovalPhase{service: state}
	c, _, err := state.coordinator(p)
	if err != nil {
		return identity.CommandResult{}, err
	}
	return c.RecoverFeatureCommand(ctx, q, caller)
}

func (s *phoneRemovalService) prepareRemoval(ctx context.Context, r phone.RemoveRequestSpec, id identity.CommandID) (*phoneRemovalPhase, error) {
	if r.Validate() != nil || !validEmailPrimaryCaller(r.Caller) {
		return nil, phone.ErrInvalidRemoval
	}
	primary, err := s.primary.Prepare(ctx, ActionPrimaryRequest{TenantID: r.TenantID, CommandID: id, RecordID: string(r.IdentifierID), Session: r.Session, Proof: r.Proof, Caller: r.Caller.Clone(), CSRFToken: r.CSRFToken})
	if err != nil {
		return nil, err
	}
	original, err := primary.Original()
	if err != nil {
		return nil, err
	}
	b, err := original.Bindings()
	if err != nil || b.UserID != r.UserID {
		return nil, identity.ForbiddenError{}
	}
	state, err := s.directory.GetIdentifierState(ctx, identity.IdentifierQuery{TenantID: r.TenantID, UserID: r.UserID, MaximumIdentifiers: 128})
	if err != nil {
		return nil, err
	}
	vector, err := b.Authority.Bindings()
	if err != nil || state.AuthorityVersion != vector.Identifier.Version {
		return nil, identity.ForbiddenError{}
	}
	factors, err := mfapg.ReadPhoneFactors(ctx, s.primary.primary.source.pool, r.TenantID, r.UserID, min(s.config().MaximumDuration, 5*time.Second))
	if err != nil {
		return nil, err
	}
	number, err := r.Number.Record()
	if err != nil || number.Profile != s.policy.Profile() {
		return nil, phone.ErrInvalidRemoval
	}
	intent := kernel.PhoneRemovalIntent{Change: identity.IdentifierChange{TenantID: r.TenantID, UserID: r.UserID, ID: r.IdentifierID, Action: identity.IdentifierRemove, ExpectedUserVersion: state.User.Version, ExpectedAuthorityVersion: state.AuthorityVersion, ExpectedIdentifierVersion: r.ExpectedIdentifierVersion, ExpectedVerificationVersion: r.ExpectedVerificationVersion}, CanonicalNumber: number.E164, NormalizationProfile: number.Profile.ID, NormalizationVersion: number.Profile.Version, Reason: string(r.Reason)}
	if _, err := identity.ApplyIdentifierChange(state, intent.Change, time.Now().UTC()); err != nil {
		return nil, err
	}
	fields, err := kernel.PhoneRemovalFields(intent)
	if err != nil {
		return nil, err
	}
	fields = append(fields, identity.FeatureField{Name: "phone.factor-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: factors.Version()}}, identity.FeatureField{Name: "phone.removal.profile", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: slices.Clone(s.profile[:])}})
	op := actionPrimaryOperation("identity.phone.remove")
	binding := identity.CommandBinding{CommandID: id, TenantID: r.TenantID, UserID: r.UserID, ActorID: identity.ActorID(r.UserID), ActorKind: authorization.SubjectUser, RecordID: string(r.IdentifierID), OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: s.config().PolicyID, PolicyVersion: s.config().RequestKeys.Policy.PolicyVersion, CorrelationID: string(id)}
	command, err := primary.Command(binding, fields)
	if err != nil {
		return nil, err
	}
	command, counter, err := s.counters.PrepareCommandCounters(command, risk.Subject{User: string(r.UserID), Session: b.SessionID, Network: r.Network}, r.Proof.Proof.IssuedAt.UTC().Truncate(time.Microsecond))
	if err != nil {
		return nil, err
	}
	return &phoneRemovalPhase{service: s, request: r, primary: primary, intent: intent, command: command, counter: counter, factorVersion: factors.Version()}, nil
}

func (s *phoneRemovalService) prepareNotice(ctx context.Context, b identity.CommandBinding, intent kernel.PhoneRemovalIntent, at time.Time) (deliverypg.PreparedDelivery, error) {
	n := s.config().Notice
	frame, err := json.Marshal([]string{string(b.TenantID), string(b.UserID), intent.CanonicalNumber, intent.NormalizationProfile})
	if err != nil {
		return deliverypg.PreparedDelivery{}, password.ErrPasswordWork
	}
	key := s.config().IntentKey
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("identity-phone-removal-notice-recipient-v1\x00"))
	_, _ = mac.Write(frame)
	clear(frame)
	recipient := delivery.Recipient{Channel: delivery.ChannelSMS, Address: intent.CanonicalNumber, ScopeDigest: hex.EncodeToString(mac.Sum(nil))}
	message := delivery.Message{Purpose: "phone-removed", Channel: delivery.ChannelSMS, Recipient: recipient, TemplateID: n.TemplateID, TemplateVersion: uint64(n.TemplateVersion), LocaleChain: n.LocaleChain}
	rendered, err := s.renderer.Render(ctx, message)
	if err != nil {
		return deliverypg.PreparedDelivery{}, err
	}
	return s.notices.Prepare(ctx, b, []deliverypg.IntentInput{{EffectIndex: 0, Purpose: message.Purpose, SubjectID: string(b.UserID), TemplateID: n.TemplateID, TemplateVersion: n.TemplateVersion, ProviderConfigVersion: n.ProviderVersion, ExpiresAt: at.Add(n.TTL).UTC().Truncate(time.Microsecond), Recipient: recipient, Rendered: rendered}})
}

// Format redacts all borrowed owners and key custody.
func (*PhoneRemovalService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passwordpostgres.PhoneRemovalService(redacted)"))
}

// MarshalJSON denies implicit owner export.
func (*PhoneRemovalService) MarshalJSON() ([]byte, error) { return nil, password.ErrPasswordWork }

// MarshalText denies implicit owner export.
func (*PhoneRemovalService) MarshalText() ([]byte, error) { return nil, password.ErrPasswordWork }

// LogValue exposes only a fixed marker.
func (*PhoneRemovalService) LogValue() slog.Value {
	return slog.StringValue("passwordpostgres.PhoneRemovalService(redacted)")
}

// Format redacts sensitive startup configuration.
func (PhoneRemovalConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passwordpostgres.PhoneRemovalConfig(redacted)"))
}

// MarshalJSON denies implicit startup export.
func (PhoneRemovalConfig) MarshalJSON() ([]byte, error) { return nil, password.ErrPasswordWork }

// MarshalText denies implicit startup export.
func (PhoneRemovalConfig) MarshalText() ([]byte, error) { return nil, password.ErrPasswordWork }
