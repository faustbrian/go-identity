package passwordpostgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
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

// PhoneChangeConfig explicitly selects existing-account, known-empty-MFA
// replacement. RequestKeys retain original new-number sends; sending changes no
// identifier. AuthenticationRisk owns send admission, while UpdateRisk/Counters
// own the separate consuming credential mutation. The distinct action proofs,
// actual independent email/password recovery owners and old-number notice are
// mandatory. Domain fixes recycling and pending change-cascade policy.
// ConfigurationID versions all borrowed semantics and must remain available for
// retained commands. Keys are dedicated and independent of other workflow keys.
// MaximumDuration is positive <=1m. This is sensitive startup input, not a log
// handle. Constructors do no IO or policy callbacks and expose no HTTP routes.
type PhoneChangeConfig struct {
	PolicyID, ConfigurationID string
	// Reason is one registered cascade reason, frozen before requesting SMS.
	// Completion must preserve it rather than choose a new policy outcome.
	Reason                   identity.PolicyReason
	MaximumDuration          time.Duration
	Domain                   kernel.PhoneChangeDomainConfig
	RequestKeys              kernel.RequestKeyConfig
	IntentKey, IdentifierKey [32]byte
	AuthenticationRisk       risk.AuthenticationAdmissionCustodyConfig
	UpdateRisk               risk.ProtectedProviderAdmissionCustodyConfig
	Counters                 riskpg.Config
	ActiveEnvelopeKeyID      string
	Issuer                   *otppg.PhoneChangeIssuer
	CurrentAttemptKeyVersion uint32
	// Notice uses the same bounded no-variable SMS catalog as removal, but
	// replacement selects its own purpose and original old-number recipient.
	Notice PhoneRemovalNoticeConfig
}

// PhoneChangeService borrows real proof, session, directory, OTP, delivery and
// recovery owners. It owns no pool, transaction, journal, retries or goroutines.
// Calls are bounded and concurrent-safe; each invocation has its own phase.
// Opaque closure custody prevents nested diagnostics from traversing keys.
type PhoneChangeService struct{ read func() *phoneChangeService }

type phoneChangeService struct {
	// Reuse only the established bounded IO/CSRF/authentication-risk helpers,
	// never its enrollment phase, identifier derivation or attachment workflow.
	common    *phoneVerificationService
	update    *ActionPrimarySource
	signin    *SigninService
	reset     *ResetService
	domain    *kernel.PhoneChangeDomain
	protected risk.ProtectedProviderAdmissionCustody
	counters  *riskpg.Repository
	notices   *deliverypg.Contributor
	renderer  *delivery.TemplateRenderer
	profile   [32]byte
	config    func() PhoneChangeConfig
}

func (s *PhoneChangeService) state() *phoneChangeService {
	if s == nil || s.read == nil {
		return nil
	}
	return s.read()
}

// NewPhoneChangeService requires separate send-verification and update primary
// owners on the same real native account/session store. Signin and reset must
// support the independent configured email/password recovery path. A number,
// verified-address count or structurally valid proof cannot replace them.
// Install forward phone-change directory and action-proof histories before use.
func NewPhoneChangeService(send, update *ActionPrimarySource, signin *SigninService, reset *ResetService, policy *phone.NumberPolicy, c PhoneChangeConfig, keys *keyring.Provider) (*PhoneChangeService, error) {
	if send == nil || send.primary == nil || send.primary.source == nil || update == nil || update.primary == nil || update.primary.source == nil ||
		!send.Matches("identity.phone.send-verification", send.primary.config.Audience) || !update.Matches("identity.phone.update", update.primary.config.Audience) ||
		send.primary.source.pool != update.primary.source.pool || send.primary.config.Transport != update.primary.config.Transport ||
		send.primary.source.c.Session != update.primary.source.c.Session || send.primary.source.c.Profile != update.primary.source.c.Profile ||
		send.primary.source.c.Issuer != update.primary.source.c.Issuer || send.primary.source.c.Environment != update.primary.source.c.Environment ||
		signin == nil || signin.pool != send.primary.source.pool || reset == nil || reset.pool != send.primary.source.pool || reset.config == nil || reset.request == nil ||
		!compatibleRemovalOwners(send.primary, signin, reset) || !compatibleRemovalOwners(update.primary, signin, reset) ||
		policy == nil || policy.Profile() != phone.CurrentNumberProfile() || keys == nil || c.Issuer == nil || c.CurrentAttemptKeyVersion == 0 ||
		c.IntentKey == ([32]byte{}) || c.IdentifierKey == ([32]byte{}) || c.IntentKey == c.IdentifierKey || c.MaximumDuration <= 0 || c.MaximumDuration > time.Minute ||
		!reauthenticationText(c.PolicyID, 128) || !reauthenticationText(c.ConfigurationID, 128) || !reauthenticationText(c.ActiveEnvelopeKeyID, 128) || !slices.Contains(c.Domain.Cascade.Reasons, string(c.Reason)) ||
		c.Domain.Directory.NormalizationProfile != policy.Profile().ID || c.Domain.Directory.NormalizationVersion != policy.Profile().Version ||
		!c.Counters.EnforceLockouts || c.Counters.CommandCounters == nil {
		return nil, password.ErrPasswordWork
	}
	primary, err := phoneChangeSendPrimary(send)
	if err != nil {
		return nil, err
	}
	source := primary.primary.source
	if source.c.Coordinator.AdmissionPolicy == nil || source.c.Coordinator.QueryPolicy == nil || c.RequestKeys.Policy.PolicyVersion != source.c.Coordinator.AdmissionPolicy.PolicyVersion {
		return nil, password.ErrPasswordWork
	}
	if _, err = NewKeyedEmailManagementConfig(c.RequestKeys, c.IntentKey); err != nil {
		return nil, err
	}
	issuer, err := c.Issuer.Configuration()
	if err != nil || c.Issuer.DeliveryContributor() == nil {
		return nil, password.ErrPasswordWork
	}
	directory, err := kernel.NewRepository(source.pool, kernel.Config{MaximumDuration: min(c.MaximumDuration, 5*time.Second)})
	if err != nil {
		return nil, err
	}
	domain, err := kernel.NewPhoneChangeDomain(directory, c.Domain)
	if err != nil {
		return nil, err
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	authentication, err := risk.NewAuthenticationAdmissionCustody(c.AuthenticationRisk)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	protected, err := risk.NewProtectedProviderAdmissionCustody(c.UpdateRisk)
	if err != nil {
		return nil, fmt.Errorf("phone change protected admission: %w", password.ErrPasswordWork)
	}
	if protected.ValidateCounterPolicy(c.Counters.CommandCounters.Policy) != nil {
		return nil, fmt.Errorf("phone change counter policy: %w", password.ErrPasswordWork)
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
	if c.Notice.TTL <= 0 || c.Notice.TTL > 24*time.Hour || c.Notice.TTL%time.Microsecond != 0 || c.Notice.TemplateVersion == 0 || c.Notice.ProviderVersion == 0 ||
		!reauthenticationText(c.Notice.TemplateID, 128) || len(c.Notice.LocaleChain) == 0 || len(c.Notice.LocaleChain) > 16 {
		return nil, password.ErrPasswordWork
	}
	for _, locale := range c.Notice.LocaleChain {
		if !reauthenticationText(locale, 64) {
			return nil, password.ErrPasswordWork
		}
	}
	if _, ok := c.Notice.Delivery.ProviderProfiles[c.Notice.ProviderVersion]; !ok {
		return nil, password.ErrPasswordWork
	}
	type templateRecord delivery.Template
	var selected []templateRecord
	for _, template := range c.Notice.Templates {
		if template.ID != c.Notice.TemplateID || template.Version != uint64(c.Notice.TemplateVersion) {
			continue
		}
		if template.Channel != delivery.ChannelSMS || template.ContentType != "text/plain" || len(template.VariableSchema) != 0 || len(template.RequiredVariables) != 0 {
			return nil, password.ErrPasswordWork
		}
		if slices.Contains(c.Notice.LocaleChain, template.Locale) {
			selected = append(selected, templateRecord(template))
		}
	}
	if len(selected) == 0 {
		return nil, password.ErrPasswordWork
	}
	templates, err := json.Marshal(selected)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	templateDigest := sha256.Sum256(templates)
	clear(templates)
	type directoryProfile kernel.PhoneEnrollmentDomainConfig
	type changeDomainProfile struct {
		Directory directoryProfile
		Cascade   kernel.IdentifierChangeCascadeConfig
	}
	frame, err := json.Marshal(struct {
		Profile, Configuration, Policy, SendAudience, UpdateAudience, Namespace, Issuer, Environment, AuthenticationRisk, UpdateRisk, CounterSchema, Template string
		PolicyVersion, CounterPolicyVersion, Provider                                                                                                         uint64
		TemplateVersion, AttemptKey                                                                                                                           uint32
		MaximumDuration, SendAge, UpdateAge, NoticeTTL                                                                                                        time.Duration
		Transport                                                                                                                                             session.CredentialKind
		Domain                                                                                                                                                changeDomainProfile
		Reason                                                                                                                                                identity.PolicyReason
		OTP, Templates, Reset, ResetRequest, IdentifierKey                                                                                                    [32]byte
		Locales                                                                                                                                               []string
	}{"identity-phone-change-v1", c.ConfigurationID, c.PolicyID, primary.primary.config.Audience, update.primary.config.Audience, c.RequestKeys.Namespace, source.c.Issuer, source.c.Environment, c.AuthenticationRisk.ConfigurationID, c.UpdateRisk.ConfigurationID, c.Counters.Schema, c.Notice.TemplateID,
		c.RequestKeys.Policy.PolicyVersion, c.Counters.PolicyVersion, c.Notice.ProviderVersion, c.Notice.TemplateVersion, c.CurrentAttemptKeyVersion, c.MaximumDuration, primary.primary.config.MaximumAge, update.primary.config.MaximumAge, c.Notice.TTL, primary.primary.config.Transport,
		changeDomainProfile{directoryProfile(c.Domain.Directory), c.Domain.Cascade}, c.Reason, issuer, templateDigest, reset.configuration, reset.request.profile, c.IdentifierKey, c.Notice.LocaleChain})
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	profile := sha256.Sum256(frame)
	clear(frame)
	c.Domain.Directory.RetainedIdentifierKeys = maps.Clone(c.Domain.Directory.RetainedIdentifierKeys)
	c.Domain.Cascade.Reasons = slices.Clone(c.Domain.Cascade.Reasons)
	c.Domain.Cascade.ConsumerContracts = maps.Clone(c.Domain.Cascade.ConsumerContracts)
	c.AuthenticationRisk.Keys = slices.Clone(c.AuthenticationRisk.Keys)
	c.UpdateRisk.Keys = slices.Clone(c.UpdateRisk.Keys)
	c.Notice.LocaleChain = slices.Clone(c.Notice.LocaleChain)
	c.Counters, c.Notice.Delivery, c.Notice.Templates = riskpg.Config{}, deliverypg.ContributorConfig{}, nil
	commonConfig := PhoneVerificationConfig{PolicyID: c.PolicyID, ConfigurationID: c.ConfigurationID, MaximumDuration: c.MaximumDuration, Domain: c.Domain.Directory, RequestKeys: c.RequestKeys, IntentKey: c.IntentKey, IdentifierKey: c.IdentifierKey, Risk: c.AuthenticationRisk, ActiveEnvelopeKeyID: c.ActiveEnvelopeKeyID, CurrentAttemptKeyVersion: c.CurrentAttemptKeyVersion}
	policyCopy := *policy
	authorization, err := authoritypg.NewAuthorityStore(source.pool.Raw(), min(c.MaximumDuration, 5*time.Second))
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	common := &phoneVerificationService{primary: primary, policy: &policyCopy, directory: directory, authorization: authorization, crypto: crypto, custody: authentication, profile: profile, config: func() PhoneVerificationConfig { return commonConfig }}
	// This digest is only request-intent custody, not the session's synchronizer.
	mac := hmac.New(sha256.New, c.IntentKey[:])
	_, _ = mac.Write([]byte("identity-phone-change-csrf-intent-v1"))
	material := mac.Sum(nil)
	common.csrf, err = session.NewCSRFKey(1, material)
	clear(material)
	if err != nil {
		return nil, err
	}
	state := &phoneChangeService{common: common, update: update, signin: signin, reset: reset, domain: domain, protected: protected, counters: counters, notices: notices, renderer: renderer, profile: profile, config: func() PhoneChangeConfig { return c }}
	return &PhoneChangeService{read: func() *phoneChangeService { return state }}, nil
}

func (s *phoneChangeService) coordinator(owner kernel.FeatureExecutionContributor, otp kernel.OTPExecutionContributor) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	a, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, err
	}
	l, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, nil, err
	}
	contributors := []kernel.Contributor{s.common.directory, a, l, owner}
	if otp == nil {
		contributors = append(contributors, s.config().Issuer.DeliveryContributor())
	} else {
		contributors = append(contributors, otp, s.counters, s.notices)
	}
	registry, err := kernel.NewContributorRegistry(contributors)
	if err != nil {
		return nil, nil, err
	}
	coordinator, err := kernel.NewCoordinatorWithRequestKeys(s.common.primary.primary.source.pool, registry, s.common.primary.primary.source.c.Coordinator, s.config().RequestKeys)
	return coordinator, registry, err
}

// Initialize binds the actual OTP owner's retained digest/lockout metadata after
// the caller applies migrations. It creates no phone, challenge or session.
func (s *PhoneChangeService) Initialize(ctx context.Context) error {
	p := s.state()
	if ctx == nil || p == nil {
		return password.ErrPasswordWork
	}
	ctx, stop := context.WithTimeout(ctx, p.config().MaximumDuration)
	defer stop()
	return p.config().Issuer.Initialize(ctx, p.common.primary.primary.source.pool)
}

// Format redacts all borrowed owners and startup custody.
func (*PhoneChangeService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passwordpostgres.PhoneChangeService(redacted)"))
}

// MarshalJSON denies implicit owner/key export.
func (*PhoneChangeService) MarshalJSON() ([]byte, error) { return nil, password.ErrPasswordWork }

// MarshalText denies implicit owner/key export.
func (*PhoneChangeService) MarshalText() ([]byte, error) { return nil, password.ErrPasswordWork }

// LogValue exposes only a fixed marker.
func (*PhoneChangeService) LogValue() slog.Value {
	return slog.StringValue("passwordpostgres.PhoneChangeService(redacted)")
}

// Format redacts the config; individually projected fields remain sensitive.
func (PhoneChangeConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passwordpostgres.PhoneChangeConfig(redacted)"))
}

// MarshalJSON denies implicit startup-key export.
func (PhoneChangeConfig) MarshalJSON() ([]byte, error) { return nil, password.ErrPasswordWork }

// MarshalText denies implicit startup-key export.
func (PhoneChangeConfig) MarshalText() ([]byte, error) { return nil, password.ErrPasswordWork }
