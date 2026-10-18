package passwordpostgres

import (
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
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/phone"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// PhoneVerificationConfig explicitly selects existing-account password-session,
// known-empty-MFA phone enrollment and consuming SMS confirmation. It enables no
// signup/signin/recovery/replacement/removal or weaker fallback. ConfigurationID
// versions borrowed policy/provider semantics. Domain must match the supplied
// NumberPolicy's complete profile and select an explicit recycling cooldown.
// IntentKey is dedicated, independent of request lookup, fingerprint, number
// reuse, envelope and risk keys. Retain original configuration and decrypt keys
// while original commands exist. CurrentAttemptKeyVersion selects an actual
// retained OTP attempt issuer for new submissions only. Issuer must be the real
// SMS/phone-verification owner and initialized after its migrations. Risk must
// own genuine counted/audited Authentication evaluation; IdentifierKey is a
// separate dedicated canonical-number counter commitment key. MaximumDuration is
// positive <=1m. This is sensitive startup input, not an opaque logging handle.
type PhoneVerificationConfig struct {
	PolicyID, ConfigurationID string
	MaximumDuration           time.Duration
	Domain                    kernel.PhoneEnrollmentDomainConfig
	RequestKeys               kernel.RequestKeyConfig
	IntentKey                 [32]byte
	IdentifierKey             [32]byte
	Risk                      risk.AuthenticationAdmissionCustodyConfig
	ActiveEnvelopeKeyID       string
	Issuer                    *otppg.PhoneEnrollmentIssuer
	CurrentAttemptKeyVersion  uint32
}

// PhoneVerificationService borrows native owners and uses only the existing
// coordinator, request-key mapping, preparation, OTP, proof and delivery owners.
// Closure custody prevents nested diagnostics from traversing borrowed keys or
// request material. Calls are bounded, concurrent-safe and invocation-local;
// no transaction, retry loop, sender, journal or goroutine is independently owned.
type PhoneVerificationService struct {
	read func() *phoneVerificationService
}

type phoneVerificationService struct {
	primary       *ActionPrimarySource
	policy        *phone.NumberPolicy
	directory     *kernel.Repository
	domain        *kernel.PhoneEnrollmentDomain
	authorization *authoritypg.AuthorityStore
	crypto        *envelope.Service
	custody       risk.AuthenticationAdmissionCustody
	csrf          session.CSRFKey
	profile       [32]byte
	config        func() PhoneVerificationConfig
}

var _ phone.VerificationService = (*PhoneVerificationService)(nil)

func (s *PhoneVerificationService) state() *phoneVerificationService {
	if s == nil || s.read == nil {
		return nil
	}
	return s.read()
}

// NewPhoneVerificationService freezes complete native composition without IO,
// entropy, provider callbacks or registration side effects. The primary must
// already select identity.phone.send-verification and its signed audience.
// Install kernel phone identifier, action-proof, request-key/preparation,
// authentication counter, MFA, OTP/session, audit and outbox histories first.
func NewPhoneVerificationService(primary *ActionPrimarySource, p *phone.NumberPolicy, c PhoneVerificationConfig, keys *keyring.Provider) (*PhoneVerificationService, error) {
	if primary == nil || primary.primary == nil || primary.primary.source == nil || !primary.Matches("identity.phone.send-verification", primary.primary.config.Audience) || p == nil || p.Profile() != phone.CurrentNumberProfile() || keys == nil || c.Issuer == nil || c.CurrentAttemptKeyVersion == 0 || c.IntentKey == ([32]byte{}) || c.IdentifierKey == ([32]byte{}) || c.IdentifierKey == c.IntentKey || c.MaximumDuration <= 0 || c.MaximumDuration > time.Minute || !reauthenticationText(c.PolicyID, 128) || !reauthenticationText(c.ConfigurationID, 128) || !reauthenticationText(c.ActiveEnvelopeKeyID, 128) || c.Domain.NormalizationProfile != p.Profile().ID || c.Domain.NormalizationVersion != p.Profile().Version {
		return nil, password.ErrPasswordWork
	}
	source := primary.primary.source
	if source.c.Coordinator.AdmissionPolicy == nil || source.c.Coordinator.QueryPolicy == nil || c.RequestKeys.Policy.PolicyVersion != source.c.Coordinator.AdmissionPolicy.PolicyVersion {
		return nil, password.ErrPasswordWork
	}
	if _, err := NewKeyedEmailManagementConfig(c.RequestKeys, c.IntentKey); err != nil {
		return nil, err
	}
	issuerProfile, err := c.Issuer.Configuration()
	if err != nil || c.Issuer.DeliveryContributor() == nil {
		return nil, password.ErrPasswordWork
	}
	directory, err := kernel.NewRepository(source.pool, kernel.Config{MaximumDuration: min(c.MaximumDuration, 5*time.Second)})
	if err != nil {
		return nil, err
	}
	domain, err := kernel.NewPhoneEnrollmentDomain(directory, c.Domain)
	if err != nil {
		return nil, err
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	custody, err := risk.NewAuthenticationAdmissionCustody(c.Risk)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	authorization, err := authoritypg.NewAuthorityStore(source.pool.Raw(), min(c.MaximumDuration, 5*time.Second))
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	c.Domain.RetainedIdentifierKeys = maps.Clone(c.Domain.RetainedIdentifierKeys)
	c.Risk.Keys = slices.Clone(c.Risk.Keys)
	frame, err := json.Marshal(struct {
		Profile, Configuration, Policy, Audience, Namespace, Comparison, Metadata, Issuer, Environment, RiskConfiguration string
		ComparisonVersion                                                                                                 uint32
		PolicyVersion                                                                                                     uint64
		MaximumAge, MaximumDuration, Cooldown                                                                             time.Duration
		Transport                                                                                                         session.CredentialKind
		OTP                                                                                                               [32]byte
		IdentifierKey                                                                                                     [32]byte
	}{"identity-phone-enrollment-v1", c.ConfigurationID, c.PolicyID, primary.primary.config.Audience, c.RequestKeys.Namespace, p.Profile().ID, p.Profile().MetadataVersion, source.c.Issuer, source.c.Environment, c.Risk.ConfigurationID, p.Profile().Version, c.RequestKeys.Policy.PolicyVersion, primary.primary.config.MaximumAge, c.MaximumDuration, c.Domain.ReuseCooldown, primary.primary.config.Transport, issuerProfile, c.IdentifierKey})
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	snapshot := *p
	s := &phoneVerificationService{primary: primary, policy: &snapshot, directory: directory, domain: domain, authorization: authorization, crypto: crypto, custody: custody, profile: sha256.Sum256(frame), config: func() PhoneVerificationConfig { return c }}
	clear(frame)
	mac := hmac.New(sha256.New, c.IntentKey[:])
	_, _ = mac.Write([]byte("identity-phone-csrf-intent-v1"))
	material := mac.Sum(nil)
	s.csrf, err = session.NewCSRFKey(1, material)
	clear(material)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	if _, _, err = s.coordinator(&phoneEnrollmentPhase{service: s}, nil); err != nil {
		return nil, password.ErrPasswordWork
	}
	return &PhoneVerificationService{read: func() *phoneVerificationService { return s }}, nil
}

func (s *phoneVerificationService) coordinator(owner kernel.FeatureExecutionContributor, otp kernel.OTPExecutionContributor) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	audit, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, err
	}
	lifecycle, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, nil, err
	}
	contributors := []kernel.Contributor{s.directory, audit, lifecycle, owner}
	if otp != nil {
		contributors = append(contributors, otp)
	} else {
		contributors = append(contributors, s.config().Issuer.DeliveryContributor())
	}
	registry, err := kernel.NewContributorRegistry(contributors)
	if err != nil {
		return nil, nil, err
	}
	c, err := kernel.NewCoordinatorWithRequestKeys(s.primary.primary.source.pool, registry, s.primary.primary.source.c.Coordinator, s.config().RequestKeys)
	return c, registry, err
}

func phoneEnrollmentIdentifier(command identity.CommandID) (identity.IdentifierID, error) {
	if _, err := identity.ParseCommandID(string(command)); err != nil {
		return "", password.ErrPasswordWork
	}
	// A single server-owned send has exactly one pending candidate. Derive its
	// record name, rather than allocating another ID during a retry or restore.
	return identity.ParseIdentifierID("phone-" + string(command))
}

// Format redacts configuration, not separately projected startup fields.
func (PhoneVerificationConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passwordpostgres.PhoneVerificationConfig(redacted)"))
}

// MarshalJSON denies implicit key/configuration export.
func (PhoneVerificationConfig) MarshalJSON() ([]byte, error) { return nil, password.ErrPasswordWork }

// MarshalText denies implicit key/configuration export.
func (PhoneVerificationConfig) MarshalText() ([]byte, error) { return nil, password.ErrPasswordWork }

// Format redacts borrowed owners.
func (*PhoneVerificationService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passwordpostgres.PhoneVerificationService(redacted)"))
}

// MarshalJSON denies implicit owner export.
func (*PhoneVerificationService) MarshalJSON() ([]byte, error) { return nil, password.ErrPasswordWork }

// MarshalText denies implicit owner export.
func (*PhoneVerificationService) MarshalText() ([]byte, error) { return nil, password.ErrPasswordWork }

// LogValue emits only a fixed marker.
func (*PhoneVerificationService) LogValue() slog.Value {
	return slog.StringValue("passwordpostgres.PhoneVerificationService(redacted)")
}
