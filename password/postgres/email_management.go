package passwordpostgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	email "github.com/faustbrian/go-identity/email"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// EmailManagementConfig selects the password-origin native adapter for the
// email owner's pending-address workflow. Policy/configuration identities,
// lifetimes, providers and domain policy are startup input, not request options.
// The profile requires known empty MFA, original fresh proof, protected counters,
// provider-only risk and encrypted delivery. MaximumDuration is positive <=1m;
// Lifetime is positive whole-second <=24h. Crypto keys must remain independent.
type EmailManagementConfig struct {
	PolicyID, ConfigurationID string
	MaximumDuration, Lifetime time.Duration
	// ResendInterval selects durable mailbox-family replacement. Zero disables
	// resend and preserves legacy grant behavior; positive values are 30s..10m.
	ResendInterval time.Duration
	// Change and ChangeNotification are selected together only for
	// change-request. Nil leaves that profile unavailable, not partially usable.
	Change             *email.ChangeProfile
	ChangeNotification *EmailChangeNotificationConfig
	Verification       email.RegistrationVerificationConfig
	// VerificationHooks selects link verification only, not change or OTP.
	// Nil preserves existing behavior; version callback semantics in ConfigurationID.
	VerificationHooks *email.VerificationHooks
	// ChangeHooks independently selects new-address link confirmation, including
	// the explicitly configured TOTP-change profile. Nil disables these hooks.
	ChangeHooks         *email.VerificationHooks
	Issuer              issuerpg.IssuerConfig
	IssuanceCustody     issuerpg.IssuancePreparationConfig
	Delivery            SignupDeliveryConfig
	Domain              kernel.EmailAttachmentDomainConfig
	Risk                risk.ProtectedProviderAdmissionCustodyConfig
	CounterPolicy       risk.Policy
	Counters            *riskpg.Repository
	ActiveEnvelopeKeyID string
}

// EmailManagementRequest borrows trusted source/transport context and new
// mailbox intent. Primary supplies the stable command/address and original
// proof; no browser-selected actor, versions, clock, template or action is used.
type EmailManagementRequest struct {
	Primary              EmailPrimaryRequest
	Address              email.AddressInput
	CallbackURL, Network string
}

// EmailManagementResult exposes metadata only after an observed commit. It is
// not mailbox ownership, current authentication or proof that a sender ran.
// Unknown/busy outcomes disclose no address/version and require scoped recovery.
type EmailManagementResult struct {
	CommandID                              identity.CommandID
	Outcome                                identity.CommitOutcome
	AddressID                              identity.IdentifierID
	IdentifierVersion, VerificationVersion uint64
	RetryAfter                             time.Duration
}

// EmailManagementService is the native password-origin adapter, composing email
// policy, kernel identifiers, original proof, MFA, risk, issuer and delivery.
// It borrows the source pool and local keys and owns no goroutines, retries,
// transaction or second journal. Each call owns its phase. Install the existing
// preparation/admission/counter, identifier retirement, email password-proof,
// MFA, issuer, delivery, audit and outbox histories before enabling it.
type EmailManagementService struct {
	primary   *EmailPrimarySource
	directory *kernel.Repository
	domain    *kernel.EmailAttachmentDomain
	address   email.AddressParser
	policy    *email.ManagedVerificationPolicy
	issuer    *issuerpg.Issuer
	codec     *issuerpg.IssuancePreparationCodec
	crypto    *envelope.Service
	custody   risk.ProtectedProviderAdmissionCustody
	config    func() EmailManagementConfig
	profile   [32]byte
}

// NewEmailManagementService snapshots local composition without IO/callbacks.
// Source must select verification-send or change-request. The existing native
// password bundle supplies proof custody; email remains the feature owner.
func NewEmailManagementService(primary *EmailPrimarySource, c EmailManagementConfig, keys *keyring.Provider) (*EmailManagementService, error) {
	if primary == nil || primary.source == nil || keys == nil || c.Counters == nil || c.ResendInterval != 0 && (c.ResendInterval < 30*time.Second || c.ResendInterval > 10*time.Minute) || c.MaximumDuration <= 0 || c.MaximumDuration > time.Minute || c.Lifetime <= 0 || c.Lifetime > 24*time.Hour || c.Lifetime%time.Second != 0 || c.Lifetime > c.Verification.MaximumLifetime || !reauthenticationText(c.PolicyID, 128) || !reauthenticationText(c.ConfigurationID, 128) || !reauthenticationText(c.ActiveEnvelopeKeyID, 128) || c.Issuer.Audience != c.Verification.Audience || c.Delivery.Owner == nil || c.Delivery.Renderer == nil || c.Delivery.Resolver == nil || c.Delivery.Resolver != c.Issuer.Crypto.Resolver || c.Delivery.ScopeKey == ([32]byte{}) || c.Delivery.TemplateVersion == 0 || c.Delivery.ProviderVersion == 0 || !reauthenticationText(c.Delivery.TemplateID, 128) || c.Delivery.Timeout <= 0 || c.Delivery.Timeout > 5*time.Second || len(c.Delivery.Locales) == 0 || len(c.Delivery.Locales) > 16 || !signinURLs([]string{c.Delivery.Endpoint}, false) {
		return nil, password.ErrPasswordWork
	}
	if primary.config.Action != "identity.email.verification-send" && primary.config.Action != "identity.email.change-request" {
		return nil, password.ErrPasswordWork
	}
	if primary.config.Action == "identity.email.change-request" {
		if c.Change == nil || c.Change.Validate() != nil || c.ChangeNotification == nil || c.ChangeNotification.validate() != nil {
			return nil, password.ErrPasswordWork
		}
		if primary.factor != nil && c.Change.CurrentAddress != email.RequirePrimaryAddress {
			// The selected TOTP profile is genuine-primary replacement only;
			// initial establishment is a distinct email goal acceptance profile.
			return nil, password.ErrPasswordWork
		}
		profile, notice := *c.Change, *c.ChangeNotification
		notice.Locales = slices.Clone(notice.Locales)
		c.Change, c.ChangeNotification = &profile, &notice
	} else if c.Change != nil || c.ChangeNotification != nil {
		return nil, password.ErrPasswordWork
	}
	endpoint, err := url.Parse(c.Delivery.Endpoint)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	q, err := url.ParseQuery(endpoint.RawQuery)
	if _, exists := q["token"]; err != nil || exists {
		return nil, password.ErrPasswordWork
	}
	address, err := email.NewAddressParser(c.Verification.Address)
	if err != nil {
		return nil, err
	}
	policy, err := email.NewManagedVerificationPolicy(c.Verification)
	if err != nil {
		return nil, err
	}
	issuer, err := issuerpg.NewIssuer(c.Issuer)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	codec, err := issuerpg.NewIssuancePreparationCodec(issuer, c.IssuanceCustody)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	custody, err := risk.NewProtectedProviderAdmissionCustody(c.Risk)
	if err != nil || custody.ValidateCounterPolicy(c.CounterPolicy) != nil {
		return nil, password.ErrPasswordWork
	}
	directory, err := kernel.NewRepository(primary.source.pool, kernel.Config{MaximumDuration: min(c.MaximumDuration, 5*time.Second)})
	if err != nil {
		return nil, err
	}
	domain, err := kernel.NewEmailAttachmentDomain(directory, c.Domain)
	if err != nil {
		return nil, err
	}
	c.Delivery.Locales = slices.Clone(c.Delivery.Locales)
	c.Domain.RetainedIdentifierKeys = maps.Clone(c.Domain.RetainedIdentifierKeys)
	c.Risk.Keys = slices.Clone(c.Risk.Keys)
	// Borrowed provider/parser/signing semantics are explicitly versioned by
	// ConfigurationID; original output also commits fixed scalar selections.
	frame, err := json.Marshal(struct {
		Profile, Configuration, Action, Policy, Audience, Comparison, Endpoint, Template string
		PolicyVersion, Provider                                                          uint64
		TemplateVersion                                                                  uint32
		Lifetime, MaximumAge, ResendInterval                                             time.Duration
		Locales                                                                          []string
		Change                                                                           *email.ChangeProfile            `json:",omitempty"`
		Notification                                                                     *emailChangeNotificationProfile `json:",omitempty"`
		TOTP                                                                             bool                            `json:",omitempty"`
	}{"identity-managed-email-v1", c.ConfigurationID, primary.config.Action, c.PolicyID, c.Verification.Audience, c.Domain.ComparisonProfile, c.Delivery.Endpoint, c.Delivery.TemplateID, primary.source.c.Coordinator.AdmissionPolicy.PolicyVersion, c.Delivery.ProviderVersion, c.Delivery.TemplateVersion, c.Lifetime, primary.config.MaximumAge, c.ResendInterval, c.Delivery.Locales, c.Change, changeNotificationProfile(c.ChangeNotification), primary.factor != nil})
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	profile := sha256.Sum256(frame)
	clear(frame)
	s := &EmailManagementService{primary: primary, directory: directory, domain: domain, address: address, policy: policy, issuer: issuer, codec: codec, crypto: crypto, custody: custody, config: func() EmailManagementConfig { return c }, profile: profile}
	return s, nil
}

// VerificationSend attaches a new pending mailbox and atomically enqueues its
// original one-use link. Existing-address resend is a separate retained profile,
// not silent replacement. It issues no session and never calls a sender here.
func (s *EmailManagementService) VerificationSend(ctx context.Context, r EmailManagementRequest) (EmailManagementResult, error) {
	return s.request(ctx, r, "identity.email.verification-send", false)
}

// ChangeRequest creates the pending candidate for a new-address-confirmed change.
// It does not swap the verified primary or claim the change complete. The later
// explicit confirmation must enforce original policy and current authority.
func (s *EmailManagementService) ChangeRequest(ctx context.Context, r EmailManagementRequest) (EmailManagementResult, error) {
	return s.request(ctx, r, "identity.email.change-request", false)
}

// VerificationResend replaces the link for an existing pending non-primary
// address, using fresh action-bound password proof and protected cooldown.
// Address may be empty; a supplied address must equal the stored canonical value.
// The sole transaction advances its versions, supersedes prior selected unused
// links and enqueues encrypted delivery. Denial/rollback preserves predecessors
// and does not spend the primary proof. It sends no mail or session itself.
func (s *EmailManagementService) VerificationResend(ctx context.Context, r EmailManagementRequest) (EmailManagementResult, error) {
	return s.request(ctx, r, "identity.email.verification-send", true)
}

func managedResendOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/email", OperationID: "identity.email.verification-send", SchemaID: "identity.email.verification-send.resend-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func (s *EmailManagementService) payload(spec email.ManagedVerificationSpec) (capability.Payload, error) {
	if s.config().ResendInterval != 0 {
		return s.policy.PayloadWithSupersession(spec)
	}
	return s.policy.Payload(spec)
}

func (s *EmailManagementService) request(ctx context.Context, r EmailManagementRequest, action string, resend bool) (out EmailManagementResult, err error) {
	out.CommandID = r.Primary.CommandID
	if ctx == nil || s == nil || s.config == nil {
		return out, password.ErrPasswordWork
	}
	ctx, stop := context.WithTimeout(ctx, s.config().MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			out = EmailManagementResult{CommandID: r.Primary.CommandID, Outcome: out.Outcome}
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			out.AddressID, out.IdentifierVersion, out.VerificationVersion = "", 0, 0
		}
	}()
	p, err := s.prepareRequest(ctx, r, action, resend)
	if err != nil {
		return out, err
	}
	plan, err := p.plan(false)
	if err != nil {
		return out, err
	}
	out.Outcome = identity.CommitOutcomeUnknown
	result, err := p.coordinator.ExecutePreparedFeature(ctx, p.command, plan)
	out.Outcome = result.Outcome
	out.RetryAfter = result.RetryAfter
	if err == nil && result.Outcome == identity.CommitOutcomeCommitted {
		out.AddressID = p.link.IdentifierID
		out.IdentifierVersion, out.VerificationVersion = p.link.IdentifierVersion, p.link.VerificationVersion
	}
	return out, err
}

// Preparation only reads original authority and freezes pure command intent.
// The keyed adapter may retain this input before the existing journal starts;
// signing, provider assessment, counter charges and mutation remain in execution.
func (s *EmailManagementService) prepareRequest(ctx context.Context, r EmailManagementRequest, action string, resend bool) (out *emailManagementPhase, err error) {
	if ctx == nil || s == nil || s.primary == nil || s.config == nil || s.primary.config.Action != action || resend && s.config().ResendInterval == 0 {
		return out, password.ErrPasswordWork
	}
	ctx, stop := context.WithTimeout(ctx, s.config().MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			out = nil
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
	}()
	if len(r.CallbackURL) == 0 || len(r.CallbackURL) > 2048 || !reauthenticationText(r.Network, 128) {
		return out, password.ErrPasswordWork
	}
	admission, err := s.primary.Prepare(ctx, r.Primary)
	if err != nil {
		return out, err
	}
	original, err := admission.Original()
	if err != nil {
		return out, err
	}
	bindings, err := original.Bindings()
	if err != nil {
		return out, err
	}
	state, err := s.directory.GetIdentifierState(ctx, identity.IdentifierQuery{TenantID: r.Primary.TenantID, UserID: bindings.UserID, MaximumIdentifiers: 128})
	if err != nil {
		return out, err
	}
	vector, err := bindings.Authority.Bindings()
	if err != nil || state.AuthorityVersion != vector.Identifier.Version {
		return out, identity.ForbiddenError{}
	}
	factorVersion, enrolled, err := mfapg.ReadPasswordSigninFactors(ctx, s.primary.source.pool, r.Primary.TenantID, bindings.UserID, min(s.config().MaximumDuration, 5*time.Second))
	if err != nil {
		return out, err
	}
	if s.primary.factor == nil && enrolled {
		return out, identity.ForbiddenError{}
	}
	if s.primary.factor != nil {
		version, err := admission.custody().factor.AuthorityVersion()
		if err != nil || !enrolled || version != factorVersion {
			return out, identity.ForbiddenError{}
		}
	}
	op := emailPrimaryOperation(action)
	identifierVersion, verificationVersion := uint64(1), uint64(1)
	var pending identity.Identifier
	if resend {
		op = managedResendOperation()
		found := false
		for n, record := range state.Identifiers {
			if record.ID != r.Primary.AddressID {
				continue
			}
			verification := state.Verifications[n]
			if record.Kind != identity.IdentifierEmail || record.Verified || record.Primary || verification.State != identity.VerificationPending || record.Version == ^uint64(0) || verification.Version == ^uint64(0) || record.Version != verification.Version {
				return out, identity.ForbiddenError{}
			}
			pending, found = record, true
			identifierVersion, verificationVersion = record.Version+1, verification.Version+1
		}
		if !found {
			return out, identity.ForbiddenError{}
		}
		if r.Address == "" {
			r.Address = email.AddressInput(pending.CanonicalValue)
		}
	}
	address, err := s.address.Parse(r.Address)
	if err != nil {
		return out, err
	}
	if len(address.Canonical().Record().Value) > 254 || len(address.Display()) > 254 {
		return out, email.ErrInvalidAddress
	}
	if resend && address.Canonical().Record().Value != pending.CanonicalValue {
		return out, identity.ForbiddenError{}
	}
	b := identity.CommandBinding{CommandID: r.Primary.CommandID, TenantID: r.Primary.TenantID, UserID: bindings.UserID, ActorID: identity.ActorID(bindings.UserID), ActorKind: authorization.SubjectUser, RecordID: string(r.Primary.AddressID), OperationID: action, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: s.config().PolicyID, PolicyVersion: s.primary.source.c.Coordinator.AdmissionPolicy.PolicyVersion, CorrelationID: string(r.Primary.CommandID)}
	intent := kernel.EmailAttachmentIntent{Change: identity.IdentifierChange{TenantID: b.TenantID, UserID: b.UserID, ID: r.Primary.AddressID, Action: identity.IdentifierAttach, Kind: identity.IdentifierEmail, CanonicalValue: address.Canonical().Record().Value, DisplayValue: address.Display(), ExpectedUserVersion: state.User.Version, ExpectedAuthorityVersion: state.AuthorityVersion}, ComparisonProfile: s.config().Domain.ComparisonProfile}
	var previous email.PreviousAddress
	if action == "identity.email.change-request" {
		previous, err = s.config().Change.SelectPrevious(state, r.Primary.AddressID, s.primary.source.c.Coordinator.QueryPolicy.Clock.Now())
		if err != nil {
			return out, identity.ForbiddenError{}
		}
		intent.Previous = kernelPrevious(previous, *s.config().Change)
	}
	if resend {
		intent.Change.Action = identity.IdentifierRestartVerification
		intent.Change.Kind, intent.Change.CanonicalValue, intent.Change.DisplayValue = "", "", ""
		intent.Change.ExpectedIdentifierVersion, intent.Change.ExpectedVerificationVersion = identifierVersion-1, verificationVersion-1
		intent.ExistingCanonicalAddress = pending.CanonicalValue
	}
	fields, err := kernel.EmailAttachmentFields(intent)
	if err != nil {
		return out, err
	}
	callback, err := url.Parse(r.CallbackURL)
	if err != nil {
		return out, password.ErrPasswordWork
	}
	at := r.Primary.Proof.Proof.IssuedAt.UTC().Truncate(time.Second)
	link := email.ManagedVerificationSpec{Binding: b, IdentifierID: r.Primary.AddressID, IdentifierVersion: identifierVersion, VerificationVersion: verificationVersion, Payload: email.CapabilityPayload{TenantID: b.TenantID, SubjectID: identity.SubjectID(b.UserID), CanonicalAddress: address.Canonical(), Purpose: "identity.identifier.verify", Redirect: *callback, Version: verificationVersion}, IssuedAt: at, ExpiresAt: at.Add(s.config().Lifetime), SessionID: bindings.SessionID, SessionVersion: bindings.Version}
	if s.primary.factor != nil {
		// The frozen TOTP email profile conserves the earliest original proof,
		// freshness and session deadline; delivered capability seconds round down.
		until, err := admission.Deadline()
		if err != nil {
			return out, err
		}
		if until.Before(link.ExpiresAt) {
			link.ExpiresAt = until.UTC().Truncate(time.Second)
		}
	}
	if s.config().Change != nil {
		link.Previous, link.ChangeProfile = previous, *s.config().Change
	}
	payload, err := s.payload(link)
	if err != nil {
		return out, err
	}
	var family issuerpg.ManagedEmailSupersessionScope
	if s.config().ResendInterval != 0 {
		family, err = issuerpg.ManagedEmailScopeFromPayload(payload)
		if err != nil {
			return out, err
		}
		digest := family.Digest()
		fields = append(fields, identity.FeatureField{Name: "email.management.family", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: slices.Clone(digest[:])}})
	}
	fields = append(fields, identity.FeatureField{Name: "email.management.callback", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: r.CallbackURL}}, identity.FeatureField{Name: "email.management.factor-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: factorVersion}}, identity.FeatureField{Name: "email.management.profile", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: slices.Clone(s.profile[:])}})
	command, err := admission.command(b, fields, resend)
	if err != nil {
		return out, err
	}
	command, counter, err := s.config().Counters.PrepareCommandCounters(command, risk.Subject{User: string(b.UserID), Session: bindings.SessionID, Network: r.Network}, r.Primary.Proof.Proof.IssuedAt.UTC().Truncate(time.Microsecond))
	if err != nil {
		return out, err
	}
	p := &emailManagementPhase{service: s, primary: admission, intent: intent, link: link, command: command, counter: counter, factorVersion: factorVersion, family: family}
	p.coordinator, p.registry, err = s.coordinator(p)
	if err != nil {
		return out, err
	}
	return p, nil
}

func (s *EmailManagementService) coordinator(p *emailManagementPhase) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	audit, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, err
	}
	lifecycle, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, nil, err
	}
	r, err := kernel.NewContributorRegistry([]kernel.Contributor{s.directory, audit, lifecycle, p, s.config().Counters, s.issuer, s.config().Delivery.Owner})
	if err != nil {
		return nil, nil, err
	}
	c, err := kernel.NewCoordinator(s.primary.source.pool, r, s.primary.source.c.Coordinator)
	return c, r, err
}

// Format omits retained source, key and provider configuration.
func (EmailManagementConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passwordpostgres.EmailManagementConfig(redacted)"))
}

// MarshalJSON rejects implicit cryptographic configuration export.
func (EmailManagementConfig) MarshalJSON() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// MarshalText rejects implicit cryptographic configuration export.
func (EmailManagementConfig) MarshalText() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// Format redacts mailbox, original proof and source credential.
func (EmailManagementRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passwordpostgres.EmailManagementRequest(redacted)"))
}

// MarshalJSON rejects implicit sensitive request export.
func (EmailManagementRequest) MarshalJSON() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// MarshalText rejects implicit sensitive request export.
func (EmailManagementRequest) MarshalText() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// Format redacts borrowed source and configuration custody.
func (EmailManagementService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passwordpostgres.EmailManagementService(redacted)"))
}

// MarshalJSON rejects implicit private service export.
func (EmailManagementService) MarshalJSON() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// MarshalText rejects implicit private service export.
func (EmailManagementService) MarshalText() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}
