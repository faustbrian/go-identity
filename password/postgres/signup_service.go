package passwordpostgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	email "github.com/faustbrian/go-identity/email"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// SignupVerificationConfig selects the actual email policy and capability
// owners. Codec must belong to Issuer. Lifetime is bounded by original flow
// expiry; no retry or recovery renews it. Dependencies remain borrowed.
type SignupVerificationConfig struct {
	Policy   *email.RegistrationVerificationPolicy
	Issuer   *issuerpg.Issuer
	Codec    *issuerpg.IssuancePreparationCodec
	Lifetime time.Duration
	// Counters optionally selects original-grant-bound confirmation. Nil keeps
	// signup/scanner behavior unchanged but disables confirmation execution.
	// Install the forward verification counter migration before selecting it.
	Counters *riskpg.Repository
	// Hooks optionally selects email-owned link-confirmation policy. Nil keeps
	// existing behavior; callback semantics belong to SignupConfig.ConfigurationID.
	Hooks *email.VerificationHooks
}

// SignupDeliveryConfig selects encrypted email preparation, not a sender.
// Endpoint is a fixed HTTPS confirmation URL without a token parameter.
// Locale/template/provider revisions and ScopeKey are trusted startup policy.
type SignupDeliveryConfig struct {
	Owner                *deliverypg.Contributor
	Renderer             *delivery.TemplateRenderer
	Resolver             *capability.KeySet
	Endpoint, TemplateID string
	TemplateVersion      uint32
	ProviderVersion      uint64
	Locales              []string
	ScopeKey             [32]byte
	Timeout              time.Duration
}

// SignupConfig is immutable startup composition, not request input. Fields
// must use FieldSchema and the selected admission revision. ConfigurationID
// versions borrowed field/ID/provider callback semantics; change it when those
// semantics change. SelectUser is bounded canonical ID policy, including ULIDs.
// Screening.Collect returns only the owned HIBP fact: Risk owns other signals,
// counted admission and audit. Separate intent/lookup/fingerprint/encryption
// keys must be retained for original recovery. Dependencies are concurrent-safe.
// This initial profile requires verified email and issues no session; immediate
// session and MFA continuation profiles remain in development and are denied.
type SignupConfig struct {
	// AuthorizationNamespace explicitly initializes the new user's policy epoch
	// through the authorization owner in the protected signup transaction. Select
	// the namespace consumed by signin/session admission. Empty preserves legacy
	// registration-only custody and does not supply authority for later signin.
	// Changing this selection changes preparation identity; retain old profiles
	// for their original recovery. Initialization cannot reset an existing epoch.
	AuthorizationNamespace    string
	Repository                Config
	Registration              password.RegistrationPolicy
	ConfigurationID, PolicyID string
	Fields                    *identity.AttributeProcessor
	FieldSchema               identity.AttributeSchema
	Address                   email.AddressParser
	SelectUser                func(context.Context) (identity.UserID, error)
	Session                   sessionpg.Config
	FlowKeys                  []session.DigestKey
	Origins, CallbackURLs     []string
	RegistrationDomain        kernel.PasswordRegistrationDomainConfig
	RequestKeys               kernel.RequestKeyConfig
	IntentKey                 [32]byte
	ActiveEnvelopeKeyID       string
	Screening                 password.HashPreparationConfig
	Risk                      risk.AuthenticationAdmissionCustodyConfig
	Coordinator               kernel.CoordinatorConfig
	Verification              SignupVerificationConfig
	Delivery                  SignupDeliveryConfig
}

// SignupService owns keyed native registration and password-free historical
// recovery. It borrows the primary pool and local keyring, owns no goroutines,
// shared request state, secondary journal, sender or automatic retries. Each
// call owns its participant; caller password custody is never destroyed here.
// Install registration/acceptance, request-key/input, preparation/admission,
// password, session pre-auth, issuance, delivery, audit and outbox histories.
type SignupService struct {
	pool       *database.Pool
	repository *Repository
	directory  *kernel.Repository
	domain     *kernel.PasswordRegistrationDomain
	crypto     *envelope.Service
	custody    risk.AuthenticationAdmissionCustody
	config     func() SignupConfig
	profile    [32]byte
}

var _ password.SignupService = (*SignupService)(nil)

// NewSignupService validates and freezes composition without callbacks, IO,
// migrations or password work. Local keyring custody excludes remote decrypt
// callbacks under the kernel's restoration locks. Zero/mixed profiles deny.
func NewSignupService(pool *database.Pool, c SignupConfig, keys *keyring.Provider) (*SignupService, error) {
	if c.AuthorizationNamespace != "" && (authoritypg.AuthorityScope{TenantID: "tenant", SubjectID: "user", PolicyNamespace: c.AuthorizationNamespace}).Validate() != nil {
		return nil, password.ErrPasswordWork
	}
	if keys == nil || c.Fields == nil || c.SelectUser == nil || c.Registration.Validate() != nil || !c.Registration.RequireVerifiedEmail || c.FieldSchema.Validate() != nil || !reauthenticationText(c.ConfigurationID, 128) || !reauthenticationText(c.PolicyID, 128) || c.IntentKey == ([32]byte{}) || !reauthenticationText(c.ActiveEnvelopeKeyID, 256) || c.Coordinator.QueryPolicy == nil || c.Coordinator.AdmissionPolicy == nil || c.RequestKeys.Policy.PolicyVersion != c.Coordinator.AdmissionPolicy.PolicyVersion || c.Screening.MinimumBytes != c.Registration.MinimumBytes || c.Screening.MaximumBytes != c.Registration.MaximumBytes || len(c.FlowKeys) == 0 || len(c.FlowKeys) > 16 || !signinURLs(c.Origins, true) || !signinURLs(c.CallbackURLs, false) || c.Verification.Policy == nil || c.Verification.Issuer == nil || c.Verification.Codec == nil || c.Verification.Lifetime <= 0 || c.Verification.Lifetime > 24*time.Hour || c.Verification.Lifetime%time.Second != 0 || c.Delivery.Owner == nil || c.Delivery.Renderer == nil || c.Delivery.Resolver == nil || c.Delivery.TemplateVersion == 0 || c.Delivery.ProviderVersion == 0 || len(c.Delivery.Locales) == 0 || len(c.Delivery.Locales) > 16 || c.Delivery.ScopeKey == ([32]byte{}) || c.Delivery.Timeout <= 0 || c.Delivery.Timeout > 5*time.Second {
		return nil, password.ErrPasswordWork
	}
	if _, err := password.NewHashPreparer(c.Screening); err != nil {
		return nil, password.ErrPasswordWork
	}
	if !signinCurrentHash(c.Screening.DummyHash, c.Repository.HashPolicy) {
		return nil, password.ErrPasswordWork
	}
	repository, err := NewRepository(pool, c.Repository)
	if err != nil {
		return nil, err
	}
	directory, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: c.Repository.MaximumDuration, AttributeSchemas: []identity.AttributeSchema{c.FieldSchema}})
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	domain, err := kernel.NewPasswordRegistrationDomain(directory, c.RegistrationDomain)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	if _, err := sessionpg.NewRepository(pool, c.Session); err != nil {
		return nil, password.ErrPasswordWork
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	custody, err := risk.NewAuthenticationAdmissionCustody(c.Risk)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	c.FlowKeys = slices.Clone(c.FlowKeys)
	c.Origins = slices.Clone(c.Origins)
	c.CallbackURLs = slices.Clone(c.CallbackURLs)
	c.Delivery.Locales = slices.Clone(c.Delivery.Locales)
	c.Risk.Keys = slices.Clone(c.Risk.Keys)
	c.Coordinator.RetainedFingerprintKeys = maps.Clone(c.Coordinator.RetainedFingerprintKeys)
	query, admission := *c.Coordinator.QueryPolicy, *c.Coordinator.AdmissionPolicy
	c.Coordinator.QueryPolicy, c.Coordinator.AdmissionPolicy = &query, &admission
	c.RegistrationDomain.RetainedIdentifierKeys = maps.Clone(c.RegistrationDomain.RetainedIdentifierKeys)
	// Callback/provider semantics use the explicit pinned ConfigurationID. Scalar
	// policy and the actual primitive profile are additionally committed here;
	// changing active encryption keys alone must not invalidate retained custody.
	p := c.Screening.Primitive.Policy()
	frame, err := json.Marshal(struct {
		Profile, Namespace, Policy, Configuration, Schema, Comparison, Risk, Endpoint, Template string
		SchemaVersion, TemplateVersion                                                          uint32
		PolicyVersion, QueryVersion, ProviderVersion                                            uint64
		Registration                                                                            password.RegistrationPolicy
		Algorithm                                                                               string
		Parameters                                                                              any
		Limits                                                                                  any
		Dummy                                                                                   [32]byte
		VerificationLifetime, ScreeningTimeout, DeliveryTimeout                                 time.Duration
		Origins, Callbacks, Locales                                                             []string
	}{"identity-password-signup-v1", c.RequestKeys.Namespace, c.PolicyID, c.ConfigurationID, c.FieldSchema.ID, c.RegistrationDomain.ComparisonProfile, c.Risk.ConfigurationID, c.Delivery.Endpoint, c.Delivery.TemplateID, c.FieldSchema.Version, c.Delivery.TemplateVersion, c.RequestKeys.Policy.PolicyVersion, query.PolicyVersion, c.Delivery.ProviderVersion, c.Registration, string(p.Algorithm()), p.Argon2idParameters(), p.Limits(), sha256.Sum256([]byte(c.Screening.DummyHash.String())), c.Verification.Lifetime, c.Screening.Timeout, c.Delivery.Timeout, c.Origins, c.CallbackURLs, c.Delivery.Locales})
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	profile := sha256.Sum256(frame)
	clear(frame)
	// Preserve the exact legacy profile when initialization is unselected.
	// Selected namespace is part of immutable original custody, not a mutable
	// callback or a later read-side bootstrap.
	if c.AuthorizationNamespace != "" {
		frame, err = json.Marshal(struct {
			Profile                [32]byte
			AuthorizationNamespace string
		}{profile, c.AuthorizationNamespace})
		if err != nil {
			return nil, password.ErrPasswordWork
		}
		profile = sha256.Sum256(frame)
		clear(frame)
	}
	s := &SignupService{pool: pool, repository: repository, directory: directory, domain: domain, crypto: crypto, custody: custody, config: func() SignupConfig { return c }, profile: profile}
	if _, _, err := s.coordinator(&signupPhase{service: s}); err != nil {
		return nil, password.ErrPasswordWork
	}
	return s, nil
}

func (s *SignupService) coordinator(p *signupPhase) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	c := s.config()
	audits, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, err
	}
	outbox, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, nil, err
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{s.directory, audits, outbox, c.Verification.Issuer, c.Delivery.Owner, p})
	if err != nil {
		return nil, nil, err
	}
	coordinator, err := kernel.NewCoordinatorWithRequestKeys(s.pool, registry, c.Coordinator, c.RequestKeys)
	return coordinator, registry, err
}

func (s *SignupService) keyPreparation() signupKeyPreparation {
	c := s.config()
	return signupKeyPreparation{profile: s.profile, crypto: s.crypto, envelopeKey: c.ActiveEnvelopeKeyID, policyID: c.PolicyID, policyVersion: c.RequestKeys.Policy.PolicyVersion, schemaID: c.FieldSchema.ID, schemaVersion: c.FieldSchema.Version, comparison: c.RegistrationDomain.ComparisonProfile, fields: c.Fields, address: c.Address, flowStorage: c.Session, flowKeys: c.FlowKeys, origins: c.Origins, callbacks: c.CallbackURLs, selectUser: c.SelectUser}
}

func (s *SignupService) generation() signupGenerationPreparation {
	c := s.config()
	return signupGenerationPreparation{screening: c.Screening, verification: signupVerificationPreparation{address: c.Address, policy: c.Verification.Policy, issuer: c.Verification.Issuer, lifetime: c.Verification.Lifetime}, delivery: signupDeliveryPreparation{owner: c.Delivery.Owner, renderer: c.Delivery.Renderer, resolver: c.Delivery.Resolver, policy: c.Verification.Policy, endpoint: c.Delivery.Endpoint, template: c.Delivery.TemplateID, templateVersion: c.Delivery.TemplateVersion, providerVersion: c.Delivery.ProviderVersion, locales: c.Delivery.Locales, scopeKey: c.Delivery.ScopeKey, timeout: c.Delivery.Timeout}, codec: c.Verification.Codec, crypto: s.crypto, envelopeKey: c.ActiveEnvelopeKeyID, profile: s.profile}
}

// Signup preserves original anonymous correlation and returns the same policy
// acknowledgement for new and occupied identifiers. Only a journal-owned first
// generation screens/hashes/issues; replays return safe historical metadata.
// Earlier deadlines win; errors and cancellation never return credentials.
func (s *SignupService) Signup(ctx context.Context, r password.SignupRequest) (result password.SignupResult, err error) {
	if ctx == nil || s == nil || s.config == nil || r.Validate() != nil {
		return result, password.ErrPasswordWork
	}
	c := s.config()
	ctx, stop := context.WithTimeout(ctx, c.Repository.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			err = password.ErrPasswordWork
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			result.VerificationRequired = false
		}
	}()
	intent, err := s.repository.signupRequestIntent(ctx, r, c.IntentKey, s.profile, c.Registration)
	if err != nil {
		return result, err
	}
	p := &signupPhase{service: s, request: func() password.SignupRequest { return r }}
	coordinator, registry, err := s.coordinator(p)
	if err != nil {
		return result, password.ErrPasswordWork
	}
	p.coordinator, p.registry = coordinator, registry
	scope := kernel.RequestKeyScope{TenantID: r.TenantID, ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: r.Caller.Request.Subject.Kind, Method: "POST", RouteID: passwordSignupOperation().OperationID}
	caller := r.Caller.Clone()
	caller.PolicyRevision = authorization.Revision(c.RequestKeys.Policy.PolicyVersion)
	caller.Request.Resource = authorization.Resource{Type: "identity.request-admission", ID: authorization.ResourceID(scope.RouteID)}
	k, wire, err := coordinator.ResolvePreparedRequestKey(ctx, scope, r.IdempotencyKey, intent, caller, p.registration(), p)
	if err != nil {
		return result, err
	}
	defer clear(wire)
	b, selected, flow, at, err := s.repository.restoreSignupInput(ctx, s.crypto, k, s.profile, wire, intent)
	if err != nil {
		return result, err
	}
	result.Recovery, err = password.NewSignupRecovery(signupQuery(b), r.PreAuthID)
	if err != nil {
		return result, password.ErrPasswordWork
	}
	result.Outcome = identity.CommitOutcomeUnknown
	if err := p.initialize(r, b, selected, flow, at); err != nil {
		return result, err
	}
	plan, err := signupExecutionPlan(coordinator, registry, p, p.original, at, kernel.CapabilityIssuancePlan{}, kernel.DeliveryPlan{})
	if err != nil {
		return result, err
	}
	receipt, err := coordinator.ExecutePreparedFeature(ctx, p.original, plan)
	if receipt.Outcome != identity.CommitOutcomeInvalid {
		result.Outcome = receipt.Outcome
	}
	result.RetryAfter = receipt.RetryAfter
	result.Replayed = p.execution == nil && result.Outcome == identity.CommitOutcomeCommitted
	result.VerificationRequired = err == nil && result.Outcome == identity.CommitOutcomeCommitted
	return result, err
}

func signupQuery(b identity.CommandBinding) identity.RecoveryQuery {
	return identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, AnonymousFlowID: b.AnonymousFlowID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID}
}

// RecoverSignup authenticates retained original input and cookie before current
// kernel disclosure/reconciliation. Flow deletion/expiry does not renew custody
// or hide history. No password, risk/provider/hash work or execution runs here.
func (s *SignupService) RecoverSignup(ctx context.Context, r password.SignupRecoveryRequest) (result password.SignupResult, err error) {
	if ctx == nil || s == nil || s.config == nil || r.Validate() != nil {
		return result, password.ErrPasswordWork
	}
	c := s.config()
	ctx, stop := context.WithTimeout(ctx, c.Repository.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			result = password.SignupResult{}
			err = password.ErrPasswordWork
		}
		if ctx.Err() != nil {
			result = password.SignupResult{}
			err = ctx.Err()
		}
	}()
	q, _, _ := r.Recovery.Bindings()
	p := &signupPhase{service: s}
	coordinator, registry, err := s.coordinator(p)
	if err != nil {
		return result, password.ErrPasswordWork
	}
	p.coordinator, p.registry = coordinator, registry
	caller := r.Caller.Clone()
	caller.PolicyRevision = authorization.Revision(c.Coordinator.QueryPolicy.PolicyVersion)
	caller.Request.Resource = authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(q.AnonymousFlowID)}
	k, wire, err := coordinator.QueryRequestPreparation(ctx, q, caller, p.registration(), p)
	if err != nil {
		return result, err
	}
	defer clear(wire)
	b, selected, flow, _, err := s.repository.recoverSignupInput(ctx, s.crypto, k, s.profile, wire)
	if err != nil || signupQuery(b) != q {
		return result, identity.ForbiddenError{}
	}
	spec, err := flow.Bindings()
	if err != nil || spec.Binding.Intent.Origin != r.Origin || !slices.Contains(c.Origins, r.Origin) {
		return result, identity.ForbiddenError{}
	}
	token, err := session.ParseToken(r.Cookie.Token())
	if err != nil {
		return result, identity.ForbiddenError{}
	}
	possessed := false
	for _, key := range c.FlowKeys {
		digest, e := token.PreAuthDigest(key, spec.Binding)
		if e == nil && digest.KeyVersion == spec.Cookie.KeyVersion && hmac.Equal(digest.Sum[:], spec.Cookie.Sum[:]) {
			possessed = true
		}
	}
	if !possessed {
		return result, identity.ForbiddenError{}
	}
	p.input.selected = selected
	result.Recovery, result.Outcome, result.Replayed = r.Recovery, identity.CommitOutcomeUnknown, true
	receipt, err := coordinator.RecoverFeatureCommand(ctx, q, caller)
	if receipt.Outcome != identity.CommitOutcomeInvalid {
		result.Outcome = receipt.Outcome
	}
	result.RetryAfter = receipt.RetryAfter
	var unknown identity.UnknownCommitError
	if errors.As(err, &unknown) {
		result.Outcome = identity.CommitOutcomeUnknown
	}
	result.VerificationRequired = err == nil && result.Outcome == identity.CommitOutcomeCommitted
	return result, err
}

func (SignupConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passwordpostgres.SignupConfig(redacted)"))
}
func (SignupConfig) MarshalJSON() ([]byte, error) { return nil, password.ErrPasswordWork }
func (SignupConfig) MarshalText() ([]byte, error) { return nil, password.ErrPasswordWork }
func (SignupDeliveryConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passwordpostgres.SignupDeliveryConfig(redacted)"))
}
func (SignupDeliveryConfig) MarshalJSON() ([]byte, error) { return nil, password.ErrPasswordWork }
func (SignupService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passwordpostgres.SignupService(redacted)"))
}
func (SignupService) MarshalJSON() ([]byte, error) { return nil, password.ErrPasswordWork }
