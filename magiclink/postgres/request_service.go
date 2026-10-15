// Package magiclinkpostgres provides optional native PostgreSQL composition for
// magic-link workflows. The core module remains independent of SQL adapters.
package magiclinkpostgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"slices"
	"strings"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/email"
	"github.com/faustbrian/go-identity/magiclink"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// RequestDeliveryConfig selects actual encrypted delivery and rendering owners.
// Endpoint is a trusted HTTPS landing URL without query/fragment/userinfo. The
// bearer goes only into the emailed fragment, never the callback or a redirect.
// The landing consumer submits it explicitly in a no-store body. This backend
// supplies no UI and never invokes a sender before request commitment.
type RequestDeliveryConfig struct {
	Owner                *deliverypg.Contributor
	Renderer             *delivery.TemplateRenderer
	Endpoint, TemplateID string
	TemplateVersion      uint32
	ProviderVersion      uint64
	Locales              []string
	ScopeKey             [32]byte
	Timeout              time.Duration
}

// RequestConfig selects immutable native request composition. ConfigurationID
// pins callback/renderer/parser semantics; change it when those semantics change.
// Keys are independent original-intent HMAC/cookie/issuance/envelope owners, not
// interchangeable credentials. Every retained cookie version must be kept while
// its flow is supported. This initial request path is signin-only; optional
// Signup remains unfinished rather than silently enabled. Resends supersede
// unused links for the exact original recipient/browser flow transactionally.
type RequestConfig struct {
	MaximumDuration                                         time.Duration
	ConfigurationID, PolicyID, GlobalAuthorityID, IssuerURL string
	Origins, Callbacks                                      []string
	Lifetime                                                time.Duration
	Address                                                 email.AddressParser
	Coordinator                                             kernel.CoordinatorConfig
	RequestKeys                                             kernel.RequestKeyConfig
	Issuer                                                  issuerpg.IssuerConfig
	IssuanceCustody                                         issuerpg.IssuancePreparationConfig
	Risk                                                    risk.AuthenticationAdmissionCustodyConfig
	Session                                                 sessionpg.Config
	CookieKeys                                              map[uint32]session.DigestKey
	IntentKey                                               [32]byte
	ActiveEnvelopeKeyID                                     string
	Delivery                                                RequestDeliveryConfig
	// Possession is explicit email-owned prospective signup acceptance. Nil
	// disables prospective issuance; it does not alter existing signin profiles
	// or enable the unfinished public signup workflow by itself.
	Possession *email.MagicLinkPossessionPolicy
	// Signup selects prospective account creation policy. Nil leaves signup
	// disabled. Possession must select the identical mailbox-policy version.
	Signup *SignupConfig
	// MFAContinuation enables primary-link requests for known enrolled accounts.
	// False preserves single-factor-only suppression. Consumption still requires
	// its separately selected native MFA branch; this flag grants no session.
	MFAContinuation bool
}

// Format redacts configuration and borrowed key custody.
func (RequestConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("magiclinkpostgres.RequestConfig(redacted)"))
}

// MarshalJSON forbids implicit configuration export.
func (RequestConfig) MarshalJSON() ([]byte, error) { return nil, invalid() }

// MarshalText forbids implicit textual configuration export.
func (RequestConfig) MarshalText() ([]byte, error) { return nil, invalid() }

// LogValue redacts structured configuration diagnostics.
func (RequestConfig) LogValue() slog.Value {
	return slog.StringValue("magiclinkpostgres.RequestConfig(redacted)")
}

// RequestService owns public request and proof-free recovery through the real
// kernel journal, capability issuer, risk and encrypted delivery participants.
// It borrows the primary pool and local keyring and starts no goroutine, retry,
// transaction outside the coordinator, sender or independent intent store.
type RequestService struct {
	pool          *database.Pool
	directory     *kernel.Repository
	issuer        *issuerpg.Issuer
	codec         *issuerpg.IssuancePreparationCodec
	crypto        *envelope.Service
	custody       risk.AuthenticationAdmissionCustody
	configuration [32]byte
	config        func() RequestConfig
	registration  *kernel.MagicLinkRegistrationDomain
}

func invalid() error { return identity.InvalidInputError{Field: "magiclink_work"} }
func visible(s string, max int) bool {
	if len(s) == 0 || len(s) > max {
		return false
	}
	for _, b := range []byte(s) {
		if b < 33 || b > 126 {
			return false
		}
	}
	return true
}
func secureURL(raw string, origin bool) bool {
	if !visible(raw, 2048) || strings.Contains(raw, "#") {
		return false
	}
	u, e := url.Parse(raw)
	return e == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Opaque == "" && (!origin || u.Path == "" && u.RawQuery == "" && !u.ForceQuery)
}

// NewRequestService freezes explicit composition without IO, migrations or
// callbacks. Install kernel preparation/request-key/authority, session pre-auth,
// MFA authority, capability issuance, delivery, audit and lifecycle histories
// first. Missing/inactive primary authority denies, never implies empty state.
func NewRequestService(pool *database.Pool, c RequestConfig, keys *keyring.Provider) (*RequestService, error) {
	d := c.Delivery
	if pool == nil || pool.Raw() == nil || keys == nil || c.MaximumDuration <= 0 || c.MaximumDuration > time.Minute || !visible(c.ConfigurationID, 128) || !visible(c.PolicyID, 128) || !visible(c.GlobalAuthorityID, 128) || !secureURL(c.IssuerURL, true) || c.Lifetime < time.Second || c.Lifetime > 24*time.Hour || c.Lifetime%time.Second != 0 || len(c.Origins) == 0 || len(c.Origins) > 32 || len(c.Callbacks) == 0 || len(c.Callbacks) > 32 || c.Coordinator.AdmissionPolicy == nil || c.Coordinator.QueryPolicy == nil || c.RequestKeys.Policy.PolicyVersion != c.Coordinator.AdmissionPolicy.PolicyVersion || c.IntentKey == ([32]byte{}) || !visible(c.ActiveEnvelopeKeyID, 256) || len(c.CookieKeys) == 0 || len(c.CookieKeys) > 16 || d.Owner == nil || d.Renderer == nil || !secureURL(d.Endpoint, false) || !visible(d.TemplateID, 128) || d.TemplateVersion == 0 || d.ProviderVersion == 0 || d.ScopeKey == ([32]byte{}) || d.Timeout <= 0 || d.Timeout > 5*time.Second || len(d.Locales) == 0 || len(d.Locales) > 16 {
		return nil, invalid()
	}
	u, _ := url.Parse(d.Endpoint)
	if u.RawQuery != "" || u.ForceQuery {
		return nil, invalid()
	}
	for _, v := range c.Origins {
		if !secureURL(v, true) {
			return nil, invalid()
		}
	}
	for _, v := range c.Callbacks {
		if !secureURL(v, false) {
			return nil, invalid()
		}
	}
	probe, _ := session.ParseToken("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB")
	for v, k := range c.CookieKeys {
		digest, e := probe.Digest(k, "magiclink-configuration")
		if v == 0 || e != nil || digest.KeyVersion != v {
			return nil, invalid()
		}
	}
	directory, e := kernel.NewRepository(pool, kernel.Config{MaximumDuration: c.MaximumDuration})
	if e != nil {
		return nil, e
	}
	var registration *kernel.MagicLinkRegistrationDomain
	var prospectiveProfile *signupProfile
	if c.Signup != nil {
		if c.Possession == nil || c.Possession.Version() != c.Signup.Domain.EmailPossessionPolicyVersion || !visible(c.Signup.SchemaID, 128) || c.Signup.SchemaVersion == 0 {
			return nil, invalid()
		}
		selected := *c.Signup
		selected.Domain.RetainedIdentifierKeys = maps.Clone(c.Signup.Domain.RetainedIdentifierKeys)
		c.Signup = &selected
		registration, e = kernel.NewMagicLinkRegistrationDomain(directory, selected.Domain)
		if e != nil {
			return nil, e
		}
		prospectiveProfile = selected.profile()
	}
	issuer, e := issuerpg.NewIssuer(c.Issuer)
	if e != nil {
		return nil, e
	}
	codec, e := issuerpg.NewIssuancePreparationCodec(issuer, c.IssuanceCustody)
	if e != nil {
		return nil, e
	}
	crypto, e := envelope.NewService(keys)
	if e != nil {
		return nil, e
	}
	custody, e := risk.NewAuthenticationAdmissionCustody(c.Risk)
	if e != nil {
		return nil, e
	}
	c.Origins = slices.Clone(c.Origins)
	c.Callbacks = slices.Clone(c.Callbacks)
	c.CookieKeys = maps.Clone(c.CookieKeys)
	c.Delivery.Locales = slices.Clone(d.Locales)
	c.Issuer.RetainedReplayKeys = maps.Clone(c.Issuer.RetainedReplayKeys)
	c.Coordinator.RetainedFingerprintKeys = maps.Clone(c.Coordinator.RetainedFingerprintKeys)
	a, q := *c.Coordinator.AdmissionPolicy, *c.Coordinator.QueryPolicy
	c.Coordinator.AdmissionPolicy = &a
	c.Coordinator.QueryPolicy = &q
	frame, e := json.Marshal(struct {
		Domain, ID, Policy, Global, Issuer, Audience, Endpoint, Template, Risk, Namespace string
		Lifetime, Timeout                                                                 time.Duration
		TemplateVersion                                                                   uint32
		Provider, PolicyVersion, QueryVersion                                             uint64
		Origins, Callbacks, Locales                                                       []string
		Signup                                                                            *signupProfile `json:",omitempty"`
		MFAContinuation                                                                   bool           `json:",omitempty"`
	}{"identity-magic-link-request-v1", c.ConfigurationID, c.PolicyID, c.GlobalAuthorityID, c.IssuerURL, c.Issuer.Audience, d.Endpoint, d.TemplateID, c.Risk.ConfigurationID, c.RequestKeys.Namespace, c.Lifetime, d.Timeout, d.TemplateVersion, d.ProviderVersion, a.PolicyVersion, q.PolicyVersion, c.Origins, c.Callbacks, c.Delivery.Locales, prospectiveProfile, c.MFAContinuation})
	if e != nil {
		return nil, invalid()
	}
	digest := sha256.Sum256(frame)
	clear(frame)
	s := &RequestService{pool: pool, directory: directory, issuer: issuer, codec: codec, crypto: crypto, custody: custody, configuration: digest, config: func() RequestConfig { return c }, registration: registration}
	if _, _, e = s.coordinator(&requestPhase{service: s}); e != nil {
		return nil, e
	}
	return s, nil
}

func requestOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/magiclink", OperationID: "identity.magic-link.request", SchemaID: "magic-link-request", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}
func descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/magiclink/postgres", ContractID: "identity.magiclink", Version: 1}
}

func (s *RequestService) coordinator(p *requestPhase) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	a, e := auditpg.NewIdentityContributor(auditpg.Config{})
	if e != nil {
		return nil, nil, e
	}
	o, e := lifecyclepg.NewContributor()
	if e != nil {
		return nil, nil, e
	}
	r, e := kernel.NewContributorRegistry([]kernel.Contributor{s.directory, a, o, p, s.issuer, s.config().Delivery.Owner})
	if e != nil {
		return nil, nil, e
	}
	c, e := kernel.NewCoordinatorWithRequestKeys(s.pool, r, s.config().Coordinator, s.config().RequestKeys)
	p.coordinator, p.registry = c, r
	return c, r, e
}

// Request preserves raw original intent in a keyed digest and issues/encrypts
// only in the journal's acknowledged first generation. Native final Work fences
// the same verified recipient, browser, MFA, directory and original risk facts,
// then stages issuer/message/audit/lifecycle atomically. Eligible and suppressed
// selections have identical acknowledgements. No bearer or selected user leaves
// this call; ambiguity never triggers automatic regeneration or a sender.
func (s *RequestService) Request(ctx context.Context, r magiclink.RequestRequest) (out magiclink.RequestResult, err error) {
	if ctx == nil || s == nil || s.config == nil || r.Validate() != nil {
		return out, invalid()
	}
	ctx, cancel := context.WithTimeout(ctx, s.config().MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil {
			out.Accepted = out.Outcome == identity.CommitOutcomeCommitted
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			out.Accepted = out.Outcome == identity.CommitOutcomeCommitted
			err = ctx.Err()
		}
	}()
	c := s.config()
	if r.Intent == magiclink.SignupIfAllowed && (c.Signup == nil || c.Possession == nil || s.registration == nil) {
		return out, identity.InvalidInputError{Field: "magiclink_signup_disabled"}
	}
	if !slices.Contains(c.Origins, r.Origin) || !slices.Contains(c.Callbacks, r.Callback) {
		return out, identity.ForbiddenError{}
	}
	address, err := c.Address.Parse(r.Email)
	if err != nil {
		return out, invalid()
	}
	flow, err := sessionpg.ReadPreAuth(ctx, s.pool.Raw(), c.Session, r.TenantID, r.PreAuthID)
	if err != nil {
		return out, err
	}
	if err = s.admitFlow(r, flow, time.Now().UTC()); err != nil {
		return out, err
	}
	frame, err := json.Marshal(struct {
		Profile                                          [32]byte
		Tenant                                           identity.TenantID
		Command                                          identity.CommandID
		Flow                                             identity.PreAuthTransactionID
		Email, Callback, Cookie, Origin, Network, Device string
		Intent                                           magiclink.Intent
	}{s.configuration, r.TenantID, r.CommandID, r.PreAuthID, string(r.Email), r.Callback, r.Cookie.Token(), r.Origin, r.Network, r.Device, r.Intent})
	if err != nil {
		return out, invalid()
	}
	defer clear(frame)
	mac := hmac.New(sha256.New, c.IntentKey[:])
	mac.Write([]byte("identity-magic-link-request-input-v1\x00"))
	mac.Write(frame)
	fields := []identity.FeatureField{{Name: "request.intent", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: hex.EncodeToString(mac.Sum(nil))}}, {Name: "request.configuration", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: hex.EncodeToString(s.configuration[:])}}}
	intent, err := identity.NewRequestIntent(fields)
	if err != nil {
		return out, err
	}
	p := &requestPhase{service: s, request: r, canonical: address.Canonical().Record().Value, flow: flow}
	// Discovery uses the pool before any coordinator transaction takes locks.
	// The protected Work later fences these exact primary versions; this read
	// cannot authorize issuance by itself.
	p.selected.recipient, err = s.directory.ResolveRecipient(ctx, kernel.RecipientQuery{TenantID: r.TenantID, Kind: identity.IdentifierEmail, CanonicalValue: p.canonical, Eligibility: kernel.RecipientVerified})
	if err != nil {
		return out, err
	}
	coordinator, _, err := s.coordinator(p)
	if err != nil {
		return out, err
	}
	scope := kernel.RequestKeyScope{TenantID: r.TenantID, ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: r.Caller.Request.Subject.Kind, Method: "POST", RouteID: requestOperation().OperationID}
	caller := r.Caller.Clone()
	caller.PolicyRevision = authorization.Revision(c.RequestKeys.Policy.PolicyVersion)
	caller.Request.Resource = authorization.Resource{Type: "identity.request-admission", ID: authorization.ResourceID(scope.RouteID)}
	key, err := coordinator.ResolveRequestKey(ctx, scope, r.IdempotencyKey, intent, caller)
	if err != nil {
		return out, err
	}
	op := requestOperation()
	b := identity.CommandBinding{CommandID: key.CommandID, TenantID: r.TenantID, AnonymousFlowID: string(r.PreAuthID), ActorID: scope.ActorID, ActorKind: scope.ActorKind, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: c.PolicyID, PolicyVersion: c.RequestKeys.Policy.PolicyVersion, CorrelationID: string(key.CommandID)}
	p.original, err = identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields})
	if err != nil {
		return out, err
	}
	mac = hmac.New(sha256.New, c.IntentKey[:])
	mac.Write([]byte("identity-magic-link-request-counter-v1\x00" + string(r.TenantID) + "\x00" + p.canonical))
	p.subject = risk.Subject{Network: r.Network, Device: r.Device, IdentifierDigest: hex.EncodeToString(mac.Sum(nil))}
	plan, err := p.plan(time.Now().UTC(), false)
	if err != nil {
		return out, err
	}
	result, err := coordinator.ExecutePreparedFeature(ctx, p.original, plan)
	return requestReceipt(key.CommandID, result, err)
}

func (s *RequestService) admitFlow(r magiclink.RequestRequest, flow session.PreAuthTransaction, now time.Time) error {
	f, e := flow.Bindings()
	if e != nil {
		return invalid()
	}
	i := f.Binding.Intent
	if f.Binding.ID != r.PreAuthID || i.TenantID != r.TenantID || i.Action != "identity.magic-link.consume" || i.Origin != r.Origin || i.CallbackURL != r.Callback || i.PolicyID != s.config().PolicyID || i.PolicyVersion != s.config().Coordinator.AdmissionPolicy.PolicyVersion {
		return identity.ForbiddenError{}
	}
	t, e := session.ParseToken(r.Cookie.Token())
	if e != nil {
		return invalid()
	}
	digest, e := t.PreAuthDigest(s.config().CookieKeys[f.Cookie.KeyVersion], f.Binding)
	if e != nil || flow.Check(now, f.Binding, digest) != nil {
		return identity.ForbiddenError{}
	}
	return nil
}

// RecoverRequest reconciles the original request through current result-access
// policy and participant custody. It takes no email/cookie/token and cannot
// issue, render, renew or send another message.
func (s *RequestService) RecoverRequest(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (magiclink.RequestResult, error) {
	if ctx == nil || s == nil || s.config == nil || q.OperationID != requestOperation().OperationID || q.UserID != "" || q.AnonymousFlowID == "" || q.RecordID != "" {
		return magiclink.RequestResult{}, invalid()
	}
	ctx, cancel := context.WithTimeout(ctx, s.config().MaximumDuration)
	defer cancel()
	coordinator, _, err := s.coordinator(&requestPhase{service: s})
	if err != nil {
		return magiclink.RequestResult{}, err
	}
	caller = caller.Clone()
	caller.PolicyRevision = authorization.Revision(s.config().Coordinator.QueryPolicy.PolicyVersion)
	caller.Request.Resource = authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(q.AnonymousFlowID)}
	r, err := coordinator.RecoverFeatureCommand(ctx, q, caller)
	return requestReceipt(q.CommandID, r, err)
}

func requestReceipt(id identity.CommandID, r identity.CommandResult, err error) (magiclink.RequestResult, error) {
	// Accepted describes known durable processing, not successful disclosure.
	// An accompanying error cannot undo an authenticated committed receipt.
	out := magiclink.RequestResult{CommandID: id, Outcome: r.Outcome, Accepted: r.Outcome == identity.CommitOutcomeCommitted}
	if r.Outcome == identity.CommitOutcomeCommitted && (r.Feature == nil || r.Feature.Operation != requestOperation()) {
		return magiclink.RequestResult{}, identity.UnavailableError{}
	}
	if out.Validate() != nil {
		if err == nil {
			err = identity.UnavailableError{}
		}
		return magiclink.RequestResult{}, err
	}
	return out, err
}

var _ magiclink.RequestService = (*RequestService)(nil)
