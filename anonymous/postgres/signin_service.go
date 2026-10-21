package anonymouspostgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"

	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// SigninConfig is immutable trusted composition. The selected DisplayNameField
// is admitted through Fields/FieldSchema as a system-created attribute, never a
// caller-selected contact. ConfigurationID versions callback semantics. The
// guest namespace/audience must be deliberately unprivileged. Separate request
// intent, lookup, flow, envelope and risk keys retain their owners/rotation.
// Install the kernel preparation/key, anonymous, directory, pre-auth, session
// issuance and CSRF, authorization, audit and outbox histories before enabling
// Signin. CSRFMigrationSource is required even in the base anonymous-only profile:
// its genuine issuer persists digest-only synchronizer state, not schema-1 rows.
type SigninConfig struct {
	Repository                                  Config
	Sessions                                    sessionpg.Config
	Profile                                     sessionpg.AnonymousAdmissionConfig
	Policy                                      anonymous.Policy
	ConfigurationID, PolicyID, DisplayNameField string
	Fields                                      *identity.AttributeProcessor
	FieldSchema                                 identity.AttributeSchema
	FlowKeys                                    []session.DigestKey
	Origins, CallbackURLs                       []string
	RequestKeys                                 kernel.RequestKeyConfig
	IntentKey                                   [32]byte
	ActiveEnvelopeKeyID                         string
	Risk                                        risk.AuthenticationAdmissionCustodyConfig
	Coordinator                                 kernel.CoordinatorConfig
	Issuer                                      session.IssuerConfig
	CSRF                                        session.CSRFKey
}

// SigninService composes concrete primary owners under the sole existing
// coordinator. It borrows the pool/local keyring and owns no transaction,
// goroutine, mutable request cache, sender or automatic retry. Every call has
// its own native phase. Keep borrowed dependencies alive until calls finish.
type SigninService struct {
	pool       *database.Pool
	repository *Repository
	directory  *kernel.Repository
	domain     *kernel.AnonymousCreationDomain
	effect     *sessionpg.AnonymousSigninEffect
	crypto     *envelope.Service
	custody    risk.AuthenticationAdmissionCustody
	config     func() SigninConfig
	profile    [32]byte
}

var _ anonymous.Issuer = (*SigninService)(nil)

// NewSigninService freezes explicit configuration without IO, callbacks,
// migrations or entropy. Applications supply configuration, not domain stores.
func NewSigninService(pool *database.Pool, c SigninConfig, keys *keyring.Provider) (*SigninService, error) {
	policy, err := c.Policy.Config()
	if err != nil || keys == nil || c.Fields == nil || c.FieldSchema.Validate() != nil || !signinText(c.ConfigurationID, 128) || !signinText(c.PolicyID, 128) || !signinText(c.DisplayNameField, 128) || !signinText(c.ActiveEnvelopeKeyID, 256) || c.IntentKey == ([32]byte{}) || len(c.FlowKeys) < 1 || len(c.FlowKeys) > 16 || !signinURLs(c.Origins, true) || !signinURLs(c.CallbackURLs, false) || c.Coordinator.QueryPolicy == nil || c.Coordinator.AdmissionPolicy == nil || c.Coordinator.AdmissionPolicy.PolicyVersion != c.RequestKeys.Policy.PolicyVersion {
		return nil, anonymous.ErrInvalidInput
	}
	found := false
	for _, f := range c.FieldSchema.Fields {
		if f.Name == c.DisplayNameField {
			found = f.Kind == identity.AttributeString && f.WriteAuthorization == identity.FieldWriteSystem
		}
	}
	if !found {
		return nil, anonymous.ErrInvalidInput
	}
	r, err := NewRepository(pool, c.Repository)
	if err != nil {
		return nil, err
	}
	d, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: c.Repository.MaximumDuration, AttributeSchemas: []identity.AttributeSchema{c.FieldSchema}})
	if err != nil {
		return nil, anonymous.ErrInvalidInput
	}
	domain, err := kernel.NewAnonymousCreationDomain(d)
	if err != nil {
		return nil, anonymous.ErrInvalidInput
	}
	effect, err := sessionpg.NewAnonymousSigninEffect(c.Sessions, c.Profile)
	if err != nil {
		return nil, anonymous.ErrInvalidInput
	}
	if _, err := sessionpg.NewRepository(pool, c.Sessions); err != nil {
		return nil, anonymous.ErrInvalidInput
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		return nil, anonymous.ErrInvalidInput
	}
	custody, err := risk.NewAuthenticationAdmissionCustody(c.Risk)
	if err != nil {
		return nil, anonymous.ErrInvalidInput
	}
	c.FlowKeys = slices.Clone(c.FlowKeys)
	c.Origins = slices.Clone(c.Origins)
	c.CallbackURLs = slices.Clone(c.CallbackURLs)
	c.Risk.Keys = slices.Clone(c.Risk.Keys)
	c.Coordinator.RetainedFingerprintKeys = maps.Clone(c.Coordinator.RetainedFingerprintKeys)
	q, a := *c.Coordinator.QueryPolicy, *c.Coordinator.AdmissionPolicy
	c.Coordinator.QueryPolicy, c.Coordinator.AdmissionPolicy = &q, &a
	// Canonical schema serialization provides a bounded deep copy of defaults.
	// The callback processor already owns its independent immutable schema.
	schemaWire, err := json.Marshal(c.FieldSchema)
	if err != nil {
		return nil, anonymous.ErrInvalidInput
	}
	if err = json.Unmarshal(schemaWire, &c.FieldSchema); err != nil {
		clear(schemaWire)
		return nil, anonymous.ErrInvalidInput
	}
	clear(schemaWire)
	frame, err := json.Marshal(struct {
		Configuration, Policy, DisplayField, Namespace string
		Anonymous                                      anonymous.Config
		Schema                                         identity.AttributeSchema
		Profile                                        sessionpg.AnonymousAdmissionConfig
		PolicyVersion, QueryVersion                    uint64
		Risk                                           string
		Origins, Callbacks                             []string
	}{c.ConfigurationID, c.PolicyID, c.DisplayNameField, c.RequestKeys.Namespace, policy, c.FieldSchema, c.Profile, a.PolicyVersion, q.PolicyVersion, c.Risk.ConfigurationID, c.Origins, c.CallbackURLs})
	if err != nil {
		return nil, anonymous.ErrInvalidInput
	}
	profile := sha256.Sum256(frame)
	clear(frame)
	s := &SigninService{pool: pool, repository: r, directory: d, domain: domain, effect: effect, crypto: crypto, custody: custody, config: func() SigninConfig { return c }, profile: profile}
	p := &signinPhase{service: s}
	if _, err = session.NewAnonymousSessionIssuerWithCSRF(p, c.Issuer, c.CSRF); err != nil {
		return nil, anonymous.ErrInvalidInput
	}
	if _, _, err = s.coordinator(p); err != nil {
		return nil, anonymous.ErrInvalidInput
	}
	return s, nil
}

func (s *SigninService) coordinator(p *signinPhase) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	a, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, err
	}
	l, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, nil, err
	}
	r, err := kernel.NewContributorRegistry([]kernel.Contributor{s.directory, a, l, p})
	if err != nil {
		return nil, nil, err
	}
	c, err := kernel.NewCoordinatorWithRequestKeys(s.pool, r, s.config().Coordinator, s.config().RequestKeys)
	return c, r, err
}

func (s *SigninService) requestIntent(r anonymous.SigninRequest) (identity.RequestIntent, error) {
	if r.Validate() != nil {
		return identity.RequestIntent{}, anonymous.ErrInvalidInput
	}
	remember, _ := r.Remember.Bindings()
	frame, err := json.Marshal(struct {
		Tenant                            identity.TenantID
		Actor                             authorization.SubjectID
		Kind                              authorization.SubjectKind
		Flow                              identity.PreAuthTransactionID
		Origin, Callback, Network, Device string
		Remember                          session.RememberPolicySpec
	}{r.TenantID, r.Caller.Request.Subject.ID, r.Caller.Request.Subject.Kind, r.PreAuthID, r.Origin, r.CallbackURL, r.Network, r.Device, remember})
	if err != nil {
		return identity.RequestIntent{}, anonymous.ErrInvalidInput
	}
	defer clear(frame)
	intentKey := s.config().IntentKey
	digest := func(purpose string, b []byte) []byte {
		mac := hmac.New(sha256.New, intentKey[:])
		mac.Write([]byte("identity-anonymous-signin-intent-v1\x00" + purpose + "\x00"))
		mac.Write(binary.BigEndian.AppendUint64(nil, uint64(len(b))))
		mac.Write(b)
		return mac.Sum(nil)
	}
	return identity.NewRequestIntent([]identity.FeatureField{{Name: "profile", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: s.profile[:]}}, {Name: "input", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest("input", frame)}}, {Name: "cookie", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest("cookie", []byte(r.Cookie.Token()))}}})
}

// Signin executes one original scoped request through native prepared-input and
// generation custody. Terminal retry/recovery cannot generate a second token.
func (s *SigninService) Signin(ctx context.Context, r anonymous.SigninRequest) (out anonymous.SigninResult, err error) {
	if ctx == nil || s == nil || s.config == nil || r.Validate() != nil {
		return out, anonymous.ErrInvalidInput
	}
	c := s.config()
	ctx, stop := context.WithTimeout(ctx, c.Repository.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if err != nil || ctx.Err() != nil {
			err = signinPublicError(ctx, err)
			out.Session = session.IssueResult{}
			out.CSRFToken = session.CSRFToken{}
		}
	}()
	intent, err := s.requestIntent(r)
	if err != nil {
		return out, err
	}
	p := &signinPhase{service: s, request: r}
	coordinator, registry, err := s.coordinator(p)
	if err != nil {
		return out, err
	}
	p.coordinator, p.registry = coordinator, registry
	p.issuer, err = session.NewAnonymousSessionIssuerWithCSRF(p, c.Issuer, c.CSRF)
	if err != nil {
		return out, err
	}
	scope := kernel.RequestKeyScope{TenantID: r.TenantID, ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: r.Caller.Request.Subject.Kind, Method: "POST", RouteID: creationOperation().OperationID}
	caller := r.Caller.Clone()
	caller.PolicyRevision = authorization.Revision(c.RequestKeys.Policy.PolicyVersion)
	caller.Request.Resource = authorization.Resource{Type: "identity.request-admission", ID: authorization.ResourceID(scope.RouteID)}
	k, wire, err := coordinator.ResolvePreparedRequestKey(ctx, scope, r.IdempotencyKey, intent, caller, p.registration(), p)
	if err != nil {
		return out, err
	}
	defer clear(wire)
	if err = p.restoreInput(ctx, k, wire, intent); err != nil {
		return out, err
	}
	b := p.input.Binding
	out.Recovery, err = anonymous.NewSigninRecovery(signinQuery(b), r.PreAuthID)
	if err != nil {
		return out, err
	}
	out.Outcome = identity.CommitOutcomeUnknown
	if err = p.initialize(); err != nil {
		return out, err
	}
	plan, err := p.plan(p.original, true)
	if err != nil {
		return out, err
	}
	receipt, err := coordinator.ExecutePreparedFeature(ctx, p.original, plan)
	if receipt.Outcome != identity.CommitOutcomeInvalid {
		out.Outcome = receipt.Outcome
	}
	out.RetryAfter = receipt.RetryAfter
	out.Replayed = receipt.Outcome == identity.CommitOutcomeCommitted && p.prepared == (session.PreparedIssuance{})
	if err != nil || receipt.Outcome != identity.CommitOutcomeCommitted || out.Replayed {
		return out, err
	}
	p.receipt, p.deliverable = receipt, true
	bound, err := p.issuer.BindAnonymous(p.prepared, p.command)
	if err != nil {
		return out, err
	}
	out.Session, err = p.issuer.Issue(ctx, bound)
	if err != nil {
		return out, err
	}
	out.CSRFToken, err = bound.CSRFToken()
	return out, err
}

// RecoverSignin authenticates original encrypted input and cookie before native
// disclosure/reconciliation. It performs no generation, external risk or retry.
func (s *SigninService) RecoverSignin(ctx context.Context, r anonymous.SigninRecoveryRequest) (out anonymous.SigninResult, err error) {
	if ctx == nil || s == nil || s.config == nil || r.Validate() != nil {
		return out, anonymous.ErrInvalidInput
	}
	c := s.config()
	ctx, stop := context.WithTimeout(ctx, c.Repository.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if err != nil || ctx.Err() != nil {
			err = signinPublicError(ctx, err)
			out.Session = session.IssueResult{}
			out.CSRFToken = session.CSRFToken{}
		}
	}()
	q, _, _ := r.Recovery.Bindings()
	p := &signinPhase{service: s}
	coordinator, registry, err := s.coordinator(p)
	if err != nil {
		return out, err
	}
	p.coordinator, p.registry = coordinator, registry
	caller := r.Caller.Clone()
	caller.PolicyRevision = authorization.Revision(c.Coordinator.QueryPolicy.PolicyVersion)
	caller.Request.Resource = authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(q.AnonymousFlowID)}
	k, wire, err := coordinator.QueryRequestPreparation(ctx, q, caller, p.registration(), p)
	if err != nil {
		return out, err
	}
	defer clear(wire)
	if err = p.restoreInput(ctx, k, wire, identity.RequestIntent{}); err != nil || signinQuery(p.input.Binding) != q {
		return out, identity.ForbiddenError{}
	}
	if !p.possessesRecovery(r) {
		return out, identity.ForbiddenError{}
	}
	out.Recovery, out.Outcome, out.Replayed = r.Recovery, identity.CommitOutcomeUnknown, true
	receipt, err := coordinator.RecoverFeatureCommand(ctx, q, caller)
	if receipt.Outcome != identity.CommitOutcomeInvalid {
		out.Outcome = receipt.Outcome
	}
	out.RetryAfter = receipt.RetryAfter
	return out, err
}

func signinQuery(b identity.CommandBinding) identity.RecoveryQuery {
	return identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, AnonymousFlowID: b.AnonymousFlowID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID}
}
func signinText(s string, n int) bool {
	if len(s) == 0 || len(s) > n {
		return false
	}
	for i := range len(s) {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
func signinURLs(all []string, origin bool) bool {
	if len(all) == 0 || len(all) > 16 {
		return false
	}
	for _, raw := range all {
		if raw == "" && !origin {
			continue
		}
		if !signinText(raw, 2048) {
			return false
		}
		u, e := url.Parse(raw)
		if e != nil || u.Opaque != "" || u.Hostname() == "" || u.User != nil || strings.Contains(raw, "#") || u.Scheme != "https" && (u.Scheme != "http" || u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" && u.Hostname() != "::1") || origin && (u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery) {
			return false
		}
	}
	return true
}
func signinPublicError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if err == nil {
		return nil
	}
	var forbidden identity.ForbiddenError
	var conflict identity.ConflictError
	var unknown identity.UnknownCommitError
	if errors.As(err, &forbidden) {
		return forbidden
	}
	if errors.As(err, &conflict) {
		return conflict
	}
	if errors.As(err, &unknown) {
		return unknown
	}
	return identity.UnavailableError{}
}
func (SigninConfig) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("anonymouspostgres.SigninConfig(redacted)"))
}
func (SigninConfig) MarshalJSON() ([]byte, error) { return nil, anonymous.ErrDisclosure }
func (SigninConfig) MarshalText() ([]byte, error) { return nil, anonymous.ErrDisclosure }
func (SigninService) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("anonymouspostgres.SigninService(redacted)"))
}
func (SigninService) MarshalJSON() ([]byte, error) { return nil, anonymous.ErrDisclosure }
