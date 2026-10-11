package passwordpostgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	email "github.com/faustbrian/go-identity/email"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/v2/postgres/identity"
)

// ResetRequestConfig selects fixed email normalization, request-key admission,
// original issuance custody and encrypted delivery. Lifetime cannot exceed the
// reset profile. ConfigurationID in ResetConfig versions borrowed parser and
// renderer semantics. No caller selects keys, templates or delivery providers.
// Dependencies must be concurrent-safe; construction performs no callbacks/IO.
type ResetRequestConfig struct {
	Address         email.AddressParser
	RequestKeys     kernel.RequestKeyConfig
	Lifetime        time.Duration
	IssuanceCustody issuerpg.IssuancePreparationConfig
	Delivery        SignupDeliveryConfig
}

// Format prevents composition secrets from entering diagnostics.
func (ResetRequestConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passwordpostgres.ResetRequestConfig(redacted)"))
}

// MarshalJSON denies implicit composition export.
func (ResetRequestConfig) MarshalJSON() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// MarshalText denies implicit textual composition export.
func (ResetRequestConfig) MarshalText() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

type resetRequestRuntime struct {
	config   ResetRequestConfig
	delivery resetRequestDeliveryPreparation
	custody  risk.AuthenticationAdmissionCustody
	profile  [32]byte
}

func (s *ResetService) newRequestRuntime(c ResetRequestConfig) (*resetRequestRuntime, error) {
	base := s.config()
	d := c.Delivery
	if c.Lifetime <= 0 || c.Lifetime > base.Profile.MaximumLifetime || c.Lifetime%time.Second != 0 || c.RequestKeys.Policy.PolicyVersion != base.Coordinator.AdmissionPolicy.PolicyVersion || d.Owner == nil || d.Renderer == nil || d.Resolver == nil || d.Resolver != base.Issuer.Crypto.Resolver || d.TemplateVersion == 0 || d.ProviderVersion == 0 || d.ScopeKey == ([32]byte{}) || !reauthenticationText(d.TemplateID, 128) || len(d.Locales) == 0 || len(d.Locales) > 16 || d.Timeout <= 0 || d.Timeout > 5*time.Second || !signinURLs([]string{d.Endpoint}, false) {
		return nil, password.ErrPasswordWork
	}
	codec, err := issuerpg.NewIssuancePreparationCodec(s.issuer, c.IssuanceCustody)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	custody, err := risk.NewAuthenticationAdmissionCustody(base.Risk)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	frame, err := json.Marshal(struct {
		Base                          [32]byte
		Namespace, Endpoint, Template string
		Policy                        uint64
		Lifetime, Timeout             time.Duration
		TemplateVersion               uint32
		ProviderVersion               uint64
		Locales                       []string
	}{s.configuration, c.RequestKeys.Namespace, d.Endpoint, d.TemplateID, c.RequestKeys.Policy.PolicyVersion, c.Lifetime, d.Timeout, d.TemplateVersion, d.ProviderVersion, d.Locales})
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	profile := sha256.Sum256(frame)
	clear(frame)
	r := &resetRequestRuntime{config: c, custody: custody, profile: profile, delivery: resetRequestDeliveryPreparation{issuer: s.issuer, codec: codec, profile: s.profile, owner: d.Owner, renderer: d.Renderer, resolver: d.Resolver, endpoint: d.Endpoint, template: d.TemplateID, templateVersion: d.TemplateVersion, providerVersion: d.ProviderVersion, locales: slices.Clone(d.Locales), scopeKey: d.ScopeKey, timeout: d.Timeout}}
	if _, _, err = s.requestCoordinator(&resetRequestPhase{service: s, runtime: r}); err != nil {
		return nil, err
	}
	return r, nil
}

func (s *ResetService) requestCoordinator(p *resetRequestPhase) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	audits, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, err
	}
	outbox, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, nil, err
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{s.directory, audits, outbox, p, s.issuer, p.runtime.delivery.owner})
	if err != nil {
		return nil, nil, err
	}
	coordinator, err := kernel.NewCoordinatorWithRequestKeys(s.pool, registry, s.config().Coordinator, p.runtime.config.RequestKeys)
	p.coordinator, p.registry = coordinator, registry
	return coordinator, registry, err
}

// ResetRequest correlates the original unnormalized intent before selecting a
// recipient. Only native first generation can issue and encrypt a message;
// matching retries restore original custody. Known commitment acknowledges
// eligible and suppressed selections identically, never returning a token.
// Earlier deadlines win; unknown outcomes retain the original CommandID.
func (s *ResetService) ResetRequest(ctx context.Context, r password.ResetRequestRequest) (out password.ResetRequestResult, err error) {
	if ctx == nil || s == nil || s.request == nil || r.Validate() != nil {
		return out, password.ErrPasswordWork
	}
	ctx, stop := context.WithTimeout(ctx, s.config().Repository.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
			out.Accepted = false
		}
		if ctx.Err() != nil {
			err = ctx.Err()
			out.Accepted = false
		}
	}()
	if !slices.Contains(s.config().Origins, r.Origin) || !slices.Contains(s.config().Profile.Callbacks, r.CallbackURL) {
		return out, identity.ForbiddenError{}
	}
	address, err := s.request.config.Address.Parse(email.AddressInput(r.Identifier))
	if err != nil {
		return out, password.ErrPasswordWork
	}
	// Complete raw intent enters only a keyed digest, never journal metadata.
	frame, err := json.Marshal(struct {
		Profile                                       [32]byte
		Tenant                                        identity.TenantID
		Command                                       identity.CommandID
		Identifier, Callback, Origin, Network, Device string
	}{s.request.profile, r.TenantID, r.CommandID, string(r.Identifier), r.CallbackURL, r.Origin, r.Network, r.Device})
	if err != nil {
		return out, password.ErrPasswordWork
	}
	defer clear(frame)
	key := s.config().IdentifierKey
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte("identity-password-reset-request-input-v1\x00"))
	mac.Write(frame)
	fields := []identity.FeatureField{{Name: "request.intent", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: hex.EncodeToString(mac.Sum(nil))}}, {Name: "request.configuration", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: hex.EncodeToString(s.request.profile[:])}}}
	intent, err := identity.NewRequestIntent(fields)
	if err != nil {
		return out, err
	}
	p := &resetRequestPhase{service: s, runtime: s.request, request: r, canonical: address.Canonical().Record().Value}
	coordinator, _, err := s.requestCoordinator(p)
	if err != nil {
		return out, err
	}
	scope := kernel.RequestKeyScope{TenantID: r.TenantID, ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: r.Caller.Request.Subject.Kind, Method: "POST", RouteID: resetRequestOperation().OperationID}
	caller := r.Caller.Clone()
	caller.PolicyRevision = authorization.Revision(s.request.config.RequestKeys.Policy.PolicyVersion)
	caller.Request.Resource = authorization.Resource{Type: "identity.request-admission", ID: authorization.ResourceID(scope.RouteID)}
	k, err := coordinator.ResolveRequestKey(ctx, scope, r.IdempotencyKey, intent, caller)
	if err != nil {
		return out, err
	}
	op := resetRequestOperation()
	// The immutable mapping owns original journal correlation. A fresh HTTP
	// request correlation must not change the same keyed command's fingerprint.
	// Admission still receives the current trusted caller and raw intent.
	b := identity.CommandBinding{CommandID: k.CommandID, TenantID: r.TenantID, AnonymousFlowID: string(r.CommandID), ActorID: scope.ActorID, ActorKind: scope.ActorKind, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: s.config().PolicyID, PolicyVersion: s.request.config.RequestKeys.Policy.PolicyVersion, CorrelationID: string(k.CommandID)}
	p.original, err = identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields})
	if err != nil {
		return out, err
	}
	mac = hmac.New(sha256.New, key[:])
	mac.Write([]byte("identity-password-reset-request-counter-v1\x00" + string(r.TenantID) + "\x00" + p.canonical))
	p.subject = risk.Subject{Network: r.Network, Device: r.Device, IdentifierDigest: hex.EncodeToString(mac.Sum(nil))}
	plan, err := p.plan(time.Now().UTC(), false)
	if err != nil {
		return out, err
	}
	result, err := coordinator.ExecutePreparedFeature(ctx, p.original, plan)
	return resetRequestReceipt(k.CommandID, result, err)
}

// RecoverResetRequest uses current result-access policy and the original
// command journal. It takes no identifier, request key or token and cannot
// generate or send another message. Uncertain outcomes remain uncertain.
func (s *ResetService) RecoverResetRequest(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (out password.ResetRequestResult, err error) {
	if ctx == nil || s == nil || s.request == nil || q.OperationID != resetRequestOperation().OperationID || q.UserID != "" || q.AnonymousFlowID == "" || q.RecordID != "" {
		return out, password.ErrPasswordWork
	}
	ctx, stop := context.WithTimeout(ctx, s.config().Repository.MaximumDuration)
	defer stop()
	coordinator, _, err := s.requestCoordinator(&resetRequestPhase{service: s, runtime: s.request})
	if err != nil {
		return out, err
	}
	caller = caller.Clone()
	caller.PolicyRevision = authorization.Revision(s.config().Coordinator.QueryPolicy.PolicyVersion)
	caller.Request.Resource = authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(q.AnonymousFlowID)}
	result, err := coordinator.RecoverFeatureCommand(ctx, q, caller)
	return resetRequestReceipt(q.CommandID, result, err)
}

func resetRequestReceipt(id identity.CommandID, r identity.CommandResult, err error) (password.ResetRequestResult, error) {
	out := password.ResetRequestResult{CommandID: id, Outcome: r.Outcome, Accepted: err == nil && r.Outcome == identity.CommitOutcomeCommitted}
	if r.Outcome == identity.CommitOutcomeCommitted && (r.Feature == nil || r.Feature.Operation != resetRequestOperation()) {
		return password.ResetRequestResult{}, identity.UnavailableError{}
	}
	if out.Validate() != nil {
		return password.ResetRequestResult{}, err
	}
	return out, err
}
