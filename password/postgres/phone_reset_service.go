package passwordpostgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/phone"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// PhonePasswordResetRequestConfig selects only the native request half of phone
// password recovery. It enables no completion, signin, fallback or HTTP route.
// Both Enabled and AcceptCarrierRisk must be explicit. ConfigurationID versions
// borrowed policy/template semantics; retain this configuration and decryption
// keys for original recovery. IntentKey is dedicated to complete request intent.
// SMS and Delivery must share the real durable delivery owner. Install their
// native histories, request-key preparation and risk counters before use.
type PhonePasswordResetRequestConfig struct {
	Enabled, AcceptCarrierRisk bool
	ConfigurationID            string
	RequestKeys                kernel.RequestKeyConfig
	IntentKey                  [32]byte
	ActiveEnvelopeKeyID        string
	NumberBindingKeyVersion    uint32
	Risk                       PhonePasswordResetRiskConfig
	SMS                        *otppg.PhonePasswordResetIssuer
	Profile                    password.ResetProfileConfig
	Issuer                     issuerpg.IssuerConfig
	IssuanceCustody            issuerpg.IssuancePreparationConfig
	Delivery                   SignupDeliveryConfig
}

func (PhonePasswordResetRequestConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passwordpostgres.PhonePasswordResetRequestConfig(redacted)"))
}
func (PhonePasswordResetRequestConfig) MarshalJSON() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}
func (PhonePasswordResetRequestConfig) MarshalText() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// PhonePasswordResetRequestService exposes queued-request and code-free recovery
// only. Calls are bounded and concurrent-safe under borrowed native dependencies;
// the pool remains caller-owned. It owns no worker, sender, transaction, retry
// loop or additional journal. This is not yet the complete PasswordResetService.
type PhonePasswordResetRequestService struct {
	read func() *phoneResetRequestService
}
type phoneResetRequestService struct {
	primary *SigninService
	source  *phonePasswordRecoverySource
	c       PhonePasswordResetRequestConfig
	link    resetRequestDeliveryPreparation
	crypto  *envelope.Service
	profile [32]byte
}

// NewPhonePasswordResetRequestService validates immutable composition without
// IO, clocks, provider calls, credential comparison, code generation or sending.
// primary supplies the actual password/session/authorization owners, not signin
// authority. NumberBindingKeyVersion identifies primary's identifier-key profile;
// operators must retain that profile unchanged for original command lifetime.
func NewPhonePasswordResetRequestService(primary *SigninService, numbers *phone.NumberPolicy, c PhonePasswordResetRequestConfig, keys *keyring.Provider) (*PhonePasswordResetRequestService, error) {
	if primary == nil || primary.pool == nil || keys == nil || !c.Enabled || !c.AcceptCarrierRisk || !reauthenticationText(c.ConfigurationID, 128) || !reauthenticationText(c.ActiveEnvelopeKeyID, 128) || c.IntentKey == ([32]byte{}) || c.NumberBindingKeyVersion == 0 || c.SMS == nil || c.Delivery.Owner == nil || c.SMS.DeliveryContributor() != c.Delivery.Owner || c.Delivery.Renderer == nil || c.Delivery.Resolver == nil || c.Delivery.Resolver != c.Issuer.Crypto.Resolver || c.Delivery.TemplateVersion == 0 || c.Delivery.ProviderVersion == 0 || c.Delivery.ScopeKey == ([32]byte{}) || c.Delivery.Timeout <= 0 || c.Delivery.Timeout > 5*time.Second || !reauthenticationText(c.Delivery.TemplateID, 128) || len(c.Delivery.Locales) < 1 || len(c.Delivery.Locales) > 16 || !signinURLs([]string{c.Delivery.Endpoint}, false) || c.RequestKeys.Policy.PolicyVersion != primary.c.Coordinator.AdmissionPolicy.PolicyVersion || c.Risk.Store.UseCounters == nil || c.Risk.Store.UseIssuer != nil || c.Risk.Issuer.Executor != nil || c.Risk.Store.PolicyVersion != c.RequestKeys.Policy.PolicyVersion {
		return nil, password.ErrPasswordWork
	}
	if _, err := NewKeyedEmailManagementConfig(c.RequestKeys, c.IntentKey); err != nil {
		return nil, err
	}
	source, err := newPhonePasswordRecoverySource(primary.pool, primary.c, numbers)
	if err != nil {
		return nil, err
	}
	profile, err := password.NewPhoneResetProfile(c.Profile)
	if err != nil || !slices.Contains(c.Profile.Callbacks, c.Delivery.Endpoint) {
		return nil, password.ErrPasswordWork
	}
	issuer, err := issuerpg.NewIssuer(c.Issuer)
	if err != nil {
		return nil, err
	}
	codec, err := issuerpg.NewIssuancePreparationCodec(issuer, c.IssuanceCustody)
	if err != nil {
		return nil, err
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		return nil, err
	}
	smsProfile, err := c.SMS.Configuration()
	if err != nil {
		return nil, err
	}
	c.Delivery.Locales = slices.Clone(c.Delivery.Locales)
	c.Profile.Callbacks = slices.Clone(c.Profile.Callbacks)
	c.Profile.RetainedBindingKeys = maps.Clone(c.Profile.RetainedBindingKeys)
	c.Risk.Store.EvidenceKeys = slices.Clone(c.Risk.Store.EvidenceKeys)
	c.Risk.Issuer.Keys = slices.Clone(c.Risk.Issuer.Keys)
	c.Risk.Store.EnvelopeKeys = maps.Clone(c.Risk.Store.EnvelopeKeys)
	for id, key := range c.Risk.Store.EnvelopeKeys {
		c.Risk.Store.EnvelopeKeys[id] = slices.Clone(key)
	}
	c.Risk.Coordinator.RetainedFingerprintKeys = maps.Clone(c.Risk.Coordinator.RetainedFingerprintKeys)
	if c.Risk.Coordinator.QueryPolicy != nil {
		v := *c.Risk.Coordinator.QueryPolicy
		c.Risk.Coordinator.QueryPolicy = &v
	}
	if c.Risk.Coordinator.AdmissionPolicy != nil {
		v := *c.Risk.Coordinator.AdmissionPolicy
		c.Risk.Coordinator.AdmissionPolicy = &v
	}
	wire, err := json.Marshal(struct {
		ID, Namespace, Endpoint, Template, Policy string
		Version, Provider                         uint64
		TemplateVersion, NumberVersion            uint32
		SMS                                       [32]byte
		Locales                                   []string
	}{c.ConfigurationID, c.RequestKeys.Namespace, c.Delivery.Endpoint, c.Delivery.TemplateID, primary.c.PolicyID, c.RequestKeys.Policy.PolicyVersion, c.Delivery.ProviderVersion, c.Delivery.TemplateVersion, c.NumberBindingKeyVersion, smsProfile, c.Delivery.Locales})
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	s := &phoneResetRequestService{primary: primary, source: source, c: c, crypto: crypto, profile: sha256.Sum256(wire), link: resetRequestDeliveryPreparation{issuer: issuer, codec: codec, profile: profile, owner: c.Delivery.Owner, renderer: c.Delivery.Renderer, resolver: c.Delivery.Resolver, endpoint: c.Delivery.Endpoint, template: c.Delivery.TemplateID, templateVersion: c.Delivery.TemplateVersion, providerVersion: c.Delivery.ProviderVersion, locales: c.Delivery.Locales, scopeKey: c.Delivery.ScopeKey, timeout: c.Delivery.Timeout}}
	clear(wire)
	if _, err = s.coordinator(&phoneResetKeyPhase{service: s}, nil); err != nil {
		return nil, err
	}
	return &PhonePasswordResetRequestService{read: func() *phoneResetRequestService { return s }}, nil
}

func (s *phoneResetRequestService) coordinator(p kernel.FeatureExecutionContributor, admission *phonePasswordRecoveryRisk) (*kernel.Coordinator, error) {
	a, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, err
	}
	l, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, err
	}
	owners := []kernel.Contributor{s.source.directory, a, l, p}
	if admission != nil {
		owners = append(owners, admission.repository, s.link.issuer, s.link.owner)
	}
	r, err := kernel.NewContributorRegistry(owners)
	if err != nil {
		return nil, err
	}
	return kernel.NewCoordinatorWithRequestKeys(s.primary.pool, r, s.primary.c.Coordinator, s.c.RequestKeys)
}

func (s *phoneResetRequestService) requestIntent(r phone.PasswordResetRequestRequestSpec) (identity.RequestIntent, error) {
	if r.Validate() != nil {
		return identity.RequestIntent{}, phone.ErrInvalidPasswordReset
	}
	number, err := r.Number.Record()
	if err != nil {
		return identity.RequestIntent{}, err
	}
	kind, id, cookie, err := r.Flow.Bindings()
	if err != nil {
		return identity.RequestIntent{}, err
	}
	wire, err := json.Marshal(struct {
		Profile                                           [32]byte
		Tenant                                            identity.TenantID
		Command, Issuance                                 identity.CommandID
		Number                                            phone.NumberRecord
		FlowKind                                          uint8
		FlowID, Cookie, Evidence, Origin, Network, Device string
		Actor                                             identity.ActorID
		ActorKind                                         authorization.SubjectKind
		Policy                                            authorization.Revision
	}{s.profile, r.TenantID, r.CommandID, r.RiskIssuanceCommandID, number, uint8(kind), id, cookie.Token(), r.RiskEvidence.Reveal(), r.Origin, r.Network, r.Device, identity.ActorID(r.Caller.Request.Subject.ID), r.Caller.Request.Subject.Kind, r.Caller.PolicyRevision})
	defer clear(wire)
	if err != nil {
		return identity.RequestIntent{}, password.ErrPasswordWork
	}
	mac := hmac.New(sha256.New, s.c.IntentKey[:])
	mac.Write([]byte("identity-phone-password-reset-request-v1\x00"))
	mac.Write(wire)
	return identity.NewRequestIntent([]identity.FeatureField{{Name: "profile", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: slices.Clone(s.profile[:])}}, {Name: "intent", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: mac.Sum(nil)}}})
}

// RequestPasswordReset retains the original keyed input before any SMS or
// capability generation. It consumes supplied, genuinely issued initiation
// evidence; it does not evaluate new risk. Commitment means two encrypted
// delivery intents are queued, never that SMS was sent. Matching retries reuse
// the canonical consumer and original check/expiry, with no provider calls.
func (s *PhonePasswordResetRequestService) RequestPasswordReset(ctx context.Context, request phone.PasswordResetRequestRequest) (out phone.PasswordResetRequestResult, err error) {
	if ctx == nil || s == nil || s.read == nil {
		return out, password.ErrPasswordWork
	}
	r, err := request.Bindings()
	if err != nil {
		return out, err
	}
	native := s.read()
	ctx, cancel := context.WithTimeout(ctx, native.primary.c.Repository.MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil {
			out, err = phone.PasswordResetRequestResult{}, identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
	}()
	intent, err := native.requestIntent(r)
	if err != nil {
		return out, err
	}
	p := &phoneResetKeyPhase{service: native, request: r}
	coordinator, err := native.coordinator(p, nil)
	if err != nil {
		return out, err
	}
	op := phoneResetRequestOperation()
	scope := kernel.RequestKeyScope{TenantID: r.TenantID, ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: r.Caller.Request.Subject.Kind, Method: "POST", RouteID: op.OperationID}
	caller := r.Caller.Clone()
	caller.Request.Resource = authorization.Resource{Type: "identity.request-admission", ID: authorization.ResourceID(op.OperationID)}
	k, wire, err := coordinator.ResolvePreparedRequestKey(ctx, scope, r.IdempotencyKey, intent, caller, kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op}, p)
	defer clear(wire)
	if err != nil {
		return out, err
	}
	stored, err := native.openInput(ctx, k, wire, intent)
	if err != nil {
		return out, err
	}
	b := stored.Spec.Binding
	admission, err := newPhonePasswordRecoveryRisk(native.primary.pool, native.c.Risk, r.Caller, b.UserID)
	if err != nil {
		return out, err
	}
	command, err := native.command(stored, r)
	if err != nil || admission.repository.ValidateRiskEvidenceCommand(command, kernel.RiskEvidencePlan(stored.Risk)) != nil {
		return out, password.ErrPasswordWork
	}
	phase := &phoneResetRequestPhase{config: native.primary.c, sms: native.c.SMS, caller: r.Caller.Clone()}
	read, err := native.coordinator(phase, admission)
	if err != nil {
		return out, err
	}
	q := phoneResetRequestQuery(b)
	caller = r.Caller.Clone()
	caller.Request.Resource = authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}
	observed, err := read.ObserveCommandAdmission(ctx, q, caller)
	if err != nil {
		return out, err
	}
	if !observed.Absent && observed.Record.Outcome != identity.CommitOutcomeInProgress {
		result, err := read.RecoverFeatureCommand(ctx, q, caller)
		return phoneResetSendReceipt(b.CommandID, result, err)
	}
	selected, err := native.restoreSelection(ctx, stored)
	if err != nil {
		return out, err
	}
	original := phoneResetOriginalRisk(r, selected)
	phase, err = restorePhoneResetRequestPhase(ctx, native.primary.pool, native.primary.c, selected, r, admission, original, risk.EvidenceUse{}, native.c.SMS, native.link, native.crypto, native.c.ActiveEnvelopeKeyID, b.CommandID, native.c.NumberBindingKeyVersion, &stored.Spec, kernel.RiskEvidencePlan(stored.Risk))
	if err != nil {
		return out, err
	}
	result, err := phase.execute(ctx)
	return phoneResetSendReceipt(b.CommandID, result, err)
}

func phoneResetRequestQuery(b identity.CommandBinding) identity.RecoveryQuery {
	return identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, RecordID: b.RecordID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID}
}
func phoneResetSendReceipt(id identity.CommandID, r identity.CommandResult, err error) (phone.PasswordResetRequestResult, error) {
	return phone.PasswordResetRequestResult{CommandID: id, Outcome: r.Outcome, RetryAfter: r.RetryAfter}, err
}

func phoneResetOriginalRisk(r phone.PasswordResetRequestRequestSpec, selected phonePasswordRecoverySelection) risk.PhoneEvidenceRequest {
	return phoneResetOriginalRiskInput(phoneResetRiskInput(r), selected)
}

func phoneResetOriginalRiskInput(r phone.PasswordResetInitiationRiskRequestSpec, selected phonePasswordRecoverySelection) risk.PhoneEvidenceRequest {
	f, _ := selected.flow.Bindings()
	number, _ := r.Number.Record()
	return risk.PhoneEvidenceRequest{CommandID: string(r.IssuanceCommandID), Actor: string(r.Caller.Request.Subject.ID), Recovery: risk.CarrierRequest{Phase: risk.PhoneResetInitiation, Binding: risk.PhoneRecoveryScope{Tenant: string(r.TenantID), Subject: string(selected.recipient.User.ID), RecoveryOperation: "identity.phone.password-reset-request", CanonicalNumber: number.E164, PreAuthTransaction: string(f.Binding.ID), Attempt: string(r.CommandID), PolicyVersion: f.Binding.Intent.PolicyVersion}}, Subject: risk.Subject{Network: r.Network, Device: r.Device, IdentifierDigest: hex.EncodeToString(f.Binding.Intent.IdentifierBinding[:])}}
}

// EvaluatePasswordResetRequestRisk resolves the actual original browser and
// verified phone/password/confirmed TOTP account before asking the existing risk
// owner to evaluate carrier/status/velocity. No caller supplies a user ID or
// provider fact. Matching original issuance retains its absolute expiry and
// does not rerun providers; this method never sends SMS or grants reset/session
// authority. Earlier deadlines win and uncertain issuance returns no evidence.
func (s *PhonePasswordResetRequestService) EvaluatePasswordResetRequestRisk(ctx context.Context, request phone.PasswordResetInitiationRiskRequest) (out risk.PhoneEvidenceResult, err error) {
	if ctx == nil || s == nil || s.read == nil {
		return out, password.ErrPasswordWork
	}
	r, err := request.Bindings()
	if err != nil {
		return out, err
	}
	native := s.read()
	ctx, cancel := context.WithTimeout(ctx, native.primary.c.Repository.MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil {
			out, err = risk.PhoneEvidenceResult{}, identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			out, err = risk.PhoneEvidenceResult{}, ctx.Err()
		}
	}()
	selected, err := native.source.prepareOriginal(ctx, r)
	if err != nil {
		return out, err
	}
	admission, err := newPhonePasswordRecoveryRisk(native.primary.pool, native.c.Risk, r.Caller, selected.recipient.User.ID)
	if err != nil {
		return out, err
	}
	return admission.issuer.Evaluate(ctx, phoneResetOriginalRiskInput(r, selected))
}

// Keep the encrypted input comparison separate from current factor selection.
// A terminal receipt must remain recoverable after the original factor expires
// or is removed; no receipt recovery may mint a new risk/SMS/reset credential.
func (s *phoneResetRequestService) command(stored phoneResetStoredInput, r phone.PasswordResetRequestRequestSpec) (identity.Command, error) {
	b := stored.Spec.Binding
	if stored.Spec.Operation != phoneResetRequestOperation() || b.TenantID != r.TenantID || b.ActorID != identity.ActorID(r.Caller.Request.Subject.ID) || b.ActorKind != r.Caller.Request.Subject.Kind || b.PolicyID != s.primary.c.PolicyID || b.PolicyVersion != uint64(r.Caller.PolicyRevision) || b.RecordID != string(b.CommandID) || len(stored.Spec.Fields) != 10 {
		return identity.Command{}, password.ErrPasswordWork
	}
	_, _, cookie, err := r.Flow.Bindings()
	if err != nil {
		return identity.Command{}, err
	}
	return identity.NewFeaturePreAuthCommand(stored.Spec, cookie)
}
