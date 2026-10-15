package reference

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	policy "github.com/faustbrian/go-authorization/v3/postgres"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// PasswordOTPLoginSendConfig selects concrete password-primary, secondary OTP,
// browser, policy, risk/counter and encryption owners. It selects neither TOTP,
// enrollment, session issuance nor HTTP. All borrowed owners/callbacks must be
// immutable and outlive calls. ConfigurationID pins callback/signing semantics:
// change it whenever those semantics change. AllowedOrigins are exact HTTPS
// origins, copied at construction. Construct intent custody with
// NewPasswordOTPLoginSendConfig, then fill the public composition fields.
type PasswordOTPLoginSendConfig struct {
	ConfigurationID, PolicyID, IssuerURL string
	MaximumDuration                      time.Duration
	Primary                              *passwordpg.SigninService
	Issuance                             *otppg.MFALoginIssuer
	Issuer                               capabilitypg.IssuerConfig
	Session                              sessionpg.Config
	Profile                              sessionpg.IdentifierAdmissionConfig
	CookieKeys                           map[uint32]session.DigestKey
	Coordinator                          kernel.CoordinatorConfig
	RequestKeys                          kernel.RequestKeyConfig
	Risk                                 risk.ProtectedProviderAdmissionCustodyConfig
	Counters                             riskpg.Config
	AllowedOrigins                       []string
	ActiveEnvelopeKeyID                  string
	intentKey                            func() [32]byte
}

// NewPasswordOTPLoginSendConfig retains an independent nonzero request-intent
// key without IO. Keep it independent of cookie/envelope/fingerprint keys and
// stable while original requests need restoration. Zero/literal custody denies.
func NewPasswordOTPLoginSendConfig(keys kernel.RequestKeyConfig, intent [32]byte, envelopeKey string) (PasswordOTPLoginSendConfig, error) {
	if keys.Namespace == "" || keys.Policy.PolicyVersion == 0 || intent == ([32]byte{}) || envelopeKey == "" {
		return PasswordOTPLoginSendConfig{}, invalidPasswordOTPSend()
	}
	return PasswordOTPLoginSendConfig{RequestKeys: keys, ActiveEnvelopeKeyID: envelopeKey, intentKey: func() [32]byte { return intent }}, nil
}

// PasswordOTPLoginSendService composes actual native owners through the existing
// request-key, preparation and transaction journals. Sending cannot consume the
// original primary/child, reset its budget, confirm a factor or issue a session.
// It owns no pool, goroutine, cache or independent transaction. Concurrent calls
// require immutable inputs; errors never contain submitted proof or cookie.
type PasswordOTPLoginSendService struct{ state func() *passwordOTPSendState }
type passwordOTPSendState struct {
	pool         *database.Pool
	config       PasswordOTPLoginSendConfig
	issuer       *capabilitypg.Issuer
	directory    *kernel.Repository
	continuation *mfapg.ContinuationReader
	factors      *mfapg.OTPFactorReader
	policy       *policy.AuthorityStore
	crypto       *envelope.Service
	custody      risk.ProtectedProviderAdmissionCustody
	counters     *riskpg.Repository
	identity     [32]byte
}

func invalidPasswordOTPSend() error {
	return identity.InvalidInputError{Field: "reference_password_otp_send"}
}
func passwordOTPSendOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa.otp-send", SchemaID: "mfa-otp-send", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}

// NewPasswordOTPLoginSendService freezes selected native composition without
// IO, callbacks, generation or bootstrap. Install all selected migration/key
// histories before serving, including the anonymous MFA-send counter upgrade,
// and initialize the actual OTP issuer. No application-written domain store or
// TOTP/session-issuance dependency is accepted. Pool/keyring remain caller-owned.
func NewPasswordOTPLoginSendService(pool *database.Pool, c PasswordOTPLoginSendConfig, keys *keyring.Provider) (*PasswordOTPLoginSendService, error) {
	if pool == nil || pool.Raw() == nil || keys == nil || c.Primary == nil || c.Issuance == nil || c.intentKey == nil || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 5*time.Second || c.Coordinator.QueryPolicy == nil || c.Coordinator.AdmissionPolicy == nil || c.Counters.CommandCounters == nil || c.Session.MaximumDuration <= 0 || c.Session.MaximumDuration > c.MaximumDuration || c.Coordinator.MaximumDuration <= 0 || c.Coordinator.MaximumDuration > c.MaximumDuration || len(c.CookieKeys) == 0 || len(c.CookieKeys) > 32 || len(c.AllowedOrigins) == 0 || len(c.AllowedOrigins) > 16 || c.Profile.CredentialKind != identity.CredentialPassword || c.Profile.CredentialOwner != "identity/password" || c.Profile.AuthenticationMethod != "password" || c.Profile.Audience != c.Issuer.Audience {
		return nil, invalidPasswordOTPSend()
	}
	for _, value := range []string{c.ConfigurationID, c.PolicyID, c.ActiveEnvelopeKeyID, c.Profile.GlobalAuthorityID, c.Profile.PolicyNamespace} {
		if _, err := identity.ParseIdentifierID(value); err != nil {
			return nil, invalidPasswordOTPSend()
		}
	}
	u, err := url.Parse(c.IssuerURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.String() != c.IssuerURL {
		return nil, invalidPasswordOTPSend()
	}
	if c.Coordinator.QueryPolicy.PolicyVersion != c.Coordinator.AdmissionPolicy.PolicyVersion || c.RequestKeys.Policy.PolicyVersion != c.Coordinator.AdmissionPolicy.PolicyVersion || !sameServerAuthorization(c.Coordinator.QueryPolicy.Authorization, c.Coordinator.AdmissionPolicy.Authorization) {
		return nil, invalidPasswordOTPSend()
	}
	c.AllowedOrigins = slices.Clone(c.AllowedOrigins)
	slices.Sort(c.AllowedOrigins)
	for index, origin := range c.AllowedOrigins {
		u, err := url.Parse(origin)
		if err != nil || len(origin) > 2048 || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.String() != origin || index > 0 && origin == c.AllowedOrigins[index-1] {
			return nil, invalidPasswordOTPSend()
		}
	}
	c.CookieKeys = maps.Clone(c.CookieKeys)
	c.Coordinator.RetainedFingerprintKeys = maps.Clone(c.Coordinator.RetainedFingerprintKeys)
	query, admission := *c.Coordinator.QueryPolicy, *c.Coordinator.AdmissionPolicy
	c.Coordinator.QueryPolicy, c.Coordinator.AdmissionPolicy = &query, &admission
	s := &passwordOTPSendState{pool: pool, config: c}
	s.issuer, err = capabilitypg.NewIssuer(c.Issuer)
	if err != nil {
		return nil, invalidPasswordOTPSend()
	}
	s.directory, err = kernel.NewRepository(pool, kernel.Config{MaximumDuration: c.MaximumDuration})
	if err != nil {
		return nil, err
	}
	s.continuation, err = mfapg.NewContinuationReader(pool, c.MaximumDuration)
	if err != nil {
		return nil, err
	}
	s.factors, err = mfapg.NewOTPFactorReader(pool, c.MaximumDuration)
	if err != nil {
		return nil, err
	}
	s.policy, err = policy.NewAuthorityStore(pool.Raw(), c.MaximumDuration)
	if err != nil {
		return nil, err
	}
	s.crypto, err = envelope.NewService(keys)
	if err != nil {
		return nil, invalidPasswordOTPSend()
	}
	s.custody, err = risk.NewProtectedProviderAdmissionCustody(c.Risk)
	if err != nil || s.custody.ValidateCounterPolicy(c.Counters.CommandCounters.Policy) != nil {
		return nil, invalidPasswordOTPSend()
	}
	s.counters, err = riskpg.NewRepository(c.Counters)
	if err != nil {
		return nil, err
	}
	configuration, err := c.Issuance.Configuration()
	if err != nil || c.Issuance.DeliveryContributor() == nil {
		return nil, invalidPasswordOTPSend()
	}
	probe, err := session.ParseToken("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		return nil, invalidPasswordOTPSend()
	}
	versions := make([]uint32, 0, len(c.CookieKeys))
	for version := range c.CookieKeys {
		versions = append(versions, version)
	}
	slices.Sort(versions)
	frame := append([]byte("reference-password-otp-send-v1\x00"), configuration[:]...)
	for _, version := range versions {
		digest, err := probe.Digest(c.CookieKeys[version], "mfa-otp-send-configuration")
		if err != nil || version == 0 || digest.KeyVersion != version {
			return nil, invalidPasswordOTPSend()
		}
		frame = append(frame, digest.Sum[:]...)
	}
	metadata, err := json.Marshal(struct {
		Configuration, Policy, Issuer, Namespace, Envelope, Global, Authorization, Audience string
		Timeout                                                                             time.Duration
		QueryPolicy, CounterPolicy                                                          uint64
		Origins                                                                             []string
	}{c.ConfigurationID, c.PolicyID, c.IssuerURL, c.RequestKeys.Namespace, c.ActiveEnvelopeKeyID, c.Profile.GlobalAuthorityID, c.Profile.PolicyNamespace, c.Profile.Audience, c.MaximumDuration, query.PolicyVersion, c.Counters.PolicyVersion, c.AllowedOrigins})
	if err != nil {
		return nil, invalidPasswordOTPSend()
	}
	frame = append(frame, metadata...)
	clear(metadata)
	key := c.intentKey()
	mac := hmac.New(sha256.New, key[:])
	clear(key[:])
	_, _ = mac.Write(frame)
	copy(s.identity[:], mac.Sum(nil))
	clear(frame)
	return &PasswordOTPLoginSendService{state: func() *passwordOTPSendState { return s }}, nil
}

// OtpSend retains the original native input before risk or entropy, then queues
// one purpose-bound challenge in the sole coordinator transaction. Matching
// retries restore original input/output and never select another destination or
// code. Queue status is not provider delivery, factor proof or login completion.
func (s *PasswordOTPLoginSendService) OtpSend(ctx context.Context, r mfa.OtpSendRequest) (out mfa.OtpSendResult, err error) {
	if ctx == nil || s == nil || s.state == nil || r.Validate() != nil {
		return out, invalidPasswordOTPSend()
	}
	state := s.state()
	if r.Enrollment != nil || !slices.Contains(state.config.AllowedOrigins, r.Origin) {
		return out, identity.ForbiddenError{}
	}
	ctx, stop := context.WithTimeout(ctx, state.config.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			out.ChallengeID = ""
			out.DeliveryState = 0
		}
	}()
	p := &passwordOTPSendPhase{state: state, request: r}
	defer p.destroy()
	if err = p.compose(); err != nil {
		return out, err
	}
	intent, err := state.intent(r)
	if err != nil {
		return out, err
	}
	scope := kernel.RequestKeyScope{TenantID: r.TenantID, ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: r.Caller.Request.Subject.Kind, Method: "POST", RouteID: passwordOTPSendOperation().OperationID}
	caller := r.Caller.Clone()
	caller.PolicyRevision = authorization.Revision(state.config.RequestKeys.Policy.PolicyVersion)
	caller.Request.Resource = authorization.Resource{Type: "identity.request-admission", ID: authorization.ResourceID(scope.RouteID)}
	k, wire, err := p.coordinator.ResolvePreparedRequestKey(ctx, scope, r.IdempotencyKey, intent, caller, kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: passwordOTPSendOperation()}, p)
	defer clear(wire)
	if err != nil {
		return out, err
	}
	out.CommandID, out.Outcome = k.Admission.CommandID, identity.CommitOutcomeUnknown
	if err = p.restoreInput(ctx, k, wire); err != nil {
		return out, err
	}
	if err = p.buildCommand(); err != nil {
		return out, err
	}
	result, err := p.coordinator.ExecutePreparedFeature(ctx, p.command, p.plan)
	if result.Outcome != 0 {
		out.Outcome = result.Outcome
	}
	if err == nil && result.Outcome == identity.CommitOutcomeCommitted {
		out.ChallengeID = string(out.CommandID)
		out.DeliveryState = delivery.StateQueued
	}
	return out, err
}

// RecoverOtpSend returns only the exact historical code/proof-free outcome
// after current result-access authorization. It never generates, redelivers,
// authenticates a factor or renews the original primary/child/browser.
func (s *PasswordOTPLoginSendService) RecoverOtpSend(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (out mfa.OtpSendResult, err error) {
	if ctx == nil || s == nil || s.state == nil || q.OperationID != passwordOTPSendOperation().OperationID {
		return out, invalidPasswordOTPSend()
	}
	state := s.state()
	ctx, stop := context.WithTimeout(ctx, state.config.MaximumDuration)
	defer stop()
	p := &passwordOTPSendPhase{state: state}
	if err = p.compose(); err != nil {
		return out, err
	}
	receipt, err := p.coordinator.RecoverFeatureCommand(ctx, q, caller)
	out.CommandID, out.Outcome = q.CommandID, receipt.Outcome
	if err == nil && receipt.Outcome == identity.CommitOutcomeCommitted {
		out.ChallengeID = string(q.CommandID)
		out.DeliveryState = delivery.StateQueued
	}
	return out, err
}

func (PasswordOTPLoginSendConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.PasswordOTPLoginSendConfig(redacted)"))
}
func (PasswordOTPLoginSendConfig) MarshalJSON() ([]byte, error) { return nil, invalidPasswordOTPSend() }
func (PasswordOTPLoginSendConfig) MarshalText() ([]byte, error) { return nil, invalidPasswordOTPSend() }
func (PasswordOTPLoginSendService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.PasswordOTPLoginSendService(redacted)"))
}
func (PasswordOTPLoginSendService) MarshalJSON() ([]byte, error) {
	return nil, invalidPasswordOTPSend()
}
func (PasswordOTPLoginSendService) MarshalText() ([]byte, error) {
	return nil, invalidPasswordOTPSend()
}
