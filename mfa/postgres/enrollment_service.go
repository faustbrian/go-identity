package mfapostgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// TOTPEnrollmentConfig selects first-factor enrollment with an explicit native
// primary source, durable protected counters and provider-only risk policy.
// Pool/keyring/source ownership stays with the caller. Profile/TTL and policy
// identity are trusted startup settings, never request overrides. Only TOTP
// without UV/trusted-device issuance is selected here; other profiles deny.
// Construct cryptographic custody with NewTOTPEnrollmentConfig, then fill the
// public composition fields before NewTOTPEnrollmentService freezes them.
type TOTPEnrollmentConfig struct {
	ConfigurationID, PolicyID string
	MaximumDuration           time.Duration
	TTL                       time.Duration
	Profile                   mfa.TOTPProfile
	Primary                   TOTPEnrollmentPrimarySource
	Coordinator               kernel.CoordinatorConfig
	RequestKeys               kernel.RequestKeyConfig
	Risk                      risk.ProtectedProviderAdmissionCustodyConfig
	Counters                  riskpg.Config
	ActiveEnvelopeKeyID       string
	RecoveryKeyVersion        uint32
	intentKey                 func() [32]byte
	recoveryKey               func() [32]byte
}

// NewTOTPEnrollmentConfig retains independent nonzero intent and recovery
// digest keys in opaque immutable custody. Neither key may equal the other;
// deployment must additionally keep them independent of envelope, lookup and
// command-fingerprint keys. The original namespace/key profile must remain
// available while pending commands or recovery sets depend on it. This pure
// constructor performs no IO, callback, generation or bootstrap.
func NewTOTPEnrollmentConfig(keys kernel.RequestKeyConfig, intent, recovery [32]byte, recoveryVersion uint32, envelopeKey string) (TOTPEnrollmentConfig, error) {
	if intent == ([32]byte{}) || recovery == ([32]byte{}) || intent == recovery || recoveryVersion == 0 || !enrollmentText(envelopeKey, 256) || keys.Namespace == "" || keys.Policy.PolicyVersion == 0 {
		return TOTPEnrollmentConfig{}, invalidEnrollment()
	}
	return TOTPEnrollmentConfig{RequestKeys: keys, ActiveEnvelopeKeyID: envelopeKey, RecoveryKeyVersion: recoveryVersion, intentKey: func() [32]byte { return intent }, recoveryKey: func() [32]byte { return recovery }}, nil
}

// Format redacts key/provider configuration for every verb.
func (TOTPEnrollmentConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.TOTPEnrollmentConfig(redacted)"))
}

// MarshalJSON denies implicit sensitive configuration export.
func (TOTPEnrollmentConfig) MarshalJSON() ([]byte, error) { return nil, invalidEnrollment() }

// MarshalText denies implicit sensitive configuration export.
func (TOTPEnrollmentConfig) MarshalText() ([]byte, error) { return nil, invalidEnrollment() }

// TOTPEnrollmentService borrows one primary pool and immutable native owners.
// It owns no goroutines, private transaction, journal or connection. Every call
// has its own comparable participant and encrypted original preparation.
// Concurrent calls require immutable inputs and concurrent-safe dependencies.
// Install the owned pending-factor/recovery and selected kernel/risk histories
// before use. Construction does not initialize missing account factor state.
type TOTPEnrollmentService struct{ state func() *totpEnrollmentState }
type totpEnrollmentState struct {
	method   string
	pool     *database.Pool
	config   TOTPEnrollmentConfig
	crypto   *envelope.Service
	preparer *TOTPEnrollmentPreparer
	domain   *kernel.Repository
	counters *riskpg.Repository
	custody  risk.ProtectedProviderAdmissionCustody
	identity [32]byte
}

func invalidEnrollment() error { return identity.InvalidInputError{Field: "mfa_enrollment"} }

// NewTOTPEnrollmentService validates explicit native composition without IO or
// secret generation. Durable lockout admission is mandatory; provider facts
// cannot substitute for protected velocity. Missing/unsupported owners deny.
// Existing account factor absence is never interpreted as known-empty state.
func NewTOTPEnrollmentService(pool *database.Pool, c TOTPEnrollmentConfig, keys *keyring.Provider) (*TOTPEnrollmentService, error) {
	return newEnrollmentService(pool, c, keys, "totp")
}

// The two selected public services share the same request-key, primary, risk,
// preparation, recovery and transaction owners. The method is frozen at startup;
// request input cannot turn a TOTP service into a weaker OTP fallback.
func newEnrollmentService(pool *database.Pool, c TOTPEnrollmentConfig, keys *keyring.Provider, method string) (*TOTPEnrollmentService, error) {
	if method != "totp" && method != "otp" {
		return nil, invalidEnrollment()
	}
	if pool == nil || pool.Raw() == nil || keys == nil || nilEnrollmentPrimary(c.Primary) || c.intentKey == nil || c.recoveryKey == nil || c.intentKey() == ([32]byte{}) || c.recoveryKey() == ([32]byte{}) || c.RecoveryKeyVersion == 0 || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 5*time.Second || c.TTL < time.Second || c.TTL > 15*time.Minute || c.TTL%time.Microsecond != 0 || method == "totp" && (c.Profile.Validate() != nil || (c.Profile.Digits != 6 && c.Profile.Digits != 8)) || c.Coordinator.QueryPolicy == nil || c.Coordinator.MaximumDuration <= 0 || c.Coordinator.MaximumDuration > c.MaximumDuration || c.Counters.CommandCounters == nil || !c.Counters.EnforceLockouts {
		return nil, invalidEnrollment()
	}
	for _, value := range []string{c.ConfigurationID, c.PolicyID} {
		if !enrollmentText(value, 128) {
			return nil, invalidEnrollment()
		}
	}
	if !enrollmentText(c.ActiveEnvelopeKeyID, 256) {
		return nil, invalidEnrollment()
	}
	if c.Coordinator.AdmissionPolicy == nil {
		copy := *c.Coordinator.QueryPolicy
		c.Coordinator.AdmissionPolicy = &copy
	}
	query, admission := *c.Coordinator.QueryPolicy, *c.Coordinator.AdmissionPolicy
	c.Coordinator.QueryPolicy, c.Coordinator.AdmissionPolicy = &query, &admission
	c.Coordinator.RetainedFingerprintKeys = maps.Clone(c.Coordinator.RetainedFingerprintKeys)
	c.Risk.Keys = slices.Clone(c.Risk.Keys)
	s := &totpEnrollmentState{pool: pool, config: c, method: method}
	var err error
	if s.domain, err = kernel.NewRepository(pool, kernel.Config{MaximumDuration: c.MaximumDuration}); err != nil {
		return nil, err
	}
	if s.crypto, err = envelope.NewService(keys); err != nil {
		return nil, invalidEnrollment()
	}
	if method == "totp" {
		if s.preparer, err = NewTOTPEnrollmentPreparer(keys, c.ActiveEnvelopeKeyID); err != nil {
			return nil, err
		}
	}
	if s.counters, err = riskpg.NewRepository(c.Counters); err != nil {
		return nil, invalidEnrollment()
	}
	if s.custody, err = risk.NewProtectedProviderAdmissionCustody(c.Risk); err != nil || s.custody.ValidateCounterPolicy(c.Counters.CommandCounters.Policy) != nil {
		return nil, invalidEnrollment()
	}
	policy, err := c.Counters.CommandCounters.Policy.Admit("identity.mfa.enable")
	if err != nil || policy.Profile.Class != risk.CredentialMutation {
		return nil, invalidEnrollment()
	}
	recoveryKey := c.recoveryKey()
	defer clear(recoveryKey[:])
	frame, err := json.Marshal(struct {
		Configuration, Policy, Namespace, Risk string
		Profile                                mfa.TOTPProfile
		TTL, Duration                          time.Duration
		Admission, Query, Request              uint64
		RecoveryVersion                        uint32
		RecoveryIdentity                       [32]byte
		CounterPolicy                          risk.Admission
	}{c.ConfigurationID, c.PolicyID, c.RequestKeys.Namespace, c.Risk.ConfigurationID, c.Profile, c.TTL, c.MaximumDuration, c.Coordinator.AdmissionPolicy.PolicyVersion, c.Coordinator.QueryPolicy.PolicyVersion, c.RequestKeys.Policy.PolicyVersion, c.RecoveryKeyVersion, sha256.Sum256(recoveryKey[:]), policy})
	if err != nil {
		return nil, invalidEnrollment()
	}
	s.identity = sha256.Sum256(frame)
	if method == "otp" {
		// Retain historical TOTP configuration identity and domain-separate the
		// explicit OTP profile and its protected-counter namespace. Moving the
		// store must not restore original requests under an uncharged owner.
		s.identity = sha256.Sum256(append([]byte("mfa-otp-enrollment-config-v1\x00"+c.Counters.Schema+"\x00"), frame...))
	}
	clear(frame)
	service := &TOTPEnrollmentService{state: func() *totpEnrollmentState { return s }}
	if _, _, err := s.coordinator(&totpEnrollmentPhase{state: s}); err != nil {
		return nil, invalidEnrollment()
	}
	return service, nil
}

func enrollmentText(text string, maximum int) bool {
	if text == "" || len(text) > maximum || !utf8.ValidString(text) || strings.TrimSpace(text) != text {
		return false
	}
	for _, r := range text {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func nilEnrollmentPrimary(p any) bool {
	if p == nil {
		return true
	}
	v := reflect.ValueOf(p)
	switch v.Kind() {
	case reflect.Ptr, reflect.Interface, reflect.Map, reflect.Func, reflect.Slice, reflect.Chan:
		return v.IsNil()
	}
	return false
}

func enrollmentOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa.enable", SchemaID: "mfa-enable", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func (s *totpEnrollmentState) coordinator(p kernel.FeatureExecutionContributor) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	audits, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, err
	}
	lifecycle, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, nil, err
	}
	contributors := []kernel.Contributor{s.domain, s.counters, audits, lifecycle, p}
	if phase, ok := p.(*totpURIPhase); ok && phase.send != nil {
		contributors = append(contributors, phase.send.issuance.DeliveryContributor())
	}
	if phase, ok := p.(*totpURIPhase); ok && phase.otpConfirmation != nil {
		contributors = append(contributors, phase.otpConfirmation.owner.ConfirmationContributor())
	}
	r, err := kernel.NewContributorRegistry(contributors)
	if err != nil {
		return nil, nil, err
	}
	c, err := kernel.NewCoordinatorWithRequestKeys(s.pool, r, s.config.Coordinator, s.config.RequestKeys)
	return c, r, err
}

// Enable retains original code-free input before risk or secret generation,
// then executes one native pending-factor/recovery mutation through the existing
// prepared coordinator. Matching retry never looks up a new original primary or
// generates successor material. Only an error-free fresh known commit returns
// recovery output; URI revelation and factor confirmation are separate commands.
// All borrowed inputs must remain immutable until return. Errors preserve
// cancellation and ambiguous outcomes and never include credentials.
func (s *TOTPEnrollmentService) Enable(ctx context.Context, r mfa.EnableRequest) (out mfa.EnableResult, err error) {
	if ctx == nil || s == nil || s.state == nil || r.Validate() != nil {
		return out, invalidEnrollment()
	}
	state := s.state()
	if r.FactorPolicy.Method != state.method || r.FactorPolicy.RequireUserVerification || r.FactorPolicy.AllowTrustedDevice {
		return out, identity.ForbiddenError{}
	}
	ctx, stop := context.WithTimeout(ctx, state.config.MaximumDuration)
	defer stop()
	ctx, expire := context.WithCancelCause(ctx)
	var deadlineStops []func()
	defer func() {
		for _, cancel := range deadlineStops {
			cancel()
		}
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if cause := context.Cause(ctx); cause != nil {
			err = cause
		}
		if err != nil {
			destroyEnrollmentDelivery(&out)
		}
		expire(nil)
	}()
	p := &totpEnrollmentPhase{state: state, request: func() mfa.EnableRequest { return r }}
	defer p.destroy()
	coordinator, registry, err := state.coordinator(p)
	if err != nil {
		return out, err
	}
	p.coordinator, p.registry = coordinator, registry
	intent, err := state.requestIntent(r)
	if err != nil {
		return out, err
	}
	scope := kernel.RequestKeyScope{TenantID: r.TenantID, ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: authorization.SubjectUser, Method: "POST", RouteID: enrollmentOperation().OperationID}
	feature := kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: enrollmentOperation()}
	keyCaller := r.Caller.Clone()
	keyCaller.PolicyRevision = authorization.Revision(state.config.RequestKeys.Policy.PolicyVersion)
	keyCaller.Request.Resource = authorization.Resource{Type: "identity.request-admission", ID: authorization.ResourceID(scope.RouteID)}
	binding, wire, err := coordinator.ResolvePreparedRequestKey(ctx, scope, r.IdempotencyKey, intent, keyCaller, feature, p)
	defer clear(wire)
	if err != nil {
		return out, err
	}
	out.CommandID, out.Outcome = binding.Admission.CommandID, identity.CommitOutcomeUnknown
	if err = p.restoreInput(ctx, binding, wire); err != nil {
		return out, err
	}
	if err = p.buildCommand(); err != nil {
		return out, err
	}
	var earliest time.Time
	p.arm = func(until time.Time) error {
		if until.IsZero() || !time.Now().Before(until) {
			return identity.ForbiddenError{}
		}
		if !earliest.IsZero() && !until.Before(earliest) {
			return nil
		}
		earliest = until
		bound, cancel := context.WithDeadline(ctx, until)
		wake := context.AfterFunc(bound, func() { expire(context.DeadlineExceeded) })
		deadlineStops = append(deadlineStops, func() { wake(); cancel() })
		return nil
	}
	receipt, err := coordinator.ExecutePreparedFeature(ctx, p.command, p.plan)
	if receipt.Outcome != 0 {
		out.Outcome = receipt.Outcome
	}
	if err != nil || receipt.Outcome != identity.CommitOutcomeCommitted {
		return out, err
	}
	m := p.input.Meta
	out.Enrollment = mfa.Enrollment{ID: mfa.EnrollmentID(m.FactorID), FactorMethod: state.method, Version: 1, ExpiresAt: m.ExpiresAt}
	if p.applied {
		out.RecoveryMaterial, err = p.recoveryDelivery(ctx)
	}
	return out, err
}

func (s *totpEnrollmentState) requestIntent(r mfa.EnableRequest) (identity.RequestIntent, error) {
	// Deliberate original-custody projection, not implicit export of the
	// redacted public selection value. Nil preserves historical TOTP bytes.
	var otp *otpEnrollmentSelection
	if r.OTP != nil {
		otp = &otpEnrollmentSelection{Channel: r.OTP.Channel, IdentifierID: r.OTP.IdentifierID}
	}
	plain, err := json.Marshal(struct {
		Primary          any
		Reauthentication any
		Policy           mfa.FactorPolicy
		Network          string
		Cookie           bool                    `json:",omitempty"`
		OTP              *otpEnrollmentSelection `json:",omitempty"`
	}{r.PrimaryProof, r.Reauthentication, r.FactorPolicy, r.Network, r.CSRFToken != (session.CSRFToken{}), otp})
	if err != nil || len(plain) > 32768 {
		clear(plain)
		return identity.RequestIntent{}, invalidEnrollment()
	}
	defer clear(plain)
	key := s.config.intentKey()
	digest := func(domain string, raw []byte) []byte {
		mac := hmac.New(sha256.New, key[:])
		_, _ = mac.Write([]byte("mfa-enable-input-v1\x00" + domain + "\x00"))
		_, _ = mac.Write(raw)
		return mac.Sum(nil)
	}
	return identity.NewRequestIntent([]identity.FeatureField{{Name: "mfa.input", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest("body", plain)}}, {Name: "mfa.bearer", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest("session", []byte(r.Session.Token()))}}, {Name: "mfa.configuration", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: slices.Clone(s.identity[:])}}})
}

func destroyEnrollmentDelivery(out *mfa.EnableResult) {
	for _, code := range out.RecoveryMaterial.Codes {
		code.Destroy()
	}
	out.RecoveryMaterial = mfa.RevealOnceCodes{}
}

// Format redacts native configuration and borrowed owners.
func (TOTPEnrollmentService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.TOTPEnrollmentService(redacted)"))
}

// MarshalJSON denies implicit native service export.
func (TOTPEnrollmentService) MarshalJSON() ([]byte, error) { return nil, invalidEnrollment() }

// MarshalText denies implicit native service export.
func (TOTPEnrollmentService) MarshalText() ([]byte, error) { return nil, invalidEnrollment() }
